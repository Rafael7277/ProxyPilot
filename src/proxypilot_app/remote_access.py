"""Secure SSH profiles, proxy tunnels, terminal channels, and SFTP transfers."""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import inspect
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import secrets
import socket
import stat
import tempfile
import threading
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Callable


PROFILE_SCHEMA_VERSION = 1
FORCE_PROXY_HEADER = b"X-ProxyPilot-Force-Proxy: 1\r\n"
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_USERNAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class RemoteAccessError(RuntimeError):
    """A safe-to-display SSH/SFTP operation error."""


class ProxyTunnelError(RemoteAccessError):
    """The configured ProxyPilot HTTP CONNECT tunnel could not be opened."""


class UnknownHostKeyError(RemoteAccessError):
    """A server key is new and requires a user-reviewed trust decision."""

    def __init__(self, hostname: str, port: int, key: Any):
        self.hostname = hostname
        self.port = port
        self.key = key
        self.fingerprint = fingerprint_sha256(key.asbytes())
        self.key_type = key.get_name()
        super().__init__(f"Unverified SSH host key for {hostname}:{port} ({self.fingerprint})")


class HostKeyChangedError(RemoteAccessError):
    """A server key differs from a previously trusted key."""


@dataclass(frozen=True)
class SSHProfile:
    profile_id: str
    name: str
    host: str
    port: int
    username: str
    identity_file: str | None = None
    use_proxy: bool = False

    @classmethod
    def create(cls, name: str, host: str, username: str, *, port: int = 22,
               identity_file: str | None = None, use_proxy: bool = False) -> "SSHProfile":
        profile = cls(str(uuid.uuid4()), name, host, port, username,
                      identity_file, use_proxy)
        return validate_profile(profile)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SSHProfile":
        try:
            profile = cls(profile_id=str(value["profile_id"]), name=str(value["name"]),
                          host=str(value["host"]), port=value["port"],
                          username=str(value["username"]),
                          identity_file=value.get("identity_file"),
                          use_proxy=value.get("use_proxy", False))
        except (KeyError, TypeError) as exc:
            raise ValueError("Invalid SSH profile record") from exc
        return validate_profile(profile)


def validate_host(host: str) -> str:
    value = host.strip().rstrip(".")
    if not value or len(value) > 253 or any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise ValueError("Host must be an IP address or DNS name without whitespace")
    if any(char in value for char in "/\\@?#[]"):
        raise ValueError("Host must not contain a URL, path, or user-info")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        pass
    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Host name is not valid IDNA") from exc
    if len(ascii_host) > 253 or any(not _HOST_LABEL.fullmatch(label)
                                    for label in ascii_host.split(".")):
        raise ValueError("Host must be an IP address or valid DNS name")
    return ascii_host.lower()


def validate_profile(profile: SSHProfile) -> SSHProfile:
    try:
        uuid.UUID(profile.profile_id)
    except (ValueError, AttributeError) as exc:
        raise ValueError("SSH profile ID must be a UUID") from exc
    name = profile.name.strip()
    if not name or len(name) > 100 or any(ord(char) < 32 for char in name):
        raise ValueError("Profile name must contain 1 to 100 printable characters")
    host = validate_host(profile.host)
    if isinstance(profile.port, bool) or not isinstance(profile.port, int) or not 1 <= profile.port <= 65535:
        raise ValueError("SSH port must be between 1 and 65535")
    username = profile.username.strip()
    if not _USERNAME.fullmatch(username):
        raise ValueError("Username may contain only letters, numbers, dot, underscore, and hyphen")
    identity_file = profile.identity_file
    if identity_file is not None:
        if not isinstance(identity_file, str) or not identity_file or any(ord(c) < 32 for c in identity_file):
            raise ValueError("Identity file path is invalid")
        identity_file = str(Path(identity_file).expanduser())
    if not isinstance(profile.use_proxy, bool):
        raise ValueError("use_proxy must be a boolean")
    return SSHProfile(profile.profile_id, name, host, profile.port, username,
                      identity_file, profile.use_proxy)


def _remote_dir(config_dir: Path | None = None) -> Path:
    if config_dir is not None:
        base = Path(config_dir)
    else:
        xdg = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")).expanduser()
        base = xdg / "proxypilot"
    return base / "remote-access"


def _ensure_remote_dir(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if directory.is_symlink() or not directory.is_dir():
        raise RemoteAccessError(f"Unsafe SSH data directory: {directory}")
    if directory.stat().st_uid != os.getuid():
        raise RemoteAccessError("SSH data directory is not owned by the current user")
    os.chmod(directory, 0o700)


def profile_path(config_dir: Path | None = None) -> Path:
    return _remote_dir(config_dir) / "profiles.json"


def known_hosts_path(config_dir: Path | None = None) -> Path:
    return _remote_dir(config_dir) / "known_hosts"


def load_profiles(config_dir: Path | None = None) -> list[SSHProfile]:
    path = profile_path(config_dir)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise RemoteAccessError(f"Cannot safely open SSH profiles: {exc}") from exc
    try:
        info = os.fstat(fd)
        if (info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or
                info.st_mode & 0o077):
            raise RemoteAccessError("SSH profile file is not a regular file owned by the current user")
        if info.st_size > 1024 * 1024:
            raise RemoteAccessError("SSH profile file exceeds the 1 MiB safety limit")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = -1
            raw = stream.read()
    except OSError as exc:
        raise RemoteAccessError(f"Cannot read SSH profiles: {exc}") from exc
    finally:
        if isinstance(fd, int) and fd >= 0:
            os.close(fd)
    try:
        document = json.loads(raw)
        if document.get("schema_version") != PROFILE_SCHEMA_VERSION or not isinstance(document.get("profiles"), list):
            raise ValueError("Unsupported SSH profile file format")
        profiles = [SSHProfile.from_dict(item) for item in document["profiles"]]
    except (json.JSONDecodeError, AttributeError, TypeError, ValueError) as exc:
        raise RemoteAccessError(f"Invalid SSH profile file: {exc}") from exc
    ids = [profile.profile_id for profile in profiles]
    if len(ids) != len(set(ids)):
        raise RemoteAccessError("SSH profile file contains duplicate profile IDs")
    return profiles


def save_profiles(profiles: list[SSHProfile], config_dir: Path | None = None) -> Path:
    directory = _remote_dir(config_dir)
    _ensure_remote_dir(directory)
    path = directory / "profiles.json"
    if path.is_symlink():
        raise RemoteAccessError("Refusing to replace SSH profiles through a symbolic link")
    if path.exists() and (not path.is_file() or path.stat().st_uid != os.getuid()):
        raise RemoteAccessError("SSH profile file is not a regular file owned by the current user")
    checked = [validate_profile(profile) for profile in profiles]
    ids = [profile.profile_id for profile in checked]
    if len(ids) != len(set(ids)):
        raise ValueError("SSH profile IDs must be unique")
    payload = json.dumps({"schema_version": PROFILE_SCHEMA_VERSION,
                          "profiles": [asdict(profile) for profile in checked]},
                         ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    fd, temp_name = tempfile.mkstemp(prefix=".profiles.", suffix=".tmp", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
        os.chmod(path, 0o600)
        dir_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise
    return path


def upsert_profile(profile: SSHProfile, config_dir: Path | None = None) -> list[SSHProfile]:
    profile = validate_profile(profile)
    profiles = load_profiles(config_dir)
    replaced = False
    result = []
    for existing in profiles:
        if existing.profile_id == profile.profile_id:
            result.append(profile)
            replaced = True
        else:
            result.append(existing)
    if not replaced:
        result.append(profile)
    save_profiles(result, config_dir)
    return result


def delete_profile(profile_id: str, config_dir: Path | None = None) -> list[SSHProfile]:
    try:
        canonical_id = str(uuid.UUID(profile_id))
    except ValueError as exc:
        raise ValueError("SSH profile ID must be a UUID") from exc
    profiles = [profile for profile in load_profiles(config_dir)
                if profile.profile_id != canonical_id]
    save_profiles(profiles, config_dir)
    return profiles


def fingerprint_sha256(key_blob: bytes) -> str:
    digest = hashlib.sha256(key_blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _connect_header(host: str, port: int) -> bytes:
    canonical = validate_host(host)
    authority_host = f"[{canonical}]" if ":" in canonical else canonical
    return (f"CONNECT {authority_host}:{port} HTTP/1.1\r\n"
            f"Host: {authority_host}:{port}\r\n").encode("ascii") + FORCE_PROXY_HEADER + b"Connection: keep-alive\r\n\r\n"


def open_proxy_tunnel(host: str, port: int, *, bridge_host: str = "127.0.0.1",
                      bridge_port: int = 18789, timeout: float = 10.0) -> socket.socket:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("SSH port must be between 1 and 65535")
    if isinstance(bridge_port, bool) or not isinstance(bridge_port, int) or not 1 <= bridge_port <= 65535:
        raise ValueError("ProxyPilot bridge port must be between 1 and 65535")
    if bridge_host == "localhost":
        # Avoid resolving localhost through a user-controlled hosts or NSS entry.
        bridge_host = "127.0.0.1"
    try:
        bridge_address = ipaddress.ip_address(bridge_host)
    except ValueError as exc:
        raise ValueError("ProxyPilot bridge must use a loopback IP address") from exc
    if not bridge_address.is_loopback:
        raise ValueError("ProxyPilot bridge must use a loopback address")
    sock = socket.create_connection((bridge_host, bridge_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(_connect_header(host, port))
        response = bytearray()
        while not response.endswith(b"\r\n\r\n"):
            chunk = sock.recv(1)
            if not chunk:
                raise ProxyTunnelError("ProxyPilot closed the CONNECT handshake")
            response.extend(chunk)
            if len(response) > 16384:
                raise ProxyTunnelError("ProxyPilot returned oversized CONNECT headers")
        status_line = bytes(response).split(b"\r\n", 1)[0].split()
        if len(status_line) < 2 or status_line[0] not in (b"HTTP/1.0", b"HTTP/1.1"):
            raise ProxyTunnelError("ProxyPilot returned an invalid CONNECT response")
        if status_line[1] != b"200":
            detail = status_line[2].decode("ascii", "replace") if len(status_line) > 2 else "connection refused"
            raise ProxyTunnelError(f"ProxyPilot proxy tunnel failed: HTTP {status_line[1].decode()} {detail}")
        sock.settimeout(None)
        return sock
    except Exception:
        sock.close()
        raise


def _paramiko():
    try:
        import paramiko
    except ImportError as exc:
        raise RemoteAccessError("SSH support requires Paramiko. Install python3-paramiko and retry.") from exc
    return paramiko


def _host_key_policy(paramiko: Any, profile: SSHProfile):
    class RejectAndReport(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            raise UnknownHostKeyError(profile.host, profile.port, key)
    return RejectAndReport()


def _legacy_ssh_algorithm_disables(paramiko: Any) -> dict[str, list[str]]:
    """Mitigate the Terrapin-vulnerable algorithm pair on distro-patched 2.x builds."""
    match = re.match(r"^(\d+)\.(\d+)", str(getattr(paramiko, "__version__", "")))
    if match and tuple(map(int, match.groups())) >= (3, 4):
        return {}
    # Paramiko 3.4 added strict key exchange. Older distro builds may backport
    # security fixes without changing the upstream version, so also disable the
    # affected ETM MACs and CBC ciphers when their version string predates 3.4.
    return {
        "macs": ["hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"],
        "ciphers": ["aes128-cbc", "aes192-cbc", "aes256-cbc"],
    }


def connect_profile(profile: SSHProfile, *, password: str | None = None,
                    passphrase: str | None = None, timeout: float = 15.0,
                    config_dir: Path | None = None, paramiko_module: Any = None) -> "RemoteSession":
    profile = validate_profile(profile)
    paramiko = paramiko_module or _paramiko()
    client = paramiko.SSHClient()
    tunnel = None
    try:
        client.load_system_host_keys()
        known_hosts = known_hosts_path(config_dir)
        try:
            fd = os.open(known_hosts, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0))
        except FileNotFoundError:
            fd = None
        except OSError as exc:
            raise RemoteAccessError(f"Cannot safely open SSH host keys: {exc}") from exc
        if fd is not None:
            try:
                info = os.fstat(fd)
                if (info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or
                        info.st_mode & 0o077 or info.st_nlink != 1):
                    raise RemoteAccessError("SSH host key file is not a private regular file owned by the current user")
                if info.st_size > 8 * 1024 * 1024:
                    raise RemoteAccessError("SSH host key file exceeds the 8 MiB safety limit")
            finally:
                os.close(fd)
            client.load_host_keys(str(known_hosts))
        client.set_missing_host_key_policy(_host_key_policy(paramiko, profile))
        if profile.use_proxy:
            import proxypilot as bridge
            config = bridge.load()
            tunnel = open_proxy_tunnel(profile.host, profile.port,
                                       bridge_port=int(config["proxy_port"]), timeout=timeout)
        else:
            tunnel = socket.create_connection((profile.host, profile.port), timeout=timeout)
        connect_options = {
            "hostname": profile.host,
            "port": profile.port,
            "username": profile.username,
            "password": password,
            "passphrase": passphrase,
            "key_filename": profile.identity_file,
            "sock": tunnel,
            "timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout,
            "allow_agent": True,
            "look_for_keys": True,
            "disabled_algorithms": _legacy_ssh_algorithm_disables(paramiko),
        }
        try:
            parameters = inspect.signature(client.connect).parameters
        except (TypeError, ValueError):
            parameters = {}
        if "channel_timeout" in parameters:
            connect_options["channel_timeout"] = timeout
        client.connect(**connect_options)
        return RemoteSession(client, profile, tunnel)
    except Exception:
        try:
            client.close()
        except Exception:
            pass
        if tunnel is not None:
            try:
                tunnel.close()
            except OSError:
                pass
        raise


def _known_host_token(profile: SSHProfile) -> str:
    host = validate_host(profile.host)
    return host if profile.port == 22 else f"[{host}]:{profile.port}"


def trust_host_key(profile: SSHProfile, key: Any, *, config_dir: Path | None = None) -> Path:
    """Persist a key only after the caller has obtained explicit user approval."""
    profile = validate_profile(profile)
    directory = _remote_dir(config_dir)
    _ensure_remote_dir(directory)
    path = directory / "known_hosts"
    if path.is_symlink():
        raise RemoteAccessError("Refusing to replace SSH host keys through a symbolic link")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RemoteAccessError("SSH host key file is not a private regular file owned by the current user")
        if info.st_size > 8 * 1024 * 1024:
            raise RemoteAccessError("SSH host key file exceeds the 8 MiB safety limit")
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        with os.fdopen(os.dup(fd), "r+", encoding="utf-8") as stream:
            text = stream.read()
            token = _known_host_token(profile)
            for raw_line in text.splitlines():
                fields = raw_line.split()
                if not fields or raw_line.startswith("#"):
                    continue
                offset = 1 if fields[0].startswith("@") else 0
                if len(fields) < offset + 3:
                    continue
                patterns = fields[offset].split(",")
                if not any(_known_host_pattern_matches(pattern, token) for pattern in patterns):
                    continue
                if (fields[0] == "@revoked" and
                        fields[offset + 1] == key.get_name() and
                        fields[offset + 2] == base64.b64encode(key.asbytes()).decode("ascii")):
                    raise HostKeyChangedError(f"The host key for {token} is marked revoked")
                if (fields[offset + 1] == key.get_name() and
                        fields[offset + 2] == base64.b64encode(key.asbytes()).decode("ascii")):
                    return path
                raise HostKeyChangedError(f"A different host key is already trusted for {token}")
            line = f"{token} {key.get_name()} {base64.b64encode(key.asbytes()).decode('ascii')}\n"
            stream.seek(0, os.SEEK_END)
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(fd)
    return path


def _known_host_pattern_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("|1|"):
        try:
            _, version, salt_text, digest_text = pattern.split("|")
            if version != "1":
                return False
            salt = base64.b64decode(salt_text, validate=True)
            expected = base64.b64decode(digest_text, validate=True)
            actual = hmac.new(salt, host.encode("utf-8"), hashlib.sha1).digest()
            return hmac.compare_digest(actual, expected)
        except (ValueError, TypeError):
            return False
    return pattern == host


def _sftp(session: "RemoteSession"):
    if session.closed:
        raise RemoteAccessError("SSH connection is closed")
    if session.sftp is None:
        session.sftp = session.client.open_sftp()
    return session.sftp


def list_remote(session: "RemoteSession", path: str) -> list[dict[str, Any]]:
    if "\x00" in path:
        raise ValueError("Remote path contains a NUL byte")
    entries = _sftp(session).listdir_attr(path)
    items = []
    for entry in entries:
        mode = entry.st_mode or 0
        items.append({"name": entry.filename, "size": entry.st_size,
                      "is_dir": stat.S_ISDIR(mode), "is_symlink": stat.S_ISLNK(mode),
                      "mtime": entry.st_mtime})
    return sorted(items, key=lambda item: (not item["is_dir"], item["name"].casefold()))


def _remote_child(path: str, name: str) -> str:
    if (not name or name in (".", "..") or "/" in name or "\\" in name or
            "\x00" in name or any(ord(char) < 32 for char in name)):
        raise ValueError("Remote file name must be a single safe path component")
    return posixpath.join(path, name)


def create_remote_directory(session: "RemoteSession", directory: str, name: str) -> str:
    path = _remote_child(directory, name)
    _sftp(session).mkdir(path)
    return path


def rename_remote(session: "RemoteSession", path: str, new_name: str) -> str:
    source = PurePosixPath(path)
    if source.name in ("", ".", ".."):
        raise ValueError("Refusing to rename a remote root directory")
    destination = _remote_child(str(source.parent), new_name)
    sftp = _sftp(session)
    if _remote_exists(sftp, destination):
        raise FileExistsError("Remote destination already exists")
    sftp.rename(path, destination)
    return destination


def delete_remote(session: "RemoteSession", path: str, *, is_dir: bool = False) -> None:
    source = PurePosixPath(path)
    if source.name in ("", ".", ".."):
        raise ValueError("Refusing to delete a remote root directory")
    sftp = _sftp(session)
    if is_dir:
        sftp.rmdir(path)  # Deliberately non-recursive: only empty folders can be removed.
    else:
        sftp.remove(path)


def list_local(path: str | Path) -> list[dict[str, Any]]:
    directory = Path(path).expanduser().resolve(strict=True)
    if not directory.is_dir():
        raise ValueError("Local path is not a directory")
    items = []
    for entry in directory.iterdir():
        try:
            info = entry.lstat()
        except OSError:
            continue
        if stat.S_ISLNK(info.st_mode):
            continue
        items.append({"name": entry.name, "size": info.st_size,
                      "is_dir": stat.S_ISDIR(info.st_mode), "is_symlink": False,
                      "mtime": int(info.st_mtime)})
    return sorted(items, key=lambda item: (not item["is_dir"], item["name"].casefold()))


def _remote_exists(sftp: Any, path: str) -> bool:
    try:
        sftp.stat(path)
        return True
    except OSError as exc:
        if getattr(exc, "errno", None) == 2 or str(exc).casefold() in ("no such file", "no such file or directory"):
            return False
        raise


def _get_sftp_file(sftp: Any, remote_path: str, local_path: str,
                   progress: Callable[[int, int], None] | None) -> None:
    kwargs: dict[str, Any] = {"callback": progress}
    try:
        parameters = inspect.signature(sftp.get).parameters
    except (TypeError, ValueError):
        parameters = {}
    if "max_concurrent_prefetch_requests" in parameters:
        kwargs["max_concurrent_prefetch_requests"] = 16
    sftp.get(remote_path, local_path, **kwargs)


def upload_file(session: "RemoteSession", local_path: str | Path, remote_path: str, *,
                overwrite: bool = False,
                progress: Callable[[int, int], None] | None = None) -> None:
    requested_source = Path(local_path).expanduser()
    if requested_source.is_symlink():
        raise ValueError("Upload source must not be a symbolic link")
    source = requested_source.resolve(strict=True)
    if not source.is_file():
        raise ValueError("Upload source must be a regular local file")
    if (not remote_path or "\x00" in remote_path or
            PurePosixPath(remote_path).name in ("", ".", "..")):
        raise ValueError("Remote destination path is invalid")
    sftp = _sftp(session)
    if not overwrite and _remote_exists(sftp, remote_path):
        raise FileExistsError("Remote destination already exists")
    temp_path = str(PurePosixPath(remote_path).with_name(
        f".{PurePosixPath(remote_path).name}.proxypilot-{secrets.token_hex(8)}.part"))
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(source, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Upload source must be a regular local file")
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                sftp.putfo(stream, temp_path, file_size=info.st_size,
                           callback=progress, confirm=True)
        finally:
            if fd >= 0:
                os.close(fd)
        if not overwrite and _remote_exists(sftp, remote_path):
            raise FileExistsError("Remote destination appeared during transfer")
        if overwrite and _remote_exists(sftp, remote_path):
            backup_path = str(PurePosixPath(remote_path).with_name(
                f".{PurePosixPath(remote_path).name}.proxypilot-{secrets.token_hex(8)}.backup"))
            sftp.rename(remote_path, backup_path)
            try:
                sftp.rename(temp_path, remote_path)
            except Exception as replacement_error:
                try:
                    sftp.rename(backup_path, remote_path)
                except Exception as restore_error:
                    raise RemoteAccessError(
                        f"Upload replacement failed; the previous file remains at {backup_path} "
                        f"because it could not be restored ({type(restore_error).__name__})"
                    ) from replacement_error
                raise
            try:
                sftp.remove(backup_path)
            except OSError:
                pass
        else:
            sftp.rename(temp_path, remote_path)
    except Exception:
        try:
            sftp.remove(temp_path)
        except OSError:
            pass
        raise


def download_file(session: "RemoteSession", remote_path: str, local_path: str | Path, *,
                  overwrite: bool = False,
                  progress: Callable[[int, int], None] | None = None) -> None:
    if not remote_path or "\x00" in remote_path:
        raise ValueError("Remote source path is invalid")
    destination = Path(local_path).expanduser()
    if not destination.name or destination.name in (".", ".."):
        raise ValueError("Local destination must name a file")
    parent = destination.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("Local destination parent is not a directory")
    final_path = parent / destination.name
    if final_path.is_symlink():
        raise RemoteAccessError("Refusing to overwrite a symbolic link")
    if final_path.exists() and not overwrite:
        raise FileExistsError("Local destination already exists")
    fd, temp_name = tempfile.mkstemp(prefix=f".{final_path.name}.", suffix=".part", dir=parent)
    os.close(fd)
    temp_path = Path(temp_name)
    try:
        _get_sftp_file(_sftp(session), remote_path, str(temp_path), progress)
        if overwrite:
            os.replace(temp_path, final_path)
        else:
            os.link(temp_path, final_path, follow_symlinks=False)
            temp_path.unlink()
    except Exception:
        try:
            temp_path.unlink()
        except OSError:
            pass
        raise


class RemoteSession:
    """One authenticated SSH transport shared by its shell and SFTP channels."""

    def __init__(self, client: Any, profile: SSHProfile, tunnel: socket.socket):
        self.client = client
        self.profile = profile
        self.tunnel = tunnel
        self.sftp = None
        self.shell = None
        self.closed = False
        self._lock = threading.RLock()

    def open_shell(self, *, term: str = "xterm-256color", width: int = 80,
                   height: int = 24):
        with self._lock:
            if self.closed:
                raise RemoteAccessError("SSH connection is closed")
            if self.shell is not None and not self.shell.closed:
                return self.shell
            shell = self.client.invoke_shell(term=term, width=max(20, width),
                                             height=max(5, height))
            shell.settimeout(0.2)
            self.shell = shell
            return shell

    def resize_shell(self, width: int, height: int) -> None:
        with self._lock:
            if self.shell is not None and not self.shell.closed:
                self.shell.resize_pty(width=max(20, width), height=max(5, height))

    def close(self) -> None:
        with self._lock:
            if self.closed:
                return
            self.closed = True
            for resource in (self.shell, self.sftp, self.client, self.tunnel):
                try:
                    if resource is not None:
                        resource.close()
                except Exception:
                    pass


__all__ = ["SSHProfile", "RemoteAccessError", "ProxyTunnelError",
           "UnknownHostKeyError", "HostKeyChangedError", "connect_profile",
           "create_remote_directory", "delete_profile", "delete_remote", "download_file",
           "fingerprint_sha256", "list_local",
           "list_remote", "load_profiles", "open_proxy_tunnel", "profile_path",
           "rename_remote", "save_profiles", "trust_host_key", "upsert_profile", "upload_file"]
