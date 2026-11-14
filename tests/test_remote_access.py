from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import socketserver
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from proxypilot_app import remote_access as remote
import proxypilot as bridge


class _ConnectHandler(socketserver.BaseRequestHandler):
    response_status = 200
    request_bytes = b""

    def handle(self):
        request = bytearray()
        while not request.endswith(b"\r\n\r\n"):
            data = self.request.recv(1)
            if not data:
                return
            request.extend(data)
            if len(request) > 16384:
                return
        type(self).request_bytes = bytes(request)
        self.request.sendall(f"HTTP/1.1 {type(self).response_status} Test\r\nContent-Length: 0\r\n\r\n".encode())
        if type(self).response_status == 200:
            data = self.request.recv(64)
            if data:
                self.request.sendall(data)


class _ConnectServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class RemoteAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config_dir = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def profile(self, **kwargs):
        values = {"name": "Build server", "host": "build.example.test",
                  "username": "rafael", "use_proxy": True}
        values.update(kwargs)
        return remote.SSHProfile.create(**values)

    def test_profiles_are_atomic_private_and_contain_no_password_field(self):
        profile = self.profile(identity_file="~/.ssh/id_ed25519")
        remote.save_profiles([profile], self.config_dir)
        path = remote.profile_path(self.config_dir)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        raw = path.read_text()
        self.assertNotIn("password", raw.casefold())
        self.assertEqual(remote.load_profiles(self.config_dir), [profile])

    def test_upsert_and_delete_profiles(self):
        profile = self.profile()
        remote.upsert_profile(profile, self.config_dir)
        changed = remote.SSHProfile(profile.profile_id, "Renamed", profile.host,
                                    profile.port, profile.username, None, False)
        self.assertEqual(remote.upsert_profile(changed, self.config_dir), [changed])
        self.assertEqual(remote.delete_profile(profile.profile_id, self.config_dir), [])

    def test_profile_rejects_shell_syntax_and_invalid_ports(self):
        with self.assertRaises(ValueError):
            self.profile(host="server.example;touch /tmp/pwned")
        with self.assertRaises(ValueError):
            self.profile(port=65536)
        with self.assertRaises(ValueError):
            self.profile(username="me\nProxyCommand=evil")

    def test_profile_store_refuses_symlink(self):
        directory = self.config_dir / "remote-access"
        directory.mkdir()
        target = self.config_dir / "target.json"
        target.write_text('{"schema_version":1,"profiles":[]}')
        remote.profile_path(self.config_dir).symlink_to(target)
        with self.assertRaises(remote.RemoteAccessError):
            remote.save_profiles([], self.config_dir)

    def test_profile_store_refuses_fifo_without_blocking(self):
        path = remote.profile_path(self.config_dir)
        path.parent.mkdir(parents=True)
        os.mkfifo(path)
        with self.assertRaises(remote.RemoteAccessError):
            remote.load_profiles(self.config_dir)

    def test_proxy_tunnel_sends_force_proxy_and_preserves_stream(self):
        server = _ConnectServer(("127.0.0.1", 0), _ConnectHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            _ConnectHandler.request_bytes = b""
            with remote.open_proxy_tunnel("build.example.test", 22,
                                          bridge_port=server.server_address[1]) as tunnel:
                tunnel.sendall(b"SSH-2.0-test\r\n")
                self.assertEqual(tunnel.recv(64), b"SSH-2.0-test\r\n")
            request = _ConnectHandler.request_bytes
            self.assertIn(b"CONNECT build.example.test:22 HTTP/1.1", request)
            self.assertIn(remote.FORCE_PROXY_HEADER, request)
        finally:
            server.shutdown()
            server.server_close()

    def test_proxy_tunnel_rejects_upstream_failure_without_direct_fallback(self):
        server = _ConnectServer(("127.0.0.1", 0), _ConnectHandler)
        _ConnectHandler.response_status = 502
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with self.assertRaises(remote.ProxyTunnelError):
                remote.open_proxy_tunnel("build.example.test", 22,
                                        bridge_port=server.server_address[1])
        finally:
            _ConnectHandler.response_status = 200
            server.shutdown()
            server.server_close()

    def test_proxy_listener_force_header_overrides_bypass_but_never_directs(self):
        old = (bridge.HOME, bridge.CFG_DIR, bridge.CFG_FILE)
        remote_socket, bridge_socket = socket.socketpair()
        seen = {}

        def routed(host, port, mode, cfg, *, force_proxy=False):
            seen.update(host=host, port=port, mode=mode, force_proxy=force_proxy)
            return bridge_socket, "proxy"

        try:
            bridge.HOME = self.config_dir
            bridge.CFG_DIR = self.config_dir / ".config/proxypilot"
            bridge.CFG_FILE = bridge.CFG_DIR / "config.json"
            server = bridge.ProxyServer(("127.0.0.1", 0), bridge.ProxyHandler)
            cfg = bridge.load()
            cfg["proxy_port"] = server.server_address[1]
            bridge.save(cfg)
            with patch.object(bridge, "destination_with_route", side_effect=routed), \
                    patch.object(bridge.socket, "create_connection",
                                 side_effect=AssertionError("unexpected direct route")):
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    client = socket.socket()
                    client.settimeout(2)
                    client.connect(server.server_address)
                    with client:
                        client.sendall(b"CONNECT bypass.example.test:22 HTTP/1.1\r\n"
                                       b"Host: bypass.example.test:22\r\n"
                                       b"X-ProxyPilot-Force-Proxy: 1\r\n\r\n")
                        self.assertIn(b"200 Connection Established", client.recv(256))
                    self.assertEqual(seen, {"host": "bypass.example.test", "port": 22,
                                            "mode": "proxy", "force_proxy": True})
                finally:
                    server.shutdown()
                    server.server_close()
        finally:
            remote_socket.close()
            if bridge_socket.fileno() >= 0:
                bridge_socket.close()
            bridge.HOME, bridge.CFG_DIR, bridge.CFG_FILE = old

    def test_host_key_fingerprint_is_sha256(self):
        class Key:
            def get_name(self):
                return "ssh-ed25519"

            def asbytes(self):
                return b"mock-host-key"

        self.assertEqual(remote.fingerprint_sha256(Key().asbytes()),
                         "SHA256:thWzewc3Nm2z1MiI3KITy87HlPz2x6SEoVZHRbYbp3I")

    def test_older_distribution_paramiko_disables_terrapin_algorithm_pair(self):
        old = type("OldParamiko", (), {"__version__": "2.12.0"})
        current = type("CurrentParamiko", (), {"__version__": "3.4.1"})
        disabled = remote._legacy_ssh_algorithm_disables(old)
        self.assertIn("hmac-sha2-256-etm@openssh.com", disabled["macs"])
        self.assertIn("aes128-cbc", disabled["ciphers"])
        self.assertEqual(remote._legacy_ssh_algorithm_disables(current), {})

    def test_host_key_trust_is_pinned_and_changed_key_is_refused(self):
        class Key:
            def __init__(self, raw):
                self.raw = raw

            def get_name(self):
                return "ssh-ed25519"

            def asbytes(self):
                return self.raw

        profile = self.profile()
        trusted = Key(b"one")
        path = remote.trust_host_key(profile, trusted, config_dir=self.config_dir)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertIn("build.example.test ssh-ed25519", path.read_text())
        with self.assertRaises(remote.HostKeyChangedError):
            remote.trust_host_key(profile, Key(b"two"), config_dir=self.config_dir)

    def test_revoked_host_key_cannot_be_pinned_again(self):
        class Key:
            def get_name(self):
                return "ssh-ed25519"

            def asbytes(self):
                return b"revoked-key"

        profile = self.profile()
        path = remote.trust_host_key(profile, Key(), config_dir=self.config_dir)
        line = path.read_text().strip()
        path.write_text("@revoked " + line + "\n")
        path.chmod(0o600)
        with self.assertRaisesRegex(remote.HostKeyChangedError, "revoked"):
            remote.trust_host_key(profile, Key(), config_dir=self.config_dir)


if __name__ == "__main__":
    unittest.main()
