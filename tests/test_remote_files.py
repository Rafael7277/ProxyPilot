from __future__ import annotations

import errno
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from proxypilot_app import remote_access


class LocalSFTP:
    """Small SFTP protocol double backed by a temporary directory."""

    def __init__(self, root: Path):
        self.root = root

    def _path(self, remote: str) -> Path:
        value = PurePosixPath(remote)
        if value.is_absolute():
            value = PurePosixPath(*value.parts[1:])
        path = self.root.joinpath(*value.parts)
        resolved = path.resolve(strict=False)
        if resolved != self.root and self.root not in resolved.parents:
            raise PermissionError("path escapes mock server root")
        return path

    def stat(self, path: str):
        return self._path(path).stat()

    def lstat(self, path: str):
        return self._path(path).lstat()

    def open(self, path: str, mode: str = "r"):
        return self._path(path).open(mode)

    def listdir_attr(self, path: str):
        result = []
        for item in self._path(path).iterdir():
            info = item.lstat()
            result.append(SimpleNamespace(filename=item.name, st_mode=info.st_mode,
                                          st_size=info.st_size, st_mtime=int(info.st_mtime)))
        return result

    def putfo(self, stream, remote: str, *, file_size=0, callback=None, confirm=True):
        destination = self._path(remote)
        copied = 0
        with destination.open("wb") as target:
            while True:
                block = stream.read(32768)
                if not block:
                    break
                target.write(block)
                copied += len(block)
                if callback:
                    callback(copied, file_size)
        if confirm:
            self.stat(remote)

    def get(self, remote: str, local: str, *, callback=None, max_concurrent_prefetch_requests=None):
        total = self._path(remote).stat().st_size
        copied = 0
        with self._path(remote).open("rb") as source, open(local, "wb") as target:
            while True:
                block = source.read(32768)
                if not block:
                    break
                target.write(block)
                copied += len(block)
                if callback:
                    callback(copied, total)

    def rename(self, source: str, destination: str):
        target = self._path(destination)
        if target.exists():
            raise OSError(errno.EEXIST, "File exists")
        self._path(source).rename(target)

    def remove(self, path: str):
        self._path(path).unlink()

    def mkdir(self, path: str):
        self._path(path).mkdir()

    def rmdir(self, path: str):
        self._path(path).rmdir()


class FailingWriter:
    def __init__(self, stream, *, fail_after: int):
        self.stream = stream
        self.fail_after = fail_after
        self.written = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()

    def seek(self, offset: int):
        self.written = offset
        return self.stream.seek(offset)

    def write(self, data: bytes):
        if self.written >= self.fail_after:
            raise OSError(errno.ECONNRESET, "test connection dropped")
        remaining = self.fail_after - self.written
        written = self.stream.write(data[:remaining])
        self.written += written
        if written < len(data):
            raise OSError(errno.ECONNRESET, "test connection dropped")
        return written

    def flush(self):
        return self.stream.flush()

    def fileno(self):
        return self.stream.fileno()


class FailingOnceSFTP(LocalSFTP):
    def __init__(self, root: Path):
        super().__init__(root)
        self.fail_next_write = True

    def open(self, path: str, mode: str = "r"):
        stream = super().open(path, mode)
        if mode == "xb" and self.fail_next_write:
            self.fail_next_write = False
            return FailingWriter(stream, fail_after=8192)
        return stream


class RemoteFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.server = self.root / "server"
        self.server.mkdir()
        self.sftp = LocalSFTP(self.server)
        self.session = SimpleNamespace(closed=False, client=None, sftp=self.sftp)
        self.local = self.root / "local"
        self.local.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_upload_and_download_are_complete_and_report_progress(self):
        source = self.local / "payload.bin"
        source.write_bytes(b"payload" * 20000)
        upload_progress = []
        remote_access.upload_file(self.session, source, "/payload.bin",
                                  progress=lambda done, total: upload_progress.append((done, total)))
        self.assertEqual((self.server / "payload.bin").read_bytes(), source.read_bytes())
        self.assertTrue(upload_progress)
        self.assertEqual(upload_progress[-1], (source.stat().st_size, source.stat().st_size))

        destination = self.local / "download.bin"
        download_progress = []
        remote_access.download_file(self.session, "/payload.bin", destination,
                                    progress=lambda done, total: download_progress.append((done, total)))
        self.assertEqual(destination.read_bytes(), source.read_bytes())
        self.assertEqual(download_progress[-1], (source.stat().st_size, source.stat().st_size))
        self.assertFalse(list(self.server.glob("*.part")))
        self.assertFalse(list(self.local.glob("*.part")))

    def test_download_supports_paramiko_versions_without_prefetch_limit_argument(self):
        source = self.server / "legacy.txt"
        source.write_text("compatible")

        class OlderSFTP(LocalSFTP):
            def get(self, remote: str, local: str, *, callback=None):
                return super().get(remote, local, callback=callback)

        self.session.sftp = OlderSFTP(self.server)
        destination = self.local / "legacy.txt"
        remote_access.download_file(self.session, "/legacy.txt", destination)
        self.assertEqual(destination.read_text(), "compatible")

    def test_overwrite_requires_explicit_flag_and_preserves_new_content(self):
        source = self.local / "payload.txt"
        source.write_text("replacement")
        (self.server / "payload.txt").write_text("old")
        with self.assertRaises(FileExistsError):
            remote_access.upload_file(self.session, source, "/payload.txt")
        remote_access.upload_file(self.session, source, "/payload.txt", overwrite=True)
        self.assertEqual((self.server / "payload.txt").read_text(), "replacement")
        self.assertFalse(list(self.server.glob("*.backup")))

        destination = self.local / "payload.txt"
        destination.write_text("old local")
        with self.assertRaises(FileExistsError):
            remote_access.download_file(self.session, "/payload.txt", destination)
        remote_access.download_file(self.session, "/payload.txt", destination, overwrite=True)
        self.assertEqual(destination.read_text(), "replacement")

    def test_failed_remote_replacement_reports_preserved_backup_path(self):
        source = self.local / "payload.txt"
        source.write_text("replacement")
        (self.server / "payload.txt").write_text("original")

        class FailingReplacement(LocalSFTP):
            def rename(self, source: str, destination: str):
                if destination == "/payload.txt":
                    raise OSError("server refused replacement")
                return super().rename(source, destination)

        self.session.sftp = FailingReplacement(self.server)
        with self.assertRaisesRegex(remote_access.RemoteAccessError, "previous file remains at"):
            remote_access.upload_file(self.session, source, "/payload.txt", overwrite=True)
        backups = list(self.server.glob(".*.backup"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_text(), "original")

    def test_transfer_refuses_symlinks_and_invalid_remote_paths(self):
        outside = self.root / "outside"
        outside.write_text("private")
        upload_link = self.local / "link"
        upload_link.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            remote_access.upload_file(self.session, upload_link, "/linked")

        download_link = self.local / "destination"
        download_link.symlink_to(outside)
        (self.server / "source").write_text("remote")
        with self.assertRaises(remote_access.RemoteAccessError):
            remote_access.download_file(self.session, "/source", download_link, overwrite=True)
        with self.assertRaises(ValueError):
            remote_access.create_remote_directory(self.session, "/", "../escape")
        self.assertFalse((self.root / "escape").exists())

    def test_remote_file_operations_are_single_component_and_non_recursive(self):
        remote_access.create_remote_directory(self.session, "/", "folder")
        (self.server / "folder" / "child.txt").write_text("keep")
        items = remote_access.list_remote(self.session, "/")
        self.assertEqual(items[0]["name"], "folder")
        self.assertTrue(items[0]["is_dir"])
        renamed = remote_access.rename_remote(self.session, "/folder", "renamed")
        self.assertEqual(renamed, "/renamed")
        with self.assertRaises(OSError):
            remote_access.delete_remote(self.session, "/renamed", is_dir=True)
        self.assertTrue((self.server / "renamed" / "child.txt").exists())
        remote_access.delete_remote(self.session, "/renamed/child.txt")
        remote_access.delete_remote(self.session, "/renamed", is_dir=True)
        with self.assertRaises(ValueError):
            remote_access.delete_remote(self.session, "/")

    def test_missing_remote_destination_is_reported_as_absent(self):
        self.assertFalse(remote_access._remote_exists(self.sftp, "/missing"))

        class Denied:
            def stat(self, _path):
                raise PermissionError(errno.EACCES, "permission denied")

        with self.assertRaises(PermissionError):
            remote_access._remote_exists(Denied(), "/private")

    def test_new_files_and_folders_rename_and_delete_local_and_remote(self):
        local_file = remote_access.create_local_file(self.local, "notes.txt")
        local_folder = remote_access.create_local_directory(self.local, "new-folder")
        with self.assertRaises(FileExistsError):
            remote_access.create_local_file(self.local, "notes.txt")
        local_file.write_text("hello")
        renamed_local = remote_access.rename_local(local_file, "renamed.txt")
        self.assertEqual(renamed_local.read_text(), "hello")
        remote_access.delete_local(renamed_local)
        remote_access.delete_local(local_folder, is_dir=True)

        remote_file = remote_access.create_remote_file(self.session, "/", "notes.txt")
        remote_folder = remote_access.create_remote_directory(self.session, "/", "new-folder")
        with self.assertRaises(FileExistsError):
            remote_access.create_remote_file(self.session, "/", "notes.txt")
        self.sftp._path(remote_file).write_text("remote")
        renamed_remote = remote_access.rename_remote_to(
            self.session, remote_file, "/renamed.txt")
        self.assertEqual(self.sftp._path(renamed_remote).read_text(), "remote")
        remote_access.delete_remote(self.session, renamed_remote)
        remote_access.delete_remote(self.session, remote_folder, is_dir=True)

    def test_file_copy_and_move_work_between_local_and_remote_endpoints(self):
        source = self.local / "upload.txt"
        source.write_text("local payload")
        uploaded = remote_access.transfer_entry(None, source, self.session, "/")
        self.assertEqual(self.sftp._path(uploaded).read_text(), "local payload")
        download_dir = self.root / "downloaded"
        download_dir.mkdir()
        downloaded = remote_access.transfer_entry(self.session, uploaded, None,
                                                  download_dir)
        self.assertEqual(Path(downloaded).read_text(), "local payload")

        self.sftp.mkdir("/moved")
        moved = remote_access.transfer_entry(None, source, self.session, "/moved",
                                             move=True)
        self.assertEqual(self.sftp._path(moved).read_text(), "local payload")
        self.assertFalse(source.exists())

    def test_remote_to_remote_move_copies_directory_before_removing_source(self):
        destination_root = self.root / "server-destination"
        destination_root.mkdir()
        destination_sftp = LocalSFTP(destination_root)
        destination_session = SimpleNamespace(closed=False, client=None,
                                              sftp=destination_sftp)
        source_folder = self.server / "release"
        (source_folder / "nested").mkdir(parents=True)
        (source_folder / "bundle.txt").write_text("bundle")
        (source_folder / "nested" / "part.txt").write_text("part")

        result = remote_access.transfer_entry(
            self.session, "/release", destination_session, "/", move=True)

        self.assertEqual(destination_sftp._path(result + "/bundle.txt").read_text(), "bundle")
        self.assertEqual(destination_sftp._path(result + "/nested/part.txt").read_text(), "part")
        self.assertFalse(source_folder.exists())
        self.assertFalse(list(destination_root.glob(".*.part")))

    def test_directory_copy_rejects_symlinks_and_cleans_staged_destination(self):
        source_folder = self.server / "linked"
        source_folder.mkdir()
        outside = self.root / "outside.txt"
        outside.write_text("private")
        (source_folder / "shortcut").symlink_to(outside)
        with self.assertRaisesRegex(remote_access.RemoteAccessError, "symbolic link"):
            remote_access.transfer_entry(self.session, "/linked", None, self.local)
        self.assertFalse((self.local / "linked").exists())
        self.assertFalse(list(self.local.glob(".linked.proxypilot-*")))

    def test_cancelled_copy_does_not_publish_a_partial_file(self):
        source = self.local / "payload.bin"
        source.write_bytes(b"payload" * 20000)
        cancelled = __import__("threading").Event()
        cancelled.set()
        with self.assertRaises(InterruptedError):
            remote_access.transfer_entry(None, source, self.session, "/",
                                         cancel=cancelled)
        self.assertFalse((self.server / "payload.bin").exists())
        self.assertFalse(list(self.server.glob("*.part")))

    def test_file_transfer_resumes_from_preserved_partial_after_connection_loss(self):
        source = self.local / "resumable.bin"
        payload = bytes(range(256)) * 4096
        source.write_bytes(payload)
        self.session.sftp = FailingOnceSFTP(self.server)
        resume_id = "a" * 32
        with self.assertRaises(OSError) as raised:
            remote_access.transfer_entry(None, source, self.session, "/",
                                         resume_id=resume_id)
        self.assertEqual(raised.exception.errno, errno.ECONNRESET)
        partial = self.server / f".resumable.bin.proxypilot-{resume_id}.part"
        self.assertGreater(partial.stat().st_size, 0)
        self.assertLess(partial.stat().st_size, len(payload))

        remote_access.transfer_entry(None, source, self.session, "/",
                                     resume_id=resume_id)
        self.assertEqual((self.server / "resumable.bin").read_bytes(), payload)
        self.assertFalse(partial.exists())

    def test_directory_transfer_resumes_current_file_after_connection_loss(self):
        source = self.local / "bundle"
        source.mkdir()
        payload = b"directory-payload" * 12000
        (source / "payload.bin").write_bytes(payload)
        self.session.sftp = FailingOnceSFTP(self.server)
        resume_id = "b" * 32

        with self.assertRaises(OSError) as raised:
            remote_access.transfer_entry(None, source, self.session, "/",
                                         resume_id=resume_id)
        self.assertEqual(raised.exception.errno, errno.ECONNRESET)
        self.assertTrue((self.server / f".proxypilot-{resume_id}.part").is_dir())

        result = remote_access.transfer_entry(None, source, self.session, "/",
                                              resume_id=resume_id)
        self.assertEqual(self.sftp._path(str(result) + "/payload.bin").read_bytes(), payload)
        self.assertFalse((self.server / f".proxypilot-{resume_id}.part").exists())

    def test_session_fork_keeps_child_sftp_channel_alive(self):
        class Resource:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        class Client(Resource):
            def __init__(self):
                super().__init__()
                self.channels = []

            def open_sftp(self):
                channel = Resource()
                self.channels.append(channel)
                return channel

        client = Client()
        tunnel = Resource()
        profile = remote_access.SSHProfile.create("lease", "127.0.0.1", "user")
        parent = remote_access.RemoteSession(client, profile, tunnel)
        child = parent.fork()
        parent_sftp = remote_access._sftp(parent)
        child_sftp = remote_access._sftp(child)
        self.assertIsNot(parent_sftp, child_sftp)

        parent.close()
        self.assertTrue(parent_sftp.closed)
        self.assertFalse(client.closed)
        self.assertFalse(tunnel.closed)
        self.assertFalse(child.closed)
        self.assertIs(remote_access._sftp(child), child_sftp)

        child.close()
        self.assertTrue(client.closed)
        self.assertTrue(tunnel.closed)


if __name__ == "__main__":
    unittest.main()
