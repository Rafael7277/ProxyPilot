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


if __name__ == "__main__":
    unittest.main()
