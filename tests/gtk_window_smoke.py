"""Small display-backed GTK smoke test for the SSH child windows and profile list."""
from __future__ import annotations

import json
import errno
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import tempfile
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from proxypilot_app import remote_access
from proxypilot_app.remote_ui import RemoteAccessPage
from proxypilot_app import remote_ui
from proxypilot_app import remote_windows
from proxypilot_app.remote_windows import RemoteFileManagerWindow, RemoteTerminalWindow


class _DialogStub:
    def destroy(self) -> None:
        pass


class _FlowStub:
    attempts: list[str | None] = []
    instances: list["_FlowStub"] = []

    def __init__(self, _parent, profile, on_connected, on_status, on_failed,
                 on_secret=None):
        self.profile = profile
        self.on_connected = on_connected
        self.on_status = on_status
        self.on_failed = on_failed
        self.on_secret = on_secret or (lambda _secret: None)
        self.cancelled = False
        self.instances.append(self)

    def connect(self, password: str | None = None) -> None:
        self.attempts.append(password)
        if password:
            self.on_secret(password)

    def cancel(self) -> None:
        self.cancelled = True


class _SessionStub:
    class _Shell:
        def __init__(self):
            self.closed = False

        def settimeout(self, _value):
            pass

        def sendall(self, _data):
            pass

        def recv_ready(self):
            return False

        def close(self):
            self.closed = True

    def __init__(self, profile, transport=None):
        self.profile = profile
        self.closed = False
        self.transport = transport or object()
        self.client = self.transport
        self.host_fingerprint = "SHA256:smoke-fingerprint"
        self.host_key_type = "ssh-ed25519"
        self.sftp = self
        self.shell = None
        self.forked = []

    def fork(self):
        child = _SessionStub(self.profile, self.transport)
        self.forked.append(child)
        return child

    def close(self):
        self.closed = True

    def normalize(self, path: str) -> str:
        return path

    def listdir_attr(self, _path: str):
        return [SimpleNamespace(filename="visible.txt", st_size=7,
                                 st_mode=0o100644, st_mtime=0)]

    def open_shell(self, **_kwargs):
        self.shell = self._Shell()
        return self.shell

    def resize_shell(self, **_kwargs):
        pass


def _drain_until(predicate, timeout: float = 3.0) -> bool:
    context = GLib.MainContext.default()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        while context.pending():
            context.iteration(False)
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def main() -> int:
    Gtk.init()
    keyring_lookup = patch.object(remote_ui.secret_store, "get_password", return_value=None)
    keyring_delete = patch.object(remote_ui.secret_store, "delete_password")
    keyring_lookup.start()
    keyring_delete.start()
    with tempfile.TemporaryDirectory(prefix="proxypilot-gtk-windows-") as temporary:
        root = Path(temporary)
        config = root / "config"
        config.mkdir()
        os.environ["XDG_CONFIG_HOME"] = str(config)
        os.environ["HOME"] = str(root)

        profile = remote_access.SSHProfile.create(
            "Smoke server", "127.0.0.1", "smoke", port=2222, use_proxy=True)
        remote_access.save_profiles([profile])
        application = Gtk.Application(application_id="io.github.rafael7277.ProxyPilot.Smoke")
        application.register(None)
        parent = Gtk.ApplicationWindow(application=application,
                                       title="ProxyPilot smoke parent")
        page = RemoteAccessPage(parent)
        profile_row = page.profile_list.get_row_at_index(0)
        assert profile_row is not None
        page.profile_list.select_row(profile_row)
        assert page.profile_id == profile.profile_id
        assert page.host_entry.get_text() == "127.0.0.1"
        assert hasattr(page, "identity_entry")
        assert not page.password_entry.get_visibility()
        assert page.delete_profile_button.get_sensitive()
        page._delete_response(_DialogStub(), Gtk.ResponseType.OK, profile.profile_id)
        assert remote_access.load_profiles() == []
        assert not page.delete_profile_button.get_sensitive()

        page.name_entry.set_text("Saved then selected")
        page.host_entry.set_text("localhost")
        page.username_entry.set_text("smoke")
        page.password_entry.set_text("smoke-secret-not-on-disk")
        with patch.object(remote_ui.RemoteAccessPage, "_load_keyring_password"):
            page._save_profile(None)
        saved = remote_access.load_profiles()
        assert len(saved) == 1
        assert page.profile_list.get_selected_row() is not None
        assert page.profile_id == saved[0].profile_id
        assert page.delete_profile_button.get_sensitive()
        assert saved[0].identity_file is None
        profile_data = json.loads(remote_access.profile_path().read_text())
        assert "smoke-secret-not-on-disk" not in remote_access.profile_path().read_text()
        assert "password" not in profile_data["profiles"][0]
        assert page._session_passwords[saved[0].profile_id] == "smoke-secret-not-on-disk"
        assert page.save_profile_button.get_label() == "Save changes"
        edit_key = str(root / ".ssh" / "test_ed25519")
        page.name_entry.set_text("Edited saved profile")
        page.identity_entry.set_text(edit_key)
        with patch.object(remote_ui.RemoteAccessPage, "_load_keyring_password"):
            page._save_profile(None)
        saved = remote_access.load_profiles()
        assert saved[0].profile_id == page.profile_id
        assert saved[0].name == "Edited saved profile"
        assert saved[0].identity_file == edit_key
        assert page.save_profile_button.get_label() == "Save changes"
        page.remember_password_check.set_active(True)
        with patch.object(remote_ui.secret_store, "store_password") as store_password:
            page._save_profile(None)
            assert _drain_until(lambda: "stored in the Linux keyring" in
                                page.status.get_text())
            store_password.assert_called_once_with(
                saved[0].profile_id, "Edited saved profile", "smoke-secret-not-on-disk")
        assert "smoke-secret-not-on-disk" not in remote_access.profile_path().read_text()
        page.remember_password_check.set_active(False)
        with patch.object(remote_ui.secret_store, "delete_password") as delete_password:
            page._save_profile(None)
            assert _drain_until(lambda: "remembered password removed" in
                                page.status.get_text())
            delete_password.assert_called_once_with(saved[0].profile_id)
        with patch.object(remote_ui.RemoteAccessPage, "_load_keyring_password"):
            page._open_file_manager(None)
        assert page.child_windows == []

        with patch.object(remote_ui, "SSHConnectionFlow", _FlowStub):
            page._connect_profile(None)
            assert _FlowStub.attempts[-1] == "smoke-secret-not-on-disk"
            flow = _FlowStub.instances[-1]
            flow.on_connected(_SessionStub(saved[0]))
            assert page._connection_session is not None
            assert page.connection_button.get_label() == "Disconnect"
            assert "SHA256:smoke-fingerprint" in page.status.get_text()
            assert page.fingerprint_button.get_sensitive()

        page.profiles.append(remote_access.SSHProfile.create(
            "Second server", "localhost", "smoke", port=2223))
        with patch.object(remote_ui.RemoteAccessPage, "_load_keyring_password"):
            page._open_file_manager(None)
        manager = page.child_windows[-1]
        assert isinstance(manager, RemoteFileManagerWindow)
        second_profile = manager.right.profiles[1]
        manager.passwords[second_profile.profile_id] = "second-secret"
        assert manager.passwords[saved[0].profile_id] == "smoke-secret-not-on-disk"
        assert not hasattr(manager.right, "connect_button")
        assert hasattr(manager, "cancel_button")
        assert not hasattr(manager, "copy_button")
        manager.left._draw([{"name": "visible.txt", "size": 7, "mtime": 0,
                             "is_dir": False, "is_symlink": False}])
        local_row = manager.left.file_list.get_row_at_index(0)
        assert local_row is not None
        assert local_row.get_activatable()
        assert not local_row.get_child().get_can_target()
        transfer_source = root / "visible.txt"
        transfer_source.write_text("visible")
        manager.left.path = str(root)
        local_row.path = str(transfer_source)
        with patch.object(remote_windows.Gio.AppInfo,
                          "launch_default_for_uri") as launch_file:
            manager.left._row_activated(manager.left.file_list, local_row)
            launch_file.assert_called_once_with(transfer_source.as_uri(), None)
        manager.left._draw([{"name": "folder", "size": 0, "mtime": 0,
                             "is_dir": True, "is_symlink": False}])
        folder_row = manager.left.file_list.get_row_at_index(0)
        with patch.object(manager.left, "refresh") as refresh_local:
            manager.left._row_activated(manager.left.file_list, folder_row)
            refresh_local.assert_called_once()
        assert manager.left.path_entry.get_text().endswith("/folder")
        manager.left._draw([{"name": "visible.txt", "size": 7, "mtime": 0,
                             "is_dir": False, "is_symlink": False}])
        local_row = manager.left.file_list.get_row_at_index(0)
        local_row.path = str(transfer_source)
        manager.left.file_list.select_row(local_row)
        manager._context_button_clicked(None, "copy", "left", local_row)
        while GLib.MainContext.default().pending():
            GLib.MainContext.default().iteration(False)
        assert manager.clipboard is not None
        assert manager.clipboard["items"][0]["name"] == "visible.txt"
        manager._context_button_clicked(None, "cut", "left", local_row)
        while GLib.MainContext.default().pending():
            GLib.MainContext.default().iteration(False)
        assert manager.clipboard["move"] is True
        with patch.object(manager, "_start_transfer") as start_transfer:
            manager._context_button_clicked(None, "paste", "right")
            while GLib.MainContext.default().pending():
                GLib.MainContext.default().iteration(False)
            start_transfer.assert_called_once()
            assert start_transfer.call_args.kwargs["move"] is True
        payload = json.dumps({"manager": manager.manager_id, "side": "left",
                              "signature": "local", "items": manager.clipboard["items"]})
        with patch.object(manager, "_start_transfer") as drag_transfer:
            assert manager._drop(None, payload, 0, 0, "right")
            drag_transfer.assert_called_once()
            assert drag_transfer.call_args.kwargs["move"] is True
        # Exercise the real button callback order: dismiss the popover, then
        # dispatch the action on the GTK main loop.
        manager._context_popover = None
        manager._context_button_clicked(None, "copy", "left", local_row)
        while GLib.MainContext.default().pending():
            GLib.MainContext.default().iteration(False)
        assert manager.clipboard["move"] is False
        manager.right._draw([{"name": "remote.txt", "size": 6, "mtime": 0,
                              "is_dir": False, "is_symlink": False}])
        remote_row = manager.right.file_list.get_row_at_index(0)
        remote_open_loop = GLib.MainLoop()
        original_remote_open_done = manager._remote_open_done

        def remote_open_done(*args):
            result = original_remote_open_done(*args)
            remote_open_loop.quit()
            return result

        manager._remote_open_done = remote_open_done

        def fake_remote_download(_session, _source, _destination_session,
                                 destination_directory, **_kwargs):
            result = Path(destination_directory) / "remote.txt"
            result.write_text("remote")
            return result

        with patch.object(remote_windows.GLib, "get_user_cache_dir",
                          return_value=str(root / "cache")), \
             patch.object(remote_windows.remote_access, "transfer_entry",
                          side_effect=fake_remote_download), \
             patch.object(remote_windows.Gio.AppInfo,
                          "launch_default_for_uri") as launch_remote:
            manager._open_file("right", remote_row)
            GLib.timeout_add(4000, lambda: (remote_open_loop.quit(), GLib.SOURCE_REMOVE)[1])
            remote_open_loop.run()
            launch_remote.assert_called_once()
            opened_uri = launch_remote.call_args.args[0]
            assert Path(opened_uri.removeprefix("file://")).read_text() == "remote"
        assert manager._opened_files and manager._opened_files[-1].name == "remote.txt"
        manager._progress_changed(.5, 5, 10, 1, 2, "visible.txt")
        assert "50%" in manager.progress.get_text()
        with patch.object(remote_windows, "SSHConnectionFlow", _FlowStub):
            manager.right.endpoint_selector.set_selected(2)
            assert _FlowStub.attempts[-1] == "second-secret"
            auto_flow = _FlowStub.instances[-1]
            manager.right.endpoint_selector.set_selected(1)
            assert auto_flow.cancelled
        transfer_attempts: list[str | None] = []

        def transfer_with_one_disconnect(*_args, **kwargs):
            transfer_attempts.append(kwargs.get("resume_id"))
            if len(transfer_attempts) == 1:
                raise ConnectionResetError(errno.ECONNRESET, "simulated link loss")
            return "/root/visible.txt"

        replacement_session = _SessionStub(saved[0])
        manager.busy = True
        manager.cancel_event = threading.Event()
        loop = GLib.MainLoop()
        original_transfer_done = manager._transfer_done

        def transfer_done(error, clear_clipboard, sessions=None):
            result = original_transfer_done(error, clear_clipboard, sessions)
            loop.quit()
            return result

        manager._transfer_done = transfer_done
        transfer_stat = transfer_source.stat()
        item = {"path": str(transfer_source), "name": "visible.txt",
                "is_dir": False, "is_symlink": False,
                "size": transfer_stat.st_size, "mtime": int(transfer_stat.st_mtime)}
        with patch.object(remote_windows.remote_access, "transfer_entry",
                          side_effect=transfer_with_one_disconnect), \
             patch.object(remote_windows.remote_access, "connect_profile",
                          return_value=replacement_session) as reconnect:
            manager._run_transfer(
                "left", [item], "right", False, False, [], manager.cancel_event,
                {"left": None, "right": manager.right.session})
            GLib.timeout_add(5000, lambda: (loop.quit(), GLib.SOURCE_REMOVE)[1])
            loop.run()
            reconnect.assert_called_once()
        assert len(transfer_attempts) == 2
        assert transfer_attempts[0] == transfer_attempts[1]
        assert manager.right.session is replacement_session
        assert manager.status.get_text() == "Transfer completed."
        assert manager.right.session is not None
        attempts_before_terminal = len(_FlowStub.attempts)
        page._open_terminal(None)
        first_terminal = page.child_windows[-1]
        page._open_terminal(None)
        second_terminal = page.child_windows[-1]
        if remote_windows.Vte is not None:
            assert len(_FlowStub.attempts) == attempts_before_terminal
            assert first_terminal.session is not page._connection_session
            assert second_terminal.session is not first_terminal.session
            assert first_terminal.session.client is page._connection_session.client
            assert second_terminal.session.client is page._connection_session.client
        assert first_terminal.password is None
        assert not hasattr(first_terminal, "reconnect_button")

        page._delete_response(_DialogStub(), Gtk.ResponseType.OK, saved[0].profile_id)
        assert remote_access.load_profiles() == []
        assert manager.left.profile is None
        assert manager.right.profile.profile_id == saved[0].profile_id
        assert manager.left.file_list.observe_controllers().get_n_items() >= 2
        assert first_terminal is not second_terminal
        assert first_terminal.get_title() != second_terminal.get_title()
        assert first_terminal.session is not second_terminal.session

        parent.present()
        manager.present()
        first_terminal.present()
        second_terminal.present()
        loop = GLib.MainLoop()

        def close_all():
            manager.close()
            first_terminal.close()
            second_terminal.close()
            parent.close()
            loop.quit()
            return GLib.SOURCE_REMOVE

        GLib.timeout_add(700, close_all)
        loop.run()
    keyring_delete.stop()
    keyring_lookup.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
