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
    def __init__(self, profile):
        self.profile = profile
        self.closed = False
        self.client = None
        self.sftp = self

    def fork(self):
        return _SessionStub(self.profile)

    def close(self):
        self.closed = True

    def normalize(self, path: str) -> str:
        return path

    def listdir_attr(self, _path: str):
        return [SimpleNamespace(filename="visible.txt", st_size=7,
                                 st_mode=0o100644, st_mtime=0)]


def main() -> int:
    Gtk.init()
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
        assert not hasattr(page, "identity_entry")
        assert not page.password_entry.get_visibility()
        assert page.delete_profile_button.get_sensitive()
        page._delete_response(_DialogStub(), Gtk.ResponseType.OK, profile.profile_id)
        assert remote_access.load_profiles() == []
        assert not page.delete_profile_button.get_sensitive()

        page.name_entry.set_text("Saved then selected")
        page.host_entry.set_text("localhost")
        page.username_entry.set_text("smoke")
        page.password_entry.set_text("smoke-secret-not-on-disk")
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
        page._open_file_manager(None)
        assert page.child_windows == []

        with patch.object(remote_ui, "SSHConnectionFlow", _FlowStub):
            page._connect_profile(None)
            assert _FlowStub.attempts[-1] == "smoke-secret-not-on-disk"
            flow = _FlowStub.instances[-1]
            flow.on_connected(_SessionStub(saved[0]))
            assert page._connection_session is not None
            assert page.connection_button.get_label() == "Disconnect"

        page.profiles.append(remote_access.SSHProfile.create(
            "Second server", "localhost", "smoke", port=2223))
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
        assert manager.left.file_list.get_row_at_index(0) is not None
        manager._show_context_menu(None, 1, 1, 1, "left")
        assert manager._context_popover is not None
        manager._context_popover.popdown()
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
        transfer_source = root / "visible.txt"
        transfer_source.write_text("visible")
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
        with patch.object(remote_windows, "SSHConnectionFlow", _FlowStub):
            assert manager.right.session is not None
            first_terminal = RemoteTerminalWindow(
                application, parent, saved[0], 1,
                password="smoke-secret-not-on-disk")
            if remote_windows.Vte is not None:
                assert _FlowStub.attempts[-1] == "smoke-secret-not-on-disk"
        assert first_terminal.password is None
        second_terminal = RemoteTerminalWindow(
            application, parent, saved[0], 2, auto_connect=False)
        assert not hasattr(first_terminal, "reconnect_button")
        assert first_terminal.session is None and second_terminal.session is None

        page._delete_response(_DialogStub(), Gtk.ResponseType.OK, saved[0].profile_id)
        assert remote_access.load_profiles() == []
        assert manager.left.profile is None
        assert manager.right.profile.profile_id == saved[0].profile_id
        assert manager.left.file_list.observe_controllers().get_n_items() >= 2
        assert first_terminal is not second_terminal
        assert first_terminal.get_title() != second_terminal.get_title()
        assert first_terminal.session is None and second_terminal.session is None

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
