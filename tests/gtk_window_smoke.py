"""Small display-backed GTK smoke test for the SSH child windows and profile list."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from proxypilot_app import remote_access
from proxypilot_app.remote_ui import RemoteAccessPage
from proxypilot_app import remote_windows
from proxypilot_app.remote_windows import RemoteFileManagerWindow, RemoteTerminalWindow


class _DialogStub:
    def destroy(self) -> None:
        pass


class _FlowStub:
    attempts: list[str | None] = []

    def __init__(self, *_args):
        pass

    def connect(self, password: str | None = None) -> None:
        self.attempts.append(password)

    def cancel(self) -> None:
        pass


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
        parent = Gtk.Window(title="ProxyPilot smoke parent")
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

        manager = RemoteFileManagerWindow(
            None, parent, saved, saved[0], passwords=page._session_passwords)
        assert manager.passwords[saved[0].profile_id] == "smoke-secret-not-on-disk"
        with patch.object(remote_windows, "SSHConnectionFlow", _FlowStub):
            manager.right._connect_clicked(None)
            assert _FlowStub.attempts[-1] == "smoke-secret-not-on-disk"
            first_terminal = RemoteTerminalWindow(
                None, parent, saved[0], 1, password="smoke-secret-not-on-disk")
            assert _FlowStub.attempts[-1] == "smoke-secret-not-on-disk"
        assert first_terminal.password is None
        second_terminal = RemoteTerminalWindow(
            None, parent, saved[0], 2, auto_connect=False)
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
