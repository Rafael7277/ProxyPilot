"""Small display-backed GTK smoke test for the SSH child windows and profile list."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from proxypilot_app import remote_access
from proxypilot_app.remote_ui import RemoteAccessPage
from proxypilot_app.remote_windows import RemoteFileManagerWindow, RemoteTerminalWindow


class _DialogStub:
    def destroy(self) -> None:
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
        assert page.delete_profile_button.get_sensitive()
        page._delete_response(_DialogStub(), Gtk.ResponseType.OK, profile.profile_id)
        assert remote_access.load_profiles() == []
        assert not page.delete_profile_button.get_sensitive()

        page.name_entry.set_text("Saved then selected")
        page.host_entry.set_text("localhost")
        page.username_entry.set_text("smoke")
        page._save_profile(None)
        saved = remote_access.load_profiles()
        assert len(saved) == 1
        assert page.profile_list.get_selected_row() is not None
        assert page.profile_id == saved[0].profile_id
        assert page.delete_profile_button.get_sensitive()
        page._delete_response(_DialogStub(), Gtk.ResponseType.OK, saved[0].profile_id)
        assert remote_access.load_profiles() == []

        manager = RemoteFileManagerWindow(None, parent, [profile], profile)
        first_terminal = RemoteTerminalWindow(
            None, parent, profile, 1, auto_connect=False)
        second_terminal = RemoteTerminalWindow(
            None, parent, profile, 2, auto_connect=False)
        assert manager.left.profile is None
        assert manager.right.profile.profile_id == profile.profile_id
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
