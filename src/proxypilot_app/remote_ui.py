"""GTK profile page that opens independent SFTP and SSH terminal windows."""
from __future__ import annotations

import importlib.util
from typing import Callable

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from . import remote_access
from .remote_windows import (RemoteFileManagerWindow, RemoteTerminalWindow,
                             SSHConnectionFlow)


def _label(text: str, *, css_class: str | None = None) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True, selectable=True)
    if css_class:
        label.add_css_class(css_class)
    return label


class RemoteAccessPage(Gtk.Box):
    """Manage saved SSH profiles and open one or many independent tool windows."""

    def __init__(self, parent: Gtk.Window, status_callback: Callable[[str], None] | None = None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.parent = parent
        self.status_callback = status_callback or (lambda _text: None)
        self.profiles: list[remote_access.SSHProfile] = []
        self.profile_id: str | None = None
        self._session_passwords: dict[str, str] = {}
        self._connection_session: remote_access.RemoteSession | None = None
        self._connection_flow: SSHConnectionFlow | None = None
        self.child_windows: list[Gtk.Window] = []
        self.terminal_sequence = 0
        self.closing = False
        self._make_ui()
        self._reload_profiles()

    def _make_ui(self) -> None:
        self.set_margin_top(18)
        self.set_margin_bottom(16)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.append(_label("SSH / SFTP", css_class="page-title"))
        self.append(_label(
            "Save server profiles here. The file manager and each terminal open in their own "
            "window. Passwords are requested when needed and are never saved in a profile.",
            css_class="muted"))

        split = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL, wide_handle=True,
                          hexpand=True, vexpand=True)
        self.append(split)
        profile_panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        profile_panel.set_size_request(250, -1)
        profile_panel.append(_label("Saved connections", css_class="title"))
        self.profile_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.profile_list.connect("row-selected", self._profile_selected)
        profile_panel.append(self._scroll(self.profile_list))
        profile_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        new_button = Gtk.Button(label="New profile")
        new_button.connect("clicked", lambda *_: self._clear_form())
        self.delete_profile_button = Gtk.Button(label="Delete")
        self.delete_profile_button.set_sensitive(False)
        self.delete_profile_button.connect("clicked", self._delete_profile)
        profile_actions.append(new_button)
        profile_actions.append(self.delete_profile_button)
        profile_panel.append(profile_actions)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=9)
        content.set_margin_start(14)
        self.name_entry = self._entry("Connection name")
        self.host_entry = self._entry("Server host or IP")
        self.port_entry = self._entry("22")
        self.port_entry.set_text("22")
        self.port_entry.set_max_width_chars(7)
        self.username_entry = self._entry("Username")
        for entry in (self.name_entry, self.host_entry, self.port_entry,
                      self.username_entry):
            entry.connect("changed", self._form_changed)
        self.password_entry = Gtk.Entry(
            placeholder_text="Password (this session only)", visibility=False,
            input_purpose=Gtk.InputPurpose.PASSWORD, hexpand=True)
        self.password_entry.set_icon_from_icon_name(
            Gtk.EntryIconPosition.SECONDARY, "view-reveal-symbolic")
        self.password_entry.set_icon_tooltip_text(
            Gtk.EntryIconPosition.SECONDARY, "Show or hide password")
        self.password_entry.connect("icon-press", self._password_icon_pressed)
        self.password_entry.connect("changed", self._password_changed)
        self.proxy_check = Gtk.CheckButton(
            label="Use ProxyPilot proxy for SSH, SFTP, and terminal")
        self.proxy_check.connect("toggled", self._form_changed)
        form = Gtk.Grid(column_spacing=8, row_spacing=8)
        self._form_row(form, 0, "Name", self.name_entry)
        self._form_row(form, 1, "Host", self.host_entry)
        self._form_row(form, 2, "Port", self.port_entry)
        self._form_row(form, 3, "User", self.username_entry)
        self._form_row(form, 4, "Password", self.password_entry)
        form.attach(self.proxy_check, 1, 5, 1, 1)
        content.append(form)
        content.append(_label(
            "With proxy routing enabled, new SSH connections use the ProxyPilot proxy-only "
            "route. If the bridge or upstream proxy is unavailable, the connection fails "
            "without falling back to a direct route.", css_class="muted"))
        content.append(_label(
            "The password is used for SSH, SFTP, and terminal connections during this run "
            "only. It is never written to the saved profile.", css_class="muted"))

        profile_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
        save_button = Gtk.Button(label="Save profile")
        save_button.connect("clicked", self._save_profile)
        self.connection_button = Gtk.Button(label="Connect")
        self.connection_button.add_css_class("suggested-action")
        self.connection_button.connect("clicked", self._connect_profile)
        self.file_button = Gtk.Button(label="Open File Manager")
        self.file_button.add_css_class("suggested-action")
        self.file_button.set_sensitive(False)
        self.file_button.connect("clicked", self._open_file_manager)
        self.terminal_button = Gtk.Button(label="New Terminal")
        self.terminal_button.add_css_class("suggested-action")
        self.terminal_button.set_sensitive(False)
        self.terminal_button.connect("clicked", self._open_terminal)
        profile_actions.append(save_button)
        profile_actions.append(self.connection_button)
        profile_actions.append(self.file_button)
        profile_actions.append(self.terminal_button)
        content.append(profile_actions)
        content.append(_label(
            "File Manager has two independent panes. Choose a local folder or SSH profile "
            "on each side to work between this computer and two servers. Every New Terminal "
            "click creates a fresh window and SSH session.", css_class="muted"))
        self.status = _label("Choose a saved profile or enter a new one.", css_class="muted")
        content.append(self.status)
        split.set_start_child(profile_panel)
        split.set_end_child(content)
        split.set_position(255)

        if importlib.util.find_spec("paramiko") is None:
            self.connection_button.set_sensitive(False)
            self.file_button.set_sensitive(False)
            self.terminal_button.set_sensitive(False)
            self.status.set_text("SSH/SFTP requires Paramiko (python3-paramiko on Ubuntu/Debian).")

    @staticmethod
    def _entry(placeholder: str) -> Gtk.Entry:
        return Gtk.Entry(placeholder_text=placeholder, hexpand=True)

    @staticmethod
    def _form_row(grid: Gtk.Grid, row: int, title: str, widget: Gtk.Widget) -> None:
        label = Gtk.Label(label=title, xalign=1)
        label.add_css_class("muted")
        grid.attach(label, 0, row, 1, 1)
        grid.attach(widget, 1, row, 1, 1)

    @staticmethod
    def _scroll(child: Gtk.Widget) -> Gtk.ScrolledWindow:
        scroller = Gtk.ScrolledWindow(hexpand=True, vexpand=True)
        scroller.set_child(child)
        return scroller

    @staticmethod
    def _clear_list(widget: Gtk.ListBox) -> None:
        child = widget.get_first_child()
        while child:
            following = child.get_next_sibling()
            widget.remove(child)
            child = following

    def _reload_profiles(self, selected_id: str | None = None) -> None:
        self._clear_list(self.profile_list)
        try:
            self.profiles = remote_access.load_profiles()
        except Exception as exc:
            self.status.set_text(f"Cannot load saved profiles: {type(exc).__name__}: {exc}")
            return
        for profile in self.profiles:
            row = Gtk.ListBoxRow()
            row.profile = profile
            row.set_selectable(True)
            row.set_activatable(True)
            route = "ProxyPilot proxy" if profile.use_proxy else "Direct"
            label = _label(
                f"{profile.name}\n{profile.username}@{profile.host}:{profile.port} · {route}")
            label.set_selectable(False)
            row.set_child(label)
            self.profile_list.append(row)
            if selected_id and profile.profile_id == selected_id:
                self.profile_list.select_row(row)

    def _profile_selected(self, _list, row) -> None:
        if row is None:
            self.delete_profile_button.set_sensitive(False)
            return
        self.delete_profile_button.set_sensitive(True)
        profile = row.profile
        if (self._connection_flow is not None and
                self._connection_flow.profile.profile_id != profile.profile_id):
            self._connection_flow.cancel()
            self._connection_flow = None
        if (self._connection_session is not None and
                self._connection_session.profile.profile_id != profile.profile_id):
            self._connection_session.close()
            self._connection_session = None
        self.profile_id = profile.profile_id
        self.name_entry.set_text(profile.name)
        self.host_entry.set_text(profile.host)
        self.port_entry.set_text(str(profile.port))
        self.username_entry.set_text(profile.username)
        self.password_entry.set_text(self._session_passwords.get(profile.profile_id, ""))
        self.proxy_check.set_active(profile.use_proxy)
        if (self._connection_session is not None and
                not self._same_target(self._connection_session.profile,
                                      self._form_profile())):
            self._connection_session.close()
            self._connection_session = None
        self._update_connection_button()
        self.status.set_text(f"Selected {profile.name}.")

    def _password_changed(self, entry: Gtk.Entry) -> None:
        if self.profile_id is None:
            return
        password = entry.get_text()
        if password:
            self._session_passwords[self.profile_id] = password
        else:
            self._session_passwords.pop(self.profile_id, None)

    def _password_icon_pressed(self, entry: Gtk.Entry, position, _event) -> None:
        if position == Gtk.EntryIconPosition.SECONDARY:
            entry.set_visibility(not entry.get_visibility())

    def _clear_form(self) -> None:
        self.profile_id = None
        self.name_entry.set_text("")
        self.host_entry.set_text("")
        self.port_entry.set_text("22")
        self.username_entry.set_text("")
        self.password_entry.set_text("")
        self.proxy_check.set_active(False)
        self.profile_list.unselect_all()
        self.delete_profile_button.set_sensitive(False)
        self._update_connection_button()
        self.status.set_text("Enter a server profile, or select a saved profile.")

    def _form_profile(self) -> remote_access.SSHProfile:
        try:
            port = int(self.port_entry.get_text().strip())
        except ValueError as exc:
            raise ValueError("SSH port must be an integer") from exc
        if self.profile_id:
            profile = remote_access.SSHProfile(
                self.profile_id, self.name_entry.get_text(), self.host_entry.get_text(),
                port, self.username_entry.get_text(), None,
                self.proxy_check.get_active())
            return remote_access.validate_profile(profile)
        return remote_access.SSHProfile.create(
            self.name_entry.get_text(), self.host_entry.get_text(),
            self.username_entry.get_text(), port=port,
            use_proxy=self.proxy_check.get_active())

    def _save_profile(self, _button) -> None:
        try:
            profile = self._form_profile()
            password = self.password_entry.get_text()
            if password:
                self._session_passwords[profile.profile_id] = password
            else:
                self._session_passwords.pop(profile.profile_id, None)
            self.profiles = remote_access.upsert_profile(profile)
            self.profile_id = profile.profile_id
            self._reload_profiles(selected_id=profile.profile_id)
            self.status.set_text(f"Saved profile: {profile.name}")
        except Exception as exc:
            self._show_error("Profile was not saved", exc)

    def _delete_profile(self, _button) -> None:
        row = self.profile_list.get_selected_row()
        if row is None:
            self.status.set_text("Click a saved profile in the left panel before deleting it.")
            return
        dialog = Gtk.MessageDialog(
            transient_for=self.parent, modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text="Delete saved connection profile?")
        dialog.set_secondary_text(
            "This removes only the local profile; no files or settings on the server are changed.")
        dialog.connect("response", self._delete_response, row.profile.profile_id)
        dialog.present()

    def _delete_response(self, dialog, response, profile_id) -> None:
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return
        try:
            remote_access.delete_profile(profile_id)
            self._session_passwords.pop(profile_id, None)
            if (self._connection_session is not None and
                    self._connection_session.profile.profile_id == profile_id):
                self._connection_session.close()
                self._connection_session = None
            self._clear_form()
            self._reload_profiles()
            self.status.set_text("Saved profile deleted.")
        except Exception as exc:
            self._show_error("Profile was not deleted", exc)

    def _open_file_manager(self, _button) -> None:
        try:
            profile = self._form_profile()
        except Exception as exc:
            self._show_error("Enter a valid server profile first", exc)
            return
        if (self._connection_session is None or
                not self._same_target(self._connection_session.profile, profile)):
            self.status.set_text("Connect to this profile on the SSH / SFTP page first.")
            return
        window = RemoteFileManagerWindow(
            self.parent.get_application(), self.parent, self.profiles, profile,
            passwords=self._passwords_for(profile),
            initial_session=self._connection_session)
        self._track_window(window)
        window.present()
        self.status.set_text("File Manager opened. Choose an endpoint in each pane.")

    def _open_terminal(self, _button) -> None:
        if len(self.child_windows) >= 32:
            self.status.set_text("Close an existing tool window before opening another.")
            return
        try:
            profile = self._form_profile()
        except Exception as exc:
            self._show_error("Enter a valid server profile first", exc)
            return
        if (self._connection_session is None or
                not self._same_target(self._connection_session.profile, profile)):
            self.status.set_text("Connect to this profile on the SSH / SFTP page first.")
            return
        self.terminal_sequence += 1
        window = RemoteTerminalWindow(
            self.parent.get_application(), self.parent, profile,
            self.terminal_sequence,
            password=self.password_entry.get_text() or None)
        self._track_window(window)
        window.present()
        self.status.set_text(f"Terminal window {self.terminal_sequence} opened.")

    def _passwords_for(self, profile: remote_access.SSHProfile) -> dict[str, str]:
        passwords = dict(self._session_passwords)
        password = self.password_entry.get_text()
        if password:
            passwords[profile.profile_id] = password
        return passwords

    def _connect_profile(self, _button) -> None:
        if self._connection_flow is not None:
            self._connection_flow.cancel()
            self._connection_flow = None
            self._update_connection_button()
            self.status.set_text("Connection attempt cancelled.")
            return
        try:
            profile = self._form_profile()
        except Exception as exc:
            self._show_error("Enter a valid server profile first", exc)
            return
        if (self._connection_session is not None and
                self._same_target(self._connection_session.profile, profile)):
            self._connection_session.close()
            self._connection_session = None
            self._update_connection_button()
            self.status.set_text("Disconnected.")
            return
        if self._connection_session is not None:
            self._connection_session.close()
            self._connection_session = None
        self.connection_button.set_label("Connecting…")
        self.connection_button.set_sensitive(False)
        self._connection_flow = SSHConnectionFlow(
            self.parent, profile, self._page_connected, self.status.set_text,
            self._page_connection_failed)
        self._update_connection_button()
        self._connection_flow.connect(self.password_entry.get_text() or None)

    def _page_connected(self, session: remote_access.RemoteSession) -> None:
        if self.closing:
            session.close()
            return
        if self._connection_session is not None:
            self._connection_session.close()
        self._connection_flow = None
        self._connection_session = session
        self._update_connection_button()
        self.status.set_text(
            f"Connected to {session.profile.host}:{session.profile.port} · "
            f"{'ProxyPilot proxy' if session.profile.use_proxy else 'Direct'} · "
            "SSH host key verified.")

    def _page_connection_failed(self) -> None:
        self._connection_flow = None
        self._update_connection_button()

    def _update_connection_button(self) -> None:
        if self._connection_flow is not None:
            self.connection_button.set_label("Cancel connection")
            self.connection_button.set_sensitive(True)
            self.file_button.set_sensitive(False)
            self.terminal_button.set_sensitive(False)
            return
        try:
            profile = self._form_profile()
        except (ValueError, remote_access.RemoteAccessError):
            profile = None
        connected = (profile is not None and self._connection_session is not None and
                     self._same_target(self._connection_session.profile, profile))
        self.connection_button.set_label("Disconnect" if connected else "Connect")
        self.connection_button.set_sensitive(profile is not None)
        self.file_button.set_sensitive(connected)
        self.terminal_button.set_sensitive(connected and len(self.child_windows) < 32)

    def _form_changed(self, *_args) -> None:
        if hasattr(self, "connection_button"):
            self._update_connection_button()

    @staticmethod
    def _same_target(left: remote_access.SSHProfile,
                     right: remote_access.SSHProfile) -> bool:
        return (left.host, left.port, left.username,
                left.identity_file, left.use_proxy) == (
                    right.host, right.port, right.username,
                    right.identity_file, right.use_proxy)

    def _track_window(self, window: Gtk.Window) -> None:
        self.child_windows.append(window)
        window.connect("close-request", self._forget_window, window)

    def _forget_window(self, _window, child) -> bool:
        try:
            self.child_windows.remove(child)
        except ValueError:
            pass
        self._update_connection_button()
        return False

    def _show_error(self, title: str, error: Exception) -> None:
        dialog = Gtk.MessageDialog(
            transient_for=self.parent, modal=True,
            message_type=Gtk.MessageType.ERROR,
            buttons=Gtk.ButtonsType.CLOSE, text=title)
        dialog.set_secondary_text(f"{type(error).__name__}: {error}")
        dialog.connect("response", lambda win, _response: win.destroy())
        dialog.present()

    def shutdown(self) -> None:
        self.closing = True
        if self._connection_flow is not None:
            self._connection_flow.cancel()
            self._connection_flow = None
        for window in list(self.child_windows):
            window.close()
        self.child_windows.clear()
        if self._connection_session is not None:
            self._connection_session.close()
            self._connection_session = None
        self._session_passwords.clear()
        self.password_entry.set_text("")


__all__ = ["RemoteAccessPage"]
