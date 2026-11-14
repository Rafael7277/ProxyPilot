"""GTK profile page that opens independent SFTP and SSH terminal windows."""
from __future__ import annotations

import importlib.util
import threading
from typing import Callable

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import GLib, Gtk

from . import remote_access, secret_store
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
        self._remembered_password_ids: set[str] = set()
        self._password_lookup_generation = 0
        self._password_lookup_pending: str | None = None
        self._deferred_connect_profile_id: str | None = None
        self._skip_keyring_lookup_id: str | None = None
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
            "window. Passwords stay out of profile files; optional keyring storage is available.",
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
        self.identity_entry = self._entry("Optional private key path, e.g. ~/.ssh/id_ed25519")
        for entry in (self.name_entry, self.host_entry, self.port_entry,
                      self.username_entry, self.identity_entry):
            entry.connect("changed", self._form_changed)
        self.password_entry = Gtk.Entry(
            placeholder_text="Password or key passphrase", visibility=False,
            input_purpose=Gtk.InputPurpose.PASSWORD, hexpand=True)
        self.password_entry.set_icon_from_icon_name(
            Gtk.EntryIconPosition.SECONDARY, "view-reveal-symbolic")
        self.password_entry.set_icon_tooltip_text(
            Gtk.EntryIconPosition.SECONDARY, "Show or hide password")
        self.password_entry.connect("icon-press", self._password_icon_pressed)
        self.password_entry.connect("changed", self._password_changed)
        self.remember_password_check = Gtk.CheckButton(
            label="Remember password securely in the Linux keyring")
        self.proxy_check = Gtk.CheckButton(
            label="Use ProxyPilot proxy for SSH, SFTP, and terminal")
        self.proxy_check.connect("toggled", self._form_changed)
        form = Gtk.Grid(column_spacing=8, row_spacing=8)
        self._form_row(form, 0, "Name", self.name_entry)
        self._form_row(form, 1, "Host", self.host_entry)
        self._form_row(form, 2, "Port", self.port_entry)
        self._form_row(form, 3, "User", self.username_entry)
        self._form_row(form, 4, "Private key", self.identity_entry)
        self._form_row(form, 5, "Password", self.password_entry)
        form.attach(self.remember_password_check, 1, 6, 1, 1)
        form.attach(self.proxy_check, 1, 7, 1, 1)
        content.append(form)
        content.append(_label(
            "With proxy routing enabled, new SSH connections use the ProxyPilot proxy-only "
            "route. If the bridge or upstream proxy is unavailable, the connection fails "
            "without falling back to a direct route.", css_class="muted"))
        content.append(_label(
            "When enabled, the password is stored by the desktop Linux keyring and never "
            "written to the profile file. Without a keyring, ProxyPilot does not save it.",
            css_class="muted"))

        profile_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
        save_button = Gtk.Button(label="Save profile")
        self.save_profile_button = save_button
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
        self.fingerprint_button = Gtk.Button(label="Server fingerprint")
        self.fingerprint_button.set_sensitive(False)
        self.fingerprint_button.connect("clicked", self._show_fingerprint)
        profile_actions.append(save_button)
        profile_actions.append(self.connection_button)
        profile_actions.append(self.file_button)
        profile_actions.append(self.terminal_button)
        profile_actions.append(self.fingerprint_button)
        content.append(profile_actions)
        content.append(_label(
            "File Manager has two independent panes. Choose a local folder or SSH profile "
            "on each side to work between this computer and two servers. Every New Terminal "
            "click creates a fresh shell window on the connected SSH transport.",
            css_class="muted"))
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
        self.save_profile_button.set_label("Save changes")
        self.name_entry.set_text(profile.name)
        self.host_entry.set_text(profile.host)
        self.port_entry.set_text(str(profile.port))
        self.username_entry.set_text(profile.username)
        self.identity_entry.set_text(profile.identity_file or "")
        self.password_entry.set_text(self._session_passwords.get(profile.profile_id, ""))
        self.remember_password_check.set_active(
            profile.profile_id in self._remembered_password_ids)
        self.proxy_check.set_active(profile.use_proxy)
        if (self._connection_session is not None and
                not self._same_target(self._connection_session.profile,
                                      self._form_profile())):
            self._connection_session.close()
            self._connection_session = None
        self._update_connection_button()
        self.status.set_text(f"Selected {profile.name}.")
        if self._skip_keyring_lookup_id == profile.profile_id:
            self._skip_keyring_lookup_id = None
        else:
            self._load_keyring_password(profile)

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
        self._password_lookup_generation += 1
        self._password_lookup_pending = None
        self._deferred_connect_profile_id = None
        self._skip_keyring_lookup_id = None
        self.name_entry.set_text("")
        self.host_entry.set_text("")
        self.port_entry.set_text("22")
        self.username_entry.set_text("")
        self.identity_entry.set_text("")
        self.password_entry.set_text("")
        self.remember_password_check.set_active(False)
        self.proxy_check.set_active(False)
        self.save_profile_button.set_label("Save profile")
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
                port, self.username_entry.get_text(),
                self.identity_entry.get_text().strip() or None,
                self.proxy_check.get_active())
            return remote_access.validate_profile(profile)
        return remote_access.SSHProfile.create(
            self.name_entry.get_text(), self.host_entry.get_text(),
            self.username_entry.get_text(), port=port,
            identity_file=self.identity_entry.get_text().strip() or None,
            use_proxy=self.proxy_check.get_active())

    def _save_profile(self, _button) -> None:
        try:
            profile = self._form_profile()
            if self._password_lookup_pending == profile.profile_id:
                self.status.set_text("Wait for the saved password lookup to finish, then save again.")
                return
            password = self.password_entry.get_text()
            remember_password = self.remember_password_check.get_active()
            if password:
                self._session_passwords[profile.profile_id] = password
            else:
                self._session_passwords.pop(profile.profile_id, None)
            self.profiles = remote_access.upsert_profile(profile)
            self.profile_id = profile.profile_id
            self._skip_keyring_lookup_id = profile.profile_id
            self._reload_profiles(selected_id=profile.profile_id)
            if remember_password:
                if not password:
                    self.status.set_text(
                        "Profile saved. Enter its password, then save again to remember it.")
                else:
                    self._store_keyring_password(profile, password)
            elif profile.profile_id in self._remembered_password_ids:
                self._delete_keyring_password(profile.profile_id,
                                              success_text="Profile saved; remembered password removed.")
            else:
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
            self._remembered_password_ids.discard(profile_id)
            if (self._connection_session is not None and
                    self._connection_session.profile.profile_id == profile_id):
                self._connection_session.close()
                self._connection_session = None
            self._clear_form()
            self._reload_profiles()
            self._delete_keyring_password(
                profile_id, success_text="Saved profile and remembered password deleted.")
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
            password=self.password_entry.get_text() or None,
            initial_session=self._connection_session)
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
        if self._password_lookup_pending == profile.profile_id:
            self._deferred_connect_profile_id = profile.profile_id
            self.status.set_text("Loading the remembered password from the Linux keyring…")
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
            self._page_connection_failed,
            lambda secret: self._accept_session_password(profile, secret))
        self._update_connection_button()
        self._connection_flow.connect(self.password_entry.get_text() or None)

    def _accept_session_password(self, profile: remote_access.SSHProfile,
                                 password: str) -> None:
        self._session_passwords[profile.profile_id] = password
        if self.profile_id == profile.profile_id:
            self.password_entry.set_text(password)

    def _page_connected(self, session: remote_access.RemoteSession) -> None:
        if self.closing:
            session.close()
            return
        if self._connection_session is not None:
            self._connection_session.close()
        self._connection_flow = None
        self._connection_session = session
        self._update_connection_button()
        password = self.password_entry.get_text()
        if self.remember_password_check.get_active() and password:
            self._store_keyring_password(session.profile, password)
        self.status.set_text(
            f"Connected to {session.profile.host}:{session.profile.port} · "
            f"{'ProxyPilot proxy' if session.profile.use_proxy else 'Direct'} · "
            f"verified {session.host_key_type or 'SSH'} host key · "
            f"{session.host_fingerprint or 'fingerprint unavailable'}.")

    def _page_connection_failed(self) -> None:
        self._connection_flow = None
        self._update_connection_button()

    def _update_connection_button(self) -> None:
        if self._connection_flow is not None:
            self.connection_button.set_label("Cancel connection")
            self.connection_button.set_sensitive(True)
            self.file_button.set_sensitive(False)
            self.terminal_button.set_sensitive(False)
            self.fingerprint_button.set_sensitive(False)
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
        self.fingerprint_button.set_sensitive(
            connected and bool(self._connection_session.host_fingerprint))

    def _show_fingerprint(self, _button) -> None:
        session = self._connection_session
        if session is None or not session.host_fingerprint:
            self.status.set_text("Connect to a verified SSH server to view its fingerprint.")
            return
        dialog = Gtk.Dialog(transient_for=self.parent, modal=True,
                            title="Verified SSH server fingerprint")
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        content = dialog.get_content_area()
        content.append(Gtk.Label(
            label=f"{session.profile.host}:{session.profile.port} · "
                  f"{session.host_key_type or 'SSH host key'}",
            xalign=0))
        value = Gtk.Entry(text=session.host_fingerprint, editable=False,
                          can_focus=True, hexpand=True)
        value.set_tooltip_text("Select and copy this SHA-256 fingerprint")
        content.append(value)
        dialog.connect("response", lambda widget, _response: widget.destroy())
        dialog.present()

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

    def _load_keyring_password(self, profile: remote_access.SSHProfile) -> None:
        self._password_lookup_generation += 1
        generation = self._password_lookup_generation
        self._password_lookup_pending = profile.profile_id

        def worker() -> None:
            try:
                password = secret_store.get_password(profile.profile_id)
                error = None
            except Exception as exc:
                password, error = None, exc
            GLib.idle_add(self._keyring_lookup_done, profile.profile_id,
                          generation, password, error)

        threading.Thread(target=worker, name="proxypilot-keyring-lookup",
                         daemon=True).start()

    def _keyring_lookup_done(self, profile_id: str, generation: int,
                             password: str | None, error: Exception | None) -> bool:
        if generation != self._password_lookup_generation:
            return False
        self._password_lookup_pending = None
        if self.closing or self.profile_id != profile_id:
            return False
        if password is not None:
            self._remembered_password_ids.add(profile_id)
            if not self.password_entry.get_text():
                self.password_entry.set_text(password)
            self.remember_password_check.set_active(True)
        elif error is None:
            self._remembered_password_ids.discard(profile_id)
            self.remember_password_check.set_active(False)
        if error is not None:
            self.status.set_text(
                "Could not read the Linux keyring. Unlock the desktop keyring, or enter the password manually.")
        elif password is not None:
            self.status.set_text("Remembered password loaded from the Linux keyring.")
        pending_connect = self._deferred_connect_profile_id
        self._deferred_connect_profile_id = None
        if pending_connect == profile_id:
            self._connect_profile(None)
        return False

    def _store_keyring_password(self, profile: remote_access.SSHProfile,
                                password: str) -> None:
        def worker() -> None:
            try:
                secret_store.store_password(profile.profile_id, profile.name, password)
                error = None
            except Exception as exc:
                error = exc
            GLib.idle_add(self._keyring_store_done, profile.profile_id, error)

        threading.Thread(target=worker, name="proxypilot-keyring-store",
                         daemon=True).start()
        self.status.set_text("Saving password securely in the Linux keyring…")

    def _keyring_store_done(self, profile_id: str, error: Exception | None) -> bool:
        if self.closing or self.profile_id != profile_id:
            return False
        if error is None:
            self._remembered_password_ids.add(profile_id)
            self.remember_password_check.set_active(True)
            self.status.set_text("Profile saved; password stored in the Linux keyring.")
        else:
            self.remember_password_check.set_active(False)
            self._remembered_password_ids.discard(profile_id)
            self.status.set_text(
                f"Profile saved, but the password was not stored: {error}")
        return False

    def _delete_keyring_password(self, profile_id: str, *, success_text: str) -> None:
        def worker() -> None:
            try:
                secret_store.delete_password(profile_id)
                error = None
            except Exception as exc:
                error = exc
            GLib.idle_add(self._keyring_delete_done, profile_id,
                          success_text, error)

        threading.Thread(target=worker, name="proxypilot-keyring-delete",
                         daemon=True).start()

    def _keyring_delete_done(self, profile_id: str, success_text: str,
                             error: Exception | None) -> bool:
        if self.closing:
            return False
        if error is None:
            self._remembered_password_ids.discard(profile_id)
            if self.profile_id == profile_id:
                self.remember_password_check.set_active(False)
            self.status.set_text(success_text)
        else:
            self.status.set_text(
                f"Profile was changed, but its keyring entry could not be removed: {error}")
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
