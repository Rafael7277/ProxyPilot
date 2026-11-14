"""GTK SSH/SFTP page. Network and file operations always run off the UI thread."""
from __future__ import annotations

import importlib.util
from pathlib import Path, PurePosixPath
import posixpath
import queue
import socket
import threading
from typing import Any

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, GLib, Gtk

try:
    gi.require_version("Vte", "3.91")
    from gi.repository import Vte
except (ImportError, ValueError):
    Vte = None

from . import remote_access


BG = "#0d1422"
CARD = "#172235"
CARD2 = "#202f47"
TEXT = "#f4f7fc"


def _label(text: str, *, css_class: str | None = None) -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0, wrap=True, selectable=True)
    if css_class:
        label.add_css_class(css_class)
    return label


def _entry(placeholder: str, *, value: str = "") -> Gtk.Entry:
    return Gtk.Entry(text=value, placeholder_text=placeholder, hexpand=True)


class RemoteAccessPage(Gtk.Box):
    """Saved connection profiles with SFTP browsing and an optional VTE shell."""

    def __init__(self, parent: Gtk.Window, status_callback=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.parent = parent
        self.status_callback = status_callback or (lambda _text: None)
        self.profiles: list[remote_access.SSHProfile] = []
        self.profile_id: str | None = None
        self.session: remote_access.RemoteSession | None = None
        self.remote_path = "."
        self.local_path = str(Path.home())
        self.transfer_cancel: threading.Event | None = None
        self.connecting = False
        self._closing = False
        self.shell_thread: threading.Thread | None = None
        self.shell_input: queue.Queue[bytes] = queue.Queue(maxsize=256)
        self._shell_size_source: int | None = None
        self._last_shell_size: tuple[int, int] | None = None
        self.terminal = None
        self._make_ui()
        self._reload_profiles()
        self._load_local_directory(self.local_path)

    def _make_ui(self) -> None:
        self.set_margin_top(18)
        self.set_margin_bottom(16)
        self.set_margin_start(20)
        self.set_margin_end(20)
        self.append(_label("SSH / SFTP", css_class="page-title"))
        self.append(_label(
            "Connect to a server, browse files, transfer with progress, and use an interactive shell. "
            "Passwords are requested per session and are never saved in a profile.", css_class="muted"))

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
        new_button = Gtk.Button(label="New")
        new_button.connect("clicked", lambda *_: self._clear_form())
        delete_button = Gtk.Button(label="Delete")
        delete_button.connect("clicked", self._delete_profile)
        profile_actions.append(new_button)
        profile_actions.append(delete_button)
        profile_panel.append(profile_actions)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        content.set_margin_start(14)
        self.name_entry = _entry("Connection name")
        self.host_entry = _entry("Server host or IP")
        self.port_entry = _entry("22", value="22")
        self.port_entry.set_max_width_chars(7)
        self.username_entry = _entry("Username")
        self.identity_entry = _entry("Optional private key path, e.g. ~/.ssh/id_ed25519")
        self.password_entry = _entry("Optional password / key passphrase (not saved)")
        self.password_entry.set_visibility(False)
        self.proxy_check = Gtk.CheckButton(label="Use ProxyPilot proxy for SSH, SFTP, and terminal")
        self.proxy_check.set_active(False)
        form = Gtk.Grid(column_spacing=8, row_spacing=7)
        self._form_row(form, 0, "Name", self.name_entry)
        self._form_row(form, 1, "Host", self.host_entry)
        self._form_row(form, 2, "Port", self.port_entry)
        self._form_row(form, 3, "User", self.username_entry)
        self._form_row(form, 4, "Private key", self.identity_entry)
        self._form_row(form, 5, "Secret", self.password_entry)
        form.attach(self.proxy_check, 1, 6, 1, 1)
        content.append(form)
        content.append(_label(
            "When checked, the connection uses the ProxyPilot proxy-only CONNECT route. "
            "If the bridge or upstream proxy fails, it does not connect directly.", css_class="muted"))

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
        self.save_button = Gtk.Button(label="Save profile")
        self.save_button.connect("clicked", self._save_profile)
        self.connect_button = Gtk.Button(label="Connect")
        self.connect_button.add_css_class("suggested-action")
        self.connect_button.connect("clicked", self._connect_clicked)
        self.disconnect_button = Gtk.Button(label="Disconnect")
        self.disconnect_button.set_sensitive(False)
        self.disconnect_button.connect("clicked", self._disconnect)
        actions.append(self.save_button)
        actions.append(self.connect_button)
        actions.append(self.disconnect_button)
        content.append(actions)
        self.connection_status = _label("Not connected.", css_class="muted")
        content.append(self.connection_status)

        self.notebook = Gtk.Notebook(hexpand=True, vexpand=True)
        self.notebook.append_page(self._build_sftp_page(), Gtk.Label(label="SFTP Files"))
        self.notebook.append_page(self._build_terminal_page(), Gtk.Label(label="Terminal"))
        content.append(self.notebook)
        split.set_start_child(profile_panel)
        split.set_end_child(content)
        split.set_position(255)

        if importlib.util.find_spec("paramiko") is None:
            self.connect_button.set_sensitive(False)
            self.connection_status.set_text(
                "SSH backend is unavailable. Install python3-paramiko or install the Debian package.")
        if Vte is None:
            self.terminal_status.set_text(
                "Embedded terminal needs GTK 4 VTE. Install gir1.2-vte-3.91.")

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

    def _build_sftp_page(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        panes = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL, wide_handle=True,
                          hexpand=True, vexpand=True)
        local_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        remote_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        local_box.append(_label("Local files", css_class="title"))
        remote_box.append(_label("Server files", css_class="title"))
        self.local_path_entry = _entry("Local directory", value=self.local_path)
        self.remote_path_entry = _entry("Remote directory")
        self.local_path_entry.connect("activate", self._local_path_activate)
        self.remote_path_entry.connect("activate", self._remote_path_activate)
        local_controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        local_controls.append(self.local_path_entry)
        local_up = Gtk.Button(label="↑")
        local_up.set_tooltip_text("Open parent directory")
        local_up.connect("clicked", lambda *_: self._local_parent())
        local_controls.append(local_up)
        remote_controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=5)
        remote_controls.append(self.remote_path_entry)
        remote_up = Gtk.Button(label="↑")
        remote_up.set_tooltip_text("Open parent directory")
        remote_up.connect("clicked", lambda *_: self._remote_parent())
        remote_controls.append(remote_up)
        local_box.append(local_controls)
        remote_box.append(remote_controls)
        self.local_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.remote_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.local_list.connect("row-activated", self._local_row_activated)
        self.remote_list.connect("row-activated", self._remote_row_activated)
        local_box.append(self._scroll(self.local_list))
        remote_box.append(self._scroll(self.remote_list))
        panes.set_start_child(local_box)
        panes.set_end_child(remote_box)
        panes.set_position(430)
        box.append(panes)
        controls = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
        self.upload_button = Gtk.Button(label="Upload selected →")
        self.download_button = Gtk.Button(label="← Download selected")
        self.cancel_transfer_button = Gtk.Button(label="Cancel transfer")
        self.cancel_transfer_button.set_sensitive(False)
        self.upload_button.connect("clicked", self._upload_selected)
        self.download_button.connect("clicked", self._download_selected)
        self.cancel_transfer_button.connect("clicked", self._cancel_transfer)
        controls.append(self.upload_button)
        controls.append(self.download_button)
        controls.append(self.cancel_transfer_button)
        box.append(controls)
        remote_actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=7)
        new_folder = Gtk.Button(label="New server folder")
        new_folder.connect("clicked", self._new_remote_folder)
        rename = Gtk.Button(label="Rename selected server item")
        rename.connect("clicked", self._rename_remote_item)
        delete = Gtk.Button(label="Delete selected server item…")
        delete.add_css_class("destructive-action")
        delete.connect("clicked", self._delete_remote_item)
        remote_actions.append(new_folder)
        remote_actions.append(rename)
        remote_actions.append(delete)
        box.append(remote_actions)
        self.transfer_progress = Gtk.ProgressBar(show_text=True)
        self.transfer_progress.set_text("Idle")
        box.append(self.transfer_progress)
        self._draw_local([])
        self.remote_path_entry.set_text(".")
        return box

    def _build_terminal_page(self) -> Gtk.Widget:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.terminal_status = _label("Connect to a server to open an interactive shell.", css_class="muted")
        box.append(self.terminal_status)
        if Vte is None:
            box.append(_label("Install the GTK 4 VTE introspection package to enable the embedded terminal."))
            self.terminal = None
        else:
            self.terminal = Vte.Terminal()
            self.terminal.set_scrollback_lines(5000)
            background = Gdk.RGBA()
            background.parse(BG)
            foreground = Gdk.RGBA()
            foreground.parse(TEXT)
            self.terminal.set_color_background(background)
            self.terminal.set_color_foreground(foreground)
            self.terminal.set_input_enabled(True)
            self.terminal.connect("commit", self._terminal_commit)
            box.append(self._scroll(self.terminal))
        return box

    def _reload_profiles(self) -> None:
        self._clear_list(self.profile_list)
        try:
            self.profiles = remote_access.load_profiles()
        except Exception as exc:
            self.connection_status.set_text(f"Cannot load saved profiles: {type(exc).__name__}: {exc}")
            return
        for profile in self.profiles:
            row = Gtk.ListBoxRow()
            row.profile = profile
            state = " · ProxyPilot proxy" if profile.use_proxy else " · direct"
            row.set_child(_label(f"{profile.name}\n{profile.username}@{profile.host}:{profile.port}{state}"))
            self.profile_list.append(row)

    @staticmethod
    def _clear_list(widget: Gtk.ListBox) -> None:
        child = widget.get_first_child()
        while child:
            following = child.get_next_sibling()
            widget.remove(child)
            child = following

    def _profile_selected(self, _list: Gtk.ListBox, row: Gtk.ListBoxRow | None) -> None:
        if row is None:
            return
        profile = row.profile
        self.profile_id = profile.profile_id
        self.name_entry.set_text(profile.name)
        self.host_entry.set_text(profile.host)
        self.port_entry.set_text(str(profile.port))
        self.username_entry.set_text(profile.username)
        self.identity_entry.set_text(profile.identity_file or "")
        self.password_entry.set_text("")
        self.proxy_check.set_active(profile.use_proxy)

    def _clear_form(self) -> None:
        self.profile_id = None
        self.name_entry.set_text("")
        self.host_entry.set_text("")
        self.port_entry.set_text("22")
        self.username_entry.set_text("")
        self.identity_entry.set_text("")
        self.password_entry.set_text("")
        self.proxy_check.set_active(False)
        self.profile_list.unselect_all()

    def _form_profile(self) -> remote_access.SSHProfile:
        try:
            port = int(self.port_entry.get_text().strip())
        except ValueError as exc:
            raise ValueError("SSH port must be an integer") from exc
        identity = self.identity_entry.get_text().strip() or None
        if self.profile_id:
            profile_id = self.profile_id
            profile = remote_access.SSHProfile(profile_id, self.name_entry.get_text(),
                self.host_entry.get_text(), port, self.username_entry.get_text(),
                identity, self.proxy_check.get_active())
            return remote_access.validate_profile(profile)
        return remote_access.SSHProfile.create(self.name_entry.get_text(),
            self.host_entry.get_text(), self.username_entry.get_text(), port=port,
            identity_file=identity, use_proxy=self.proxy_check.get_active())

    def _save_profile(self, _button) -> None:
        try:
            profile = self._form_profile()
            self.profiles = remote_access.upsert_profile(profile)
            self.profile_id = profile.profile_id
            self._reload_profiles()
            self.connection_status.set_text(f"Saved profile: {profile.name}")
        except Exception as exc:
            self._show_error("Profile was not saved", exc)

    def _delete_profile(self, _button) -> None:
        if not self.profile_id:
            self.connection_status.set_text("Select a saved profile first.")
            return
        dialog = Gtk.MessageDialog(transient_for=self.parent, modal=True,
            message_type=Gtk.MessageType.WARNING, buttons=Gtk.ButtonsType.OK_CANCEL,
            text="Delete saved connection profile?")
        dialog.set_secondary_text("This removes only the local profile. It does not change anything on the server.")
        dialog.connect("response", self._confirm_delete, self.profile_id)
        dialog.present()

    def _confirm_delete(self, dialog, response, profile_id: str) -> None:
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return
        try:
            remote_access.delete_profile(profile_id)
            self._clear_form()
            self._reload_profiles()
            self.connection_status.set_text("Saved profile deleted.")
        except Exception as exc:
            self._show_error("Profile was not deleted", exc)

    def _connect_clicked(self, _button) -> None:
        if self.session and not self.session.closed:
            self.connection_status.set_text("Disconnect the current server before connecting to another one.")
            return
        if self.connecting:
            return
        try:
            profile = self._form_profile()
        except Exception as exc:
            self._show_error("Connection profile is invalid", exc)
            return
        self._start_connect(profile, self.password_entry.get_text() or None)

    def _start_connect(self, profile: remote_access.SSHProfile, password: str | None) -> None:
        if self._closing:
            return
        self.connecting = True
        self.connect_button.set_sensitive(False)
        route = "through ProxyPilot proxy only" if profile.use_proxy else "directly"
        self.connection_status.set_text(f"Connecting {route} to {profile.host}:{profile.port}…")
        self.status_callback(f"SSH connection starting {route}.")
        def worker():
            try:
                session = remote_access.connect_profile(profile, password=password,
                                                        passphrase=password)
                result = (profile, session, None)
            except Exception as exc:
                result = (profile, None, exc)
            GLib.idle_add(self._connect_done, *result)
        threading.Thread(target=worker, name="proxypilot-ssh-connect", daemon=True).start()

    def _connect_done(self, profile, session, error) -> bool:
        self.connecting = False
        if self._closing:
            if session is not None:
                session.close()
            return GLib.SOURCE_REMOVE
        self.connect_button.set_sensitive(True)
        if error is not None:
            if isinstance(error, remote_access.UnknownHostKeyError):
                self._ask_trust_host_key(profile, error)
                return GLib.SOURCE_REMOVE
            self.password_entry.set_text("")
            if type(error).__name__ in {"AuthenticationException", "UnableToAuthenticate"}:
                self._ask_password(profile)
                return GLib.SOURCE_REMOVE
            self.connection_status.set_text(f"Connection failed: {type(error).__name__}: {error}")
            self.status_callback("SSH connection failed; no direct fallback was attempted." if profile.use_proxy else "SSH connection failed.")
            return GLib.SOURCE_REMOVE
        self.session = session
        self.password_entry.set_text("")
        self.disconnect_button.set_sensitive(True)
        self.connection_status.set_text(
            f"Connected to {profile.host}:{profile.port} · " +
            ("ProxyPilot proxy route active · server key verified" if profile.use_proxy
             else "Direct route · server key verified"))
        self.status_callback("SSH session connected; shell and SFTP use the same SSH transport.")
        self._load_remote_directory(self.remote_path)
        self._start_shell()
        return GLib.SOURCE_REMOVE

    def _ask_trust_host_key(self, profile: remote_access.SSHProfile,
                            error: remote_access.UnknownHostKeyError) -> None:
        dialog = Gtk.MessageDialog(transient_for=self.parent, modal=True,
            message_type=Gtk.MessageType.WARNING, buttons=Gtk.ButtonsType.OK_CANCEL,
            text="Verify this server's SSH host key")
        dialog.set_secondary_text(
            f"{profile.host}:{profile.port}\n{error.key_type}\n{error.fingerprint}\n\n"
            "Compare this fingerprint with the server administrator using a trusted channel. "
            "Only approve it if it matches.")
        dialog.connect("response", self._trust_host_key_response, profile, error.key)
        dialog.present()

    def _trust_host_key_response(self, dialog, response, profile, key) -> None:
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            self.password_entry.set_text("")
            self.connection_status.set_text("Connection cancelled; the unknown host key was not saved.")
            return
        try:
            remote_access.trust_host_key(profile, key)
        except Exception as exc:
            self._show_error("Host key was not saved", exc)
            return
        self.connection_status.set_text("Host key verified and saved; retrying connection…")
        self._start_connect(profile, self.password_entry.get_text() or None)

    def _ask_password(self, profile: remote_access.SSHProfile) -> None:
        dialog = Gtk.Dialog(transient_for=self.parent, modal=True, title="SSH authentication")
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Connect", Gtk.ResponseType.OK)
        box = dialog.get_content_area()
        box.append(_label(f"Password or private-key passphrase for {profile.username}@{profile.host}"))
        secret = Gtk.Entry(visibility=False, hexpand=True, activates_default=True)
        secret.set_placeholder_text("This value is used once and is not saved")
        box.append(secret)
        dialog.set_default_response(Gtk.ResponseType.OK)
        dialog.connect("response", self._password_response, profile, secret)
        dialog.present()

    def _password_response(self, dialog, response, profile, secret) -> None:
        value = secret.get_text()
        dialog.destroy()
        if response != Gtk.ResponseType.OK or not value:
            self.connection_status.set_text("Authentication cancelled.")
            return
        self.password_entry.set_text(value)
        self._start_connect(profile, value)

    def _disconnect(self, _button) -> None:
        self._stop_session("Disconnected by user.")

    def _stop_session(self, message: str) -> None:
        session = self.session
        self.session = None
        self.disconnect_button.set_sensitive(False)
        if self.transfer_cancel is not None:
            self.transfer_cancel.set()
            self.transfer_cancel = None
            self.cancel_transfer_button.set_sensitive(False)
            self.upload_button.set_sensitive(True)
            self.download_button.set_sensitive(True)
        while True:
            try:
                self.shell_input.get_nowait()
            except queue.Empty:
                break
        if self._shell_size_source is not None:
            try:
                GLib.source_remove(self._shell_size_source)
            except Exception:
                pass
            self._shell_size_source = None
        self._last_shell_size = None
        if session is not None:
            session.close()
        self.connection_status.set_text(message)
        self.terminal_status.set_text(message)

    def _build_terminal_message(self, text: str) -> None:
        if self.terminal is not None:
            self.terminal.feed(("\r\n" + text + "\r\n").encode("utf-8", "replace"))

    def _start_shell(self) -> None:
        session = self.session
        if session is None:
            return
        if self.terminal is None:
            self.terminal_status.set_text("SFTP is ready. Install gir1.2-vte-3.91 to enable the embedded shell.")
            return
        while True:
            try:
                self.shell_input.get_nowait()
            except queue.Empty:
                break
        self.terminal.reset(True, True)
        self.terminal_status.set_text("Opening interactive shell…")
        width = max(20, self.terminal.get_column_count())
        height = max(5, self.terminal.get_row_count())
        def worker():
            try:
                channel = session.open_shell(width=width, height=height)
                result = (channel, None)
            except Exception as exc:
                result = (None, exc)
            GLib.idle_add(self._shell_opened, session, *result)
        self.shell_thread = threading.Thread(target=worker, name="proxypilot-ssh-shell", daemon=True)
        self.shell_thread.start()

    def _shell_opened(self, session, channel, error) -> bool:
        if self.session is not session:
            if channel is not None:
                channel.close()
            return GLib.SOURCE_REMOVE
        if error is not None:
            self.terminal_status.set_text(f"Could not open remote shell: {type(error).__name__}: {error}")
            return GLib.SOURCE_REMOVE
        self.terminal_status.set_text("Interactive shell connected. Terminal input is sent over this SSH session.")
        self.terminal.grab_focus()
        self._last_shell_size = (self.terminal.get_column_count(), self.terminal.get_row_count())
        self._shell_size_source = GLib.timeout_add(400, self._poll_terminal_size, session)
        thread = threading.Thread(target=self._shell_io, args=(session, channel),
                                  name="proxypilot-ssh-terminal", daemon=True)
        self.shell_thread = thread
        thread.start()
        return GLib.SOURCE_REMOVE

    def _shell_io(self, session, channel) -> None:
        idle_wait = threading.Event()
        while self.session is session and not session.closed and not channel.closed:
            try:
                while True:
                    data = self.shell_input.get_nowait()
                    channel.sendall(data)
            except queue.Empty:
                pass
            except OSError as exc:
                GLib.idle_add(self._terminal_disconnected, session, str(exc))
                return
            try:
                if channel.recv_ready():
                    data = channel.recv(32768)
                    if not data:
                        break
                    GLib.idle_add(self._terminal_feed, data)
            except socket.timeout:
                pass
            except OSError as exc:
                GLib.idle_add(self._terminal_disconnected, session, str(exc))
                return
            idle_wait.wait(0.02)
        GLib.idle_add(self._terminal_disconnected, session, "Remote shell closed.")

    def _terminal_feed(self, data: bytes) -> bool:
        if self.terminal is not None:
            self.terminal.feed(data)
        return GLib.SOURCE_REMOVE

    def _terminal_commit(self, _terminal, text, size) -> None:
        if self.session is None or self.session.closed:
            return
        data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        if isinstance(size, int):
            data = data[:size]
        try:
            self.shell_input.put_nowait(data)
        except queue.Full:
            self.connection_status.set_text("Terminal input queue is full; wait for the server to respond.")

    def _poll_terminal_size(self, session) -> bool:
        if self.session is not session or session.closed or self.terminal is None:
            self._shell_size_source = None
            return GLib.SOURCE_REMOVE
        size = (self.terminal.get_column_count(), self.terminal.get_row_count())
        if size != self._last_shell_size:
            self._last_shell_size = size
            threading.Thread(target=self._resize_shell, args=(session, *size),
                             name="proxypilot-ssh-resize", daemon=True).start()
        return GLib.SOURCE_CONTINUE

    @staticmethod
    def _resize_shell(session, width: int, height: int) -> None:
        try:
            session.resize_shell(width, height)
        except Exception:
            # A resize is advisory; the shell and transfer channels remain usable.
            pass

    def _terminal_disconnected(self, session, message: str) -> bool:
        if self.session is not session:
            return GLib.SOURCE_REMOVE
        self.terminal_status.set_text(message)
        return GLib.SOURCE_REMOVE

    def _local_path_activate(self, entry) -> None:
        self._load_local_directory(entry.get_text())

    def _remote_path_activate(self, entry) -> None:
        self._load_remote_directory(entry.get_text())

    def _local_parent(self) -> None:
        path = Path(self.local_path)
        self._load_local_directory(str(path.parent))

    def _remote_parent(self) -> None:
        self._load_remote_directory(posixpath.dirname(self.remote_path.rstrip("/")) or "/")

    def _load_local_directory(self, requested: str) -> None:
        def worker():
            try:
                directory = Path(requested).expanduser().resolve(strict=True)
                entries = remote_access.list_local(directory)
                result = (str(directory), entries, None)
            except Exception as exc:
                result = (requested, [], exc)
            GLib.idle_add(self._local_directory_done, *result)
        threading.Thread(target=worker, name="proxypilot-local-files", daemon=True).start()

    def _local_directory_done(self, path, entries, error) -> bool:
        if error is not None:
            self.status_callback(f"Cannot list local folder: {error}")
            return GLib.SOURCE_REMOVE
        self.local_path = path
        self.local_path_entry.set_text(path)
        self._draw_local(entries)
        return GLib.SOURCE_REMOVE

    def _draw_local(self, entries: list[dict[str, Any]]) -> None:
        self._clear_list(self.local_list)
        for item in entries:
            row = Gtk.ListBoxRow()
            row.item = item
            marker = "📁" if item["is_dir"] else "📄"
            detail = "directory" if item["is_dir"] else f"{item['size']} bytes"
            row.set_child(_label(f"{marker}  {item['name']}    ·    {detail}"))
            self.local_list.append(row)

    def _local_row_activated(self, _list, row) -> None:
        if row and row.item["is_dir"]:
            self._load_local_directory(str(Path(self.local_path) / row.item["name"]))

    def _load_remote_directory(self, requested: str) -> None:
        session = self.session
        if session is None or session.closed:
            self.status_callback("Connect to a server before browsing remote files.")
            return
        path = requested.strip() or "."
        def worker():
            try:
                sftp = remote_access._sftp(session)
                canonical = sftp.normalize(path)
                entries = remote_access.list_remote(session, canonical)
                result = (canonical, entries, None)
            except Exception as exc:
                result = (path, [], exc)
            GLib.idle_add(self._remote_directory_done, session, *result)
        threading.Thread(target=worker, name="proxypilot-remote-files", daemon=True).start()

    def _remote_directory_done(self, session, path, entries, error) -> bool:
        if self.session is not session:
            return GLib.SOURCE_REMOVE
        if error is not None:
            self.status_callback(f"Cannot list remote folder: {type(error).__name__}: {error}")
            return GLib.SOURCE_REMOVE
        self.remote_path = path
        self.remote_path_entry.set_text(path)
        self._draw_remote(entries)
        return GLib.SOURCE_REMOVE

    def _draw_remote(self, entries: list[dict[str, Any]]) -> None:
        self._clear_list(self.remote_list)
        for item in entries:
            row = Gtk.ListBoxRow()
            row.item = item
            marker = "📁" if item["is_dir"] else "📄"
            detail = "directory" if item["is_dir"] else f"{item['size']} bytes"
            row.set_child(_label(f"{marker}  {item['name']}    ·    {detail}"))
            self.remote_list.append(row)

    def _remote_row_activated(self, _list, row) -> None:
        if row and row.item["is_dir"]:
            self._load_remote_directory(posixpath.join(self.remote_path, row.item["name"]))

    def _new_remote_folder(self, _button) -> None:
        self._ask_remote_name("Create server folder", "Folder name", self._create_remote_folder)

    def _rename_remote_item(self, _button) -> None:
        row = self.remote_list.get_selected_row()
        if row is None:
            self.status_callback("Select a server item to rename.")
            return
        self._ask_remote_name("Rename server item", "New name", lambda name: self._rename_remote_to(row.item, name))

    def _ask_remote_name(self, title: str, prompt: str, callback) -> None:
        dialog = Gtk.Dialog(transient_for=self.parent, modal=True, title=title)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Continue", Gtk.ResponseType.OK)
        box = dialog.get_content_area()
        box.append(_label(prompt))
        entry = Gtk.Entry(hexpand=True)
        box.append(entry)
        dialog.set_default_response(Gtk.ResponseType.OK)
        dialog.connect("response", self._remote_name_response, entry, callback)
        dialog.present()
        entry.grab_focus()

    def _remote_name_response(self, dialog, response, entry, callback) -> None:
        name = entry.get_text()
        dialog.destroy()
        if response == Gtk.ResponseType.OK:
            callback(name)

    def _create_remote_folder(self, name: str) -> None:
        session = self.session
        if session is None or session.closed:
            return
        def worker():
            try:
                remote_access.create_remote_directory(session, self.remote_path, name)
                error = None
            except Exception as exc:
                error = exc
            GLib.idle_add(self._remote_mutation_done, session, error)
        threading.Thread(target=worker, name="proxypilot-sftp-mkdir", daemon=True).start()

    def _rename_remote_to(self, item: dict[str, Any], new_name: str) -> None:
        session = self.session
        if session is None or session.closed:
            return
        path = posixpath.join(self.remote_path, item["name"])
        def worker():
            try:
                remote_access.rename_remote(session, path, new_name)
                error = None
            except Exception as exc:
                error = exc
            GLib.idle_add(self._remote_mutation_done, session, error)
        threading.Thread(target=worker, name="proxypilot-sftp-rename", daemon=True).start()

    def _delete_remote_item(self, _button) -> None:
        row = self.remote_list.get_selected_row()
        if row is None:
            self.status_callback("Select a server item to delete.")
            return
        item = row.item
        dialog = Gtk.MessageDialog(transient_for=self.parent, modal=True,
            message_type=Gtk.MessageType.WARNING, buttons=Gtk.ButtonsType.OK_CANCEL,
            text="Delete this server item?")
        detail = ("Only empty folders can be deleted." if item["is_dir"] else
                  "This permanently deletes the selected remote file.")
        dialog.set_secondary_text(f"{item['name']}\n{detail}")
        dialog.connect("response", self._delete_remote_response, item)
        dialog.present()

    def _delete_remote_response(self, dialog, response, item) -> None:
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return
        session = self.session
        if session is None or session.closed:
            return
        path = posixpath.join(self.remote_path, item["name"])
        def worker():
            try:
                remote_access.delete_remote(session, path, is_dir=item["is_dir"])
                error = None
            except Exception as exc:
                error = exc
            GLib.idle_add(self._remote_mutation_done, session, error)
        threading.Thread(target=worker, name="proxypilot-sftp-delete", daemon=True).start()

    def _remote_mutation_done(self, session, error) -> bool:
        if self.session is not session:
            return GLib.SOURCE_REMOVE
        if error is not None:
            self.status_callback(f"Remote file operation failed: {type(error).__name__}: {error}")
        else:
            self.status_callback("Remote file operation completed.")
            self._load_remote_directory(self.remote_path)
        return GLib.SOURCE_REMOVE

    def _upload_selected(self, _button) -> None:
        row = self.local_list.get_selected_row()
        if row is None or row.item["is_dir"]:
            self.status_callback("Select a local file to upload.")
            return
        source = str(Path(self.local_path) / row.item["name"])
        destination = posixpath.join(self.remote_path, row.item["name"])
        self._begin_transfer("upload", source, destination)

    def _download_selected(self, _button) -> None:
        row = self.remote_list.get_selected_row()
        if row is None or row.item["is_dir"]:
            self.status_callback("Select a remote file to download.")
            return
        source = posixpath.join(self.remote_path, row.item["name"])
        destination = str(Path(self.local_path) / row.item["name"])
        self._begin_transfer("download", source, destination)

    def _begin_transfer(self, direction: str, source: str, destination: str) -> None:
        session = self.session
        if session is None or session.closed:
            self.status_callback("Connect to a server before transferring files.")
            return
        if self.transfer_cancel is not None:
            self.status_callback("A file transfer is already running.")
            return
        cancel = threading.Event()
        self.transfer_cancel = cancel
        self.cancel_transfer_button.set_sensitive(True)
        self.upload_button.set_sensitive(False)
        self.download_button.set_sensitive(False)
        self.transfer_progress.set_fraction(0)
        self.transfer_progress.set_text("Checking destination…")
        def worker():
            try:
                if direction == "upload":
                    exists = remote_access._remote_exists(remote_access._sftp(session), destination)
                else:
                    exists = Path(destination).exists()
                GLib.idle_add(self._transfer_destination_ready, session, direction,
                              source, destination, exists, cancel)
            except Exception as exc:
                GLib.idle_add(self._transfer_done, session, exc)
        threading.Thread(target=worker, name="proxypilot-transfer-check", daemon=True).start()

    def _transfer_destination_ready(self, session, direction, source, destination,
                                   exists: bool, cancel: threading.Event) -> bool:
        if self.session is not session:
            self._transfer_done(session, RuntimeError("SSH session closed"))
            return GLib.SOURCE_REMOVE
        if exists:
            dialog = Gtk.MessageDialog(transient_for=self.parent, modal=True,
                message_type=Gtk.MessageType.WARNING, buttons=Gtk.ButtonsType.OK_CANCEL,
                text="Replace the destination file?")
            dialog.set_secondary_text(f"{destination}\nThe existing file will be replaced only after confirmation.")
            dialog.connect("response", self._transfer_overwrite_response, session,
                           direction, source, destination, cancel)
            dialog.present()
        else:
            self._start_transfer_worker(session, direction, source, destination, False, cancel)
        return GLib.SOURCE_REMOVE

    def _transfer_overwrite_response(self, dialog, response, session, direction,
                                     source, destination, cancel) -> None:
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            self._transfer_done(session, RuntimeError("Transfer cancelled by user"))
            return
        self._start_transfer_worker(session, direction, source, destination, True, cancel)

    def _start_transfer_worker(self, session, direction, source, destination,
                               overwrite, cancel: threading.Event) -> None:
        self.transfer_progress.set_text("Transferring…")
        def progress(transferred: int, total: int) -> None:
            if cancel.is_set():
                raise InterruptedError("Transfer cancelled")
            fraction = min(1.0, transferred / total) if total else 0.0
            GLib.idle_add(self._transfer_progress, fraction, transferred, total)
        def worker():
            try:
                if direction == "upload":
                    remote_access.upload_file(session, source, destination,
                                              overwrite=overwrite, progress=progress)
                else:
                    remote_access.download_file(session, source, destination,
                                                overwrite=overwrite, progress=progress)
                result = None
            except Exception as exc:
                result = exc
            GLib.idle_add(self._transfer_done, session, result)
        threading.Thread(target=worker, name=f"proxypilot-sftp-{direction}", daemon=True).start()

    def _transfer_progress(self, fraction: float, transferred: int, total: int) -> bool:
        self.transfer_progress.set_fraction(fraction)
        self.transfer_progress.set_text(f"{transferred:,} / {total:,} bytes")
        return GLib.SOURCE_REMOVE

    def _transfer_done(self, session, error) -> bool:
        if self.session is not session and session is not None:
            return GLib.SOURCE_REMOVE
        self.transfer_cancel = None
        self.cancel_transfer_button.set_sensitive(False)
        self.upload_button.set_sensitive(True)
        self.download_button.set_sensitive(True)
        if error is None:
            self.transfer_progress.set_fraction(1)
            self.transfer_progress.set_text("Transfer complete")
            self._load_local_directory(self.local_path)
            self._load_remote_directory(self.remote_path)
        else:
            message = str(error)
            self.transfer_progress.set_text("Transfer failed or cancelled")
            self.status_callback(f"SFTP transfer failed: {type(error).__name__}: {message}")
        return GLib.SOURCE_REMOVE

    def _cancel_transfer(self, _button) -> None:
        if self.transfer_cancel is not None:
            self.transfer_cancel.set()
            self.cancel_transfer_button.set_sensitive(False)
            self.transfer_progress.set_text("Cancelling after current SFTP block…")

    def _show_error(self, title: str, error: Exception) -> None:
        dialog = Gtk.MessageDialog(transient_for=self.parent, modal=True,
            message_type=Gtk.MessageType.ERROR, buttons=Gtk.ButtonsType.CLOSE, text=title)
        dialog.set_secondary_text(f"{type(error).__name__}: {error}")
        dialog.connect("response", lambda win, _response: win.destroy())
        dialog.present()

    def shutdown(self) -> None:
        self._closing = True
        if self.transfer_cancel is not None:
            self.transfer_cancel.set()
        self._stop_session("ProxyPilot closed.")
