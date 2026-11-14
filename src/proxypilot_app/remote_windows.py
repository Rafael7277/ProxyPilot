"""Independent two-sided SFTP file manager and one-shell-per-window SSH terminals."""
from __future__ import annotations

import json
import posixpath
import queue
import socket
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gdk, GLib, GObject, Gtk

try:
    gi.require_version("Vte", "3.91")
    from gi.repository import Vte
except (ImportError, ValueError):
    Vte = None

from . import remote_access


class SSHConnectionFlow:
    """Connect without blocking GTK and require explicit host-key approval."""

    def __init__(self, parent: Gtk.Window, profile: remote_access.SSHProfile,
                 on_connected: Callable[[remote_access.RemoteSession], None],
                 on_status: Callable[[str], None],
                 on_failed: Callable[[], None] | None = None):
        self.parent = parent
        self.profile = profile
        self.on_connected = on_connected
        self.on_status = on_status
        self.on_failed = on_failed or (lambda: None)
        self.cancelled = False

    def connect(self, secret: str | None = None) -> None:
        if self.cancelled:
            return
        self.on_status(f"Connecting to {self.profile.username}@{self.profile.host}:{self.profile.port}…")

        def worker():
            try:
                session = remote_access.connect_profile(
                    self.profile, password=secret, passphrase=secret)
                result = (session, None, secret)
            except Exception as exc:
                result = (None, exc, secret)
            GLib.idle_add(self._complete, *result)

        threading.Thread(target=worker, name="proxypilot-window-ssh-connect",
                         daemon=True).start()

    def _complete(self, session, error, secret) -> bool:
        if self.cancelled:
            if session is not None:
                session.close()
            return GLib.SOURCE_REMOVE
        if error is None:
            self.on_connected(session)
            return GLib.SOURCE_REMOVE
        if isinstance(error, remote_access.UnknownHostKeyError):
            self._ask_trust(error, secret)
            return GLib.SOURCE_REMOVE
        if type(error).__name__ in {"AuthenticationException", "UnableToAuthenticate"}:
            self._ask_secret()
            return GLib.SOURCE_REMOVE
        self.on_failed()
        self.on_status(f"Connection failed: {type(error).__name__}: {error}")
        return GLib.SOURCE_REMOVE

    def _ask_trust(self, error: remote_access.UnknownHostKeyError,
                   secret: str | None) -> None:
        dialog = Gtk.MessageDialog(
            transient_for=self.parent, modal=True,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text="Verify this server's SSH host key")
        dialog.set_secondary_text(
            f"{self.profile.host}:{self.profile.port}\n{error.key_type}\n"
            f"{error.fingerprint}\n\nCompare this fingerprint with the server administrator "
            "over a trusted channel before accepting it.")
        dialog.connect("response", self._trust_response, error.key, secret)
        dialog.present()

    def _trust_response(self, dialog, response, key, secret) -> None:
        dialog.destroy()
        if response != Gtk.ResponseType.OK or self.cancelled:
            self.on_failed()
            self.on_status("Connection cancelled; the unknown host key was not saved.")
            return
        try:
            remote_access.trust_host_key(self.profile, key)
        except Exception as exc:
            self.on_failed()
            self.on_status(f"Host key was not saved: {type(exc).__name__}: {exc}")
            return
        self.connect(secret)

    def _ask_secret(self) -> None:
        if self.cancelled:
            return
        dialog = Gtk.Dialog(transient_for=self.parent, modal=True,
                            title="SSH authentication")
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Connect", Gtk.ResponseType.OK)
        content = dialog.get_content_area()
        label = Gtk.Label(
            label=f"SSH password for {self.profile.username}@{self.profile.host}",
            xalign=0, wrap=True)
        content.append(label)
        entry = Gtk.Entry(visibility=False, hexpand=True, activates_default=True)
        entry.set_placeholder_text("Used for this connection only; not saved")
        content.append(entry)
        dialog.set_default_response(Gtk.ResponseType.OK)
        dialog.connect("response", self._secret_response, entry)
        dialog.present()

    def _secret_response(self, dialog, response, entry) -> None:
        secret = entry.get_text()
        dialog.destroy()
        if response != Gtk.ResponseType.OK or not secret or self.cancelled:
            self.on_failed()
            self.on_status("Authentication cancelled.")
            return
        self.connect(secret)

    def cancel(self) -> None:
        self.cancelled = True


class FilePane(Gtk.Box):
    def __init__(self, owner: "RemoteFileManagerWindow", side: str,
                 profiles: list[remote_access.SSHProfile],
                 initial_profile: remote_access.SSHProfile | None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=7)
        self.owner = owner
        self.side = side
        self.session: remote_access.RemoteSession | None = None
        self.profile: remote_access.SSHProfile | None = None
        self.flow: SSHConnectionFlow | None = None
        self.path = str(Path.home()) if side == "left" else "."
        self.items: list[dict[str, Any]] = []
        self.closing = False
        self.refresh_generation = 0
        self.profiles = self._unique_profiles(profiles, initial_profile)
        self._initializing_selector = True
        self._make_ui()
        self._apply_selection(initial_profile)
        self._initializing_selector = False

    @staticmethod
    def _unique_profiles(profiles, initial_profile):
        result = []
        seen = set()
        for profile in [*profiles, *([initial_profile] if initial_profile else [])]:
            if profile.profile_id not in seen:
                result.append(profile)
                seen.add(profile.profile_id)
        return result

    def _make_ui(self) -> None:
        self.set_margin_top(10)
        self.set_margin_bottom(10)
        self.set_margin_start(10)
        self.set_margin_end(10)
        heading = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.title_label = Gtk.Label(label="Local machine", xalign=0, hexpand=True)
        self.title_label.add_css_class("title")
        heading.append(self.title_label)
        self.endpoint_model = Gtk.StringList.new(["Local machine"] + [
            f"{profile.name} · {profile.username}@{profile.host}:{profile.port}"
            for profile in self.profiles])
        self.endpoint_selector = Gtk.DropDown(model=self.endpoint_model,
                                               hexpand=True)
        self.endpoint_selector.set_tooltip_text("Choose local files or a saved SSH profile")
        self.endpoint_selector.connect("notify::selected", self._selection_changed)
        heading.append(self.endpoint_selector)
        self.connect_button = Gtk.Button(label="Connect")
        self.connect_button.connect("clicked", self._connect_clicked)
        heading.append(self.connect_button)
        self.append(heading)

        location = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.path_entry = Gtk.Entry(text=self.path, hexpand=True)
        self.path_entry.connect("activate", self._path_activated)
        location.append(self.path_entry)
        parent = Gtk.Button(label="↑")
        parent.set_tooltip_text("Open parent folder")
        parent.connect("clicked", lambda *_: self.go_parent())
        location.append(parent)
        refresh = Gtk.Button(label="Refresh")
        refresh.connect("clicked", lambda *_: self.refresh())
        location.append(refresh)
        self.append(location)

        self.file_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.MULTIPLE,
                                     hexpand=True, vexpand=True)
        self.file_list.add_css_class("file-list")
        self.file_list.connect("row-activated", self._row_activated)
        self.file_list.connect("selected-rows-changed",
                               self.owner._selection_changed, self.side)
        pane_click = Gtk.GestureClick.new()
        pane_click.connect("pressed", self.owner._pane_activated, self.side)
        self.file_list.add_controller(pane_click)
        target = Gtk.DropTarget.new(GObject.TYPE_STRING, Gdk.DragAction.MOVE)
        target.connect("drop", self.owner._drop, self.side)
        self.file_list.add_controller(target)
        self.append(self.owner._scroll(self.file_list))
        self.status = Gtk.Label(label="", xalign=0, wrap=True)
        self.status.add_css_class("muted")
        self.append(self.status)

    def _apply_selection(self, profile) -> None:
        if profile is None:
            index = 0
        else:
            index = next((i + 1 for i, candidate in enumerate(self.profiles)
                          if candidate.profile_id == profile.profile_id), 0)
        self.endpoint_selector.set_selected(index)
        self._set_profile_index(index, reload=True)

    def _selection_changed(self, *_args) -> None:
        if self._initializing_selector:
            return
        self._set_profile_index(self.endpoint_selector.get_selected(), reload=True)

    @property
    def signature(self) -> str:
        return "local" if self.profile is None else self.profile.profile_id

    def _set_profile_index(self, index: int, *, reload: bool) -> None:
        self.refresh_generation += 1
        old_session = self.session
        if old_session is not None:
            old_session.close()
        self.session = None
        if self.flow is not None:
            self.flow.cancel()
            self.flow = None
        self.profile = self.profiles[index - 1] if index > 0 and index <= len(self.profiles) else None
        is_local = self.profile is None
        self.connect_button.set_label("Local" if is_local else "Connect")
        self.connect_button.set_sensitive(not is_local)
        self.title_label.set_text("Local machine" if is_local else self.profile.name)
        self.path = str(Path.home()) if is_local else "."
        self.path_entry.set_text(self.path)
        self.status.set_text("Browse local files." if is_local else "Not connected.")
        if reload:
            self.refresh()

    def _connect_clicked(self, _button) -> None:
        if self.session is not None:
            self.session.close()
            self.session = None
            self.connect_button.set_label("Connect")
            self.status.set_text("Disconnected.")
            self._draw([])
            return
        if self.flow is not None or self.profile is None:
            return
        self.connect_button.set_sensitive(False)
        self.connect_button.set_label("Connecting…")
        self.flow = SSHConnectionFlow(self.owner, self.profile,
                                      self._connected, self.status.set_text,
                                      self._connection_failed)
        self.flow.connect(self.owner.passwords.get(self.profile.profile_id))

    def _connected(self, session: remote_access.RemoteSession) -> None:
        if self.closing or self.owner.closing:
            session.close()
            return
        self.flow = None
        self.session = session
        self.connect_button.set_label("Disconnect")
        self.connect_button.set_sensitive(True)
        route = "ProxyPilot proxy" if session.profile.use_proxy else "Direct"
        self.status.set_text(f"Connected · {route} · SSH host key verified")
        self.path = "."
        self.path_entry.set_text(self.path)
        self.refresh()

    def _connection_failed(self) -> None:
        self.flow = None
        if not self.closing:
            self.connect_button.set_label("Connect")
            self.connect_button.set_sensitive(self.profile is not None)

    def _path_activated(self, _entry) -> None:
        self.refresh()

    def go_parent(self) -> None:
        if self.session is None:
            parent = Path(self.path).expanduser().parent
            self.path_entry.set_text(str(parent))
        else:
            parent = posixpath.dirname(self.path.rstrip("/")) or "/"
            self.path_entry.set_text(parent)
        self.refresh()

    def refresh(self) -> None:
        self.refresh_generation += 1
        generation = self.refresh_generation
        requested = self.path_entry.get_text().strip() or ("." if self.profile else str(Path.home()))
        session = self.session
        if self.profile is not None and session is None:
            self.path = requested
            self.status.set_text("Connect to this server to browse its files.")
            self._draw([])
            return

        def worker():
            try:
                if session is None:
                    canonical = str(Path(requested).expanduser().resolve(strict=True))
                    entries = remote_access.list_local(canonical)
                else:
                    canonical = remote_access.normalize_remote_path(session, requested)
                    entries = remote_access.list_remote(session, canonical)
                result = (canonical, entries, None)
            except Exception as exc:
                result = (requested, [], exc)
            GLib.idle_add(self._refresh_done, session, generation, *result)

        threading.Thread(target=worker, name=f"proxypilot-files-{self.side}",
                         daemon=True).start()

    def _refresh_done(self, session, generation, path, entries, error) -> bool:
        if (self.closing or self.owner.closing or self.session is not session or
                generation != self.refresh_generation):
            return GLib.SOURCE_REMOVE
        if error is not None:
            self.status.set_text(f"Cannot list folder: {type(error).__name__}: {error}")
            self._draw([])
            return GLib.SOURCE_REMOVE
        self.path = str(path)
        self.path_entry.set_text(self.path)
        self.items = entries
        self.status.set_text(f"{len(entries)} item(s) · {self.path}")
        self._draw(entries)
        return GLib.SOURCE_REMOVE

    def _draw(self, entries: list[dict[str, Any]]) -> None:
        child = self.file_list.get_first_child()
        while child is not None:
            following = child.get_next_sibling()
            self.file_list.remove(child)
            child = following
        self.items = entries
        for item in entries:
            row = Gtk.ListBoxRow()
            row.item = item
            row.path = (posixpath.join(self.path, item["name"]) if self.session is not None
                        else str(Path(self.path) / item["name"]))
            marker = "🔗" if item["is_symlink"] else ("📁" if item["is_dir"] else "📄")
            detail = "link" if item["is_symlink"] else (
                "folder" if item["is_dir"] else f"{item['size']:,} bytes")
            label = Gtk.Label(label=f"{marker}  {item['name']}    ·    {detail}",
                              xalign=0, selectable=True, ellipsize=3)
            row.set_child(label)
            source = Gtk.DragSource.new()
            source.set_actions(Gdk.DragAction.MOVE)
            source.connect("prepare", self.owner._drag_prepare, self.side, row)
            row.add_controller(source)
            self.file_list.append(row)

    def selected(self) -> list[dict[str, Any]]:
        return [{"name": row.item["name"], "path": row.path,
                 "is_dir": row.item["is_dir"],
                 "is_symlink": row.item["is_symlink"]}
                for row in self.file_list.get_selected_rows()]

    def _row_activated(self, _list, row) -> None:
        if row is None or not row.item["is_dir"]:
            return
        if row.item["is_symlink"]:
            self.status.set_text("Symbolic links are displayed but are not followed.")
            return
        self.path_entry.set_text(row.path)
        self.refresh()

    def close(self) -> None:
        self.closing = True
        if self.flow is not None:
            self.flow.cancel()
        if self.session is not None:
            self.session.close()
            self.session = None

    def set_busy(self, busy: bool) -> None:
        self.endpoint_selector.set_sensitive(not busy)
        self.connect_button.set_sensitive(not busy and self.profile is not None)
        self.path_entry.set_sensitive(not busy)
        self.file_list.set_sensitive(not busy)


class RemoteFileManagerWindow(Gtk.Window):
    """Two-pane local/remote manager supporting two independent SSH profiles."""

    def __init__(self, application: Gtk.Application, parent: Gtk.Window,
                 profiles: list[remote_access.SSHProfile],
                 initial_profile: remote_access.SSHProfile | None = None, *,
                 passwords: dict[str, str] | None = None):
        super().__init__(application=application, title="ProxyPilot File Manager")
        self.set_transient_for(parent)
        self.set_default_size(1200, 720)
        self.set_size_request(860, 520)
        self.manager_id = str(uuid.uuid4())
        self.closing = False
        self.busy = False
        self.cancel_event: threading.Event | None = None
        self.clipboard: dict[str, Any] | None = None
        self.passwords = dict(passwords or {})
        self.active_side = "left"
        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        root.set_margin_top(12)
        root.set_margin_bottom(12)
        root.set_margin_start(12)
        root.set_margin_end(12)
        self.set_child(root)
        title = Gtk.Label(label="File Manager", xalign=0)
        title.add_css_class("page-title")
        root.append(title)
        subtitle = Gtk.Label(
            label="Choose a local folder or SSH profile on each side. Dragging moves files; "
                  "Copy and Cut/Paste work between local folders and two servers.",
            xalign=0, wrap=True)
        subtitle.add_css_class("muted")
        root.append(subtitle)

        panes = Gtk.Paned(orientation=Gtk.Orientation.HORIZONTAL,
                          wide_handle=True, hexpand=True, vexpand=True)
        self.left = FilePane(self, "left", profiles, None)
        self.right = FilePane(self, "right", profiles, initial_profile)
        panes.set_start_child(self.left)
        panes.set_end_child(self.right)
        panes.set_position(660)
        root.append(panes)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.copy_button = self._button("Copy", self._copy)
        self.cut_button = self._button("Cut", self._cut)
        self.paste_left_button = self._button("Paste to left", lambda *_: self._paste("left"))
        self.paste_right_button = self._button("Paste to right", lambda *_: self._paste("right"))
        self.new_file_button = self._button("New file", self._new_file)
        self.new_folder_button = self._button("New folder", self._new_folder)
        self.rename_button = self._button("Rename", self._rename)
        self.delete_button = self._button("Delete…", self._delete)
        self.cancel_button = self._button("Cancel transfer", lambda *_: self.cancel_transfer())
        for button in (self.copy_button, self.cut_button, self.paste_left_button,
                       self.paste_right_button, self.new_file_button,
                       self.new_folder_button, self.rename_button, self.delete_button,
                       self.cancel_button):
            actions.append(button)
        root.append(actions)
        self.progress = Gtk.ProgressBar(show_text=True)
        self.progress.set_text("Ready")
        root.append(self.progress)
        self.status = Gtk.Label(label="Select one side, then connect or choose local files.",
                                xalign=0, wrap=True)
        self.status.add_css_class("muted")
        root.append(self.status)
        keyboard = Gtk.EventControllerKey()
        keyboard.connect("key-pressed", self._key_pressed)
        self.add_controller(keyboard)
        self.connect("close-request", self._close_request)
        self._update_buttons()

    @staticmethod
    def _button(label: str, callback) -> Gtk.Button:
        button = Gtk.Button(label=label)
        button.connect("clicked", callback)
        return button

    def _key_pressed(self, _controller, keyval, _keycode, state) -> bool:
        key = Gdk.keyval_name(keyval)
        control = bool(state & Gdk.ModifierType.CONTROL_MASK)
        shift = bool(state & Gdk.ModifierType.SHIFT_MASK)
        if control and key in ("c", "C"):
            self._copy(None)
            return True
        if control and key in ("x", "X"):
            self._cut(None)
            return True
        if control and key in ("v", "V"):
            self._paste(self.active_side)
            return True
        if control and shift and key in ("n", "N"):
            self._new_folder(None)
            return True
        if key == "F2":
            self._rename(None)
            return True
        if key == "Delete":
            self._delete(None)
            return True
        return False

    @staticmethod
    def _scroll(child: Gtk.Widget) -> Gtk.ScrolledWindow:
        scroller = Gtk.ScrolledWindow(hexpand=True, vexpand=True)
        scroller.set_child(child)
        return scroller

    def pane(self, side: str) -> FilePane:
        return self.left if side == "left" else self.right

    def _selection_changed(self, _widget, side: str) -> None:
        self.active_side = side
        self._update_buttons()

    def _pane_activated(self, _gesture, _presses, _x, _y, side: str) -> None:
        self.active_side = side
        self._update_buttons()

    def _update_buttons(self) -> None:
        active = self.pane(self.active_side)
        selected = active.selected()
        ready = not self.busy and bool(selected)
        self.copy_button.set_sensitive(ready)
        self.cut_button.set_sensitive(ready)
        self.rename_button.set_sensitive(ready and len(selected) == 1)
        self.delete_button.set_sensitive(ready)
        self.paste_left_button.set_sensitive(not self.busy and self.clipboard is not None)
        self.paste_right_button.set_sensitive(not self.busy and self.clipboard is not None)
        self.new_file_button.set_sensitive(not self.busy)
        self.new_folder_button.set_sensitive(not self.busy)
        self.cancel_button.set_sensitive(self.busy and self.cancel_event is not None)

    def _copy(self, _button) -> None:
        self._set_clipboard(move=False)

    def _cut(self, _button) -> None:
        self._set_clipboard(move=True)

    def _set_clipboard(self, *, move: bool) -> None:
        pane = self.pane(self.active_side)
        items = pane.selected()
        if not items:
            self.status.set_text("Select one or more files or folders first.")
            return
        if any(item["is_symlink"] for item in items):
            self.status.set_text("Symbolic links cannot be copied, cut, or moved.")
            return
        self.clipboard = {"side": self.active_side, "items": items, "move": move,
                          "signature": pane.signature}
        operation = "Cut" if move else "Copied"
        self.status.set_text(f"{operation} {len(items)} item(s). Select a destination pane and paste.")
        self._update_buttons()

    def _paste(self, destination_side: str) -> None:
        if self.clipboard is None:
            return
        source_side = self.clipboard["side"]
        if self.clipboard.get("signature") != self.pane(source_side).signature:
            self.status.set_text("The source pane changed. Select the files again and copy or cut them.")
            self.clipboard = None
            self._update_buttons()
            return
        self._start_transfer(source_side, self.clipboard["items"], destination_side,
                             move=self.clipboard["move"], clear_clipboard=True)

    def _prepare_drag(self, _source, _x, _y, side: str, row):
        pane = self.pane(side)
        selected_rows = pane.file_list.get_selected_rows()
        if row not in selected_rows:
            selected_rows = [row]
        items = [{"path": candidate.path, "name": candidate.item["name"],
                  "is_dir": candidate.item["is_dir"],
                  "is_symlink": candidate.item["is_symlink"]}
                 for candidate in selected_rows]
        payload = json.dumps({"manager": self.manager_id, "side": side,
                              "signature": pane.signature,
                              "items": items}, separators=(",", ":"))
        return Gdk.ContentProvider.new_for_value(payload)

    def _drop(self, _target, value, _x, _y, destination_side: str) -> bool:
        try:
            payload = json.loads(value)
            source_side = payload["side"]
            items = payload["items"]
            if payload.get("manager") != self.manager_id or source_side == destination_side:
                return False
            if payload.get("signature") != self.pane(source_side).signature:
                return False
            if not items or any(item.get("is_symlink") for item in items):
                return False
        except (TypeError, KeyError, json.JSONDecodeError):
            return False
        self.active_side = source_side
        self._start_transfer(source_side, items, destination_side, move=True)
        return True

    def _start_transfer(self, source_side: str, items: list[dict[str, Any]],
                        destination_side: str, *, move: bool,
                        clear_clipboard: bool = False) -> None:
        if self.busy:
            return
        source = self.pane(source_side)
        destination = self.pane(destination_side)
        if source.profile is not None and source.session is None:
            self.status.set_text(f"Connect the {source_side} server first.")
            return
        if destination.profile is not None and destination.session is None:
            self.status.set_text(f"Connect the {destination_side} server first.")
            return
        source_session = source.session
        destination_session = destination.session
        destination_directory = destination.path
        cancel = threading.Event()
        self.cancel_event = cancel
        self.busy = True
        self.left.set_busy(True)
        self.right.set_busy(True)
        self._update_buttons()
        self.progress.set_fraction(0)
        self.progress.set_text("Checking destination…")

        def preflight():
            try:
                conflicts = []
                for item in items:
                    if item["is_symlink"]:
                        raise remote_access.RemoteAccessError(
                            f"Symbolic links cannot be copied: {item['name']}")
                    path = (posixpath.join(destination_directory, item["name"])
                            if destination_session is not None
                            else str(Path(destination_directory) / item["name"]))
                    kind = remote_access.entry_type(destination_session, path)
                    if kind == "symlink" or kind == "special":
                        raise remote_access.RemoteAccessError(
                            f"Destination is not a regular file: {item['name']}")
                    if kind == "directory":
                        raise FileExistsError(
                            f"Folder already exists: {item['name']}. Folder merging is disabled.")
                    if kind == "file":
                        if item["is_dir"]:
                            raise FileExistsError(
                                f"A file already uses the folder name {item['name']}.")
                        conflicts.append(item["name"])
                GLib.idle_add(self._preflight_done, source_side, items, destination_side,
                              move, clear_clipboard, conflicts, None, cancel)
            except Exception as exc:
                GLib.idle_add(self._preflight_done, source_side, items, destination_side,
                              move, clear_clipboard, [], exc, cancel)

        threading.Thread(target=preflight, name="proxypilot-transfer-preflight",
                         daemon=True).start()

    def _preflight_done(self, source_side, items, destination_side, move,
                        clear_clipboard, conflicts, error, cancel) -> bool:
        if self.closing:
            self._transfer_done(error or InterruptedError("Window closed"), None)
            return GLib.SOURCE_REMOVE
        if error is not None:
            self._transfer_done(error, None)
            return GLib.SOURCE_REMOVE
        if conflicts:
            operation = "move" if move else "copy"
            dialog = Gtk.MessageDialog(
                transient_for=self, modal=True, message_type=Gtk.MessageType.WARNING,
                buttons=Gtk.ButtonsType.OK_CANCEL,
                text=f"Replace existing file(s) to {operation}?")
            shown = ", ".join(conflicts[:8])
            if len(conflicts) > 8:
                shown += f" and {len(conflicts) - 8} more"
            dialog.set_secondary_text(
                f"{shown}\nEach existing file is replaced atomically after the new copy completes.")
            dialog.connect("response", self._overwrite_response,
                           source_side, items, destination_side, move,
                           clear_clipboard, conflicts, cancel)
            dialog.present()
            return GLib.SOURCE_REMOVE
        self._run_transfer(source_side, items, destination_side, move,
                           clear_clipboard, [], cancel)
        return GLib.SOURCE_REMOVE

    def _overwrite_response(self, dialog, response, source_side, items,
                            destination_side, move, clear_clipboard, conflicts,
                            cancel) -> None:
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            self._transfer_done(InterruptedError("Transfer cancelled"), None)
            return
        self._run_transfer(source_side, items, destination_side, move,
                           clear_clipboard, conflicts, cancel)

    def _run_transfer(self, source_side: str, items: list[dict[str, Any]],
                      destination_side: str, move: bool, clear_clipboard: bool,
                      overwrite_names: list[str], cancel: threading.Event) -> None:
        source = self.pane(source_side)
        destination = self.pane(destination_side)
        source_session = source.session
        destination_session = destination.session
        destination_directory = destination.path
        self.progress.set_text("Transferring…")

        def progress(transferred: int, total: int) -> None:
            if cancel.is_set():
                raise InterruptedError("Transfer cancelled")
            fraction = min(1.0, transferred / total) if total else 1.0
            GLib.idle_add(self._progress_changed, fraction, transferred, total)

        def worker():
            try:
                for item in items:
                    if cancel.is_set():
                        raise InterruptedError("Transfer cancelled")
                    remote_access.transfer_entry(
                        source_session, item["path"], destination_session,
                        destination_directory, move=move,
                        overwrite=item["name"] in overwrite_names,
                        progress=progress, cancel=cancel)
                result = None
            except Exception as exc:
                result = exc
            GLib.idle_add(self._transfer_done, result,
                          clear_clipboard and move)

        threading.Thread(target=worker, name="proxypilot-two-pane-transfer",
                         daemon=True).start()

    def _progress_changed(self, fraction: float, transferred: int, total: int) -> bool:
        if self.closing:
            return GLib.SOURCE_REMOVE
        self.progress.set_fraction(fraction)
        self.progress.set_text(f"{transferred:,} / {total:,} bytes")
        return GLib.SOURCE_REMOVE

    def _transfer_done(self, error, clear_clipboard) -> bool:
        self.busy = False
        self.cancel_event = None
        self.left.set_busy(False)
        self.right.set_busy(False)
        if clear_clipboard:
            self.clipboard = None
        if not self.closing:
            self._update_buttons()
            if error is None:
                self.status.set_text("Transfer completed.")
                self.progress.set_fraction(1)
                self.progress.set_text("Complete")
                self.left.refresh()
                self.right.refresh()
            else:
                self.status.set_text(f"Transfer stopped: {type(error).__name__}: {error}")
                self.progress.set_text("Stopped or failed")
        return GLib.SOURCE_REMOVE

    def _new_file(self, _button) -> None:
        self._ask_name("Create new file", "File name", self._create_item,
                       is_directory=False)

    def _new_folder(self, _button) -> None:
        self._ask_name("Create new folder", "Folder name", self._create_item,
                       is_directory=True)

    def _ask_name(self, title: str, prompt: str, callback, *, is_directory=None,
                  item=None) -> None:
        dialog = Gtk.Dialog(transient_for=self, modal=True, title=title)
        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Continue", Gtk.ResponseType.OK)
        content = dialog.get_content_area()
        content.append(Gtk.Label(label=prompt, xalign=0))
        entry = Gtk.Entry(hexpand=True)
        if item is not None:
            entry.set_text(item["name"])
        content.append(entry)
        dialog.set_default_response(Gtk.ResponseType.OK)
        dialog.connect("response", self._name_response, entry, callback,
                       is_directory, item)
        dialog.present()
        entry.grab_focus()

    def _name_response(self, dialog, response, entry, callback,
                       is_directory, item) -> None:
        name = entry.get_text()
        dialog.destroy()
        if response == Gtk.ResponseType.OK:
            callback(name, is_directory, item)

    def _create_item(self, name: str, is_directory: bool, _item) -> None:
        if self.busy:
            self.status.set_text("Wait for the current transfer to finish.")
            return
        pane = self.pane(self.active_side)
        if pane.profile is not None and pane.session is None:
            self.status.set_text("Connect this server before creating files.")
            return

        def worker():
            try:
                if pane.session is None:
                    result = (remote_access.create_local_directory(pane.path, name)
                              if is_directory else remote_access.create_local_file(pane.path, name))
                else:
                    result = (remote_access.create_remote_directory(pane.session, pane.path, name)
                              if is_directory else remote_access.create_remote_file(pane.session, pane.path, name))
                error = None
            except Exception as exc:
                result, error = None, exc
            GLib.idle_add(self._simple_action_done, pane.side, result, error,
                          "Created")

        threading.Thread(target=worker, name="proxypilot-create-entry", daemon=True).start()

    def _rename(self, _button) -> None:
        if self.busy:
            return
        pane = self.pane(self.active_side)
        selected = pane.selected()
        if len(selected) != 1:
            self.status.set_text("Select one file or folder to rename.")
            return
        self._ask_name("Rename item", "New name", self._rename_item,
                       item=selected[0])

    def _rename_item(self, name: str, _is_directory, item) -> None:
        pane = self.pane(self.active_side)
        if pane.profile is not None and pane.session is None:
            self.status.set_text("Connect this server before renaming files.")
            return

        def worker():
            try:
                if pane.session is None:
                    result = remote_access.rename_local(item["path"], name)
                else:
                    new_path = posixpath.join(pane.path, name)
                    result = remote_access.rename_remote_to(
                        pane.session, item["path"], new_path)
                error = None
            except Exception as exc:
                result, error = None, exc
            GLib.idle_add(self._simple_action_done, pane.side, result, error,
                          "Renamed")

        threading.Thread(target=worker, name="proxypilot-rename-entry", daemon=True).start()

    def _delete(self, _button) -> None:
        if self.busy:
            return
        pane = self.pane(self.active_side)
        items = pane.selected()
        if not items:
            self.status.set_text("Select files or empty folders to delete.")
            return
        if any(item["is_symlink"] for item in items):
            self.status.set_text("Symbolic links are not deleted by ProxyPilot.")
            return
        dialog = Gtk.MessageDialog(
            transient_for=self, modal=True, message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.OK_CANCEL, text="Delete selected item(s)?")
        dialog.set_secondary_text(
            "Files are permanently removed. Folders must be empty; no recursive delete is performed.\n" +
            ", ".join(item["name"] for item in items[:8]))
        dialog.connect("response", self._delete_response, pane.side, items)
        dialog.present()

    def _delete_response(self, dialog, response, side, items) -> None:
        dialog.destroy()
        if response != Gtk.ResponseType.OK:
            return
        pane = self.pane(side)
        if pane.profile is not None and pane.session is None:
            self.status.set_text("Connect this server before deleting files.")
            return

        def worker():
            try:
                for item in items:
                    if pane.session is None:
                        remote_access.delete_local(item["path"], is_dir=item["is_dir"])
                    else:
                        remote_access.delete_remote(pane.session, item["path"],
                                                    is_dir=item["is_dir"])
                error = None
            except Exception as exc:
                error = exc
            GLib.idle_add(self._simple_action_done, side, None, error, "Deleted")

        threading.Thread(target=worker, name="proxypilot-delete-entries", daemon=True).start()

    def _simple_action_done(self, side, result, error, verb) -> bool:
        if self.closing:
            return GLib.SOURCE_REMOVE
        if error is not None:
            self.status.set_text(f"{verb} failed: {type(error).__name__}: {error}")
        else:
            self.status.set_text(f"{verb}: {result}")
            self.pane(side).refresh()
        return GLib.SOURCE_REMOVE

    def cancel_transfer(self) -> None:
        if self.cancel_event is not None:
            self.cancel_event.set()
            self.status.set_text("Cancelling transfer after the current file block…")

    def _close_request(self, *_args) -> bool:
        self.closing = True
        self.cancel_transfer()
        self.left.close()
        self.right.close()
        self.passwords.clear()
        return False


class RemoteTerminalWindow(Gtk.Window):
    """A fresh SSH transport and PTY per window; repeated opens never reuse shells."""

    def __init__(self, application: Gtk.Application, parent: Gtk.Window,
                 profile: remote_access.SSHProfile, sequence: int, *,
                 password: str | None = None, auto_connect: bool = True):
        super().__init__(application=application,
                         title=f"SSH terminal {sequence} · {profile.name}")
        self.set_transient_for(parent)
        self.set_default_size(900, 620)
        self.set_size_request(600, 360)
        self.profile = profile
        self.password = password
        self.closing = False
        self.session: remote_access.RemoteSession | None = None
        self.flow: SSHConnectionFlow | None = None
        self.shell_channel = None
        self.shell_thread: threading.Thread | None = None
        self.input_queue: queue.Queue[bytes] = queue.Queue(maxsize=256)
        self._size_source: int | None = None
        self._last_size: tuple[int, int] | None = None

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        root.set_margin_top(8)
        root.set_margin_bottom(8)
        root.set_margin_start(8)
        root.set_margin_end(8)
        self.set_child(root)
        heading = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.status = Gtk.Label(label="Starting SSH connection…", xalign=0,
                                hexpand=True, wrap=True)
        self.status.add_css_class("muted")
        heading.append(self.status)
        self.reconnect_button = Gtk.Button(label="Reconnect")
        self.reconnect_button.connect("clicked", self._reconnect)
        heading.append(self.reconnect_button)
        root.append(heading)
        if Vte is None:
            root.append(Gtk.Label(
                label="The embedded terminal requires gir1.2-vte-3.91.",
                xalign=0, wrap=True))
            self.terminal = None
            self.status.set_text("Terminal unavailable: GTK 4 VTE is not installed.")
            self.reconnect_button.set_sensitive(False)
        else:
            self.terminal = Vte.Terminal()
            self.terminal.set_scrollback_lines(10000)
            self.terminal.set_input_enabled(True)
            self.terminal.connect("commit", self._terminal_commit)
            root.append(RemoteFileManagerWindow._scroll(self.terminal))
            if auto_connect:
                self._connect()
            else:
                self.status.set_text("Smoke mode: shell connection intentionally disabled.")
        self.connect("close-request", self._close_request)

    def _connect(self) -> None:
        if self.closing:
            return
        if self.flow is not None:
            return
        self.reconnect_button.set_sensitive(False)
        self.flow = SSHConnectionFlow(self, self.profile, self._connected,
                                      self.status.set_text, self._connection_failed)
        password = self.password
        self.password = None
        self.flow.connect(password)

    def _connection_failed(self) -> None:
        self.flow = None
        if not self.closing:
            self.reconnect_button.set_sensitive(True)

    def _connected(self, session: remote_access.RemoteSession) -> None:
        if self.closing:
            session.close()
            return
        self.flow = None
        self.session = session
        route = "ProxyPilot proxy" if self.profile.use_proxy else "Direct"
        self.status.set_text(f"Connected · {route} · verified host key · {self.profile.host}")
        self.terminal.reset(True, True)
        self.terminal.grab_focus()
        width = max(20, self.terminal.get_column_count())
        height = max(5, self.terminal.get_row_count())

        def open_shell():
            try:
                channel = session.open_shell(width=width, height=height)
                error = None
            except Exception as exc:
                channel, error = None, exc
            GLib.idle_add(self._shell_opened, session, channel, error)

        self.shell_thread = threading.Thread(target=open_shell,
                                             name="proxypilot-terminal-open",
                                             daemon=True)
        self.shell_thread.start()

    def _shell_opened(self, session, channel, error) -> bool:
        if self.closing or self.session is not session:
            if channel is not None:
                channel.close()
            return GLib.SOURCE_REMOVE
        self.reconnect_button.set_sensitive(True)
        if error is not None:
            self.status.set_text(f"Could not open shell: {type(error).__name__}: {error}")
            return GLib.SOURCE_REMOVE
        self.shell_channel = channel
        self.status.set_text("Interactive SSH shell is ready.")
        self._last_size = (self.terminal.get_column_count(), self.terminal.get_row_count())
        self._size_source = GLib.timeout_add(400, self._poll_size, session)
        self.shell_thread = threading.Thread(target=self._shell_io,
                                             args=(session, channel),
                                             name="proxypilot-terminal-io",
                                             daemon=True)
        self.shell_thread.start()
        return GLib.SOURCE_REMOVE

    def _shell_io(self, session, channel) -> None:
        idle = threading.Event()
        while not self.closing and self.session is session and not session.closed and not channel.closed:
            try:
                while True:
                    channel.sendall(self.input_queue.get_nowait())
            except queue.Empty:
                pass
            except OSError as exc:
                GLib.idle_add(self._shell_ended, session, str(exc))
                return
            try:
                if channel.recv_ready():
                    data = channel.recv(32768)
                    if not data:
                        break
                    GLib.idle_add(self._feed, data)
            except socket.timeout:
                pass
            except OSError as exc:
                GLib.idle_add(self._shell_ended, session, str(exc))
                return
            idle.wait(0.02)
        GLib.idle_add(self._shell_ended, session, "Remote shell closed.")

    def _feed(self, data: bytes) -> bool:
        if not self.closing and self.terminal is not None:
            self.terminal.feed(data)
        return GLib.SOURCE_REMOVE

    def _terminal_commit(self, _terminal, text, size) -> None:
        if self.session is None or self.session.closed:
            return
        data = text.encode("utf-8") if isinstance(text, str) else bytes(text)
        if isinstance(size, int):
            data = data[:size]
        try:
            self.input_queue.put_nowait(data)
        except queue.Full:
            self.status.set_text("Terminal input queue is full; wait for the server to respond.")

    def _poll_size(self, session) -> bool:
        if self.closing or self.session is not session or session.closed:
            self._size_source = None
            return GLib.SOURCE_REMOVE
        size = (self.terminal.get_column_count(), self.terminal.get_row_count())
        if size != self._last_size:
            self._last_size = size
            threading.Thread(target=self._resize_shell,
                             args=(session, *size), daemon=True).start()
        return GLib.SOURCE_CONTINUE

    @staticmethod
    def _resize_shell(session, width, height) -> None:
        try:
            session.resize_shell(width, height)
        except Exception:
            pass

    def _shell_ended(self, session, message) -> bool:
        if self.session is session and not self.closing:
            self.status.set_text(message)
        return GLib.SOURCE_REMOVE

    def _reconnect(self, _button) -> None:
        if self.session is not None:
            self.session.close()
            self.session = None
        if self._size_source is not None:
            try:
                GLib.source_remove(self._size_source)
            except Exception:
                pass
            self._size_source = None
        while True:
            try:
                self.input_queue.get_nowait()
            except queue.Empty:
                break
        self._connect()

    def _close_request(self, *_args) -> bool:
        self.closing = True
        self.password = None
        if self.flow is not None:
            self.flow.cancel()
        if self.session is not None:
            self.session.close()
            self.session = None
        if self._size_source is not None:
            try:
                GLib.source_remove(self._size_source)
            except Exception:
                pass
            self._size_source = None
        return False


__all__ = ["RemoteFileManagerWindow", "RemoteTerminalWindow"]
