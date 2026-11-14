"""Small Secret Service client for passwords stored in the Linux keyring.

This module stores no credentials itself. Values are sent to the user's
freedesktop Secret Service and never enter ProxyPilot's profile JSON or logs.
Call its synchronous functions from a worker thread, not from GTK callbacks.
"""
from __future__ import annotations

import uuid
from typing import Any


SERVICE = "org.freedesktop.secrets"
ROOT = "/org/freedesktop/secrets"
SERVICE_IFACE = "org.freedesktop.Secret.Service"
APP_ATTRIBUTE = "io.github.rafael7277.ProxyPilot"


class SecretStoreError(RuntimeError):
    """The desktop keyring could not safely read or store a secret."""


def _gio_types() -> tuple[Any, Any]:
    try:
        import gi
        gi.require_version("Gio", "2.0")
        from gi.repository import Gio, GLib
    except (ImportError, ValueError) as exc:
        raise SecretStoreError("PyGObject D-Bus support is unavailable") from exc
    return Gio, GLib


def _gio() -> tuple[Any, Any, Any]:
    Gio, GLib = _gio_types()
    try:
        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    except Exception as exc:
        raise SecretStoreError("The desktop session bus is unavailable") from exc
    return Gio, GLib, bus


def _call(bus: Any, path: str, interface: str, method: str,
          parameters: Any, reply_signature: str) -> Any:
    Gio, GLib = _gio_types()
    try:
        result = bus.call_sync(
            SERVICE, path, interface, method, parameters,
            GLib.VariantType.new(reply_signature), Gio.DBusCallFlags.NONE,
            5000, None)
    except Exception as exc:
        # D-Bus errors can be verbose. Do not include values or message bodies.
        raise SecretStoreError(
            f"Linux keyring operation {method} failed ({type(exc).__name__})") from exc
    return result.unpack()


def _valid_profile_id(profile_id: str) -> str:
    try:
        return str(uuid.UUID(profile_id))
    except (ValueError, TypeError, AttributeError) as exc:
        raise ValueError("Profile ID must be a UUID") from exc


def _open_session(bus: Any, GLib: Any) -> str:
    _output, session = _call(
        bus, ROOT, SERVICE_IFACE, "OpenSession",
        GLib.Variant("(sv)", ("plain", GLib.Variant("s", ""))), "(vo)")
    if session == "/":
        raise SecretStoreError("Linux keyring did not create a Secret Service session")
    return session


def _attributes(profile_id: str) -> dict[str, str]:
    return {"application": APP_ATTRIBUTE,
            "profile_id": _valid_profile_id(profile_id)}


def _unlocked_items(bus: Any, GLib: Any, attributes: dict[str, str]) -> list[str]:
    unlocked, locked = _call(
        bus, ROOT, SERVICE_IFACE, "SearchItems",
        GLib.Variant("(a{ss})", (attributes,)), "(aoao)")
    if locked:
        newly_unlocked, prompt = _call(
            bus, ROOT, SERVICE_IFACE, "Unlock",
            GLib.Variant("(ao)", (locked,)), "(aoo)")
        if prompt != "/":
            raise SecretStoreError(
                "The keyring is locked. Unlock it in the desktop session and retry.")
        unlocked.extend(newly_unlocked)
    return list(dict.fromkeys(unlocked))


def get_password(profile_id: str) -> str | None:
    """Return a remembered password, or None when the profile has no secret."""
    attributes = _attributes(profile_id)
    Gio, GLib, bus = _gio()
    session = _open_session(bus, GLib)
    try:
        items = _unlocked_items(bus, GLib, attributes)
        if not items:
            return None
        (secrets_by_item,) = _call(
            bus, ROOT, SERVICE_IFACE, "GetSecrets",
            GLib.Variant("(aoo)", (items, session)), "(a{o(oayays)})")
        secret = secrets_by_item.get(items[0])
        if secret is None:
            raise SecretStoreError("The keyring returned no password for this profile")
        try:
            return bytes(secret[2]).decode("utf-8")
        except (IndexError, UnicodeDecodeError, TypeError) as exc:
            raise SecretStoreError("The saved keyring entry is not a valid text password") from exc
    finally:
        _call(bus, session, "org.freedesktop.Secret.Session", "Close", None, "()")


def store_password(profile_id: str, label: str, password: str) -> None:
    """Store or replace a password in the desktop's default keyring collection."""
    if not isinstance(password, str) or not password:
        raise ValueError("A non-empty password is required")
    if "\x00" in password:
        raise ValueError("Password contains an unsupported NUL character")
    attributes = _attributes(profile_id)
    Gio, GLib, bus = _gio()
    session = _open_session(bus, GLib)
    try:
        (collection,) = _call(
            bus, ROOT, SERVICE_IFACE, "ReadAlias",
            GLib.Variant("(s)", ("default",)), "(o)")
        if collection == "/":
            raise SecretStoreError("No default Linux keyring collection is available")
        properties = {
            "org.freedesktop.Secret.Item.Label": GLib.Variant(
                "s", f"ProxyPilot SSH · {label[:100]}"),
            "org.freedesktop.Secret.Item.Attributes": GLib.Variant("a{ss}", attributes),
        }
        secret = (session, b"", password.encode("utf-8"), "text/plain")
        _item, prompt = _call(
            bus, collection, "org.freedesktop.Secret.Collection", "CreateItem",
            GLib.Variant("(a{sv}(oayays)b)", (properties, secret, True)), "(oo)")
        if prompt != "/":
            raise SecretStoreError(
                "The keyring needs unlocking. Unlock it in the desktop session and retry.")
    finally:
        _call(bus, session, "org.freedesktop.Secret.Session", "Close", None, "()")


def delete_password(profile_id: str) -> None:
    """Remove all ProxyPilot keyring entries associated with a profile."""
    attributes = _attributes(profile_id)
    Gio, GLib, bus = _gio()
    session = _open_session(bus, GLib)
    try:
        for item in _unlocked_items(bus, GLib, attributes):
            (prompt,) = _call(
                bus, item, "org.freedesktop.Secret.Item", "Delete", None, "(o)")
            if prompt != "/":
                raise SecretStoreError(
                    "The keyring needs unlocking. Unlock it in the desktop session and retry.")
    finally:
        _call(bus, session, "org.freedesktop.Secret.Session", "Close", None, "()")


__all__ = ["SecretStoreError", "delete_password", "get_password", "store_password"]
