from __future__ import annotations

import sys
from pathlib import Path
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

try:
    import gi
    gi.require_version("Gio", "2.0")
    from gi.repository import Gio, GLib
except (ImportError, ValueError):
    raise unittest.SkipTest("Secret Service variant tests require PyGObject")

from proxypilot_app import secret_store


class SecretServiceDouble:
    def __init__(self):
        self.item = "/org/freedesktop/secrets/collection/login/test"
        self.password: bytes | None = None
        self.attributes: dict[str, str] | None = None
        self.closed_sessions = 0

    def call_sync(self, _destination, path, interface, method, parameters,
                  reply_type, _flags, _timeout, _cancellable):
        signature = reply_type.dup_string()
        if method == "OpenSession":
            return GLib.Variant("(vo)", (GLib.Variant("s", ""), "/session/test"))
        if method == "Close":
            self.closed_sessions += 1
            return GLib.Variant("()", ())
        if method == "ReadAlias":
            return GLib.Variant("(o)", ("/org/freedesktop/secrets/collection/login",))
        if method == "SearchItems":
            attributes = parameters.unpack()[0]
            found = self.password is not None and attributes == self.attributes
            return GLib.Variant("(aoao)", ([self.item] if found else [], []))
        if method == "CreateItem":
            properties, secret, replace = parameters.unpack()
            self.attributes = properties["org.freedesktop.Secret.Item.Attributes"]
            if not replace:
                raise AssertionError("ProxyPilot must replace the matching keyring entry")
            self.password = bytes(secret[2])
            return GLib.Variant("(oo)", (self.item, "/"))
        if method == "GetSecrets":
            _items, session = parameters.unpack()
            value = {self.item: (session, [], list(self.password or b""), "text/plain")}
            return GLib.Variant("(a{o(oayays)})", (value,))
        if method == "Delete":
            self.password = None
            return GLib.Variant("(o)", ("/",))
        raise AssertionError(f"Unexpected Secret Service method: {interface}.{method} ({signature}) at {path}")


class SecretStoreTests(unittest.TestCase):
    def setUp(self):
        self.bus = SecretServiceDouble()
        self.bus_patch = patch.object(
            secret_store, "_gio", return_value=(Gio, GLib, self.bus))
        self.bus_patch.start()

    def tearDown(self):
        self.bus_patch.stop()

    def test_password_round_trip_replace_and_delete_uses_keyring_only(self):
        profile_id = str(uuid.uuid4())
        secret_store.store_password(profile_id, "Production server", "first-secret")
        self.assertEqual(secret_store.get_password(profile_id), "first-secret")
        secret_store.store_password(profile_id, "Production server", "updated-secret")
        self.assertEqual(secret_store.get_password(profile_id), "updated-secret")
        secret_store.delete_password(profile_id)
        self.assertIsNone(secret_store.get_password(profile_id))
        self.assertEqual(self.bus.closed_sessions, 6)
        self.assertNotIn("updated-secret", repr(self.bus.attributes))

    def test_unknown_profile_returns_no_password(self):
        self.assertIsNone(secret_store.get_password(str(uuid.uuid4())))

    def test_invalid_profile_id_is_rejected_before_dbus_access(self):
        with self.assertRaisesRegex(ValueError, "UUID"):
            secret_store.get_password("not-an-id")
        self.assertEqual(self.bus.closed_sessions, 0)


if __name__ == "__main__":
    unittest.main()
