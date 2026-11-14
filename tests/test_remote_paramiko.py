from __future__ import annotations

import pathlib
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

try:
    import paramiko
except ImportError:
    paramiko = None

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from proxypilot_app import remote_access
import proxypilot as bridge


@unittest.skipIf(paramiko is None, "Paramiko is installed by project and Debian dependencies")
class ParamikoClientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.config_dir = pathlib.Path(self.temp.name)
        self.host_key = paramiko.RSAKey.generate(2048)
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        self.stop = threading.Event()
        self.connections = []
        self.server_thread = threading.Thread(target=self._serve, daemon=True)
        self.server_thread.start()
        self.profile = remote_access.SSHProfile.create(
            "Local mock", "127.0.0.1", "testuser", port=self.listener.getsockname()[1])

    def tearDown(self):
        self.stop.set()
        try:
            self.listener.close()
        except OSError:
            pass
        for transport in self.connections:
            try:
                transport.close()
            except Exception:
                pass
        self.server_thread.join(timeout=2)
        self.temp.cleanup()

    def _serve(self):
        while not self.stop.is_set():
            try:
                connection, _address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            transport = paramiko.Transport(connection)
            self.connections.append(transport)
            transport.add_server_key(self.host_key)
            try:
                transport.start_server(server=_EchoSSHServer())
            except (OSError, paramiko.SSHException):
                transport.close()
                continue
            channel = transport.accept(5)
            if channel is None:
                transport.close()
                continue
            try:
                while not self.stop.is_set() and not channel.closed:
                    if channel.recv_ready():
                        value = channel.recv(4096)
                        if not value:
                            break
                        channel.sendall(b"echo:" + value)
                    else:
                        time.sleep(0.01)
            except (OSError, paramiko.SSHException):
                pass
            finally:
                channel.close()
                transport.close()

    def test_new_server_key_requires_review_then_shell_uses_verified_transport(self):
        with self.assertRaises(remote_access.UnknownHostKeyError) as caught:
            remote_access.connect_profile(self.profile, password="secret",
                                          config_dir=self.config_dir)
        self.assertEqual(caught.exception.fingerprint,
                         remote_access.fingerprint_sha256(self.host_key.asbytes()))

        remote_access.trust_host_key(self.profile, self.host_key,
                                    config_dir=self.config_dir)
        session = remote_access.connect_profile(self.profile, password="secret",
                                                config_dir=self.config_dir)
        try:
            channel = session.open_shell(width=91, height=32)
            channel.sendall(b"printf test\n")
            received = bytearray()
            deadline = time.monotonic() + 3
            while b"echo:printf test\n" not in received and time.monotonic() < deadline:
                if channel.recv_ready():
                    received.extend(channel.recv(4096))
                else:
                    time.sleep(0.01)
            self.assertIn(b"echo:printf test\n", received)
        finally:
            session.close()

    def test_proxy_profile_routes_ssh_through_force_proxy_bridge(self):
        profile = remote_access.SSHProfile(
            self.profile.profile_id, "Local via bridge", self.profile.host,
            self.profile.port, self.profile.username, use_proxy=True)
        remote_access.trust_host_key(profile, self.host_key, config_dir=self.config_dir)
        routes = []
        cfg = dict(bridge.DEFAULTS)

        def route(host, port, mode, settings, *, force_proxy=False):
            routes.append((host, port, mode, force_proxy))
            if not force_proxy:
                raise AssertionError("proxy-enabled SSH did not request the strict proxy route")
            # This test bridge forwards to the local SSH fixture as its mock upstream.
            return socket.create_connection(("127.0.0.1", self.profile.port), timeout=3), "proxy"

        proxy = bridge.ProxyServer(("127.0.0.1", 0), bridge.ProxyHandler)
        cfg["proxy_port"] = proxy.server_address[1]
        worker = threading.Thread(target=proxy.serve_forever, daemon=True)
        worker.start()
        try:
            with patch.object(bridge, "load", return_value=cfg), \
                    patch.object(bridge, "destination_with_route", side_effect=route), \
                    patch.object(bridge.traffic, "identify_caller", return_value=(None, None)), \
                    patch.object(bridge.traffic, "record"):
                session = remote_access.connect_profile(profile, password="secret",
                                                        config_dir=self.config_dir)
                try:
                    channel = session.open_shell(width=90, height=30)
                    channel.sendall(b"proxy-route\n")
                    received = bytearray()
                    deadline = time.monotonic() + 3
                    while b"echo:proxy-route\n" not in received and time.monotonic() < deadline:
                        if channel.recv_ready():
                            received.extend(channel.recv(4096))
                        else:
                            time.sleep(0.01)
                    self.assertIn(b"echo:proxy-route\n", received)
                finally:
                    session.close()
            self.assertEqual(routes, [("127.0.0.1", self.profile.port, "proxy", True)])
        finally:
            proxy.shutdown()
            proxy.server_close()


class _EchoSSHServer(paramiko.ServerInterface if paramiko else object):
    def check_auth_password(self, username, password):
        if username == "testuser" and password == "secret":
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, _username):
        return "password"

    def check_channel_request(self, kind, _channel_id):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, _channel, _term, _width, _height,
                                  _width_pixels, _height_pixels, _modes):
        return True

    def check_channel_shell_request(self, _channel):
        return True


if __name__ == "__main__":
    unittest.main()
