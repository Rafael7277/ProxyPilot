import importlib.util, pathlib, tempfile, unittest, socket, threading, json
from unittest.mock import patch, MagicMock
p=pathlib.Path(__file__).resolve().parents[1]/'proxypilot.py'
spec=importlib.util.spec_from_file_location('proxypilot',p)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class Tests(unittest.TestCase):
    def test_config_directory_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);real=root/'real';real.mkdir()
            link=root/'.config/proxypilot';link.parent.mkdir();link.symlink_to(real)
            old=(mod.CFG_DIR,mod.CFG_FILE)
            mod.CFG_DIR=link;mod.CFG_FILE=link/'config.json'
            try:
                with self.assertRaisesRegex(RuntimeError,'config directory symlink'):
                    mod.load()
            finally:mod.CFG_DIR,mod.CFG_FILE=old

    def test_legacy_config_migrates_with_private_backup_and_preserves_unknown_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            old=(mod.HOME,mod.CFG_DIR,mod.CFG_FILE)
            mod.HOME=pathlib.Path(tmp);mod.CFG_DIR=mod.HOME/'.config/proxypilot'
            mod.CFG_FILE=mod.CFG_DIR/'config.json';mod.CFG_DIR.mkdir(parents=True)
            original='{"upstream_port":12345,"custom_user_key":{"keep":true}}\n'
            mod.CFG_FILE.write_text(original)
            try:
                cfg=mod.load()
                self.assertEqual(cfg['schema_version'],1)
                self.assertTrue(cfg['allow_direct_fallback'])
                self.assertEqual(cfg['custom_user_key'],{'keep':True})
                self.assertEqual((mod.CFG_DIR/'config.pre-1.0.json').read_text(),original)
                self.assertEqual((mod.CFG_DIR/'config.pre-1.0.json').stat().st_mode & 0o777,0o600)
            finally:mod.HOME,mod.CFG_DIR,mod.CFG_FILE=old

    def test_host_bypass(self):
        d={'bypass_hosts':['localhost','.arvancloudai.ir','127.0.0.1']}
        self.assertTrue(mod.bypass('api.arvancloudai.ir',d))
        self.assertTrue(mod.bypass('localhost',d))
        self.assertFalse(mod.bypass('evil-arvancloudai.ir',d))
    def test_modes(self):
        d={'auto_port':18787,'proxy_port':18789}
        self.assertIn('http://127.0.0.1:18787',mod.credentials_env('auto',d).values())
        self.assertIn('http://127.0.0.1:18789',mod.credentials_env('proxy',d).values())
        self.assertEqual({},mod.credentials_env('direct',d))
    def test_proxy_upstream_fallback(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        port=listener.getsockname()[1]
        d={'upstream_host':'127.0.0.1','upstream_port':1,'bypass_hosts':[]}
        s=mod.destination('127.0.0.1',port,'auto',d)
        s.close(); listener.close()
        with self.assertRaises(OSError):mod.destination('127.0.0.1',port,'proxy',d)
    def test_auto_fails_closed_when_direct_fallback_is_disabled(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        try:
            d={'upstream_host':'127.0.0.1','upstream_port':1,'bypass_hosts':[],
               'allow_direct_fallback':False}
            with self.assertRaises(OSError):
                mod.destination('127.0.0.1',listener.getsockname()[1],'auto',d)
            listener.settimeout(.05)
            with self.assertRaises(socket.timeout):listener.accept()
        finally:listener.close()
    def test_socks5_handshake_health_check_does_not_probe_public_host(self):
        fake=MagicMock()
        fake.recv.return_value=b'\x05\x00'
        with patch.object(mod.socket,'create_connection',return_value=fake) as connect:
            self.assertTrue(mod.upstream_ok({'upstream_host':'127.0.0.1','upstream_port':10808}))
        connect.assert_called_once_with(('127.0.0.1',10808),timeout=1.5)
        fake.sendall.assert_called_once_with(b'\x05\x01\x00')
    def test_socks5_request_uses_ipv6_address_type(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        observed=[]
        def server():
            conn,_=listener.accept()
            with conn:
                self.assertEqual(mod.recv_exact(conn,3),b'\x05\x01\x00')
                conn.sendall(b'\x05\x00')
                header=mod.recv_exact(conn,4)
                observed.append(header)
                observed.append(mod.recv_exact(conn,16))
                observed.append(mod.recv_exact(conn,2))
                conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
        thread=threading.Thread(target=server,daemon=True);thread.start()
        try:
            remote=mod.connect_upstream('2001:db8::1',443,{'upstream_host':'127.0.0.1','upstream_port':listener.getsockname()[1]})
            remote.close();thread.join(timeout=2)
            self.assertEqual(observed[0],b'\x05\x01\x00\x04')
            self.assertEqual(len(observed[1]),16)
        finally:listener.close()
    def test_desktop_entry_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            oldhome,oldapp=mod.HOME,mod.APP_DIR;mod.HOME=pathlib.Path(tmp)
            try:
                folder=pathlib.Path(tmp)/'.local/share/applications';mod.APP_DIR=folder;folder.mkdir(parents=True)
                (folder/'test-app.desktop').write_text('[Desktop Entry]\nName=Test Example\nType=Application\nExec=/usr/bin/true\n')
                self.assertTrue(any(a['id']=='test-app.desktop' for a in mod.scan_apps()))
            finally:mod.HOME,mod.APP_DIR=oldhome,oldapp
    def test_desktop_exec_quote_escapes_literal_percent(self):
        self.assertEqual(mod._desktop_exec_quote('/home/test name/100% app'),
                         '"/home/test name/100%% app"')
if __name__=='__main__':unittest.main()

class IntegrationTests(unittest.TestCase):
    def test_custom_desktop_backup_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            oldhome,oldcfg,oldapp=mod.HOME,mod.CFG_DIR,mod.APP_DIR
            mod.HOME=pathlib.Path(tmp)
            mod.CFG_DIR=mod.HOME/'.config/proxypilot'
            mod.APP_DIR=mod.HOME/'.local/share/applications'
            mod.APP_DIR.mkdir(parents=True)
            path=mod.APP_DIR/'my-browser.desktop'
            original='[Desktop Entry]\nType=Application\nName=Browser\nIcon=browser-icon\nExec=env XDG_CURRENT_DESKTOP=GNOME /usr/bin/true %U\n'
            path.write_text(original)
            try:
                mod.integrate('my-browser.desktop')
                managed=path.read_text()
                self.assertIn('X-ProxyPilot-Source=',managed)
                self.assertIn(' %U\n',managed)
                self.assertNotIn("Exec='/",managed)
                mod.restore_app('my-browser.desktop')
                self.assertEqual(original,path.read_text())
            finally:
                mod.HOME,mod.CFG_DIR,mod.APP_DIR=oldhome,oldcfg,oldapp

    def test_refuses_dbus_activatable_desktop_entry_without_modifying_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            oldhome,oldcfg,oldapp=mod.HOME,mod.CFG_DIR,mod.APP_DIR
            mod.HOME=pathlib.Path(tmp)
            mod.CFG_DIR=mod.HOME/'.config/proxypilot'
            mod.APP_DIR=mod.HOME/'.local/share/applications'
            mod.APP_DIR.mkdir(parents=True)
            path=mod.APP_DIR/'dbus-app.desktop'
            original='[Desktop Entry]\nType=Application\nName=D-Bus app\nDBusActivatable=true\nExec=/usr/bin/true\n'
            path.write_text(original)
            try:
                with self.assertRaisesRegex(ValueError,'D-Bus activation'):
                    mod.integrate('dbus-app.desktop')
                self.assertEqual(path.read_text(),original)
            finally:mod.HOME,mod.CFG_DIR,mod.APP_DIR=oldhome,oldcfg,oldapp

class LauncherArgumentTests(unittest.TestCase):
    def test_launch_forwards_uri_arguments_from_desktop_field_code(self):
        app={'id':'browser.desktop','name':'Browser','source':'/tmp/browser.desktop',
             'exec':'/usr/bin/browser %U','icon':'browser'}
        fake_socket=MagicMock()
        fake_socket.__enter__=lambda self: self
        fake_socket.__exit__=lambda self,*args: None
        with patch.object(mod,'load',return_value={'apps':{'browser.desktop':'proxy'},
                                                    'auto_port':18787,'proxy_port':18789}), \
             patch.object(mod,'scan_apps',return_value=[app]), \
             patch.object(mod,'app_port',return_value=21000), \
             patch.object(mod.socket,'create_connection',return_value=fake_socket), \
             patch.object(mod.subprocess,'Popen') as popen:
            mod.launch('browser.desktop',['https://example.invalid/a','file:///tmp/b'])
        argv=popen.call_args.args[0]
        self.assertEqual(argv,['/usr/bin/browser','https://example.invalid/a','file:///tmp/b'])

class RunningAndRoutingTests(unittest.TestCase):
    def test_direct_bypasses_unavailable_proxy(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        try:
            d={'upstream_host':'127.0.0.1','upstream_port':1,'bypass_hosts':[]}
            remote=mod.destination('127.0.0.1',listener.getsockname()[1],'direct',d)
            remote.close()
        finally:listener.close()

    def test_route_changes_live_on_new_connections(self):
        with tempfile.TemporaryDirectory() as tmp:
            old=(mod.HOME,mod.CFG_DIR,mod.CFG_FILE,mod.APP_DIR)
            mod.HOME=pathlib.Path(tmp)
            mod.CFG_DIR=mod.HOME/'.config/proxypilot'
            mod.CFG_FILE=mod.CFG_DIR/'config.json'
            mod.APP_DIR=mod.HOME/'.local/share/applications'
            mod.APP_DIR.mkdir(parents=True)
            (mod.APP_DIR/'test.desktop').write_text('[Desktop Entry]\nType=Application\nName=Test\nExec=/bin/true\n')
            try:
                port=mod.app_port('test.desktop')
                d=mod.load()
                self.assertEqual(d['app_ports']['test.desktop'],port)
                result=mod.activate_app('test.desktop','proxy')
                self.assertFalse(result['live'])
                self.assertEqual(mod.load()['apps']['test.desktop'],'proxy')
                mod.activate_app('test.desktop','direct')
                self.assertEqual(mod.load()['apps']['test.desktop'],'direct')
                self.assertIn(str(port),list(mod.credentials_env('auto',mod.load(),'test.desktop').values())[0])
            finally:mod.HOME,mod.CFG_DIR,mod.CFG_FILE,mod.APP_DIR=old

    def test_process_list_structure(self):
        items=mod.running_processes([])
        self.assertIsInstance(items,list)
        self.assertTrue(all('pid' in x and 'managed_live' in x for x in items))
