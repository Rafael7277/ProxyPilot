import importlib.util, pathlib, tempfile, unittest, socket, threading, json
p=pathlib.Path(__file__).resolve().parents[1]/'proxypilot.py'
spec=importlib.util.spec_from_file_location('proxypilot',p)
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class Tests(unittest.TestCase):
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
    def test_desktop_entry_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            oldhome,oldapp=mod.HOME,mod.APP_DIR;mod.HOME=pathlib.Path(tmp)
            try:
                folder=pathlib.Path(tmp)/'.local/share/applications';mod.APP_DIR=folder;folder.mkdir(parents=True)
                (folder/'test-app.desktop').write_text('[Desktop Entry]\nName=Test Example\nType=Application\nExec=/usr/bin/true\n')
                self.assertTrue(any(a['id']=='test-app.desktop' for a in mod.scan_apps()))
            finally:mod.HOME,mod.APP_DIR=oldhome,oldapp
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
            original='[Desktop Entry]\nType=Application\nName=Browser\nExec=env XDG_CURRENT_DESKTOP=GNOME /usr/bin/true %U\n'
            path.write_text(original)
            try:
                mod.integrate('my-browser.desktop')
                self.assertIn('X-ProxyPilot-Source=',path.read_text())
                mod.restore_app('my-browser.desktop')
                self.assertEqual(original,path.read_text())
            finally:
                mod.HOME,mod.CFG_DIR,mod.APP_DIR=oldhome,oldcfg,oldapp

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
