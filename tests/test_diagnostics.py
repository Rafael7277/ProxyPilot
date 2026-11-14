import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import diagnostics

class DiagnosticsTest(unittest.TestCase):
    def test_proxy_url_removes_user_password_and_path(self):
        url='socks5h://username:mysecret@127.0.0.1:10808/private'
        result=diagnostics.public_proxy_endpoint(url)
        self.assertEqual(result,'socks5h://127.0.0.1:10808')
        self.assertNotIn('mysecret',result)

    def test_bad_proxy_url_does_not_echo_secret(self):
        result=diagnostics.public_proxy_endpoint('garbage-password-for-login')
        self.assertEqual(result,'<set; endpoint hidden>')

    def test_process_env_reports_proxy_without_secret(self):
        with tempfile.TemporaryDirectory() as td:
            fake=Path(td)/str(os.getpid());fake.mkdir()
            (fake/'environ').write_bytes(b'HTTP_PROXY=http://name:secret@127.0.0.1:18787\x00')
            r=diagnostics.process_proxies([os.getpid()], Path(td))
            self.assertEqual(r['status'],'Proxy variables present')
            self.assertEqual(r['sampled'],1)
            self.assertIn('127.0.0.1:18787',r['detail'])
            self.assertNotIn('secret',r['detail'])

    def test_process_env_mixed(self):
        with tempfile.TemporaryDirectory() as td:
            for pid,content in [(100000,b''),(100001,b'HTTPS_PROXY=socks5h://127.0.0.1:10808\x00')]:
                f=Path(td)/str(pid);f.mkdir();(f/'environ').write_bytes(content)
            r=diagnostics.process_proxies([100000,100001],Path(td))
            self.assertEqual(r['status'],'Mixed environment')
            self.assertEqual(r['without_proxy'],1)

    def test_system_mismatch_is_a_warning_not_a_routing_proof(self):
        cfg={'global_mode':'auto','upstream_host':'127.0.0.1','upstream_port':10808,'auto_port':18787}
        def fake_gget(schema,key):
            if key=='mode':return 'manual'
            if key=='host':return '127.0.0.1'
            if key=='port':return 10808
        with patch.object(diagnostics,'_gget',side_effect=fake_gget),patch.object(diagnostics,'user_systemd_proxies',return_value={'https_proxy':'socks5h://127.0.0.1:10808'}):
            r=diagnostics.system_snapshot(cfg)
        self.assertTrue(any('GNOME' in x for x in r['notes']))
        self.assertTrue(any('systemd' in x for x in r['notes']))
        self.assertNotIn('upstream_listening',r)  # No network probing unless explicitly requested.

    def test_system_mode_off_does_not_mean_direct(self):
        with patch.object(diagnostics,'_gget',return_value='manual'),patch.object(diagnostics,'user_systemd_proxies',return_value={}):
            r=diagnostics.system_snapshot({'global_mode':'off'})
        self.assertTrue(any('OFF does not mean direct' in x for x in r['notes']))

    def test_xprop_fallback_detects_window_owner(self):
        from unittest.mock import patch
        import manager
        def fake_run(args, **kwargs):
            if '-root' in args:
                return '_NET_CLIENT_LIST(WINDOW): window id # 0x1200001, 0x1200002'
            if '0x1200001' in args:
                return '_NET_WM_PID(CARDINAL) = 4567'
            return '_NET_WM_PID:  not found.'
        with patch.dict(os.environ,{'DISPLAY':':0'}),patch.object(manager.shutil,'which',side_effect=lambda x: '/usr/bin/xprop' if x=='xprop' else None),patch.object(manager,'_run',side_effect=fake_run):
            self.assertEqual(manager._pid_window_ids(),{4567})

    def test_no_window_tools_means_unknown_not_orphan(self):
        from unittest.mock import patch
        import manager
        with patch.dict(os.environ,{'DISPLAY':':0'}),patch.object(manager.shutil,'which',return_value=None):
            self.assertIsNone(manager._pid_window_ids())

    def test_service_override_reports_directives_but_no_secrets(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'.config/systemd/user/sample-gateway.service.d';p.mkdir(parents=True)
            (p/'90-proxypilot.conf').write_text('[Service]\nEnvironment="HTTPS_PROXY=http://token:secret@127.0.0.1:10808"\n')
            with patch.object(diagnostics.Path,'home',return_value=Path(td)):
                lines=diagnostics.service_override_info(['sample-gateway.service'])
            self.assertEqual(len(lines),1)
            self.assertIn('sets proxy environment',lines[0])
            self.assertNotIn('secret',lines[0])

if __name__=='__main__':unittest.main()
