import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT=pathlib.Path(__file__).resolve().parents[1]


class UninstallerTests(unittest.TestCase):
    def _env(self,root):
        home=root/'home';home.mkdir()
        config=home/'.config';data=home/'.local/share'
        env=os.environ.copy()
        env.update({'HOME':str(home),'XDG_CONFIG_HOME':str(config),
                    'XDG_DATA_HOME':str(data),'XDG_STATE_HOME':str(home/'.local/state'),
                    'PROXYPILOT_DEST':str(data/'proxypilot'),
                    'PROXYPILOT_BIN_DIR':str(home/'.local/bin'),
                    'PROXYPILOT_SYSTEMD_DIR':str(config/'systemd/user'),
                    'PROXYPILOT_APP_DIR':str(data/'applications'),
                    'PYTHONPATH':str(ROOT/'src')})
        env.pop('DISPLAY',None)
        return env,home,data,config

    def test_dry_run_preserves_settings_and_unrelated_launchers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);env,home,data,config=self._env(root)
            dest=data/'proxypilot';dest.mkdir(parents=True)
            (dest/'proxypilot.py').write_text('# ProxyPilot bridge')
            unrelated=data/'applications/other-app.desktop';unrelated.parent.mkdir(parents=True)
            unrelated.write_text('custom launcher')
            proxy=config/'environment.d/90-v2ray.conf';proxy.parent.mkdir(parents=True)
            proxy.write_text('user proxy config')
            settings=config/'proxypilot/config.json';settings.parent.mkdir(parents=True)
            settings.write_text(json.dumps({'global_mode':'off'}))
            result=subprocess.run([sys.executable,'-m','proxypilot_app.uninstall','--dry-run'],
                                  cwd=ROOT,env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('proxypilot.py',result.stdout)
            self.assertTrue((dest/'proxypilot.py').exists())
            self.assertEqual(unrelated.read_text(),'custom launcher')
            self.assertEqual(proxy.read_text(),'user proxy config')
            self.assertTrue(settings.exists())

    def test_active_global_profile_blocks_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);env,home,data,config=self._env(root)
            settings=config/'proxypilot/config.json';settings.parent.mkdir(parents=True)
            settings.write_text(json.dumps({'global_mode':'auto'}))
            result=subprocess.run([sys.executable,'-m','proxypilot_app.uninstall','--dry-run'],
                                  cwd=ROOT,env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,2)
            self.assertIn('restore it in ProxyPilot first',result.stderr)


if __name__=='__main__':
    unittest.main()
