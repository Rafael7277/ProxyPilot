import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.install import generated_files


ROOT=pathlib.Path(__file__).resolve().parents[1]
INSTALLER=ROOT/'scripts/install.py'
sys.path.insert(0,str(ROOT/'src'))
from proxypilot_app import __version__


class InstallerTests(unittest.TestCase):
    def _env(self,root,fake_systemctl=None):
        home=root/'home';home.mkdir(exist_ok=True)
        config=home/'.config';data=home/'.local/share';state=home/'.local/state'
        bins=root/'bin';bins.mkdir(exist_ok=True)
        env=os.environ.copy()
        env.update({'HOME':str(home),'XDG_CONFIG_HOME':str(config),'XDG_DATA_HOME':str(data),
                    'XDG_STATE_HOME':str(state),'PROXYPILOT_DEST':str(data/'proxypilot'),
                    'PROXYPILOT_BIN_DIR':str(home/'.local/bin'),
                    'PROXYPILOT_SYSTEMD_DIR':str(config/'systemd/user'),
                    'PROXYPILOT_APP_DIR':str(data/'applications'),
                    'PROXYPILOT_SYSTEMCTL':str(fake_systemctl or 'systemctl'),
                    'PATH':str(bins)+os.pathsep+env.get('PATH','')})
        if fake_systemctl:
            loginctl=bins/'loginctl'
            loginctl.write_text('#!/bin/sh\nprintf "Linger=yes\\n"\n')
            loginctl.chmod(0o755)
        return env,home,data,config

    def test_cli_only_install_is_isolated_and_preserves_unrelated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);systemctl=root/'systemctl'
            systemctl.write_text('#!/bin/sh\nexit 0\n');systemctl.chmod(0o755)
            env,home,data,config=self._env(root,systemctl)
            app_dir=data/'applications';app_dir.mkdir(parents=True)
            unrelated=app_dir/'other-app.desktop';unrelated.write_text('user launcher stays')
            env_file=config/'environment.d/90-v2ray.conf';env_file.parent.mkdir(parents=True)
            env_file.write_text('user proxy config stays')
            old_config=config/'proxypilot/config.json';old_config.parent.mkdir(parents=True)
            old_config.write_text('{"apps":{"kept":"auto"}}')
            result=subprocess.run([sys.executable,str(INSTALLER),'--cli-only','--no-start'],
                                  env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue((home/'.local/bin/proxypilot').is_file())
            self.assertTrue((data/'proxypilot/src/proxypilot_app/updates.py').is_file())
            self.assertTrue((data/'proxypilot/src/proxypilot_app/remote_access.py').is_file())
            self.assertTrue((data/'proxypilot/src/proxypilot_app/remote_windows.py').is_file())
            self.assertTrue((data/'proxypilot/src/proxypilot_app/remote_ui.py').is_file())
            self.assertTrue((config/'systemd/user/proxypilot.service').is_file())
            self.assertFalse((app_dir/'proxypilot.desktop').exists())
            version=subprocess.run([str(home/'.local/bin/proxypilot'),'--version'],
                                   env=env,capture_output=True,text=True,timeout=15)
            self.assertEqual(version.returncode,0,version.stderr)
            self.assertIn(f'ProxyPilot {__version__}',version.stdout)
            self.assertEqual(unrelated.read_text(),'user launcher stays')
            self.assertEqual(env_file.read_text(),'user proxy config stays')
            self.assertEqual(old_config.read_text(),'{"apps":{"kept":"auto"}}')
            self.assertIn('Files staged',result.stdout)

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);env,home,data,config=self._env(root)
            result=subprocess.run([sys.executable,str(INSTALLER),'--cli-only','--dry-run'],
                                  env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('Install plan',result.stdout)
            self.assertFalse(data.exists())
            self.assertFalse(config.exists())

    def test_generated_user_unit_passes_systemd_verify_with_spaced_paths(self):
        if not shutil.which('systemd-analyze'):
            self.skipTest('systemd-analyze is unavailable')
        with tempfile.TemporaryDirectory(prefix='ProxyPilot unit ') as tmp:
            root=pathlib.Path(tmp);home=root/'home with space';home.mkdir()
            data=home/'.local/share';config=home/'.config';dest=data/'proxypilot'
            dest.mkdir(parents=True)
            paths={'home':home,'config':config,'data':data,'state':home/'.local/state',
                   'dest':dest,'bin':home/'.local/bin','units':config/'systemd/user',
                   'apps':data/'applications','icons':data/'icons/hicolor/scalable/apps'}
            files=generated_files(paths,sys.executable,False)
            content=next(item[0] for path,item in files.items()
                         if path.name=='proxypilot.service' and item[2]=='unit')
            unit=root/'proxypilot.service';unit.write_bytes(content)
            result=subprocess.run(['systemd-analyze','verify',str(unit)],
                                  capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            desktop_content=next(item[0] for path,item in files.items()
                                 if path.name=='proxypilot.desktop' and item[2]=='desktop').decode()
            self.assertIn(f"Icon={paths['icons']/'proxypilot.svg'}\n",desktop_content)
            self.assertNotIn('Icon="',desktop_content)
            self.assertEqual(desktop_content.count('Categories='),1)
            validator=shutil.which('desktop-file-validate')
            if validator:
                desktop=root/'proxypilot.desktop';desktop.write_text(desktop_content)
                result=subprocess.run([validator,str(desktop)],capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_upgrade_recognizes_legacy_modules_without_brand_markers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);systemctl=root/'systemctl'
            systemctl.write_text('#!/bin/sh\nexit 0\n');systemctl.chmod(0o755)
            env,home,data,config=self._env(root,systemctl)
            dest=data/'proxypilot';dest.mkdir(parents=True)
            legacy=[]
            for name in ('appicons.py','netobserve.py'):
                content=(ROOT/name).read_bytes()
                if name=='appicons.py':
                    # The original 0.x resolver used fixed ~/.local/share paths.
                    content=content.replace(
                        b"data_home=Path(os.environ.get('XDG_DATA_HOME',Path.home()/'.local/share'))\n        roots=[data_home/'icons',Path.home()/'.icons',",
                        b"roots=[Path.home()/'.local/share/icons',Path.home()/'.icons',")
                    content=content.replace(
                        b"data_home/'flatpak/exports/share/icons'",
                        b"Path.home()/'.local/share/flatpak/exports/share/icons'")
                    self.assertNotEqual(content,(ROOT/name).read_bytes())
                legacy.append((name,content))
                (dest/name).write_bytes(content)
            result=subprocess.run([sys.executable,str(INSTALLER),'--cli-only','--no-start'],
                                  env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((dest/'appicons.py').read_bytes(),(ROOT/'appicons.py').read_bytes())
            self.assertEqual((dest/'netobserve.py').read_bytes(),(ROOT/'netobserve.py').read_bytes())
            backups=list((data/'proxypilot-backups').rglob('appicons.py'))
            self.assertEqual(len(backups),1)
            self.assertEqual(backups[0].read_bytes(),legacy[0][1])

    def test_service_failure_rolls_back_code_and_unit_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp);systemctl=root/'systemctl'
            systemctl.write_text('#!/bin/sh\nif [ "$2" = "is-active" ]; then exit 3; fi\nexit 0\n')
            systemctl.chmod(0o755)
            env,home,data,config=self._env(root,systemctl)
            dest=data/'proxypilot';dest.mkdir(parents=True)
            old_code=dest/'proxypilot.py';old_code.write_text('# ProxyPilot legacy code')
            result=subprocess.run([sys.executable,str(INSTALLER),'--cli-only','--yes'],
                                  env=env,capture_output=True,text=True,timeout=30)
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(old_code.read_text(),'# ProxyPilot legacy code')
            self.assertFalse((config/'systemd/user/proxypilot.service').exists())
            self.assertFalse((home/'.local/bin/proxypilot').exists())


if __name__=='__main__':
    unittest.main()
