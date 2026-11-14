import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import proxypilot as core
import manager

class ManagerTests(unittest.TestCase):
    def test_stem_and_grouping(self):
        self.assertEqual(manager._stem('sample-gateway.service'),'sample')
        self.assertEqual(manager._stem('org.gnome.Sample.desktop'),'sample')
        with patch.object(core,'scan_apps',return_value=[
            {'id':'sample.desktop','name':'Sample App','exec':'/usr/bin/sample desktop','managed':False}]), \
             patch.object(core,'service_list',return_value=['sample-gateway.service']), \
             patch.object(manager,'proc_snapshot',return_value=[]), \
             patch.object(core,'load',return_value={'apps':{},'services':{},'profiles':{},'app_ports':{}}):
            groups=manager.inventory()
        sample=[g for g in groups if g['id']=='sample']
        self.assertEqual(len(sample),1)
        self.assertEqual(sample[0]['services'],['sample-gateway.service'])
        self.assertEqual(len(sample[0]['apps']),1)

    def test_review_only_not_kill(self):
        g={'id':'sample-browser','name':'Sample Browser','memory_mb':50,'processes':[
            {'pid':101,'ppid':1,'argv':['sample-browser','--headless','--remote-debugging-pipe']} ]}
        with patch.object(manager,'_pid_window_ids',return_value={20}):
            found=manager.cleanup_candidates([g])
        self.assertEqual(len(found),1)
        self.assertEqual(found[0]['auto_pids'],[101])

    def test_refuses_to_kill_reused_pid(self):
        ps=[{'pid':999998,'start':1,'cmd':'sample-app','argv':['sample-app'], 'cgroup':''}]
        out=manager.terminate_verified(ps)
        self.assertEqual(out['signaled'],[])

    def test_protects_ssh_and_shell_processes_from_cleanup_signals(self):
        from types import SimpleNamespace
        ps=[{'pid':999998,'start':77,'cmd':'sshd-session','argv':['sshd-session'], 'cgroup':''},
            {'pid':999997,'start':78,'cmd':'bash','argv':['bash','-l'], 'cgroup':''}]
        with patch.object(manager.pathlib.Path,'stat',return_value=SimpleNamespace(st_uid=os.getuid())), \
             patch.object(manager,'_pid_identity',side_effect=[77,78]), \
             patch.object(manager.os,'kill') as kill:
            out=manager.terminate_verified(ps,'TERM')
        self.assertEqual(out['signaled'],[])
        self.assertEqual(set(out['skipped']),{999997,999998})
        kill.assert_not_called()

    def test_uses_pidfd_for_final_signal_when_available(self):
        from types import SimpleNamespace
        ps=[{'pid':999996,'start':79,'cmd':'browser-helper','argv':['browser-helper'], 'cgroup':''}]
        with patch.object(manager.pathlib.Path,'stat',return_value=SimpleNamespace(st_uid=os.getuid())), \
             patch.object(manager,'_pid_identity',return_value=79), \
             patch.object(manager.os,'pidfd_open',return_value=42,create=True) as open_pid, \
             patch.object(manager.os,'pidfd_send_signal',create=True) as send_signal, \
             patch.object(manager.os,'close') as close_fd:
            out=manager.terminate_verified(ps,'TERM')
        self.assertEqual(out['signaled'],[999996])
        open_pid.assert_called_once_with(999996,0)
        send_signal.assert_called_once_with(42,manager.signal.SIGTERM,None,0)
        close_fd.assert_called_once_with(42)

    def test_global_profile_backup_and_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            old=(core.CFG_DIR,core.CFG_FILE)
            core.CFG_DIR=root/'cfg';core.CFG_FILE=core.CFG_DIR/'config.json'
            try:
                gp=manager.GlobalProxy();gp.config_dir=core.CFG_DIR
                gp.env_file=root/'99-proxypilot.conf';gp.backup_file=gp.config_dir/'global-backup.json'
                changes=[]
                def fakeget(schema,key): return "'manual'" if key=='mode' else "'original'" if key=='host' else '10808'
                def fakeset(schema,key,value): changes.append((schema,key,value))
                with patch.object(gp,'_gget',side_effect=fakeget),patch.object(gp,'_gset',side_effect=fakeset), \
                     patch.object(gp,'_current_systemd',return_value=None), \
                     patch('manager.shutil.which',return_value=None):
                    gp.apply('auto')
                    self.assertTrue(gp.env_file.exists())
                    self.assertIn('HTTP_PROXY=http://127.0.0.1:18787',gp.env_file.read_text())
                    self.assertTrue(gp.backup_file.exists())
                    self.assertEqual(core.load()['global_mode'],'auto')
                    gp.apply('off')
                self.assertEqual(core.load()['global_mode'],'off')
                self.assertFalse(gp.env_file.exists())
                self.assertFalse(gp.backup_file.exists())
                self.assertTrue(any(x[1]=='mode' and x[2]=="'manual'" for x in changes))
            finally:core.CFG_DIR,core.CFG_FILE=old

    def test_refuses_global_proxy_backup_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            gp=manager.GlobalProxy();gp.config_dir=root/'cfg'
            gp.env_file=root/'90-proxypilot.conf';gp.backup_file=gp.config_dir/'global-backup.json'
            gp.config_dir.mkdir()
            target=root/'user-backup.json';target.write_text('{"keep":true}')
            gp.backup_file.symlink_to(target)
            with patch.object(gp,'_gget',return_value=None),patch.object(manager,'_run',return_value=''):
                with self.assertRaisesRegex(RuntimeError,'backup symlink'):
                    gp._snapshot()
            self.assertEqual(target.read_text(),'{"keep":true}')

if __name__=='__main__':unittest.main()
