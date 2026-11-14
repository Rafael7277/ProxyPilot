import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import proxypilot as core


class ServiceOverrideTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.old_units=core.USER_UNITS
        core.USER_UNITS=pathlib.Path(self.tmp.name)/'systemd/user'
        self.unit='example-worker.service'
        self.dropin=core.USER_UNITS/(self.unit+'.d/90-proxypilot.conf')
        self.config={'services':{},'apps':{},'auto_port':18787,'proxy_port':18789,
                     'bypass_hosts':['localhost','127.0.0.1','::1']}

    def tearDown(self):
        core.USER_UNITS=self.old_units
        self.tmp.cleanup()

    def test_unknown_existing_dropin_is_preserved(self):
        self.dropin.parent.mkdir(parents=True)
        original='[Service]\nEnvironment=KEEP=untouched\n'
        self.dropin.write_text(original)
        with patch.object(core,'service_list',return_value=[self.unit]), \
             patch.object(core,'load',return_value=self.config), \
             patch.object(core.subprocess,'run') as run:
            with self.assertRaisesRegex(ValueError,'Unknown file'):
                core.service_override(self.unit,'proxy')
        self.assertEqual(self.dropin.read_text(),original)
        run.assert_not_called()

    def test_restart_failure_restores_previous_dropin_and_skips_config_save(self):
        self.dropin.parent.mkdir(parents=True)
        self.config['services'][self.unit]='direct'
        clear='HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy NO_PROXY no_proxy'
        original=core.legacy_for('direct',clear,self.config)
        self.dropin.write_bytes(original)
        results=[subprocess.CompletedProcess([],0,'',''),
                 subprocess.CompletedProcess([],1,'','restart failed'),
                 subprocess.CompletedProcess([],0,'',''),
                 subprocess.CompletedProcess([],0,'','')]
        with patch.object(core,'service_list',return_value=[self.unit]), \
             patch.object(core,'load',return_value=self.config), \
             patch.object(core,'save') as save, \
             patch.object(core.subprocess,'run',side_effect=results):
            with self.assertRaisesRegex(RuntimeError,'restart failed'):
                core.service_override(self.unit,'proxy')
        self.assertEqual(self.dropin.read_bytes(),original)
        save.assert_not_called()


if __name__=='__main__':
    unittest.main()
