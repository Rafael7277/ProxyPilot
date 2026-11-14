import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT=pathlib.Path(__file__).resolve().parents[1]


class HeadlessCliTests(unittest.TestCase):
    def test_status_json_runs_without_display_or_gui_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            home=root/'home';home.mkdir()
            env=os.environ.copy()
            env.update({'HOME':str(home),'XDG_CONFIG_HOME':str(root/'config'),
                        'XDG_DATA_HOME':str(root/'data'),'XDG_STATE_HOME':str(root/'state'),
                        'PYTHONPATH':str(ROOT/'src')})
            env.pop('DISPLAY',None)
            result=subprocess.run([sys.executable,'-m','proxypilot_app','status','--json'],
                                  cwd=ROOT,env=env,capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            report=json.loads(result.stdout)
            self.assertEqual(report['schema_version'],1)
            self.assertIn('service',report)
            probe=subprocess.run([sys.executable,'-c',
                                  "import sys; import proxypilot_app.cli; "
                                  "assert 'proxypilot_app.gtk_ui' not in sys.modules"],
                                 cwd=ROOT,env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(probe.returncode,0,probe.stderr)


if __name__=='__main__':
    unittest.main()
