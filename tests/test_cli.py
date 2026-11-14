import contextlib
import io
import json
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'src'))
from proxypilot_app import api, cli


class CliTests(unittest.TestCase):
    def test_apps_json_has_versioned_envelope(self):
        with patch.object(api,'app_list',return_value=[{'id':'demo','name':'Demo'}]):
            out=io.StringIO()
            with contextlib.redirect_stdout(out):code=cli.main(['apps','--json'])
        payload=json.loads(out.getvalue())
        self.assertEqual(code,0)
        self.assertEqual(payload['schema_version'],1)
        self.assertEqual(payload['apps'][0]['id'],'demo')

    def test_doctor_configuration_notes_are_warnings_not_service_failures(self):
        report={"service":{"active_state":"active"},
                "user_manager":{"available":True,"linger":True},
                "listeners":{"auto":True,"proxy_only":True,"upstream":True},
                "system_proxy":{"notes":["Other proxy variables are configured."]}}
        with patch.object(api,'status',return_value=report):
            result=api.doctor()
        self.assertTrue(result['ok'])
        self.assertEqual(result['checks'][-1]['severity'],'warning')

    def test_process_inventory_contains_pid_parent_and_observed_peer(self):
        group={'id':'browser','name':'Browser','process_count':1,'memory_mb':1,
               'cpu_percent':0.0,'processes':[{'pid':4321,'ppid':42,'start':7,
                   'cmd':'browser','state':'S','age_s':60,'cpu_percent':0.0,
                   'rss_kb':1024,'argv':['browser']}]}
        with patch.object(api,'groups',return_value=[group]), \
             patch.object(api.manager,'cleanup_candidates',return_value=[]), \
             patch.object(api.netobserve,'observe',return_value=[{'pid':4321,'start':7,
                   'remote_ip':'203.0.113.8','remote_port':443,'kind':'external','ts':100.0}]), \
             patch.object(api.bridge,'load',return_value={}):
            result=api.process_list()
        process=result[0]['process_tree'][0]
        self.assertEqual(process['parent_pid'],42)
        self.assertEqual(process['connections'][0]['peer'],'203.0.113.8:443')
        self.assertEqual(process['category'],'Background/active')

    def test_route_set_is_dry_run_by_default(self):
        with patch.object(api, 'set_route', return_value={
                'applied': False, 'dry_run': True, 'plan': {'requested_policy': 'proxy'}}) as set_route:
            out=io.StringIO()
            with contextlib.redirect_stdout(out):
                code=cli.main(['route','set','sample-app','proxy','--json'])
        self.assertEqual(code,2)
        set_route.assert_called_once_with('sample-app','proxy',apply=False,
                                          manage_launchers=False,restart_services=False)
        self.assertIn('"dry_run": true',out.getvalue())

    def test_route_apply_requires_explicit_noninteractive_confirmation(self):
        with patch.object(api, 'set_route') as set_route:
            err=io.StringIO()
            with contextlib.redirect_stderr(err):
                code=cli.main(['route','set','sample-app','proxy','--apply'])
        self.assertEqual(code,2)
        self.assertIn('--apply requires --yes',err.getvalue())
        set_route.assert_not_called()

    def test_route_service_restart_requires_apply(self):
        with patch.object(api, 'set_route') as set_route:
            err=io.StringIO()
            with contextlib.redirect_stderr(err):
                code=cli.main(['route','set','sample-app','proxy','--restart-services','--yes'])
        self.assertEqual(code,2)
        self.assertIn('Service restart requires --apply --yes',err.getvalue())
        set_route.assert_not_called()

    def test_run_direct_clears_proxy_variables(self):
        env={'HOME':'/tmp/home','HTTP_PROXY':'http://secret.invalid','NO_PROXY':'old'}
        with patch.dict('os.environ',env,clear=True):
            out=cli._proxy_env('direct')
        self.assertNotIn('HTTP_PROXY',out)
        self.assertNotIn('NO_PROXY',out)
        self.assertEqual(out['HOME'],'/tmp/home')

    def test_ambiguous_app_match_is_reported(self):
        groups=[{'id':'alpha.desktop','name':'Alpha','apps':[]},
                {'id':'beta.desktop','name':'Alpha Browser','apps':[]}]
        with self.assertRaisesRegex(ValueError,'Ambiguous'):
            api.find_group('Alp',groups)


if __name__=='__main__':
    unittest.main()
