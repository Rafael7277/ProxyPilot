import os
import socket
import sys
import time
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import appstatus
import netobserve

CFG={'upstream_port':10808,'auto_port':18787,'proxy_port':18789,'app_ports':{'sample.desktop':21000}}
GROUP={'id':'sample','name':'Sample app','mode':'auto', 'process_count':1,
       'processes':[{'pid':4242,'start':123}], 'apps':[{'id':'sample.desktop'}],
       'services':[],'bridged_count':0}
NOW=10000.0

class EvidenceTests(unittest.TestCase):
    def test_no_observation_not_direct_claim(self):
        r=appstatus.group_evidence(GROUP,[],[],now=NOW)
        self.assertEqual(r['title'],'Not yet verified')
        self.assertEqual(r['level'],'uncertain')

    def test_xray_socket_is_observation_not_end_to_end_proof(self):
        sock={'pid':4242,'start':123,'remote_ip':'127.0.0.1','remote_port':10808,
              'kind':'xray','last_seen':NOW-1}
        r=appstatus.group_evidence(GROUP,[sock],[],now=NOW)
        self.assertEqual(r['title'],'Connected to Xray')
        self.assertEqual(r['level'],'observed')

    def test_bridge_proxy_event_is_confirmed_routing(self):
        event={'pid':4242,'app_id':'sample.desktop','route':'proxy','event':'open',
               'ts':NOW-2,'host':'example.org','port':443}
        r=appstatus.group_evidence(GROUP,[],[event],now=NOW)
        self.assertEqual(r['title'],'ProxyPilot PROXY confirmed')
        self.assertEqual(r['level'],'confirmed')

    def test_failed_bridge_event_is_not_a_successful_route(self):
        event={'pid':4242,'app_id':'sample.desktop','route':'proxy','event':'open',
               'status':'failed','ts':NOW-2,'host':'example.org','port':443}
        r=appstatus.group_evidence(GROUP,[],[event],now=NOW)
        self.assertEqual(r['title'],'Connection error seen')
        self.assertNotEqual(r['level'],'confirmed')

    def test_unrelated_pid_event_not_misattributed(self):
        event={'pid':9999,'route':'proxy','event':'open','ts':NOW-2}
        r=appstatus.group_evidence(GROUP,[],[event],now=NOW)
        self.assertEqual(r['level'],'uncertain')

    def test_public_tcp_not_proof_of_direct(self):
        sock={'pid':4242,'start':123,'remote_ip':'203.0.113.1','remote_port':443,
              'kind':'external','last_seen':NOW-1}
        r=appstatus.group_evidence(GROUP,[sock],[],now=NOW)
        self.assertIn('NOT prove unproxied',r['explanation'])
        self.assertEqual(r['level'],'uncertain')

    def test_observations_before_watch_not_used(self):
        ev={'pid':4242,'route':'proxy','event':'open','ts':NOW-20}
        r=appstatus.group_evidence(GROUP,[],[ev],now=NOW,since=NOW-5)
        self.assertEqual(r['title'],'Not yet verified')

    def test_process_pid_reuse_not_associated(self):
        sock={'pid':4242,'start':124,'kind':'xray','last_seen':NOW}
        r=appstatus.group_evidence(GROUP,[sock],[],now=NOW)
        self.assertEqual(r['title'],'Not yet verified')

    def test_classifications(self):
        self.assertEqual(netobserve.classify('127.0.0.1',10808,CFG),'xray')
        self.assertEqual(netobserve.classify('127.0.0.1',18787,CFG),'bridge')
        self.assertEqual(netobserve.classify('127.0.0.1',21000,CFG),'bridge')
        self.assertEqual(netobserve.classify('1.1.1.1',443,CFG),'external')
        self.assertEqual(netobserve.classify('192.168.1.1',443,CFG),'lan')
        self.assertEqual(netobserve.classify('::ffff:127.0.0.1',10808,CFG),'xray')

    def test_tcp_decoder(self):
        self.assertEqual(netobserve.decode_endpoint('0100007F:2A38',socket.AF_INET),('127.0.0.1',10808))
        self.assertEqual(netobserve.decode_endpoint('00000000000000000000000001000000:2A38',socket.AF_INET6),('::1',10808))

    def test_live_local_proxy_socket_owner(self):
        listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(1)
        cfg=dict(CFG, upstream_port=listener.getsockname()[1])
        client=socket.create_connection(listener.getsockname(), timeout=2)
        peer,_=listener.accept()
        try:
            found=netobserve.observe(cfg)
            self.assertTrue(any(x['pid']==os.getpid() and x['kind']=='xray' for x in found),found)
        finally:
            client.close();peer.close();listener.close()

    def test_recent_connections_expires(self):
        recent=netobserve.RecentConnections(window_s=5)
        sock={'pid':42,'start':1,'inode':'55','remote_ip':'127.0.0.1','remote_port':10808}
        recent.update([sock],now=NOW)
        self.assertEqual(len(recent.recent(now=NOW+1)),1)
        self.assertEqual(len(recent.recent(now=NOW+6)),0)

if __name__ == '__main__': unittest.main()

class UnmanageLauncherTest(unittest.TestCase):
    def test_unmanaged_restores_previously_managed_launcher(self):
        from unittest.mock import patch
        import manager
        group={'id':'demo','name':'Demo','apps':[{'id':'demo.desktop','name':'Demo','managed':True}],
               'services':[], 'process_count':0,'bridged_count':0}
        state={'apps':{'demo.desktop':'auto'},'profiles':{'demo':'auto'}}
        with patch.object(manager,'inventory',return_value=[group]),\
             patch.object(manager.core,'load',return_value=state),\
             patch.object(manager.core,'save'),\
             patch.object(manager.core,'restore_app') as restored:
            outcome=manager.set_group_mode('demo','unmanaged',manage_launchers=False)
        restored.assert_called_once_with('demo.desktop')
        self.assertFalse(outcome['errors'])
        self.assertNotIn('demo',state['profiles'])
