"""Offline tests for ProxyPilot actual-path logging and local PID attribution."""
import pathlib
import socket
import tempfile
import threading
import time
import unittest
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import traffic
import proxypilot as core

class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        payload=b'proxy-pilot-traffic-test'
        self.send_response(200)
        self.send_header('Content-Length',str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    def log_message(self,*args):pass

class TestTraffic(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.old=(traffic.DATA_DIR,traffic.EVENT_FILE,traffic.EVENT_BACKUP,
                  core.HOME,core.CFG_DIR,core.CFG_FILE)
        root=pathlib.Path(self.temp.name)
        traffic.DATA_DIR=root/'state'
        traffic.EVENT_FILE=traffic.DATA_DIR/'traffic.jsonl'
        traffic.EVENT_BACKUP=traffic.DATA_DIR/'traffic.previous.jsonl'
        core.HOME=root
        core.CFG_DIR=root/'config'
        core.CFG_FILE=core.CFG_DIR/'config.json'
        self.addCleanup(self._restore)

    def _restore(self):
        traffic.DATA_DIR,traffic.EVENT_FILE,traffic.EVENT_BACKUP,core.HOME,core.CFG_DIR,core.CFG_FILE=self.old

    def test_reader_summary_and_privacy(self):
        traffic.record(event='open',id='1',pid=123,process='curl',host='test.invalid',port=443,
                       route='proxy',mode='auto',scope='system',status='connected')
        traffic.record(event='close',id='1',bytes_up=125,bytes_down=1024,duration_ms=40,status='closed')
        r=traffic.TrafficReader()
        r.poll()
        data=r.connections()
        self.assertEqual(data[0]['host'],'test.invalid')
        self.assertEqual(data[0]['bytes_down'],1024)
        self.assertEqual(r.summary()['proxy'],1)
        self.assertEqual(r.summary()['requests'],1)
        self.assertEqual(traffic.EVENT_FILE.stat().st_mode & 0o777,0o600)
        self.assertNotIn('http://',traffic.EVENT_FILE.read_text())
        traffic.clear_history()
        self.assertFalse(traffic.EVENT_FILE.exists())

    def test_pid_from_local_socket(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        try:
            client=socket.create_connection(listener.getsockname())
            accepted,_=listener.accept()
            try:
                pid,name=traffic.identify_caller('127.0.0.1',client.getsockname()[1],listener.getsockname()[1])
                self.assertEqual(pid,__import__('os').getpid(),name)
            finally:accepted.close();client.close()
        finally:listener.close()

    def test_auto_fallback_events_from_bridge(self):
        origin=ThreadingHTTPServer(('127.0.0.1',0),Target)
        self.addCleanup(origin.server_close)
        thread=threading.Thread(target=origin.serve_forever,daemon=True);thread.start()
        self.addCleanup(origin.shutdown)
        bridge=core.ProxyServer(('127.0.0.1',0),core.ProxyHandler)
        self.addCleanup(bridge.server_close)
        cfg=core.load()
        cfg['auto_port']=bridge.server_address[1]
        cfg['upstream_port']=1
        cfg['bypass_hosts']=[]
        core.save(cfg)
        worker=threading.Thread(target=bridge.serve_forever,daemon=True);worker.start()
        self.addCleanup(bridge.shutdown)
        with socket.create_connection(bridge.server_address,timeout=4) as c:
            c.sendall((f'GET http://127.0.0.1:{origin.server_address[1]}/secret-path?key=do-not-log HTTP/1.1\r\n'
                       f'Host: 127.0.0.1\r\nConnection: close\r\n\r\n').encode())
            c.settimeout(4)
            parts=[]
            while True:
                data=c.recv(16384)
                if not data:break
                parts.append(data)
            self.assertIn(b'proxy-pilot-traffic-test',b''.join(parts))
        deadline=time.monotonic()+3
        while not traffic.EVENT_FILE.exists() and time.monotonic()<deadline:time.sleep(.01)
        r=traffic.TrafficReader();r.poll()
        found=r.connections()
        self.assertGreaterEqual(len(found),1)
        self.assertEqual(found[0]['route'],'fallback')
        self.assertEqual(found[0]['pid'],__import__('os').getpid())
        self.assertNotIn('do-not-log',traffic.EVENT_FILE.read_text())

if __name__=='__main__':unittest.main()
