import pathlib
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import proxypilot as core

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        data=b'proxy-pilot-ok'
        self.send_response(200)
        self.send_header('Content-Length',str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self,*args):pass

class ProxyHTTPTests(unittest.TestCase):
    def _temporary_config(self,tmp):
        old=(core.HOME,core.CFG_DIR,core.CFG_FILE)
        core.HOME=pathlib.Path(tmp);core.CFG_DIR=core.HOME/'.config/proxypilot'
        core.CFG_FILE=core.CFG_DIR/'config.json'
        return old

    def test_proxy_only_bridge_uses_configured_socks5_upstream(self):
        upstream=socket.socket();upstream.bind(('127.0.0.1',0));upstream.listen()
        observed={};done=threading.Event()
        def socks_server():
            try:
                conn,_=upstream.accept()
                with conn:
                    observed['greeting']=core.recv_exact(conn,3)
                    conn.sendall(b'\x05\x00')
                    header=core.recv_exact(conn,4);atyp=header[3]
                    if atyp==3:
                        size=core.recv_exact(conn,1)[0]
                        observed['host']=core.recv_exact(conn,size).decode()
                    elif atyp==1:observed['host']='.'.join(str(x) for x in core.recv_exact(conn,4))
                    else:raise AssertionError(f'unexpected SOCKS5 address type {atyp}')
                    observed['port']=int.from_bytes(core.recv_exact(conn,2),'big')
                    conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                    request=b''
                    while b'\r\n\r\n' not in request:
                        part=conn.recv(4096)
                        if not part:break
                        request+=part
                    observed['request']=request
                    payload=b'response-from-mock-socks'
                    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(payload)).encode()+
                                 b'\r\nConnection: close\r\n\r\n'+payload)
            except Exception as exc:observed['error']=repr(exc)
            finally:done.set()
        worker=threading.Thread(target=socks_server,daemon=True);worker.start()
        bridge=core.ProxyServer(('127.0.0.1',0),core.ProxyHandler)
        bridge_worker=None
        old=None
        try:
            with tempfile.TemporaryDirectory() as tmp:
                old=self._temporary_config(tmp)
                cfg=core.load();cfg.update({'proxy_port':bridge.server_address[1],
                    'upstream_host':'127.0.0.1','upstream_port':upstream.getsockname()[1],
                    'bypass_hosts':[]})
                core.save(cfg)
                bridge_worker=threading.Thread(target=bridge.serve_forever,daemon=True)
                bridge_worker.start()
                with socket.create_connection(bridge.server_address,timeout=4) as client:
                    client.settimeout(4)
                    client.sendall(b'GET http://example.test:8443/route HTTP/1.1\r\n'
                                   b'Host: example.test:8443\r\nConnection: close\r\n\r\n')
                    response=b''
                    while True:
                        chunk=client.recv(4096)
                        if not chunk:break
                        response+=chunk
                self.assertIn(b'response-from-mock-socks',response)
                self.assertTrue(done.wait(2))
                self.assertEqual(observed.get('greeting'),b'\x05\x01\x00')
                self.assertEqual(observed.get('host'),'example.test')
                self.assertEqual(observed.get('port'),8443)
                self.assertIn(b'GET /route HTTP/1.1',observed.get('request',b''))
                self.assertNotIn('error',observed)
        finally:
            bridge.shutdown();bridge.server_close();upstream.close()
            if old:core.HOME,core.CFG_DIR,core.CFG_FILE=old

    def test_proxy_only_does_not_fall_back_to_direct(self):
        direct=socket.socket();direct.bind(('127.0.0.1',0));direct.listen()
        direct.settimeout(.4)
        bridge=core.ProxyServer(('127.0.0.1',0),core.ProxyHandler)
        old=None
        try:
            with tempfile.TemporaryDirectory() as tmp:
                old=self._temporary_config(tmp)
                cfg=core.load();cfg.update({'proxy_port':bridge.server_address[1],
                    'upstream_host':'127.0.0.1','upstream_port':1,'bypass_hosts':[],
                    'allow_direct_fallback':True})
                core.save(cfg)
                worker=threading.Thread(target=bridge.serve_forever,daemon=True);worker.start()
                with socket.create_connection(bridge.server_address,timeout=4) as client:
                    client.settimeout(4)
                    client.sendall((f'GET http://127.0.0.1:{direct.getsockname()[1]}/ HTTP/1.1\r\n'
                                    f'Host: 127.0.0.1:{direct.getsockname()[1]}\r\n\r\n').encode())
                    response=client.recv(4096)
                self.assertIn(b'502 Bad Gateway',response)
                with self.assertRaises(socket.timeout):direct.accept()
        finally:
            bridge.shutdown();bridge.server_close();direct.close()
            if old:core.HOME,core.CFG_DIR,core.CFG_FILE=old

    def test_force_proxy_overrides_bypass_and_never_opens_direct_socket(self):
        expected=object()
        cfg={'bypass_hosts':['build.example.test'],'allow_direct_fallback':True}
        with patch.object(core,'connect_upstream',return_value=expected) as upstream, \
             patch.object(core.socket,'create_connection',side_effect=AssertionError('direct route leaked')) as direct:
            sock,route=core.destination_with_route('build.example.test',22,'proxy',cfg,force_proxy=True)
        self.assertIs(sock,expected)
        self.assertEqual(route,'proxy')
        upstream.assert_called_once_with('build.example.test',22,cfg)
        direct.assert_not_called()

    def test_force_proxy_failure_does_not_fall_back_to_direct(self):
        cfg={'bypass_hosts':['build.example.test'],'allow_direct_fallback':True}
        with patch.object(core,'connect_upstream',side_effect=OSError('upstream down')) as upstream, \
             patch.object(core.socket,'create_connection',side_effect=AssertionError('direct route leaked')) as direct:
            with self.assertRaisesRegex(OSError,'upstream down'):
                core.destination_with_route('build.example.test',22,'proxy',cfg,force_proxy=True)
        upstream.assert_called_once()
        direct.assert_not_called()

    def test_http_forward_via_auto_direct_fallback(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),SimpleHandler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        bridge=core.ProxyServer(('127.0.0.1',0),core.ProxyHandler)
        # Bridge chooses auto only when bound to configured auto_port.
        old=(core.HOME,core.CFG_DIR,core.CFG_FILE)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                core.HOME=pathlib.Path(tmp);core.CFG_DIR=core.HOME/'.config/proxypilot'
                core.CFG_FILE=core.CFG_DIR/'config.json'
                cfg=core.load();cfg['auto_port']=bridge.server_address[1]
                cfg['upstream_host']='127.0.0.1';cfg['upstream_port']=1;cfg['bypass_hosts']=[]
                core.save(cfg)
                worker=threading.Thread(target=bridge.serve_forever,daemon=True);worker.start()
                with socket.create_connection(('127.0.0.1',bridge.server_address[1]),timeout=4) as conn:
                    port=server.server_address[1]
                    conn.sendall((f'GET http://127.0.0.1:{port}/ping HTTP/1.1\r\n'
                                  f'Host: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n').encode())
                    # A client may half-close its request stream and still
                    # expect the server response. The bridge must relay EOF
                    # in one direction without dropping the reverse stream.
                    conn.shutdown(socket.SHUT_WR)
                    chunks=[]
                    while True:
                        data=conn.recv(4096)
                        if not data:break
                        chunks.append(data)
                    self.assertIn(b'proxy-pilot-ok',b''.join(chunks))
        finally:
            bridge.shutdown();bridge.server_close()
            server.shutdown();server.server_close()
            core.HOME,core.CFG_DIR,core.CFG_FILE=old

if __name__=='__main__':unittest.main()
