import os
from pathlib import Path
import socket
import sys
import threading
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import socketwatch
import manager

class LocalSocketObservability(unittest.TestCase):
    def test_linux_tcp_parser_established_and_target(self):
        lines=('  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'
               '  1: 0100007F:C0DE 0100007F:2A38 01 00000000:00000000 00:00000000 00000000 1000 0 12345 1\n'
               '  2: 0100007F:C0DF 0100007F:2A38 0A 00000000:00000000 00:00000000 00000000 1000 0 99999 1\n')
        out=socketwatch._tcp_sockets({10808},lines)
        self.assertEqual(len(out),1)
        self.assertEqual(out['12345']['remote_port'],10808)
        self.assertEqual(out['12345']['remote_ip'],'127.0.0.1')

    def test_observe_real_user_owned_socket(self):
        listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen(1)
        port=listener.getsockname()[1]
        client=socket.create_connection(('127.0.0.1',port),timeout=2)
        peer,_=listener.accept()
        try:
            found=socketwatch.observe({port})
            self.assertTrue(any(x['pid']==os.getpid() and x['remote_port']==port for x in found),found)
        finally:
            client.close();peer.close();listener.close()

    def test_application_group_variants(self):
        self.assertEqual(manager._stem('sample-browser-stable'),'sample-browser')
        self.assertEqual(manager._stem('sample_browser.desktop'),'sample-browser')
        self.assertEqual(manager._stem('org.gnome.SampleBrowser.desktop'),'samplebrowser')

if __name__ == '__main__': unittest.main()
