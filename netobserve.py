"""Read-only TCP connection sampling with same-user process attribution.

Does not intercept packets, resolve a SOCKS target, or prove public egress IP.
Observations are ephemeral and can miss short-lived connections. No sudo.
"""
from __future__ import annotations
import ipaddress
import os
from pathlib import Path
import socket
import time

TCP_ESTABLISHED = '01'


def decode_endpoint(value, family):
    try:
        address, port = value.split(':')
        raw = bytes.fromhex(address)
        if family == socket.AF_INET:
            if len(raw) != 4: return None
            ip = socket.inet_ntop(family, raw[::-1])
        else:
            if len(raw) != 16: return None
            # /proc/net/tcp6 writes four little-endian 32-bit words.
            ip = socket.inet_ntop(family, b''.join(raw[i:i+4][::-1] for i in range(0, 16, 4)))
        return ip, int(port, 16)
    except (ValueError, OSError): return None


def parse_table(raw, family):
    entries = {}
    for line in raw.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10 or fields[3] != TCP_ESTABLISHED:
            continue
        local = decode_endpoint(fields[1], family)
        remote = decode_endpoint(fields[2], family)
        inode = fields[9]
        if not local or not remote or not inode.isdigit() or int(inode) == 0:
            continue
        entries[inode] = {'local_ip': local[0], 'local_port': local[1],
                          'remote_ip': remote[0], 'remote_port': remote[1],
                          'inode': inode}
    return entries


def classify(remote_ip, remote_port, cfg):
    """Classify *socket peer*, not promised end-to-end network routing."""
    try:
        ip = ipaddress.ip_address(remote_ip)
        if getattr(ip, "ipv4_mapped", None): ip = ip.ipv4_mapped
        port = int(remote_port)
    except (ValueError, TypeError): return 'unknown'
    upstream = int(cfg.get('upstream_port', 10808))
    bridge_ports = {int(cfg.get('auto_port', 18787)), int(cfg.get('proxy_port', 18789))}
    bridge_ports.update(int(x) for x in cfg.get('app_ports', {}).values())
    if ip.is_loopback:
        if port == upstream: return 'xray'
        if port in bridge_ports: return 'bridge'
        return 'local'
    if ip.is_global: return 'external'
    return 'lan'


def observe(cfg, proc_root=Path('/proc')):
    """Return current ESTABLISHED TCP client sockets owned by this Unix user.

    A given socket may have several owners (FD inheritance). They are retained
    individually rather than incorrectly assigned to an arbitrary process.
    """
    table = {}
    for path, family in ((proc_root/'net/tcp',socket.AF_INET), (proc_root/'net/tcp6',socket.AF_INET6)):
        try:
            table.update(parse_table(path.read_text(encoding='ascii'), family))
        except (OSError, UnicodeError): pass
    if not table: return []
    uid = os.getuid()
    result = []
    seen = set()
    try:
        entries = list(proc_root.iterdir())
    except OSError: return []
    for proc in entries:
        if not proc.name.isdigit(): continue
        try:
            if proc.stat().st_uid != uid: continue
            with os.scandir(proc/'fd') as fds:
                for fd in fds:
                    try: dest = os.readlink(fd.path)
                    except OSError: continue
                    if not dest.startswith('socket:[') or not dest.endswith(']'): continue
                    inode = dest[8:-1]
                    if inode not in table: continue
                    key = (proc.name, inode)
                    if key in seen: continue
                    seen.add(key)
                    sock = table[inode]
                    kind = classify(sock['remote_ip'], sock['remote_port'], cfg)
                    if kind == 'local': continue
                    try: pname = (proc/'comm').read_text(encoding='utf-8').strip()
                    except OSError: pname = 'Unknown'
                    # A PID may be reused between samples; keep process start ticks.
                    try:
                        raw = (proc/'stat').read_text(encoding='utf-8')
                        start = int(raw[raw.rfind(') ')+2:].split()[19])
                    except (OSError, ValueError, IndexError): start = 0
                    result.append(dict(sock, kind=kind, pid=int(proc.name),
                                       start=start, process=pname[:80], ts=time.time()))
        except (OSError, PermissionError): continue
    return result


class RecentConnections:
    """In-memory recent *observations*; not request counts or a traffic history."""
    def __init__(self, window_s=90, limit=3000):
        self.window_s = window_s
        self.limit = limit
        self.items = {}

    def update(self, observations, now=None):
        now = time.time() if now is None else now
        for obj in observations:
            key = (obj['pid'], obj.get('start', 0), obj['inode'],
                   obj['remote_ip'], obj['remote_port'])
            self.items[key] = dict(obj, last_seen=now)
        self.items = {k:v for k,v in self.items.items() if now-v['last_seen'] <= self.window_s}
        if len(self.items) > self.limit:
            keys = sorted(self.items, key=lambda k:self.items[k]['last_seen'], reverse=True)
            self.items = {k:self.items[k] for k in keys[:self.limit]}

    def recent(self, now=None, window_s=None):
        now = time.time() if now is None else now
        span = self.window_s if window_s is None else window_s
        return [v for v in self.items.values() if now-v['last_seen'] <= span]
