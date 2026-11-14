"""Read-only observation of local TCP sockets to configured proxy ports.

Not a sniffer: sockets may be missed between samples, and cannot reveal an
independent SOCKS proxy's remote target or request bytes. No elevated rights.
"""
from __future__ import annotations
import os
from pathlib import Path
import socket


def _decode_ipv4(hex_address):
    try:
        ip, port = hex_address.split(':')
        return socket.inet_ntop(socket.AF_INET, bytes.fromhex(ip)[::-1]), int(port, 16)
    except (ValueError, OSError):
        return None


def _tcp_sockets(port_set, tcp_text):
    """Return TCP sockets connected as clients to one of the selected ports."""
    found = {}
    for line in tcp_text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10 or fields[3] != '01':
            continue  # ESTABLISHED only
        local = _decode_ipv4(fields[1]); remote = _decode_ipv4(fields[2])
        if not local or not remote or remote[0] not in ('127.0.0.1',) or remote[1] not in port_set:
            continue
        if not fields[9].isdigit() or int(fields[9]) <= 0:
            continue
        found[fields[9]] = {'local_ip':local[0], 'local_port':local[1],
                           'remote_ip':remote[0], 'remote_port':remote[1],
                           'inode':fields[9]}
    return found


def observe(ports):
    """Return list of same-UID client socket owners and their observed proxy ports.

    Ownership is a point-in-time best effort. Avoid root, and never report
    'all traffic covered'; applications may bypass system proxy settings.
    """
    targets={int(p) for p in ports if 1 <= int(p) <= 65535}
    if not targets: return []
    try:
        sockets = _tcp_sockets(targets,Path('/proc/net/tcp').read_text(encoding='ascii'))
    except (OSError, UnicodeError):
        return []
    if not sockets:return []
    uid=os.getuid()
    owned={}
    try:
        proc_entries=list(Path('/proc').iterdir())
    except OSError:
        return []
    for proc in proc_entries:
        if not proc.name.isdigit():continue
        try:
            if proc.stat().st_uid != uid:continue
            with os.scandir(proc/'fd') as fds:
                for fd in fds:
                    try:
                        link=os.readlink(fd.path)
                    except OSError:continue
                    if not link.startswith('socket:[') or not link.endswith(']'):continue
                    inode=link[8:-1]
                    if inode not in sockets or inode in owned:continue
                    # ProxyPilot itself dials Xray on behalf of managed apps.
                    # Those connections already have precise bridge events and
                    # must not masquerade as independent external app traffic.
                    try:
                        cmdline=(proc/'cmdline').read_bytes().replace(b'\x00',b' ')
                        if b'proxypilot.py serve' in cmdline: continue
                    except OSError: pass
                    try:name=(proc/'comm').read_text().strip()
                    except OSError:name='Unknown process'
                    owned[inode]={'pid':int(proc.name),'process':name[:100]}
        except (OSError, PermissionError):continue
        if len(owned)==len(sockets):break
    return [dict(sock,**owned[inode]) for inode,sock in sockets.items() if inode in owned]
