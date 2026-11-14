#!/usr/bin/env python3
"""Privacy-aware connection telemetry for ProxyPilot's own HTTP bridge only.

Not a packet sniffer. A request that bypasses the bridge is not observed.
Logs only destination HOST/PORT (never URL paths, headers, payload or tokens).
"""
from __future__ import annotations
import collections
import csv
import json
import os
from pathlib import Path
import socket
import threading
import time
import uuid

DATA_HOME = Path(os.environ.get('XDG_STATE_HOME', Path.home() / '.local' / 'state'))
DATA_DIR = DATA_HOME / 'proxypilot'
EVENT_FILE = DATA_DIR / 'traffic.jsonl'
EVENT_BACKUP = DATA_DIR / 'traffic.previous.jsonl'
ROTATE_BYTES = 4 * 1024 * 1024
_LOCK = threading.RLock()


def record(**fields):
    """Append one small event, safely rotating a bounded user-private log."""
    event = {'ts': round(time.time(), 3)}
    allowed = {'event', 'id', 'pid', 'process', 'app_id', 'scope', 'host', 'port',
               'route', 'mode', 'status', 'bytes_up', 'bytes_down', 'duration_ms', 'error'}
    for key in allowed:
        if key in fields and fields[key] is not None:
            val = fields[key]
            event[key] = val[:255] if isinstance(val, str) else val
    payload = (json.dumps(event, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
    with _LOCK:
        DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(DATA_DIR, 0o700)
        if EVENT_FILE.exists() and EVENT_FILE.stat().st_size >= ROTATE_BYTES:
            # Never follow symlinks in the log path: data is private, not privileged.
            if EVENT_FILE.is_symlink() or EVENT_BACKUP.is_symlink():
                raise RuntimeError('Unexpected traffic log symlink')
            EVENT_FILE.replace(EVENT_BACKUP)
        fd = os.open(EVENT_FILE, os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, payload)
        finally:
            os.close(fd)


def new_id():
    return uuid.uuid4().hex[:16]


def identify_caller(client_ip: str, client_port: int, server_port: int):
    """Best-effort local socket -> process mapping using /proc, no sudo.

    Missing PID means *unknown* and must never be silently assigned to a group.
    Only sockets owned by this Unix user can be reliably attributed.
    """
    result = (None, 'Unattributed')
    if client_ip != '127.0.0.1':
        return result
    needle_local = f'0100007F:{client_port:04X}'
    needle_remote = f'0100007F:{server_port:04X}'
    inode = None
    try:
        with open('/proc/net/tcp', encoding='ascii') as f:
            next(f, None)
            for line in f:
                items = line.split()
                if len(items) > 9 and items[1] == needle_local and items[2] == needle_remote:
                    inode = items[9]
                    break
    except OSError:
        return result
    if not inode or inode == '0':
        return result
    target = f'socket:[{inode}]'
    try:
        with os.scandir('/proc') as processes:
            for entry in processes:
                if not entry.name.isdigit():
                    continue
                try:
                    if entry.stat(follow_symlinks=False).st_uid != os.getuid():
                        continue
                    fd_path = f'/proc/{entry.name}/fd'
                    with os.scandir(fd_path) as fds:
                        for fdesc in fds:
                            try:
                                if os.readlink(fdesc.path) == target:
                                    pid = int(entry.name)
                                    try:
                                        name = Path(f'/proc/{pid}/comm').read_text().strip()
                                    except OSError:
                                        name = 'PID ' + str(pid)
                                    return pid, name[:100]
                            except OSError:
                                continue
                except (OSError, PermissionError):
                    continue
    except OSError:
        pass
    return result


class TrafficReader:
    """Incremental reader for the GUI (never reads remote browser data)."""
    def __init__(self, max_events=2500):
        self.events = collections.deque(maxlen=max_events)
        self.offset = 0
        self.inode = None
        self.partial = b''

    def poll(self):
        try:
            stat = EVENT_FILE.stat()
            if self.inode != stat.st_ino or stat.st_size < self.offset:
                self.offset, self.partial, self.inode = 0, b'', stat.st_ino
            with EVENT_FILE.open('rb') as f:
                f.seek(self.offset)
                data = f.read(1024 * 1024)
                self.offset = f.tell()
        except (FileNotFoundError, PermissionError):
            return list(self.events)
        lines = (self.partial + data).split(b'\n')
        self.partial = lines.pop()
        for raw in lines:
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict) and obj.get('event') in ('open', 'close', 'error'):
                    self.events.append(obj)
            except (ValueError, UnicodeError):
                continue
        return list(self.events)

    def connections(self):
        """Return most recent opens/errors with close traffic counters attached."""
        result = {}
        order = []
        for e in self.events:
            conn_id = e.get('id')
            if not conn_id:
                continue
            kind = e.get('event')
            if kind in ('open', 'error'):
                item = dict(e)
                result[conn_id] = item
                order.append(conn_id)
            elif kind == 'close' and conn_id in result:
                result[conn_id].update({k: e.get(k) for k in ('bytes_up', 'bytes_down', 'duration_ms')})
                result[conn_id]['status'] = e.get('status', 'closed')
        return [result[i] for i in reversed(order) if i in result]

    def summary(self):
        conns = self.connections()
        return {
            'requests': len(conns),
            'proxy': sum(x.get('route') == 'proxy' for x in conns),
            'direct': sum(x.get('route') in ('direct', 'bypass') for x in conns),
            'fallback': sum(x.get('route') == 'fallback' for x in conns),
            'failed': sum(x.get('event') == 'error' for x in conns),
            'applications': len({(x.get('app_id') or x.get('process') or 'Unknown') for x in conns}),
        }

    def export_csv(self, path):
        keys = ['ts','app_id','process','pid','scope','host','port','mode','route','status','bytes_up','bytes_down','duration_ms','error']
        with open(path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
            writer.writeheader()
            writer.writerows(self.connections())


def clear_history():
    """Privacy control: delete only ProxyPilot logs, never any app settings."""
    for item in (EVENT_FILE, EVENT_BACKUP):
        if item.is_file() and not item.is_symlink():
            item.unlink()
