"""Read-only, conservative Linux proxy diagnostics for ProxyPilot.

This module distinguishes a configured proxy from a verified socket route.
It never reads or displays API keys or application-specific private settings.
"""
from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
from urllib.parse import urlsplit

ENV_KEYS = ('http_proxy','https_proxy','all_proxy')


def _run(args, timeout=2.5):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _gget(schema, key):
    raw = _run(['gsettings','get',schema,key]) if shutil.which('gsettings') else None
    if raw is None:
        return None
    try:
        return ast.literal_eval(raw)
    except (SyntaxError, ValueError):
        return raw.strip("'\"")


def public_proxy_endpoint(value):
    """Only return scheme/host/port, never credentials or URL paths."""
    if not value:
        return None
    try:
        u = urlsplit(value)
        if u.scheme not in ('http','https','socks','socks4','socks4a','socks5','socks5h') or not u.hostname:
            return '<set; endpoint hidden>'
        host = u.hostname
        if ':' in host:
            host = f'[{host}]'
        return f'{u.scheme}://{host}:{u.port or "default"}'
    except (ValueError, TypeError):
        return '<set; endpoint hidden>'


def user_systemd_proxies():
    raw = _run(['systemctl','--user','show-environment'])
    found = {}
    for line in (raw or '').splitlines():
        k,sep,v = line.partition('=')
        if sep and k.lower() in ENV_KEYS:
            found[k.lower()] = public_proxy_endpoint(v)
    return found


def process_proxies(pids, proc_root=Path('/proc')):
    """Summarize same-user process env. Skips inaccessible processes.

    Never returns secrets; a heterogeneous group is explicitly marked mixed.
    """
    by_pid = {}
    for item in list(pids)[:60]:
        try:
            pid = int(item)
            f = proc_root / str(pid)
            if f.stat().st_uid != os.getuid():
                continue
            blob = (f/'environ').read_bytes()[:1024*1024]
            found = {}
            for e in blob.split(b'\x00'):
                k,sep,v = e.partition(b'=')
                if not sep:
                    continue
                key = k.decode('ascii','ignore').lower()
                if key in ENV_KEYS:
                    found[key] = public_proxy_endpoint(v.decode('utf-8','replace'))
            by_pid[pid] = found
        except (OSError, ValueError, PermissionError):
            continue
    if not by_pid:
        return {'status':'Unavailable','detail':'Running process environment could not be read.', 'sampled':0}
    with_proxy = {p:tuple(sorted((k,v) for k,v in e.items() if v)) for p,e in by_pid.items() if any(e.values())}
    without = len(by_pid) - len(with_proxy)
    endpoints = sorted({v for e in by_pid.values() for v in e.values() if v})
    if with_proxy and without:
        status = 'Mixed environment'
    elif with_proxy:
        status = 'Proxy variables present'
    else:
        status = 'No proxy environment variables'
    return {'status':status, 'detail':', '.join(endpoints[:5]) if endpoints else 'None',
            'sampled':len(by_pid), 'with_proxy':len(with_proxy), 'without_proxy':without}


def _reachable(host, port, timeout=0.18):
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def system_snapshot(cfg, probe=False):
    """Get effective configured proxy endpoints, not a promise of traffic routing."""
    gmode = _gget('org.gnome.system.proxy','mode')
    gports = {}
    for s in ('http','https','socks'):
        schema = 'org.gnome.system.proxy.'+s
        h = _gget(schema,'host')
        p = _gget(schema,'port')
        if isinstance(p, int) and 1<=p<=65535 and h:
            gports[s] = f'{h}:{p}'
    env = user_systemd_proxies()
    upstream = f'{cfg.get("upstream_host","127.0.0.1")}:{cfg.get("upstream_port",10808)}'
    bridge = f'127.0.0.1:{cfg.get("auto_port",18787)}'
    expected = cfg.get('global_mode','off')
    notes = []
    if gmode is None:
        notes.append('GNOME proxy settings could not be inspected in this session.')
    if expected in ('auto','proxy') and gmode != 'manual':
        notes.append(f'ProxyPilot profile is {expected}, but GNOME is {gmode or "unavailable"}.')
    if expected == 'off' and (gmode == 'manual' or env):
        notes.append('ProxyPilot system mode is OFF, but Linux still has other proxy settings. OFF does not mean direct.')
    if expected == 'auto' and gmode == 'manual' and not any(str(cfg.get('auto_port')) in x for x in gports.values()):
        notes.append('GNOME proxy does not point to the ProxyPilot AUTO bridge; some apps may bypass its fallback.')
    if expected == 'auto' and env and not any(str(cfg.get('auto_port')) in str(x) for x in env.values()):
        notes.append('User systemd proxy differs from ProxyPilot AUTO bridge; new service processes may use another route.')
    file_path = Path(os.environ.get('XDG_CONFIG_HOME', Path.home()/'.config'))/'environment.d/90-v2ray.conf'
    if file_path.is_file():
        notes.append('A separate 90-v2ray.conf persists proxy variables across logins.')
    out = {'proxy_pilot_mode':expected,'gnome_mode':gmode if gmode is not None else 'unavailable',
           'gnome':gports,'systemd':env,'upstream':upstream,'bridge':bridge,'notes':notes}
    if probe:
        # This probes an endpoint listener only. It does NOT assert good egress.
        out['upstream_listening'] = _reachable(cfg.get('upstream_host','127.0.0.1'),cfg.get('upstream_port',10808))
        out['bridge_listening'] = _reachable('127.0.0.1',cfg.get('auto_port',18787))
    return out


def service_override_info(units):
    """Only report service drop-in filenames and proxy-related directives, not secret values."""
    info = []
    for unit in units[:12]:
        if not re.fullmatch(r'[\w@.-]+\.service',unit):
            continue
        unit_dir = Path.home()/'.config/systemd/user'/(unit+'.d')
        try:
            files = sorted(unit_dir.glob('*.conf'))
        except OSError:
            files=[]
        for f in files:
            try:
                content = f.read_text(encoding='utf-8')
            except (OSError,UnicodeError):
                continue
            directives = []
            for line in content.splitlines():
                v = line.strip().lower()
                if v.startswith('unsetenvironment=') and ('proxy' in v):
                    directives.append('removes proxy environment')
                if v.startswith('environment=') and ('proxy' in v):
                    directives.append('sets proxy environment')
            if directives:
                info.append(f'{unit} / {f.name}: {", ".join(dict.fromkeys(directives))}')
    return info


def app_snapshot(group, cfg, sockets=(), events=(), now=None):
    """Human-readable app inspection; all claims are evidence scoped."""
    import appstatus
    pids = [p['pid'] for p in group.get('processes',[]) if 'pid' in p]
    observed = appstatus.group_evidence(group, sockets, events, now=now)
    env = process_proxies(pids) if pids else {'status':'App not running','detail':'—','sampled':0}
    routes = {}
    lines = []
    for s in sorted(observed['connections'], key=lambda x:x.get('last_seen',0),reverse=True):
        kind = s.get('kind','unknown')
        routes[kind] = routes.get(kind,0)+1
        host = s.get('remote_ip','?')
        port = s.get('remote_port','?')
        p = s.get('pid','?')
        lines.append({'pid':p,'process':s.get('process','?'),'kind':kind,
                      'peer':f'{host}:{port}', 'last_seen':s.get('last_seen',s.get('ts',0))})
    override=service_override_info(group.get('services',[]))
    caveats=[]
    if group.get('mode')!='unmanaged' and group.get('process_count') and not group.get('bridged_count'):
        caveats.append('Saved app rule is not proof that existing processes use the ProxyPilot bridge.')
    if override:
        caveats.append('This app has service-specific proxy overrides. Inspect before relying on a saved app rule.')
    if routes.get('external'):
        caveats.append('An external TCP peer is not proof that traffic bypasses a VPN/router.')
    if routes.get('xray'):
        caveats.append('A local Xray socket proves proxy contact, not all web requests or final egress.')
    return {'observed':observed, 'env':env, 'overrides':override, 'sockets':lines,
            'routes':routes,'caveats':caveats,'group':group.get('name','?')}
