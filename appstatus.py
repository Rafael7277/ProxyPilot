"""Explain the distinction between requested proxy rules and observed traffic.

Never infer that unobserved traffic is direct, or that a socket to Xray
necessarily means a completed web request. All results are conservative.
"""
from __future__ import annotations
import time


def group_evidence(group, sockets, bridge_events, now=None, lookback_s=90, since=None):
    now = time.time() if now is None else now
    pids = {p['pid']:p.get('start') for p in group.get('processes', [])}
    appids = {app['id'] for app in group.get('apps', [])}
    mine = []
    for s in sockets:
        if s['pid'] not in pids: continue
        if pids[s['pid']] and s.get('start') and pids[s['pid']] != s['start']: continue
        if now - s.get('last_seen', s.get('ts', now)) > lookback_s: continue
        if since is not None and s.get('last_seen', s.get('ts', now)) < since: continue
        mine.append(s)
    events = []
    for e in bridge_events:
        if now - e.get('ts', 0) > lookback_s: continue
        if since is not None and e.get('ts', 0) < since: continue
        pid = e.get('pid')
        if pid in pids or e.get('app_id') in appids:
            events.append(e)
    by_kind = {kind: [x for x in mine if x['kind'] == kind]
               for kind in ('xray','bridge','external','lan')}
    by_route = {route:[x for x in events if x.get('route') == route and x.get('event') != 'error' and x.get('status') != 'failed']
                for route in ('proxy','direct','fallback','bypass')}
    errors = [e for e in events if e.get('event') == 'error' or e.get('status') == 'failed']
    # Order by strongest evidence; multiple observations are reported separately.
    if by_route['proxy']:
        title, level = 'ProxyPilot PROXY confirmed', 'confirmed'
        explanation = 'ProxyPilot reported routing a matching connection via SOCKS5.'
    elif by_route['fallback']:
        title, level = 'Direct fallback confirmed', 'confirmed'
        explanation = 'ProxyPilot reported switching a matching connection to direct access.'
    elif by_route['direct'] or by_route['bypass']:
        title, level = 'ProxyPilot DIRECT confirmed', 'confirmed'
        explanation = 'ProxyPilot reported a direct or bypass route for a matching connection.'
    elif by_kind['xray']:
        title, level = 'Connected to Xray', 'observed'
        explanation = 'This app had a TCP connection to the local SOCKS5 port. The final web destination is not visible here.'
    elif by_kind['bridge']:
        title, level = 'Connected to ProxyPilot', 'observed'
        explanation = 'The app had a TCP connection to the local bridge; the actual onward route is not yet verified.'
    elif by_kind['external']:
        title, level = 'External TCP observed', 'uncertain'
        explanation = 'A public IP socket was seen. It does NOT prove unproxied internet access (other VPNs and proxies exist).'
    elif errors:
        title, level = 'Connection error seen', 'uncertain'
        explanation = 'A matching ProxyPilot connection failed. No successful route was verified.'
    else:
        title, level = 'Not yet verified', 'uncertain'
        explanation = 'No matching network connection was captured in the observation window. This does not mean the app is offline.'
    evidence = []
    for route in ('proxy','fallback','direct','bypass'):
        if by_route[route]:
            newest = max(by_route[route], key=lambda e:e.get('ts',0))
            evidence.append(f'Bridge {route.upper()}: {len(by_route[route])} observed; latest {newest.get("host","?")}:{newest.get("port","?")}')
    if by_kind['xray']:
        evidence.append(f'Xray SOCKS5: {len(by_kind["xray"])} observed socket(s)')
    if by_kind['bridge']:
        evidence.append(f'ProxyPilot local bridge: {len(by_kind["bridge"])} observed socket(s)')
    if by_kind['external']:
        evidence.append(f'Other external TCP: {len(by_kind["external"])} observed socket(s) (not route proof)')
    if errors: evidence.append(f'Bridge errors: {len(errors)}')
    # Ambiguous/mixed observations should be visible without a green blanket guarantee.
    if sum(bool(by_route[k]) for k in by_route) > 1:
        explanation += ' Multiple ProxyPilot routes were seen: read the evidence lines.'
    return {'title':title,'level':level,'explanation':explanation,'lines':evidence,
            'connections':mine,'events':events, 'last_seen':max((s.get('last_seen',0) for s in mine),default=None)}


def requested_label(group, global_mode):
    mode = group.get('mode','unmanaged')
    if mode == 'unmanaged':
        return f'Follow app / Linux settings (system: {global_mode})'
    return {'auto':'Auto: prefer proxy, allow direct fallback',
            'proxy':'Proxy only (for participating connections)',
            'direct':'Direct (for participating connections)'}.get(mode,mode)


def next_step(group, evidence, global_mode):
    if not group.get('process_count'):
        return 'App is not running. Start it, then use Watch this app.'
    if evidence['level'] == 'confirmed':
        return 'Recent bridge routing was observed. Other connections can take different paths.'
    if evidence['title']=='Connected to Xray':
        return 'A SOCKS5 connection was seen. To verify the exit IP, use an IP-check page inside this app.'
    if group.get('mode') != 'unmanaged' and not group.get('bridged_count'):
        if group.get('services'):
            return 'Rule may be saved but not active in the running service. Review service restart/overrides; do not assume the rule is applied.'
        return 'A per-app rule may be saved without affecting this running instance. Launch through ProxyPilot or integrate its launcher.'
    if global_mode in ('auto','proxy'):
        return 'System proxy is configured for compatible apps. Perform a new network action while watching; not all apps honor it.'
    return 'Click Watch this app, then browse or make a request inside that application.'
