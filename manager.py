#!/usr/bin/env python3
"""App inventory, reversible system-wide profiles, and conservative process review.

No privileged network interception is performed. Never treats 'idle' as dead.
"""
from __future__ import annotations
import os
import pathlib
import re
import shlex
import shutil
import signal
import subprocess
import time
import json
import threading
from dataclasses import dataclass, asdict
from collections import defaultdict
import proxypilot as core

PROXY_KEYS = ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy','NO_PROXY','no_proxy')
ENV_MARKER = '# ProxyPilot managed file — safe to remove using the application\n'
PROTECTED = {'systemd', 'systemd-user', 'dbus', 'dbus-daemon', 'dbus-broker', 'xfce4-session',
             'xfce4-panel', 'xfce4-terminal', 'xfwm4', 'xorg', 'xwayland', 'pipewire',
             'wireplumber', 'pulseaudio', 'gnome-keyring-daemon', 'networkmanager',
             'nm-applet', 'ssh', 'ssh-session', 'sshd', 'sshd-session', 'ssh-agent',
             'bash', 'sh', 'dash', 'zsh', 'fish', 'tmux', 'screen', 'mosh',
             'mosh-server', 'mosh-client', 'login', 'sudo', 'su', 'doas', 'init',
             'proxypilot.py', 'desktop.py'}


def _run(cmd, timeout=8, check=True):
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"{' '.join(cmd[:2])}: {result.stderr.strip()[:300]}")
    return result.stdout.strip()


def _stem(s):
    s = pathlib.Path(s or '').name.casefold()
    s = re.sub(r'\.desktop$|\.service$', '', s)
    s = re.sub(r'^org\.(?:google|gnome|kde|xfce)\.', '', s)
    s = s.replace('_', '-')
    s = re.sub(r'-stable$|-bin$', '', s)
    if s in ('code', 'code-oss', 'visual-studio-code'): return 'code'
    # Only strip well-known service suffixes, not arbitrary words.
    s = re.sub(r'-(?:gateway|agent|daemon|desktop|backend|frontend|service)$', '', s)
    return s


def _command_key(exec_string, desktop_id=''):
    try: argv = shlex.split(exec_string)
    except ValueError: argv=[]
    if argv and argv[0]=='env':
        argv=argv[1:]
        while argv and '=' in argv[0] and not argv[0].startswith('-'):
            argv=argv[1:]
    if argv and argv[0] in ('flatpak', '/usr/bin/flatpak'):
        if 'run' in argv:
            idx=argv.index('run')
            items=[v for v in argv[idx+1:] if not v.startswith('-')]
            return _stem(items[0].split('.')[-1]) if items else _stem(desktop_id)
    if argv:
        cmd=_stem(argv[0])
        if cmd in ('python','python3','bash','sh','env','gtk-launch'):
            return _stem(desktop_id)
        return cmd
    return _stem(desktop_id)


def _service_key(unit, app_keys):
    k=_stem(unit)
    if k in app_keys:return k
    # Associate a descriptive service with its app only if there's an unambiguous prefix.
    candidates=[x for x in app_keys if len(x)>3 and k.startswith(x+'-')]
    return sorted(candidates,key=len,reverse=True)[0] if candidates else k


def proc_snapshot():
    """Read user-owned processes without root; identity contains kernel start ticks.

    A process is never considered abandoned solely from CPU use or a missing window.
    """
    out=[]; proc=pathlib.Path('/proc')
    try: entries=proc.iterdir()
    except OSError:return []
    uid=os.getuid()
    try: uptime = float(pathlib.Path('/proc/uptime').read_text().split()[0]); hz = os.sysconf('SC_CLK_TCK')
    except (OSError, ValueError): uptime, hz = 0., 100
    for path in entries:
        if not path.name.isdigit():continue
        try:
            if path.stat().st_uid != uid:continue
            raw=(path/'cmdline').read_bytes()
            stat=(path/'stat').read_text()
            argv=[a.decode('utf-8','replace') for a in raw.split(b'\x00') if a]
            # Zombie processes usually have an empty cmdline, but should remain visible.
            if not argv and stat[stat.rfind(') ')+2:].split()[0] != 'Z':continue
            if not argv:argv=[stat[stat.find('(')+1:stat.rfind(')')]]
            # Field 2 (comm) may have spaces or parens; parse after final ') '.
            rest=stat[stat.rfind(') ')+2:].split()
            state=rest[0]; ppid=int(rest[1]); start_ticks=int(rest[19])
            cpu_ticks=int(rest[11])+int(rest[12])
            try: exe=os.readlink(path/'exe')
            except OSError:exe=argv[0]
            cmd=pathlib.Path(exe).name
            cgroup=''
            try: cgroup=(path/'cgroup').read_text()[:4096]
            except OSError: pass
            rss=0
            try:
                for line in (path/'status').read_text().splitlines():
                    if line.startswith('VmRSS:'):
                        rss=int(line.split()[1]);break
            except (OSError,IndexError,ValueError):pass
            out.append({'pid':int(path.name),'ppid':ppid,'state':state,'start':start_ticks,
                        'cmd':cmd,'argv':argv[:24],'exe':exe,'rss_kb':rss,'cgroup':cgroup,
                        'age_s':max(0,int(uptime-start_ticks/hz)),'cpu_ticks':cpu_ticks})
        except (OSError,ValueError,IndexError,PermissionError):continue
    return out


def _pid_window_ids():
    """Best-effort visible X11 window PIDs, using wmctrl OR xprop.

    Return None when inspection is unavailable, not an empty set: otherwise
    a missing tool could falsely flag every background process as orphaned.
    """
    if not os.environ.get('DISPLAY'):
        return None
    # wmctrl/xprop only see X11 clients. A Wayland native window without an
    # XWayland surface must never be classified as an orphan.
    if os.environ.get('XDG_SESSION_TYPE','').casefold()=='wayland':
        return None
    if shutil.which('wmctrl'):
        try:
            rows=_run(['wmctrl','-lp'],timeout=4,check=False).splitlines()
            return {int(x.split()[2]) for x in rows
                    if len(x.split())>=3 and x.split()[2].isdigit()}
        except (OSError,subprocess.TimeoutExpired):
            pass
    if not shutil.which('xprop'):
        return None
    try:
        data=_run(['xprop','-root','_NET_CLIENT_LIST'],timeout=2,check=False)
        if '_NET_CLIENT_LIST' not in data or 'not found' in data.lower():
            return None
        ids=re.findall(r'0x[0-9a-fA-F]+',data)
        owners=set()
        # Cap diagnostic overhead on systems with many windows.
        for window_id in ids[:80]:
            entry=_run(['xprop','-id',window_id,'_NET_WM_PID'],timeout=0.7,check=False)
            m=re.search(r'_NET_WM_PID[^=]*=\s*(\d+)',entry)
            if m:owners.add(int(m.group(1)))
        return owners
    except (OSError,subprocess.TimeoutExpired):
        return None



class ProcessSampler:
    """CPU percent of a single core since the previous inventory snapshot."""
    def __init__(self):
        self.previous = {}
        self.last = None
        self.lock = threading.Lock()
        self.hz = os.sysconf('SC_CLK_TCK')

    def sample(self, processes):
        with self.lock:
            now = time.monotonic()
            interval = now-self.last if self.last else 0
            new = {}
            for p in processes:
                key=(p['pid'], p['start'])
                old = self.previous.get(key)
                cpu=100*(p['cpu_ticks']-old)/(self.hz*interval) if old is not None and interval>0.2 else 0.
                p['cpu_percent'] = round(max(0., cpu),1)
                new[key] = p['cpu_ticks']
            self.previous = new
            self.last = now


def inventory(sampler=None):
    apps=core.scan_apps()
    services=core.service_list()
    processes=proc_snapshot()
    if sampler is not None: sampler.sample(processes)
    groups={}
    app_keys={}
    for app in apps:
        if app['id']=='proxypilot.desktop':continue
        k=_command_key(app['exec'],app['id'])
        if not k:k=_stem(app['id'])
        app_keys.setdefault(k,[]).append(app)
        g=groups.setdefault(k,{'id':k,'name':app['name'],'apps':[],'services':[],
                                'processes':[],'sources':set()})
        g['apps'].append(app);g['sources'].add('desktop')
    for unit in services:
        k=_service_key(unit,app_keys)
        g=groups.setdefault(k,{'id':k,'name':re.sub(r'\.service$','',unit),
                                  'apps':[],'services':[],'processes':[],'sources':set()})
        g['services'].append(unit);g['sources'].add('service')
    for proc in processes:
        match=re.search(r'([A-Za-z0-9_.@-]+\.service)',proc['cgroup'])
        if match and match.group(1) in services:
            k=_service_key(match.group(1),app_keys)
        else:
            k=_stem(proc['cmd'])
            if k not in groups:
                cmdline=' '.join(proc['argv'][:3]).casefold()
                candidates=[known for known in groups if len(known)>3 and
                            re.search(rf'(?<![a-z0-9_-]){re.escape(known)}(?![a-z0-9_-])',cmdline)]
                if len(candidates)==1:k=candidates[0]
        if not k:continue
        g=groups.setdefault(k,{'id':k,'name':proc['cmd'],'apps':[],
                                  'services':[],'processes':[],'sources':set()})
        g['processes'].append(proc);g['sources'].add('process')
    config=core.load();modes=config.get('profiles',{})
    app_ports=config.get('app_ports',{})
    for g in groups.values():
        g['sources']=sorted(g['sources'])
        g['process_count']=len(g['processes'])
        g['memory_mb']=round(sum(p['rss_kb'] for p in g['processes'])/1024)
        g['cpu_percent']=round(sum(p.get('cpu_percent',0.) for p in g['processes']),1)
        old_app_mode=next((config.get('apps',{}).get(a['id']) for a in g['apps'] if a['id'] in config.get('apps',{})),None)
        old_service_mode=next((config.get('services',{}).get(u) for u in g['services'] if u in config.get('services',{})),None)
        g['mode']=modes.get(g['id'], old_service_mode or old_app_mode or 'unmanaged')
        g['integrated']=bool(g['apps']) and all(x['managed'] for x in g['apps'])
        # Clear distinction: some processes are active but not bridged.
        g['bridged_count']=sum(1 for p in g['processes'] if _bridged(p,g,app_ports))
    return sorted(groups.values(),key=lambda x:(not bool(x['apps']),not bool(x['process_count']),x['name'].casefold()))


def _bridged(proc,group,app_ports=None):
    try:
        blob=(pathlib.Path('/proc')/str(proc['pid'])/'environ').read_bytes()
        ports=core.load().get('app_ports',{}) if app_ports is None else app_ports
        return any(f'127.0.0.1:{ports[a["id"]]}'.encode() in blob for a in group['apps'] if a['id'] in ports)
    except OSError:return False


def set_group_mode(group_id,mode,manage_launchers=False,restart_services=False):
    """One logical route for a whole app. No silent restarts or modifications."""
    if mode not in ('direct','proxy','auto','unmanaged'):raise ValueError('Unknown route mode')
    groups={g['id']:g for g in inventory()}
    if group_id not in groups:raise ValueError('App/process group no longer exists')
    g=groups[group_id]
    changed=[];errors=[]
    for app in g['apps']:
        try:
            if mode!='unmanaged':
                core.activate_app(app['id'],mode)
                if manage_launchers and not app['managed']:
                    core.integrate(app['id']);changed.append('menu '+app['id'])
            else:
                if app['managed']:
                    # Unmanaged means return to the original launcher, not
                    # keep routing all future launches through ProxyPilot.
                    core.restore_app(app['id']);changed.append('restore '+app['id'])
                state=core.load();state.get('apps',{}).pop(app['id'],None);core.save(state)
        except Exception as ex:errors.append(f"{app['name']}: {ex}")
    # Explicit user confirmation in UI required before allowing any service restart.
    if restart_services:
        for unit in g['services']:
            try:
                core.service_override(unit,'off' if mode=='unmanaged' else mode)
                changed.append('service '+unit)
            except Exception as ex: errors.append(f'{unit}: {ex}')
    cfg=core.load()
    if mode=='unmanaged':cfg.setdefault('profiles',{}).pop(group_id,None)
    else:cfg.setdefault('profiles',{})[group_id]=mode
    core.save(cfg)
    return {'changed':changed,'errors':errors,'running':g['process_count'],
            'service_count':len(g['services']), 'bridged':g['bridged_count']}


def cleanup_candidates(groups=None):
    """Only *review candidates*; zero automatic killing. Avoid claiming idleness proves abandonment."""
    groups=groups or inventory()
    windows=_pid_window_ids()
    result=[]
    for g in groups:
        ps=g['processes']
        if not ps:continue
        review=[]
        for p in ps:
            args=' '.join(p['argv']).lower()
            automation=any(s in args for s in ('--headless','--remote-debugging-pipe','playwright','puppeteer','selenium'))
            if automation:review.append(p['pid'])
        no_windows = windows is not None and not any(p['pid'] in windows for p in ps)
        detached=[p['pid'] for p in ps if p['ppid']==1 and '.service' not in p.get('cgroup','')
                  and g.get('apps')]
        reason=[]
        if review:
            old=sum(1 for p in ps if p['pid'] in review and p.get('age_s',0)>=900)
            reason.append(f'{len(review)} automation/headless processes ({old} older than 15 min)')
        if detached:reason.append(f'{len(detached)} adopted by PID 1 (may be normal)')
        zombies=[p['pid'] for p in ps if p.get('state')=='Z']
        if zombies: reason.append(f'{len(zombies)} zombie processes (cannot kill directly)')
        if no_windows and g.get('apps'):
            reason.append('no visible window reported by wmctrl (may be background operation)')
        if reason:
            result.append({'id':g['id'],'name':g['name'],'pids':[p['pid'] for p in ps],
                           'memory_mb':g['memory_mb'], 'reasons':reason,'auto_pids':review})
    return result


def _pid_identity(pid):
    try:
        data=(pathlib.Path('/proc')/str(pid)/'stat').read_text()
        return int(data[data.rfind(') ')+2:].split()[19])
    except (ValueError,IndexError,OSError):return None


def protected_process(process):
    """Return whether the cleaner must never signal this process."""
    argv=process.get('argv',[])
    return (process.get('pid',0)<=1 or _stem(process.get('cmd','')) in PROTECTED
            or 'proxypilot.service' in process.get('cgroup','')
            or any('proxypilot.py' in arg or '/proxypilot/desktop.py' in arg for arg in argv))


def terminate_verified(processes, signal_name='TERM'):
    """Kill only explicitly confirmed, still-identical user-owned PIDs (no kill by name)."""
    if signal_name not in ('TERM','KILL'):raise ValueError('Unsupported signal')
    # Protect this GUI and every parent in its control tree.
    self_ancestors=set();parent=os.getpid()
    for _ in range(32):
        if parent in self_ancestors or parent<=1:break
        self_ancestors.add(parent)
        try:
            stat=(pathlib.Path('/proc')/str(parent)/'stat').read_text()
            parent=int(stat[stat.rfind(') ')+2:].split()[1])
        except (OSError,ValueError,IndexError):break
    killed=[];skipped=[]
    for p in sorted(processes,key=lambda x:x.get('pid',0),reverse=True):
        pid=p['pid']
        if pid in self_ancestors or protected_process(p):
            skipped.append(pid);continue
        try:
            path=pathlib.Path('/proc')/str(pid)
            sig=signal.SIGTERM if signal_name=='TERM' else signal.SIGKILL
            if callable(getattr(os,'pidfd_open',None)) and callable(getattr(os,'pidfd_send_signal',None)):
                # A pidfd pins process identity across the final signal call;
                # recheck start time after opening it to reject PID reuse.
                pidfd=os.pidfd_open(pid,0)
                try:
                    if path.stat().st_uid!=os.getuid() or _pid_identity(pid)!=p['start']:
                        skipped.append(pid);continue
                    os.pidfd_send_signal(pidfd,sig,None,0)
                finally:os.close(pidfd)
            else:
                if path.stat().st_uid!=os.getuid() or _pid_identity(pid)!=p['start']:
                    skipped.append(pid);continue
                os.kill(pid,sig)
            killed.append(pid)
        except (PermissionError,ProcessLookupError,OSError):skipped.append(pid)
    return {'signaled':killed,'skipped':skipped}


class GlobalProxy:
    """GNOME & user-systemd proxy-aware profile; *not* a TUN or universal packet router."""
    def __init__(self):
        self.config_dir=core.CFG_DIR
        self.env_file=core.CONFIG_HOME/'environment.d/99-proxypilot.conf'
        self.backup_file=self.config_dir/'global-backup.json'

    def active_mode(self):
        try:return core.load().get('global_mode','off')
        except Exception:return 'off'

    def _gget(self,schema,key):
        if not shutil.which('gsettings'):return None
        try:return _run(['gsettings','get',schema,key],timeout=3)
        except Exception:return None

    def _gset(self,schema,key,val):
        if shutil.which('gsettings'):
            _run(['gsettings','set',schema,key,val],timeout=4)

    def _snapshot(self):
        snapshot={'gnome':{},'env':{},'file_preexists':self.env_file.exists()}
        for schema,keys in [('org.gnome.system.proxy',['mode','use-same-proxy','ignore-hosts']),
                            ('org.gnome.system.proxy.http',['host','port']),
                            ('org.gnome.system.proxy.https',['host','port']),
                            ('org.gnome.system.proxy.socks',['host','port'])]:
            for key in keys:
                value=self._gget(schema,key)
                if value is not None:snapshot['gnome'][f'{schema}::{key}']=value
        try:
            for line in _run(['systemctl','--user','show-environment']).splitlines():
                key,_,val=line.partition('=')
                if key in PROXY_KEYS:snapshot['env'][key]=val
        except Exception:pass
        if snapshot['file_preexists']:
            raise RuntimeError('Existing 99-proxypilot.conf found. Refusing to replace an unknown file.')
        if self.env_file.is_symlink():
            raise RuntimeError('Refusing to replace 99-proxypilot.conf symlink')
        self.config_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
        file=self.backup_file
        if file.is_symlink():raise RuntimeError('Refusing global proxy backup symlink')
        if file.exists(): raise RuntimeError('Existing global backup found; restore it before creating another.')
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
        if hasattr(os,'O_NOFOLLOW'):flags|=os.O_NOFOLLOW
        fd=os.open(file,flags,0o600)
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as stream:
                stream.write(json.dumps(snapshot,indent=2));stream.flush();os.fsync(stream.fileno())
        except Exception:
            file.unlink(missing_ok=True)
            raise
        return snapshot

    def _env_vars(self,mode,d):
        if mode=='direct':
            return {k:'' for k in PROXY_KEYS}
        port=int(d['auto_port'] if mode=='auto' else d['proxy_port'])
        proxy=f'http://127.0.0.1:{port}'
        result={k:proxy for k in PROXY_KEYS if 'PROXY' in k.upper() and not k.upper().startswith('NO_')}
        no_proxy=','.join(d.get('bypass_hosts',['localhost','127.0.0.1','::1']))
        result['NO_PROXY']=no_proxy;result['no_proxy']=no_proxy
        return result

    def _current_systemd(self, values):
        # Session manager children and already-running programs do not inherit these changes.
        if not shutil.which('systemctl'):return
        setvars=[f'{k}={v}' for k,v in values.items()]
        if setvars:_run(['systemctl','--user','set-environment',*setvars],timeout=8)

    def _gnome_mode(self,mode,d):
        if mode=='direct':
            self._gset('org.gnome.system.proxy','mode','none');return
        port=int(d['auto_port'] if mode=='auto' else d['proxy_port'])
        for part in ('http','https'):
            schema='org.gnome.system.proxy.'+part
            self._gset(schema,'host','127.0.0.1')
            self._gset(schema,'port',str(port))
        # Do not pretend the bridge is a SOCKS endpoint; clear preexisting SOCKS setting
        self._gset('org.gnome.system.proxy.socks','host','')
        self._gset('org.gnome.system.proxy.socks','port','0')
        self._gset('org.gnome.system.proxy','use-same-proxy','false')
        self._gset('org.gnome.system.proxy','ignore-hosts',
                   '['+','.join(repr(x) for x in d['bypass_hosts'])+']')
        self._gset('org.gnome.system.proxy','mode','manual')

    def apply(self,mode):
        if mode not in ('off','direct','auto','proxy'):raise ValueError('Bad global mode')
        d=core.load();previous=d.get('global_mode','off')
        if mode=='off':
            if previous=='off' and not self.backup_file.exists():return
            self.restore();return
        fresh=previous=='off'
        if fresh:self._snapshot()
        try:
            values=self._env_vars(mode,d)
            if self.env_file.is_symlink():raise RuntimeError('Refusing to replace 99-proxypilot.conf symlink')
            if self.env_file.exists() and not self.env_file.read_text().startswith(ENV_MARKER):
                raise RuntimeError('Unexpected file at 99-proxypilot.conf; refusing to overwrite')
            temp=self.env_file.with_suffix('.tmp')
            temp.parent.mkdir(parents=True,exist_ok=True)
            fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w',encoding='utf-8') as stream:
                stream.write(ENV_MARKER+''.join(f'{k}={v}\n' for k,v in values.items()))
                stream.flush();os.fsync(stream.fileno())
            temp.replace(self.env_file)
            self._current_systemd(values)
            self._gnome_mode(mode,d)
            d=core.load();d['global_mode']=mode;core.save(d)
        except Exception:
            if fresh:
                try:self.restore()
                except Exception:pass
            raise

    def restore(self):
        if self.backup_file.is_symlink():raise RuntimeError('Refusing global proxy backup symlink')
        if not self.backup_file.exists():raise RuntimeError('Missing global backup; cannot restore safely')
        if self.env_file.is_symlink():raise RuntimeError('Refusing to remove 99-proxypilot.conf symlink')
        old=json.loads(self.backup_file.read_text())
        for k,v in old.get('gnome',{}).items():
            schema,key=k.split('::',1)
            self._gset(schema,key,v)
        before=old.get('env',{})
        if shutil.which('systemctl'):
            missing=[k for k in PROXY_KEYS if k not in before]
            if missing:_run(['systemctl','--user','unset-environment',*missing])
            if before:self._current_systemd(before)
        if self.env_file.exists():
            if not self.env_file.read_text().startswith(ENV_MARKER):
                raise RuntimeError('Global profile file was changed externally; not deleting it')
            self.env_file.unlink()
        self.backup_file.unlink()
        d=core.load();d['global_mode']='off';core.save(d)
