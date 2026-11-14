#!/usr/bin/env python3
"""ProxyPilot: opt-in per-app proxy manager for Linux desktop and user services."""
import argparse, configparser, copy, hashlib, html, json, os, pathlib, re, secrets, shlex, shutil, signal, socket, socketserver, subprocess, sys, tempfile, threading, time, urllib.parse
import traffic
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOME = pathlib.Path.home()
CONFIG_HOME = pathlib.Path(os.environ.get('XDG_CONFIG_HOME', HOME / '.config'))
DATA_HOME = pathlib.Path(os.environ.get('XDG_DATA_HOME', HOME / '.local' / 'share'))
STATE_HOME = pathlib.Path(os.environ.get('XDG_STATE_HOME', HOME / '.local' / 'state'))
CFG_DIR = CONFIG_HOME / 'proxypilot'
CFG_FILE = CFG_DIR / 'config.json'
APP_DIR = DATA_HOME / 'applications'
USER_UNITS = CONFIG_HOME / 'systemd' / 'user'
MANAGED = '90-proxypilot.conf'
SERVICE_MARKER = '# ProxyPilot managed service override; preserve this marker'
CONFIG_SCHEMA_VERSION=1
DEFAULTS = {'schema_version':CONFIG_SCHEMA_VERSION,'upstream_host':'127.0.0.1','upstream_port':10808,'auto_port':18787,'proxy_port':18789,'panel_port':18788,'app_port_start':21000,'bypass_hosts':['localhost','127.0.0.1','::1'], 'traffic_monitor_enabled':True, 'allow_direct_fallback':True, 'apps':{}, 'services':{}}
lock = threading.RLock()


def load():
    with lock:
        if CFG_DIR.is_symlink():
            raise RuntimeError('Refusing to use config directory symlink')
        CFG_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(CFG_DIR, 0o700)
        if not CFG_FILE.exists():
            d = dict(DEFAULTS)
            d['token'] = secrets.token_urlsafe(32)
            save(d)
        if CFG_FILE.is_symlink():
            raise RuntimeError('Refusing to read config symlink')
        try:
            d = json.loads(CFG_FILE.read_text())
        except Exception as e:
            raise RuntimeError(f'Cannot read config: {e}')
        if not isinstance(d,dict):
            raise RuntimeError('Cannot read config: expected a JSON object')
        schema=int(d.get('schema_version',0) or 0)
        if schema>CONFIG_SCHEMA_VERSION:
            raise RuntimeError(f'Config schema {schema} is newer than supported schema {CONFIG_SCHEMA_VERSION}')
        migrated=schema<CONFIG_SCHEMA_VERSION
        if migrated:
            backup=CFG_DIR/'config.pre-1.0.json'
            if backup.is_symlink():raise RuntimeError('Refusing to replace config backup symlink')
            if not backup.exists():
                fd=os.open(backup,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
                try:
                    os.write(fd,CFG_FILE.read_bytes());os.fsync(fd)
                finally:os.close(fd)
            d['schema_version']=CONFIG_SCHEMA_VERSION
        for k,v in DEFAULTS.items(): d.setdefault(k, copy.deepcopy(v))
        if not isinstance(d.get('allow_direct_fallback'),bool):
            d['allow_direct_fallback']=True
            migrated=True
        if 'token' not in d:
            d['token'] = secrets.token_urlsafe(32); migrated=True
        if migrated:save(d)
        return d


def save(d):
    if CFG_DIR.is_symlink():raise RuntimeError('Refusing to use config directory symlink')
    CFG_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(CFG_DIR,0o700)
    if CFG_FILE.is_symlink():raise RuntimeError('Refusing to replace config symlink')
    d.setdefault('schema_version',CONFIG_SCHEMA_VERSION)
    fd,tmp=tempfile.mkstemp(prefix='.config.',suffix='.tmp',dir=CFG_DIR)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(d,stream,indent=2,ensure_ascii=False)
            stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,CFG_FILE)
    except Exception:
        try:os.unlink(tmp)
        except OSError:pass
        raise


def scan_apps():
    dirs = [APP_DIR,DATA_HOME/'flatpak/exports/share/applications',pathlib.Path('/usr/local/share/applications'),pathlib.Path('/usr/share/applications'),pathlib.Path('/var/lib/flatpak/exports/share/applications'),pathlib.Path('/var/lib/snapd/desktop/applications')]
    out = {}
    for folder in dirs:
        if not folder.exists(): continue
        for p in sorted(folder.glob('*.desktop')):
            appid = p.name
            if appid in out: continue
            try:
                c=configparser.ConfigParser(interpolation=None,strict=False)
                c.optionxform=str
                c.read(p,encoding='utf-8')
                s=c['Desktop Entry']
                if s.get('Type','Application') != 'Application' or s.get('Hidden','false').lower()=='true': continue
                src=s.get('X-ProxyPilot-Source','')
                if src:
                    original=pathlib.Path(src)
                    if not original.is_file(): continue
                    c=configparser.ConfigParser(interpolation=None,strict=False); c.optionxform=str
                    c.read(original,encoding='utf-8'); s=c['Desktop Entry']
                else: original=p
                command=s.get('Exec','').strip()
                if not command: continue
                out[appid]={'id':appid,'name':s.get('Name',appid),'exec':command,'path':str(p),'source':str(original),'managed':bool(src),'hidden':s.get('NoDisplay','false').lower()=='true','icon':s.get('Icon','').strip(),'dbus_activatable':s.get('DBusActivatable','false').strip().lower()=='true','actions':[x for x in s.get('Actions','').split(';') if x]}
            except (OSError, KeyError, configparser.Error): continue
    return sorted(out.values(),key=lambda x:x['name'].casefold())


def service_list():
    try:
        result=subprocess.run(['systemctl','--user','list-unit-files','--type=service','--no-legend','--no-pager'],text=True,capture_output=True,timeout=8)
        names=[row.split()[0] for row in result.stdout.splitlines() if row.split()]
        return sorted(n for n in names if re.fullmatch(r'[\w@.\\-]+\.service',n))
    except Exception: return []


def app_port(appid, d=None):
    """Stable per-app loopback HTTP proxy port, using a persisted allocation table."""
    if not isinstance(appid,str) or len(appid)>200 or not appid.endswith('.desktop') or '/' in appid or '\x00' in appid or '\n' in appid:
        raise ValueError("Invalid desktop application ID")
    with lock:
        cfg=load()
        ports=cfg.setdefault('app_ports', {})
        if appid not in ports:
            used=set(ports.values()) | {int(cfg['auto_port']),int(cfg['proxy_port']),int(cfg['panel_port'])}
            for candidate in range(int(cfg.get('app_port_start',21000)), 29000):
                if candidate not in used:
                    ports[appid]=candidate
                    save(cfg)
                    break
            else: raise RuntimeError('ProxyPilot application port capacity reached')
        return int(ports[appid])


def running_processes(apps=None):
    """Discover processes visible to the current user via /proc; no privileged inspection."""
    apps=apps if apps is not None else scan_apps()
    matched=[]
    candidates=[]
    for app in apps:
        try:
            parts=shlex.split(app['exec'])
            if parts and parts[0]=='env':
                parts=parts[1:]
                while parts and '=' in parts[0] and not parts[0].startswith('-'):
                    parts=parts[1:]
            if parts:
                if pathlib.Path(parts[0]).name in ('flatpak','snap') and len(parts)>2:
                    executable=parts[-1]
                else: executable=parts[0]
                candidates.append((app, pathlib.Path(executable).name.lower()))
        except ValueError:continue
    try: proc_dirs=list(pathlib.Path('/proc').iterdir())
    except OSError:return []
    for folder in proc_dirs:
        if not folder.name.isdigit():continue
        try:
            if folder.stat().st_uid!=os.getuid():continue
            raw=(folder/'cmdline').read_bytes()
            if not raw: continue
            argv=[x.decode('utf-8','replace') for x in raw.split(b'\0') if x]
            if not argv:continue
            exe=pathlib.Path(argv[0]).name.lower()
            try: exe_path=os.readlink(folder/'exe')
            except OSError:exe_path=argv[0]
            matching=[]
            for a,cmd in candidates:
                if not cmd or cmd in ('env','python','python3','bash','sh','flatpak','snap','gio','gtk-launch'):
                    continue
                if exe==cmd or pathlib.Path(exe_path).name.lower()==cmd:
                    matching.append(a)
            # A known app can be mapped by the visible executable. Unmatched processes remain discoverable.
            name=matching[0]['name'] if matching else exe
            appid=matching[0]['id'] if matching else None
            # An actively running process may be using the per-app bridge even if
            # it was started before ProxyPilot opened; inspect its actual environment.
            managed=False
            try:
                env=(folder/'environ').read_bytes()
                if appid:
                    port=load().get('app_ports',{}).get(appid)
                    managed=bool(port and f'127.0.0.1:{port}'.encode() in env)
            except (OSError,PermissionError):pass
            # Some helper processes have the same command name; display them separately.
            matched.append({'pid':int(folder.name),'name':name,'app_id':appid,
                            'command':exe,'managed_live':managed})
        except (OSError,PermissionError,ValueError):continue
    return sorted(matched,key=lambda x:(x['app_id'] is None,x['name'].casefold(),x['pid']))


def application_running(appid):
    return [p for p in running_processes() if p['app_id']==appid]


def activate_app(appid, mode):
    """Persist route mode. Per-app bridge reads this on every NEW connection."""
    if mode not in ('direct','proxy','auto'):raise ValueError('Unsupported mode')
    if appid not in {a['id'] for a in scan_apps()}:raise ValueError('Unknown desktop app')
    app_port(appid)  # Ensure dedicated bridge allocation before persisting the route.
    d=load();d['apps'][appid]=mode;save(d)
    return {'live':any(p['managed_live'] for p in application_running(appid)),
            'running':len(application_running(appid))}


def credentials_env(mode, d, appid=None):
    if appid is not None: port=app_port(appid,d)
    elif mode=='auto': port=d['auto_port']
    elif mode=='proxy': port=d['proxy_port']
    else: return {}
    url=f'http://127.0.0.1:{port}'
    env={k:url for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy')}
    env.update({'NO_PROXY':'localhost,127.0.0.1,::1','no_proxy':'localhost,127.0.0.1,::1'})
    return env


def launch(appid, launch_args=()):
    d=load(); apps={x['id']:x for x in scan_apps()}
    if appid not in apps: raise RuntimeError('Application no longer installed')
    app=apps[appid]; mode=d['apps'].get(appid, 'direct')
    app_port(appid)
    env=os.environ.copy()
    for name in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY','http_proxy','https_proxy','all_proxy','no_proxy'):
        env.pop(name,None)
    env.update(credentials_env(mode,d,appid=appid))
    port=app_port(appid)
    for _ in range(30):
        try:
            with socket.create_connection(('127.0.0.1',port),timeout=.15):break
        except OSError:time.sleep(.1)
    else:raise RuntimeError('ProxyPilot application bridge is not listening; check proxypilot.service')
    raw=shlex.split(app['exec'])
    launch_args=list(launch_args)
    if launch_args and launch_args[0]=='--':launch_args=launch_args[1:]
    field_code=next((v for v in raw if v in ('%f','%F','%u','%U')),None)
    argv=[]
    for v in raw:
        if v==field_code:
            if field_code in ('%F','%U'):
                argv.extend(launch_args)
            elif launch_args:
                argv.append(launch_args[0])
            continue
        if v=='%i':
            if app.get('icon'):argv.extend(('--icon',app['icon']))
            continue
        if v=='%c': v=app['name']
        elif v=='%k': v=app['source']
        else:
            v=re.sub(r'%%','%',v)
            v=re.sub(r'%[fFuUdDnNickvm]','',v)
        if v: argv.append(v)
    if not argv: raise RuntimeError('Empty desktop Exec')
    p=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    return p.pid


def integrate(appid):
    apps={x['id']:x for x in scan_apps()}
    if appid not in apps: raise ValueError('Desktop entry not found')
    a=apps[appid]; original=pathlib.Path(a['source'])
    if a.get('dbus_activatable'):
        raise ValueError('This launcher uses D-Bus activation; ProxyPilot cannot safely route it through Exec yet.')
    if a.get('actions'):
        raise ValueError('This launcher has desktop actions that are not managed by ProxyPilot; refusing a partial integration.')
    if original == APP_DIR/appid and not a['managed']:
        # Explicit opt-in: preserve custom user desktop entries before integration.
        backups=CFG_DIR/'launchers'
        backups.mkdir(parents=True,exist_ok=True,mode=0o700)
        saved=backups/(hashlib.sha256(appid.encode()).hexdigest()+'.desktop')
        if saved.exists(): raise ValueError('Backup already exists; refusing to overwrite')
        shutil.copy2(original,saved)
        original=saved
    dest=APP_DIR/appid
    if dest.is_symlink(): raise ValueError('Refusing to overwrite a symlink')
    APP_DIR.mkdir(parents=True,exist_ok=True)
    lines=original.read_text(encoding='utf-8').splitlines(keepends=True)
    try:exec_args=shlex.split(a['exec'])
    except ValueError as ex:raise ValueError(f'Invalid desktop Exec field: {ex}') from ex
    forward_code=next((v for v in exec_args if v in ('%f','%F','%u','%U')),None)
    launcher=' '.join((_desktop_exec_quote(sys.executable),
                       _desktop_exec_quote(str(pathlib.Path(__file__).resolve())),
                       _desktop_exec_quote('launch'),_desktop_exec_quote(appid)))
    if forward_code:launcher+=' '+forward_code
    out=[]; in_main=False; written_exec=False; written_source=False
    for ln in lines:
        if ln.startswith('['):
            if in_main and not written_source: out.append(f'X-ProxyPilot-Source={original}\n')
            in_main=ln.strip()=='[Desktop Entry]'
        if in_main and ln.startswith('Exec='):
            ln=f'Exec={launcher}\n'; written_exec=True
        if in_main and ln.startswith('X-ProxyPilot-Source='):
            ln=f'X-ProxyPilot-Source={original}\n'; written_source=True
        out.append(ln)
    if in_main and not written_source: out.append(f'X-ProxyPilot-Source={original}\n')
    if not written_exec: raise ValueError('No Exec field')
    data=''.join(out).encode('utf-8')
    fd,tmp=tempfile.mkstemp(prefix=f'.{appid}.',suffix='.tmp',dir=APP_DIR)
    try:
        os.fchmod(fd,0o644)
        with os.fdopen(fd,'wb') as stream:
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,dest)
    except Exception:
        try:os.unlink(tmp)
        except OSError:pass
        raise
    return str(dest)


def _desktop_exec_quote(value):
    """Quote one Exec argument using the Desktop Entry (not shell) grammar."""
    escaped=''.join(('\\'+char) if char in ('\\','"','$','`') else char for char in str(value))
    return '"'+escaped.replace('%','%%')+'"'


def restore_app(appid):
    dest=APP_DIR/appid
    if dest.is_symlink() or not dest.is_file(): raise ValueError('No ProxyPilot launcher to restore')
    c=configparser.ConfigParser(interpolation=None, strict=False); c.optionxform=str
    c.read(dest,encoding='utf-8')
    source=pathlib.Path(c['Desktop Entry'].get('X-ProxyPilot-Source',''))
    if not source.is_file() or not source.is_absolute():raise ValueError('Not a valid ProxyPilot-managed launcher')
    backup_dir=CFG_DIR/'launchers'
    if source.parent==backup_dir and source.name==hashlib.sha256(appid.encode()).hexdigest()+'.desktop':
        shutil.copy2(source,dest);source.unlink()
    else: dest.unlink()


def service_override(unit,mode):
    if unit not in service_list(): raise ValueError('Unknown user service')
    if not re.fullmatch(r'[\w@.\\-]+\.service',unit): raise ValueError('Invalid service name')
    if mode not in ('off','direct','auto','proxy'): raise ValueError('Unsupported service route')
    d=load(); target=USER_UNITS/(unit+'.d')
    if target.is_symlink(): raise ValueError('Refusing service drop-in directory symlink')
    target.mkdir(parents=True,exist_ok=True)
    path=target/MANAGED
    if path.is_symlink(): raise ValueError('Refusing service drop-in symlink')
    old=target/'no-proxy.conf'; backup=target/'no-proxy.conf.proxypilot-backup'
    if backup.is_symlink(): raise ValueError('Refusing service override backup symlink')
    clear=' '.join(('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy','NO_PROXY','no_proxy'))
    prior_mode=d.get('services',{}).get(unit)
    previous=path.read_bytes() if path.exists() else None
    if previous is not None:
        recognized=previous.startswith((SERVICE_MARKER+'\n').encode())
        if not recognized and prior_mode in ('direct','auto','proxy'):
            recognized=previous==legacy_for(prior_mode,clear,d)
        if not recognized:
            raise ValueError(f'Unknown file at {path}; refusing to replace or remove it')
    move_conflict=False
    if mode in ('proxy','auto') and old.exists():
        if backup.exists():
            raise ValueError('A saved UnsetEnvironment override already exists; resolve it manually before enabling proxy')
        if old.is_symlink() or not old.is_file(): raise ValueError('Refusing unsafe no-proxy.conf path')
        if 'UnsetEnvironment=' not in old.read_text(): raise ValueError('Unknown no-proxy.conf; not touching it')
        move_conflict=True
    restore_conflict=mode=='off' and backup.exists() and not old.exists()
    if restore_conflict and (backup.is_symlink() or not backup.is_file()):
        raise ValueError('Refusing unsafe saved no-proxy.conf path')
    if move_conflict: old.rename(backup)
    content=None if mode=='off' else SERVICE_MARKER.encode()+b'\n'+legacy_for(mode,clear,d)
    changed=move_conflict
    try:
        if content is None:
            path.unlink(missing_ok=True)
        else:
            fd,tmp=tempfile.mkstemp(prefix='.90-proxypilot.',suffix='.tmp',dir=target)
            try:
                os.fchmod(fd,0o644)
                with os.fdopen(fd,'wb') as stream:
                    stream.write(content);stream.flush();os.fsync(stream.fileno())
                os.replace(tmp,path)
            except Exception:
                try: os.unlink(tmp)
                except OSError: pass
                raise
        changed=True
        if restore_conflict: backup.rename(old)
        subprocess.run(['systemctl','--user','daemon-reload'],check=True,timeout=12,
                       capture_output=True,text=True)
        result=subprocess.run(['systemctl','--user','restart',unit],capture_output=True,text=True,timeout=80)
        if result.returncode: raise RuntimeError(result.stderr.strip()[:350] or 'Service restart failed')
        d.setdefault('services',{})
        if mode=='off': d['services'].pop(unit,None)
        else: d['services'][unit]=mode
        save(d)
    except Exception as exc:
        if changed:
            try:
                if previous is None: path.unlink(missing_ok=True)
                else:
                    fd,tmp=tempfile.mkstemp(prefix='.90-proxypilot.rollback.',suffix='.tmp',dir=target)
                    os.fchmod(fd,0o644)
                    with os.fdopen(fd,'wb') as stream:
                        stream.write(previous);stream.flush();os.fsync(stream.fileno())
                    os.replace(tmp,path)
                if move_conflict and backup.exists() and not old.exists(): backup.rename(old)
                if restore_conflict and old.exists() and not backup.exists(): old.rename(backup)
                subprocess.run(['systemctl','--user','daemon-reload'],check=False,
                               capture_output=True,text=True,timeout=12)
                subprocess.run(['systemctl','--user','restart',unit],check=False,
                               capture_output=True,text=True,timeout=80)
            except Exception as rollback_error:
                raise RuntimeError(f'{exc}; rollback also failed: {rollback_error}') from exc
        raise
    return {'mode':mode,'unit':unit,'requires_service_restart':True,'applied':True}


def legacy_for(mode,clear,d):
    content='[Service]\n'
    if mode=='direct': content+=f'UnsetEnvironment={clear}\n'
    elif mode in ('auto','proxy'):
        for k,v in credentials_env(mode,d).items(): content+=f'Environment="{k}={v}"\n'
    return content.encode()


def connect_upstream(host,port,d):
    s=socket.create_connection((d['upstream_host'],int(d['upstream_port'])),timeout=2.5)
    try:
        s.settimeout(5)
        s.sendall(b'\x05\x01\x00')
        if recv_exact(s,2)!=b'\x05\x00': raise OSError('SOCKS5 method rejected')
        import ipaddress
        try:
            ip=ipaddress.ip_address(host)
        except ValueError:
            try: addr=host.encode('idna')
            except UnicodeError: raise OSError('Invalid host')
            if not addr or len(addr)>255: raise OSError('Domain too long')
            address=b'\x03'+bytes((len(addr),))+addr
        else:
            atyp=b'\x01' if ip.version==4 else b'\x04'
            address=atyp+ip.packed
        req=b'\x05\x01\x00'+address+int(port).to_bytes(2,'big')
        s.sendall(req)
        rep=recv_exact(s,4)
        if rep[1]!=0: raise OSError(f'SOCKS5 error {rep[1]}')
        at=rep[3]
        if at==1: recv_exact(s,4)
        elif at==4: recv_exact(s,16)
        elif at==3: recv_exact(s,recv_exact(s,1)[0])
        else: raise OSError('Bad SOCKS5 reply')
        recv_exact(s,2); s.settimeout(None)
        return s
    except Exception:
        s.close();raise


def recv_exact(sock,n):
    buf=b''
    while len(buf)<n:
        part=sock.recv(n-len(buf))
        if not part: raise ConnectionError('Connection closed')
        buf+=part
    return buf


def bypass(host,d):
    h=host.lower().rstrip('.')
    return any(h==x.lower().lstrip('.').rstrip('.') or (x.startswith('.') and h.endswith(x.lower())) for x in d.get('bypass_hosts',[]))


def destination_with_route(host, port, mode, d, *, force_proxy=False):
    """Return (connected socket, actual path). Logs use the chosen *actual* path."""
    # Explicit proxy clients such as SSH/SFTP can opt out of user bypass rules.
    # In this mode a bypass match may never create a direct socket.
    if bypass(host,d) and not force_proxy:
        return socket.create_connection((host,port),timeout=7), 'bypass'
    if mode == 'direct' and not force_proxy:
        return socket.create_connection((host,port),timeout=7), 'direct'
    if mode == 'proxy' or force_proxy:
        return connect_upstream(host,port,d), 'proxy'
    try:
        return connect_upstream(host,port,d), 'proxy'
    except (OSError, ConnectionError):
        if not d.get('allow_direct_fallback', True):
            raise
        return socket.create_connection((host,port),timeout=7), 'fallback'


def destination(host, port, mode, d):
    """Backward-compatible socket-only helper from ProxyPilot 0.4."""
    sock, _ = destination_with_route(host, port, mode, d)
    return sock


class ProxyHandler(socketserver.StreamRequestHandler):
    rbufsize = 0

    def handle(self):
        self.connection.settimeout(20)
        started = time.monotonic()
        cid = traffic.new_id()
        # Exact app identity is known for dedicated app ports. For a global
        # port, resolve process ownership from its loopback TCP socket.
        peer_ip, peer_port = self.client_address[:2]
        listen_port = self.server.server_address[1]
        pid, pname = traffic.identify_caller(peer_ip, peer_port, listen_port)
        appid = getattr(self.server, 'appid', None)
        cfg = load()
        monitor = cfg.get('traffic_monitor_enabled', True)
        mode = cfg['apps'].get(appid, 'direct') if appid else ('auto' if listen_port == int(cfg['auto_port']) else 'proxy')
        scope = 'app' if appid else 'shared-bridge'
        context = {'id':cid,'pid':pid,'process':pname,'app_id':appid,
                   'scope':scope,'mode':mode}
        opened = False
        host = ''
        port = 0
        remote = None
        try:
            first = self.rfile.readline(65537)
            if not first or len(first)>65536: return
            parts = first.decode('latin1').strip().split(' ',2)
            if len(parts) != 3:return
            method, uri, proto = parts
            if proto not in ('HTTP/1.0','HTTP/1.1'):return
            headers=[]
            for _ in range(100):
                ln = self.rfile.readline(65537)
                if len(ln)>65536:return
                if ln in (b'\r\n',b'\n',b''):break
                headers.append(ln)
            else:return
            force_values=[]
            for header in headers:
                name,sep,value=header.partition(b':')
                if sep and name.strip().lower()==b'x-proxypilot-force-proxy':
                    force_values.append(value.strip().lower())
            if len(force_values)>1 or (force_values and force_values[0]!=b'1'):
                self.connection.sendall(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                return
            force_proxy=bool(force_values)
            if force_proxy and (method.upper()!='CONNECT' or
                                listen_port!=int(cfg['proxy_port'])):
                self.connection.sendall(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                return
            if method.upper() == 'CONNECT':
                # CONNECT takes host:port (or [IPv6]:port).
                authority = urllib.parse.urlsplit('//'+uri)
                host = authority.hostname
                port = authority.port
                if not host or port is None or authority.username is not None:return
                initial = None
            else:
                p = urllib.parse.urlsplit(uri)
                if p.scheme != 'http' or not p.hostname:return
                host = p.hostname
                port = p.port or 80
                target = urllib.parse.urlunsplit(('', '', p.path or '/',p.query,''))
                initial = f'{method} {target} {proto}\r\n'.encode('latin1')
                # Forward the normal HTTP request without proxy credentials.
                initial += b''.join(x for x in headers if not x.lower().startswith((b'proxy-connection:',b'proxy-authorization:')))+b'\r\n'
            if not (1<=port<=65535):return
            remote, route = destination_with_route(host,port,mode,cfg,force_proxy=force_proxy)
            if monitor:
                traffic.record(event='open', **context, host=host,port=port,route=route,status='connected')
            opened = True
            if initial is None:
                self.connection.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            else:
                remote.sendall(initial)
            up, down = self.relay(remote)
            if initial is not None: up += len(initial)
            if monitor:
                traffic.record(event='close', id=cid, bytes_up=up,bytes_down=down,
                               duration_ms=int((time.monotonic()-started)*1000),status='closed')
        except Exception as e:
            if monitor:
                traffic.record(event='error' if not opened else 'close', **(context if not opened else {'id': cid}),
                               host=host if not opened else None,port=port if not opened else None,
                               status='failed',error=type(e).__name__)
            if not opened:
                try:self.connection.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                except OSError:pass
        finally:
            if remote is not None:remote.close()

    def relay(self,other):
        """Bidirectional TCP relay. Counts application bytes, never stores content."""
        import selectors
        self.connection.setblocking(False)
        other.setblocking(False)
        counts=[0,0]
        readable={self.connection,other}
        with selectors.DefaultSelector() as sel:
            sel.register(self.connection,selectors.EVENT_READ,(other,0))
            sel.register(other,selectors.EVENT_READ,(self.connection,1))
            while True:
                events=sel.select(timeout=120)
                if not events:return tuple(counts)
                for key,_ in events:
                    try:data=key.fileobj.recv(65536)
                    except (OSError,BlockingIOError):return tuple(counts)
                    dst,index=key.data
                    if not data:
                        # TCP half-close: forward EOF in this direction but
                        # continue relaying the response in the other direction.
                        try:sel.unregister(key.fileobj)
                        except (KeyError,ValueError):pass
                        readable.discard(key.fileobj)
                        try:dst.shutdown(socket.SHUT_WR)
                        except OSError:pass
                        if not readable:return tuple(counts)
                        continue
                    counts[index]+=len(data)
                    try:
                        dst.setblocking(True)
                        dst.settimeout(30)
                        dst.sendall(data)
                    except OSError:return tuple(counts)
                    finally:
                        dst.settimeout(None)
                        dst.setblocking(False)


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True


def upstream_ok(d):
    """Check only the configured SOCKS listener; do not probe a public host."""
    s=None
    try:
        s=socket.create_connection((d['upstream_host'],int(d['upstream_port'])),timeout=1.5)
        s.settimeout(1.5)
        s.sendall(b'\x05\x01\x00')
        return recv_exact(s,2)==b'\x05\x00'
    except Exception:return False
    finally:
        if s is not None:s.close()


def serve_app_proxy(appid):
    port=app_port(appid)
    server=ProxyServer(('127.0.0.1',port),ProxyHandler)
    server.appid=appid
    try: server.serve_forever()
    finally:server.server_close()


def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('serve');lp=sub.add_parser('launch');lp.add_argument('desktop_id');lp.add_argument('launch_args',nargs=argparse.REMAINDER)
    ap=sub.add_parser('app-proxy');ap.add_argument('desktop_id')
    args=p.parse_args()
    if args.command=='launch':launch(args.desktop_id,args.launch_args);return
    if args.command=='app-proxy':serve_app_proxy(args.desktop_id);return
    d=load();servers=[]
    for port in (d['auto_port'],d['proxy_port']):
        server=ProxyServer(('127.0.0.1',int(port)),ProxyHandler)
        servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start()
    # Each managed application's bridge runs on a stable port. New entries are
    # discovered while the service is running, enabling route changes in-place.
    app_servers={}
    def sync_app_servers():
        while True:
            try:
                cfg=load()
                for aid in list(cfg.get('app_ports',{})):
                    if aid in app_servers:continue
                    port=int(cfg['app_ports'][aid])
                    try:
                        server=ProxyServer(('127.0.0.1',port),ProxyHandler)
                        server.appid=aid
                        app_servers[aid]=server
                        threading.Thread(target=server.serve_forever,daemon=True).start()
                    except OSError as ex: print(f'Cannot bind app proxy {aid}: {ex}',file=sys.stderr,flush=True)
            except Exception as ex:print(f'Proxy synchronization failed: {ex}',file=sys.stderr,flush=True)
            time.sleep(2)
    threading.Thread(target=sync_app_servers,daemon=True).start()
    print(f'ProxyPilot bridge listening on 127.0.0.1:{d["auto_port"]} (auto), {d["proxy_port"]} (proxy)',flush=True)
    try:
        while True:time.sleep(86400)
    except KeyboardInterrupt:pass
    finally:
        for s in servers + list(app_servers.values()):s.shutdown();s.server_close()
if __name__=='__main__':main()
