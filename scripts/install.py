#!/usr/bin/env python3
"""Install ProxyPilot into the current user's XDG directories."""
from __future__ import annotations

import argparse
import configparser
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT=Path(__file__).resolve().parents[1]
PY_MODULES=("proxypilot.py","manager.py","desktop.py","appicons.py","traffic.py",
            "socketwatch.py","netobserve.py","appstatus.py","checkui.py","diagnostics.py")
PACKAGE_FILES=tuple((Path("src/proxypilot_app")/name) for name in
                    ("__init__.py","__main__.py","api.py","cli.py","gtk_ui.py",
                     "updates.py","uninstall.py","remote_access.py","remote_ui.py"))


def desktop_quote(value: str) -> str:
    escaped=str(value)
    for char in ("\\",'"',"$","`"):
        escaped=escaped.replace(char,"\\"+char)
    return '"'+escaped.replace("%","%%")+'"'


def systemd_quote(value: str) -> str:
    escaped=str(value).replace("\\","\\\\").replace('"','\\"').replace("%","%%")
    return '"'+escaped+'"'


def systemd_path(value: str | Path) -> str:
    """Escape a path value for non-shell systemd directives such as WorkingDirectory."""
    return (str(value).replace("\\", "\\x5c").replace('"', "\\x22")
            .replace("\n", "\\x0a").replace("\r", "\\x0d").replace("%", "%%"))


def atomic_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.is_symlink():raise RuntimeError(f"Refusing to replace symlink: {path}")
    fd,tmp=tempfile.mkstemp(prefix=f".{path.name}.",suffix=".tmp",dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,"wb") as stream:
            stream.write(content);stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
    except Exception:
        try:os.unlink(tmp)
        except OSError:pass
        raise


def safe_dir(path: Path) -> None:
    path.mkdir(parents=True,exist_ok=True)
    if path.is_symlink() or not path.is_dir():raise RuntimeError(f"Unsafe destination directory: {path}")


def existing_owned(path: Path, kind: str) -> bool:
    if not path.exists():return False
    if path.is_symlink() or not path.is_file():raise RuntimeError(f"Refusing unknown destination: {path}")
    text=path.read_text(errors="replace")
    if kind=="unit" and "ProxyPilot" in text and "proxypilot.py" in text:return True
    if kind=="desktop" and "Name=ProxyPilot" in text and "Exec=" in text:return True
    if kind=="wrapper" and "ProxyPilot-managed launcher" in text:return True
    if kind=="manifest" and '"owner": "ProxyPilot"' in text:return True
    if kind=="code" and "ProxyPilot" in text:return True
    if kind=="code":
        # Two original 0.x modules had no brand string. Accept only a byte-for-byte
        # match with the reviewed source tree so an upgrade can migrate that install.
        candidates=(ROOT/path.name,ROOT/"src/proxypilot_app"/path.name,
                    ROOT/"proxypilot-icon.svg")
        try:content=path.read_bytes()
        except OSError:return False
        if any(candidate.is_file() and candidate.read_bytes()==content for candidate in candidates):
            return True
        # The original Tk icon helper predates XDG support and therefore differs
        # from the current source. Its stable module/class/method shape identifies
        # that specific ProxyPilot-owned file; the installer still backs it up
        # before replacement. Do not generalize this exception to arbitrary code.
        if (path.name=="appicons.py" and
                '"""Native desktop-entry icon resolver for Tk.' in text and
                "class AppIcons:" in text and "def _dirs():" in text and
                "def find(self, icon_name):" in text and
                "def load(self, icon_name):" in text and "tk.PhotoImage" in text):
            return True
    raise RuntimeError(f"Refusing to replace unrecognized file: {path}")


def user_paths() -> dict[str,Path]:
    home=Path.home()
    config=Path(os.environ.get("XDG_CONFIG_HOME",home/".config")).expanduser()
    data=Path(os.environ.get("XDG_DATA_HOME",home/".local/share")).expanduser()
    state=Path(os.environ.get("XDG_STATE_HOME",home/".local/state")).expanduser()
    return {"home":home,"config":config,"data":data,"state":state,
            "dest":Path(os.environ.get("PROXYPILOT_DEST",data/"proxypilot")).expanduser(),
            "bin":Path(os.environ.get("PROXYPILOT_BIN_DIR",home/".local/bin")).expanduser(),
            "units":Path(os.environ.get("PROXYPILOT_SYSTEMD_DIR",config/"systemd/user")).expanduser(),
            "apps":Path(os.environ.get("PROXYPILOT_APP_DIR",data/"applications")).expanduser(),
            "icons":data/"icons/hicolor/scalable/apps"}


def wrapper(python: str, dest: Path, gui: bool, module: str | None=None) -> bytes:
    module=module or ("proxypilot_app.gtk_ui" if gui else "proxypilot_app.cli")
    source=("#!/usr/bin/env python3\n# ProxyPilot-managed launcher\n"
            "import sys\n"
            f"sys.path.insert(0, {str(dest)!r})\n"
            f"sys.path.insert(0, {str(dest/'src')!r})\n"
            f"from {module} import main\n"
            "raise SystemExit(main())\n")
    return source.encode()


def generated_files(paths: dict[str,Path], python: str, cli_only: bool) -> dict[Path,tuple[bytes,int,str]]:
    dest=paths["dest"]
    files={}
    for name in PY_MODULES:
        files[dest/name]=((ROOT/name).read_bytes(),0o755,"code")
    for rel in PACKAGE_FILES:
        target=dest/rel
        files[target]=((ROOT/rel).read_bytes(),0o644,"code")
    files[dest/"proxypilot-icon.svg"]=((ROOT/"proxypilot-icon.svg").read_bytes(),0o644,"code")
    files[paths["bin"]/"proxypilot"]=(wrapper(python,dest,False),0o755,"wrapper")
    files[paths["bin"]/"proxypilot-uninstall"]=(
        wrapper(python,dest,False,"proxypilot_app.uninstall"),0o755,"wrapper")
    unit=("[Unit]\nDescription=ProxyPilot local HTTP/SOCKS bridge and traffic monitor\n"
          "After=network.target\n\n[Service]\nType=simple\n"
          f"ExecStart={systemd_quote(python)} {systemd_quote(dest/'proxypilot.py')} serve\n"
          f"WorkingDirectory={systemd_path(dest)}\n"
          f"Environment=XDG_CONFIG_HOME={systemd_quote(os.environ.get('XDG_CONFIG_HOME',str(paths['home']/'.config')))}\n"
          f"Environment=XDG_DATA_HOME={systemd_quote(os.environ.get('XDG_DATA_HOME',str(paths['home']/'.local/share')))}\n"
          f"Environment=XDG_STATE_HOME={systemd_quote(os.environ.get('XDG_STATE_HOME',str(paths['home']/'.local/state')))}\n"
          "Restart=on-failure\nRestartSec=3\nNoNewPrivileges=true\n\n"
          "[Install]\nWantedBy=default.target\n")
    files[paths["units"]/"proxypilot.service"]=(unit.encode(),0o644,"unit")
    if not cli_only:
        files[paths["bin"]/"proxypilot-gui"]=(wrapper(python,dest,True),0o755,"wrapper")
        icon=paths["icons"]/"proxypilot.svg"
        desktop=("[Desktop Entry]\nType=Application\nVersion=1.0\nName=ProxyPilot\n"
                 "GenericName=Proxy and Process Manager\nComment=Inspect and manage proxy-aware Linux applications\n"
                 f"Exec={desktop_quote(str(paths['bin']/'proxypilot-gui'))}\n"
                 f"TryExec={desktop_quote(str(paths['bin']/'proxypilot-gui'))}\n"
                 f"Icon={icon}\nTerminal=false\nStartupNotify=true\n"
                 "Categories=Network;\nKeywords=Proxy;Network;SOCKS5;\n")
        files[paths["apps"]/"proxypilot.desktop"]=(desktop.encode(),0o644,"desktop")
        files[icon]=((ROOT/"proxypilot-icon.svg").read_bytes(),0o644,"code")
    manifest={"owner":"ProxyPilot","format":1,
              "files":{str(path):hashlib.sha256(content).hexdigest()
                       for path,(content,_,_) in files.items()}}
    files[dest/".proxypilot-manifest.json"]=(
        (json.dumps(manifest,sort_keys=True,indent=2)+"\n").encode(),0o600,"manifest")
    return files


def call_systemctl(systemctl: str, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    result=subprocess.run([systemctl,"--user",*args],capture_output=True,text=True,timeout=20)
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip()[:350] or "systemctl --user failed")
    return result


def optional_ssh_runtime_gaps(python: str) -> list[str]:
    gaps=[]
    paramiko=subprocess.run([python,"-c","import paramiko"],capture_output=True,text=True)
    if paramiko.returncode:
        gaps.append("SSH/SFTP needs Paramiko (python3-paramiko on Ubuntu/Debian).")
    vte=subprocess.run([python,"-c",
        "import gi; gi.require_version('Vte','3.91'); from gi.repository import Vte"],
        capture_output=True,text=True)
    if vte.returncode:
        gaps.append("The embedded SSH terminal needs GTK 4 VTE (gir1.2-vte-3.91); SFTP remains available without it.")
    return gaps


def install(args: argparse.Namespace) -> int:
    paths=user_paths();python=str(Path(sys.executable).resolve())
    ssh_runtime_gaps=[]
    if not args.cli_only:
        gtk=subprocess.run([python,"-c","import gi; gi.require_version('Gtk','4.0'); from gi.repository import Gtk"],
                           capture_output=True,text=True)
        if gtk.returncode:
            raise RuntimeError("GTK 4 bindings are unavailable for this Python. Install python3-gi and gir1.2-gtk-4.0, or use --cli-only.")
        ssh_runtime_gaps=optional_ssh_runtime_gaps(python)
    files=generated_files(paths,python,args.cli_only)
    collisions=[]
    for path,(_,_,kind) in files.items():
        if path.exists() and existing_owned(path,kind):collisions.append(path)
        elif path.exists():existing_owned(path,kind)  # raises for unknown files
        if path.is_symlink():raise RuntimeError(f"Refusing symlink destination: {path}")
    systemctl=os.environ.get("PROXYPILOT_SYSTEMCTL","systemctl")
    if not args.no_start and not args.dry_run:
        probe=call_systemctl(systemctl,"show-environment",check=False)
        if probe.returncode:
            raise RuntimeError("The systemd user manager is unavailable in this session. Use --no-start to stage files, then enable the service from a session with a user bus.")
    print("Install plan:")
    print(f"  code: {paths['dest']}")
    print(f"  CLI: {paths['bin']/'proxypilot'}")
    print(f"  user unit: {paths['units']/'proxypilot.service'}")
    if not args.cli_only:print(f"  desktop entry: {paths['apps']/'proxypilot.desktop'}")
    print("  existing ProxyPilot-owned files will be backed up; unrelated app and proxy settings are untouched")
    for gap in ssh_runtime_gaps:print(f"  feature dependency: {gap}")
    if args.dry_run:return 0
    if not args.yes and not args.no_start:
        if not sys.stdin.isatty():raise RuntimeError("Use --yes for a non-interactive installation.")
        answer=input("Install ProxyPilot and start/restart only its user service? [y/N] ").strip().casefold()
        if answer not in ("y","yes"):print("Installation cancelled.");return 1
    for directory in {p.parent for p in files}:safe_dir(directory)
    stamp=dt.datetime.now().strftime("%Y%m%d-%H%M%S")+f"-{os.getpid()}"
    backup=paths["data"]/"proxypilot-backups"/stamp
    old={}
    for path in files:
        if path.exists():
            rel=str(path).lstrip("/").replace(":","_")
            backup_path=backup/rel
            backup_path.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(path,backup_path)
            old[path]=backup_path
    if old:safe_dir(backup);print(f"Backup: {backup}")
    installed=[]
    try:
        for path,(content,mode,_) in files.items():
            atomic_write(path,content,mode);installed.append(path)
        if args.no_start:
            print("Files staged. Service was not enabled or restarted (--no-start).")
            return 0
        call_systemctl(systemctl,"daemon-reload")
        active=call_systemctl(systemctl,"is-active","--quiet","proxypilot.service",check=False).returncode==0
        if active:call_systemctl(systemctl,"restart","proxypilot.service")
        else:call_systemctl(systemctl,"enable","--now","proxypilot.service")
        result=call_systemctl(systemctl,"is-active","--quiet","proxypilot.service",check=False)
        if result.returncode:raise RuntimeError("ProxyPilot service did not become active")
    except Exception:
        for path in reversed(installed):
            backup_path=old.get(path)
            if backup_path and backup_path.exists():shutil.copy2(backup_path,path)
            else:
                try:path.unlink()
                except OSError:pass
        try:call_systemctl(systemctl,"daemon-reload",check=False)
        except Exception:pass
        raise
    linger=subprocess.run(["loginctl","show-user",str(os.getuid()),"-p","Linger"],
                          capture_output=True,text=True)
    if linger.returncode or "Linger=yes" not in linger.stdout:
        print("Notice: linger is not enabled or could not be checked; the user service may stop after logout.")
    print("ProxyPilot installed. Unrelated desktop apps, user services, proxy settings and environment files were not changed.")
    print("For headless administration, add ~/.local/bin to PATH and run: proxypilot status")
    print("AUTO direct fallback remains a configurable policy; use Proxy Only to fail closed through the bridge.")
    for gap in ssh_runtime_gaps:print(f"Feature dependency: {gap}")
    return 0


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run",action="store_true",help="Show destinations and checks without writing files")
    parser.add_argument("--yes",action="store_true",help="Confirm service start/restart in non-interactive use")
    parser.add_argument("--no-start",action="store_true",help="Install code and units without calling systemd")
    parser.add_argument("--cli-only",action="store_true",help="Skip GTK GUI and desktop entry")
    args=parser.parse_args()
    try:return install(args)
    except (OSError,RuntimeError,ValueError,subprocess.TimeoutExpired) as exc:
        print(f"install: {type(exc).__name__}: {exc}",file=sys.stderr)
        return 2


if __name__=="__main__":raise SystemExit(main())
