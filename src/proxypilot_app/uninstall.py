"""Remove only files owned by a user-local ProxyPilot install."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


HOME=Path.home()
CONFIG_HOME=Path(os.environ.get("XDG_CONFIG_HOME",HOME/".config")).expanduser()
DATA_HOME=Path(os.environ.get("XDG_DATA_HOME",HOME/".local/share")).expanduser()
DEST=Path(os.environ.get("PROXYPILOT_DEST",DATA_HOME/"proxypilot")).expanduser()
BIN=Path(os.environ.get("PROXYPILOT_BIN_DIR",HOME/".local/bin")).expanduser()
UNIT=Path(os.environ.get("PROXYPILOT_SYSTEMD_DIR",CONFIG_HOME/"systemd/user")).expanduser()/"proxypilot.service"
APP=Path(os.environ.get("PROXYPILOT_APP_DIR",DATA_HOME/"applications")).expanduser()/"proxypilot.desktop"
ICON=DATA_HOME/"icons/hicolor/scalable/apps/proxypilot.svg"
MODULES=("proxypilot.py","manager.py","desktop.py","appicons.py","traffic.py",
         "socketwatch.py","netobserve.py","appstatus.py","checkui.py","diagnostics.py")
PACKAGE=("__init__.py","__main__.py","api.py","cli.py","gtk_ui.py","uninstall.py")


def _manifest() -> dict[str,str]:
    path=DEST/".proxypilot-manifest.json"
    if not path.exists():return {}
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("Refusing unsafe ProxyPilot ownership manifest")
    try:data=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,ValueError) as exc:
        raise RuntimeError("Cannot verify installed files; ownership manifest is invalid") from exc
    if data.get("owner")!="ProxyPilot" or data.get("format")!=1 or not isinstance(data.get("files"),dict):
        raise RuntimeError("Cannot verify installed files; ownership manifest is not recognized")
    return data["files"]


def _owned(path: Path, kind: str, manifest: dict[str,str]) -> bool:
    if path.is_symlink():
        raise RuntimeError(f"Refusing to follow or remove symlink: {path}")
    if not path.exists():
        return False
    if not path.is_file():
        raise RuntimeError(f"Refusing to remove non-file: {path}")
    content=path.read_bytes()
    text=content.decode("utf-8","replace")
    if kind=="manifest":
        return '"owner": "ProxyPilot"' in text and '"format": 1' in text
    expected=manifest.get(str(path))
    matches_manifest=bool(expected and hashlib.sha256(content).hexdigest()==expected)
    if kind=="wrapper":return "ProxyPilot-managed launcher" in text
    if kind=="unit":return "ProxyPilot" in text and "proxypilot.py" in text
    if kind=="desktop":return "Name=ProxyPilot" in text and "Exec=" in text
    if kind=="code":
        if matches_manifest or "ProxyPilot" in text:return True
        root=Path(__file__).resolve().parents[2]
        candidates=(() if not (root/"scripts/install.py").is_file() else
                    (root/path.name,root/"src/proxypilot_app"/path.name,
                     root/"proxypilot-icon.svg"))
        return any(candidate.is_file() and candidate.read_bytes()==content for candidate in candidates)
    if kind=="icon":
        if matches_manifest:return True
        root=Path(__file__).resolve().parents[2]
        source=root/"proxypilot-icon.svg"
        return (root/"scripts/install.py").is_file() and source.is_file() and source.read_bytes()==content
    return False


def _safety_issues() -> list[str]:
    issues=[]
    config=CONFIG_HOME/"proxypilot/config.json"
    backup=config.parent/"global-backup.json"
    global_mode="off"
    if config.is_symlink() or backup.is_symlink():
        return ["Refusing to inspect proxy configuration or backup symlink during uninstall."]
    if config.is_file():
        try:data=json.loads(config.read_text(encoding="utf-8"))
        except (OSError,ValueError) as exc:
            return [f"Cannot inspect settings safely: {type(exc).__name__}"]
        global_mode=data.get("global_mode","off")
    if global_mode!="off" or backup.exists():
        issues.append("A ProxyPilot global proxy profile or its restore backup is active; restore it in ProxyPilot first.")
    apps=DATA_HOME/"applications"
    if apps.is_dir():
        for entry in apps.glob("*.desktop"):
            try:text=entry.read_text(encoding="utf-8",errors="replace")
            except OSError:continue
            if "X-ProxyPilot-Source=" in text and "proxypilot.py" in text:
                issues.append(f"Restore the managed application launcher before uninstalling: {entry.name}")
    units=CONFIG_HOME/"systemd/user"
    if units.is_dir():
        for dropin in units.glob("*.service.d/90-proxypilot.conf"):
            try:text=dropin.read_text(encoding="utf-8",errors="replace")
            except OSError:continue
            issues.append(f"Remove or restore the ProxyPilot service override first: {dropin.name}")
    return issues


def _targets() -> list[tuple[Path,str]]:
    result=[(DEST/name,"code") for name in MODULES]
    result.extend((DEST/"src/proxypilot_app"/name,"code") for name in PACKAGE)
    result.extend(((DEST/"proxypilot-icon.svg","icon"),
                   (DEST/".proxypilot-manifest.json","manifest"),
                   (BIN/"proxypilot","wrapper"),(BIN/"proxypilot-gui","wrapper"),
                   (BIN/"proxypilot-uninstall","wrapper"),(UNIT,"unit"),
                   (APP,"desktop"),(ICON,"icon")))
    return result


def main(argv: list[str] | None=None) -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run",action="store_true",help="Show the removal plan without changing files")
    parser.add_argument("--yes",action="store_true",help="Confirm removal of ProxyPilot-owned files")
    args=parser.parse_args(argv)
    try:
        if DEST.is_symlink():raise RuntimeError(f"Refusing install directory symlink: {DEST}")
        issues=_safety_issues()
        if issues:
            print("Uninstall stopped; restore these managed settings first:",file=sys.stderr)
            for issue in issues:print(f"- {issue}",file=sys.stderr)
            return 2
        manifest=_manifest()
        files=[(path,kind) for path,kind in _targets() if _owned(path,kind,manifest)]
        print("ProxyPilot user-install removal plan:")
        for path,_ in files:print(f"  remove {path}")
        print("  preserve configuration, traffic history, and backups")
        print("  preserve unrelated applications, services, proxy settings, and environment files")
        if args.dry_run:return 0
        if not args.yes:
            if not sys.stdin.isatty():
                raise RuntimeError("Use --yes for non-interactive removal.")
            answer=input("Remove the listed ProxyPilot files and stop its user service? [y/N] ").strip().casefold()
            if answer not in ("y","yes"):
                print("Uninstall cancelled.");return 1
        if UNIT.exists():
            probe=subprocess.run(["systemctl","--user","show-environment"],capture_output=True,text=True,timeout=10)
            if probe.returncode:
                raise RuntimeError("The systemd user manager is unavailable; no files were removed.")
            subprocess.run(["systemctl","--user","disable","--now","proxypilot.service"],
                           check=True,capture_output=True,text=True,timeout=30)
            subprocess.run(["systemctl","--user","daemon-reload"],check=True,
                           capture_output=True,text=True,timeout=15)
        for path,_ in files:
            path.unlink()
        for directory in (DEST/"src/proxypilot_app",DEST,BIN,UNIT.parent,APP.parent,ICON.parent):
            try:directory.rmdir()
            except OSError:pass
        print("ProxyPilot code and menu entry removed. Settings and backups remain.")
        return 0
    except (OSError,RuntimeError,subprocess.SubprocessError) as exc:
        print(f"uninstall: {type(exc).__name__}: {exc}",file=sys.stderr)
        return 2


if __name__=="__main__":raise SystemExit(main())
