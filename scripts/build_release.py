#!/usr/bin/env python3
"""Create source archives and a Debian package without installing them."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile


ROOT=Path(__file__).resolve().parents[1]
EXCLUDE={".git","__pycache__",".pytest_cache",".mypy_cache",".ruff_cache",
         ".venv","venv","build","dist","*.egg-info"}
PRIVATE_REL={"docs/LOCAL_AUDIT.private.md"}
MODULES=("proxypilot.py","manager.py","desktop.py","appicons.py","traffic.py",
         "socketwatch.py","netobserve.py","appstatus.py","checkui.py","diagnostics.py")
RELEASE_VERSION=re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?$")
PYTHON_VERSION=re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:(a|b|rc)(\d+))?$")


def version() -> str:
    sys.path.insert(0,str(ROOT/"src"))
    from proxypilot_app import __version__
    return __version__


def _to_python_version(release_version: str) -> str:
    match=RELEASE_VERSION.fullmatch(release_version)
    if not match:raise ValueError("Release version must be SemVer: X.Y.Z[-(alpha|beta|rc).N]")
    major,minor,patch,stage,number=match.groups()
    if not stage:return f"{major}.{minor}.{patch}"
    marker={"alpha":"a","beta":"b","rc":"rc"}[stage]
    return f"{major}.{minor}.{patch}{marker}{number}"


def _to_release_version(package_version: str) -> str:
    semver=RELEASE_VERSION.fullmatch(package_version)
    if semver:return package_version
    match=PYTHON_VERSION.fullmatch(package_version)
    if not match:raise ValueError("Package version must be a stable or alpha/beta/rc PEP 440 version")
    major,minor,patch,stage,number=match.groups()
    if not stage:return f"{major}.{minor}.{patch}"
    name={"a":"alpha","b":"beta","rc":"rc"}[stage]
    return f"{major}.{minor}.{patch}-{name}.{number}"


def _to_debian_version(release_version: str) -> str:
    match=RELEASE_VERSION.fullmatch(release_version)
    if not match:raise ValueError("Release version must be SemVer: X.Y.Z[-(alpha|beta|rc).N]")
    major,minor,patch,stage,number=match.groups()
    if not stage:return f"{major}.{minor}.{patch}"
    return f"{major}.{minor}.{patch}~{stage}{number}"


def _copy_source(destination: Path) -> None:
    destination.mkdir(parents=True,exist_ok=True)
    for path in ROOT.rglob("*"):
        rel=path.relative_to(ROOT)
        rel_text=rel.as_posix()
        if any(part in EXCLUDE or part.endswith(".egg-info") for part in rel.parts):continue
        if rel_text in PRIVATE_REL:continue
        if path.is_symlink():continue
        target=destination/rel
        if path.is_dir():target.mkdir(parents=True,exist_ok=True)
        elif path.is_file():
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(path,target)


def _deb_script(module: str) -> bytes:
    return ("#!/usr/bin/python3\n"
            "# ProxyPilot package entry point\n"
            "import sys\n"
            "sys.path.insert(0, '/usr/lib/proxypilot')\n"
            "sys.path.insert(0, '/usr/lib/proxypilot/src')\n"
            f"from proxypilot_app.{module} import main\n"
            "raise SystemExit(main())\n").encode()


def _desktop_quote(value: str) -> str:
    for char in ("\\",'"',"$","`"):
        value=value.replace(char,"\\"+char)
    return '"'+value.replace("%","%%")+'"'


def _systemd_quote(value: str) -> str:
    return '"'+value.replace("\\","\\\\").replace('"','\\"').replace("%","%%")+'"'


def _make_deb(output: Path, release_version: str, arch: str, maintainer: str) -> Path:
    debian_version=_to_debian_version(release_version)
    with tempfile.TemporaryDirectory(prefix="proxypilot-deb-") as tmp:
        root=Path(tmp)
        payload=root/"usr/lib/proxypilot"
        payload.mkdir(parents=True)
        for name in MODULES:shutil.copy2(ROOT/name,payload/name)
        shutil.copy2(ROOT/"proxypilot-icon.svg",payload/"proxypilot-icon.svg")
        shutil.copytree(ROOT/"src/proxypilot_app",payload/"src/proxypilot_app",
                        ignore=shutil.ignore_patterns("__pycache__","*.pyc"))
        debian=root/"DEBIAN";debian.mkdir()
        control=(f"Package: proxypilot\nVersion: {debian_version}\nArchitecture: {arch}\n"
                 f"Maintainer: {maintainer}\nSection: net\nPriority: optional\n"
                 "Depends: python3 (>= 3.11), python3-gi, gir1.2-gtk-4.0\n"
                 "Description: Linux proxy manager for proxy-aware apps\n"
                 " GTK desktop and SSH-capable CLI using a local HTTP-to-SOCKS5 bridge.\n")
        (debian/"control").write_text(control)
        copyright=root/"usr/share/doc/proxypilot/copyright"
        copyright.parent.mkdir(parents=True,exist_ok=True)
        license_text=(ROOT/"LICENSE").read_text(encoding="utf-8").splitlines()
        debian_license=["Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/",
                        "Upstream-Name: ProxyPilot",
                        "Source: https://github.com/Rafael7277/ProxyPilot",
                        "",
                        "Files: *",
                        "Copyright: 2026 Rafael",
                        "License: MIT"]
        debian_license.extend(" "+line if line else " ." for line in license_text)
        copyright.write_text("\n".join(debian_license)+"\n",encoding="utf-8")
        for name,module in (("proxypilot","cli"),("proxypilot-gui","gtk_ui")):
            path=root/"usr/bin"/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(_deb_script(module));path.chmod(0o755)
        unit=root/"usr/lib/systemd/user/proxypilot.service"
        unit.parent.mkdir(parents=True,exist_ok=True)
        unit.write_text("[Unit]\nDescription=ProxyPilot local HTTP/SOCKS bridge\nAfter=network.target\n\n"
                        "[Service]\nType=simple\n"
                        f"ExecStart={_systemd_quote('/usr/bin/python3')} {_systemd_quote('/usr/lib/proxypilot/proxypilot.py')} serve\n"
                        f"WorkingDirectory={_systemd_quote('/usr/lib/proxypilot')}\n"
                        "Restart=on-failure\nRestartSec=3\nNoNewPrivileges=true\n\n"
                        "[Install]\nWantedBy=default.target\n")
        app=root/"usr/share/applications/proxypilot.desktop";app.parent.mkdir(parents=True,exist_ok=True)
        app.write_text("[Desktop Entry]\nType=Application\nVersion=1.0\nName=ProxyPilot\n"
                       "Comment=Inspect and manage proxy-aware Linux applications\n"
                       "Exec=proxypilot-gui\nTryExec=proxypilot-gui\nIcon=proxypilot\n"
                       "Terminal=false\nCategories=Network;Settings;\n")
        icon=root/"usr/share/icons/hicolor/scalable/apps/proxypilot.svg"
        icon.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/"proxypilot-icon.svg",icon)
        path=output/f"proxypilot_{debian_version}_{arch}.deb"
        subprocess.run(["dpkg-deb","--build","--root-owner-group",str(root),str(path)],check=True,
                       capture_output=True,text=True)
        info=subprocess.run(["dpkg-deb","--info",str(path)],check=True,capture_output=True,text=True)
        if f"Version: {debian_version}" not in info.stdout or f"Architecture: {arch}" not in info.stdout:
            raise RuntimeError("Built Debian package metadata does not match the requested version/architecture")
        return path


def _validate_artifacts(output: Path, artifacts: list[Path], package_version: str) -> None:
    manifest=output/"SHA256SUMS"
    checked=subprocess.run(["sha256sum","--check",str(manifest)],cwd=output,
                           capture_output=True,text=True)
    if checked.returncode:
        raise RuntimeError(f"Artifact checksum validation failed: {checked.stderr.strip()}")
    for archive_path in (p for p in artifacts if p.suffix in (".zip", ".gz")):
        if archive_path.suffix==".zip":
            with zipfile.ZipFile(archive_path) as archive:
                names=set(archive.namelist())
        else:
            with tarfile.open(archive_path,"r:gz") as archive:
                names={member.name for member in archive.getmembers()}
        if any("LOCAL_AUDIT.private.md" in name for name in names):
            raise RuntimeError(f"Private local audit leaked into {archive_path.name}")
        if not any(name.endswith("src/proxypilot_app/cli.py") for name in names):
            raise RuntimeError(f"Source archive is missing the CLI package: {archive_path.name}")
        if not any(name.endswith("/LICENSE") for name in names):
            raise RuntimeError(f"Source archive is missing the license: {archive_path.name}")
    wheels=[p for p in artifacts if p.suffix==".whl"]
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            names=set(archive.namelist())
            if "proxypilot_app/cli.py" not in names or "proxypilot.py" not in names:
                raise RuntimeError(f"Wheel has an incomplete package layout: {wheel.name}")
        env=os.environ.copy();env["PYTHONPATH"]=str(wheel)
        result=subprocess.run([sys.executable,"-m","proxypilot_app","--version"],
                              cwd=output,env=env,capture_output=True,text=True,timeout=10)
        if result.returncode or package_version not in result.stdout:
            raise RuntimeError(f"Wheel CLI smoke test failed: {result.stderr.strip()}")
    debs=[p for p in artifacts if p.suffix==".deb"]
    for deb in debs:
        with tempfile.TemporaryDirectory(prefix="proxypilot-deb-check-") as temp:
            root=Path(temp)
            subprocess.run(["dpkg-deb","--extract",str(deb),str(root)],check=True,
                           capture_output=True,text=True)
            payload=root/"usr/lib/proxypilot"
            if not (payload/"proxypilot.py").is_file() or not (payload/"src/proxypilot_app/cli.py").is_file():
                raise RuntimeError("Debian package payload is incomplete")
            copyright= root/"usr/share/doc/proxypilot/copyright"
            if not copyright.is_file() or "License: MIT" not in copyright.read_text(encoding="utf-8"):
                raise RuntimeError("Debian package is missing its MIT copyright notice")
            env=os.environ.copy()
            env["PYTHONPATH"]=os.pathsep.join((str(payload/"src"),str(payload)))
            result=subprocess.run([sys.executable,"-m","proxypilot_app","--version"],
                                  cwd=root,env=env,capture_output=True,text=True,timeout=10)
            if result.returncode or package_version not in result.stdout:
                raise RuntimeError(f"Debian payload CLI smoke test failed: {result.stderr.strip()}")


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=ROOT/"build/release")
    parser.add_argument("--version",default=None)
    parser.add_argument("--maintainer",default=os.environ.get(
        "PROXYPILOT_MAINTAINER","Rafael <97381065+Rafael7277@users.noreply.github.com>"))
    parser.add_argument("--source-only",action="store_true",help="Skip wheel and .deb generation")
    args=parser.parse_args()
    package_version=version()
    try:
        requested=(args.version or _to_release_version(package_version)).removeprefix("v")
        if requested!=_to_release_version(package_version):
            print(f"Requested release version {requested} does not match source metadata {package_version}.",file=sys.stderr)
            return 2
    except ValueError as exc:
        print(str(exc),file=sys.stderr);return 2
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=True)
    stem=f"proxypilot-{requested}-source"
    with tempfile.TemporaryDirectory(prefix="proxypilot-source-") as tmp:
        tree=Path(tmp)/f"proxypilot-{requested}"
        _copy_source(tree)
        tar_path=output/f"{stem}.tar.gz"
        with tarfile.open(tar_path,"w:gz") as archive:archive.add(tree,arcname=tree.name)
        zip_path=output/f"{stem}.zip"
        with zipfile.ZipFile(zip_path,"w",compression=zipfile.ZIP_DEFLATED) as archive:
            for path in tree.rglob("*"):
                if path.is_file():archive.write(path,path.relative_to(tree.parent))
    artifacts=[tar_path,zip_path]
    if not args.source_only:
        arch=subprocess.run(["dpkg","--print-architecture"],capture_output=True,text=True,check=True).stdout.strip()
        artifacts.append(_make_deb(output,requested,arch,args.maintainer))
        wheel_dir=output
        subprocess.run([sys.executable,"-m","pip","wheel",str(ROOT),"--no-deps","--no-build-isolation",
                        "--wheel-dir",str(wheel_dir)],check=True)
        wheel_version=_to_python_version(requested)
        artifacts.extend(wheel_dir.glob(f"proxypilot-{wheel_version}-*.whl"))
        if not any(path.suffix==".whl" for path in artifacts):
            raise RuntimeError("Python wheel build did not create a wheel for this version")
    sums=[]
    for path in artifacts:
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        sums.append(f"{digest}  {path.relative_to(output).as_posix()}")
    sums_path=output/"SHA256SUMS";sums_path.write_text("\n".join(sums)+"\n")
    _validate_artifacts(output,artifacts,package_version)
    print(f"Built {len(artifacts)} artifact(s) in {output}")
    for path in artifacts:print(f"{path.name} ({path.stat().st_size} bytes)")
    print(sums_path.name)
    return 0


if __name__=="__main__":raise SystemExit(main())
