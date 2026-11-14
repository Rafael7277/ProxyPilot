"""Read-only GitHub Releases lookup for ProxyPilot updates."""
from __future__ import annotations

import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from . import __version__


REPOSITORY_PATTERN=re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
VERSION_PATTERN=re.compile(
    r"^v?(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+)|(?:a|b|rc)(\d+)|\.dev(\d+))?$"
)
DEFAULT_REPOSITORY="Rafael7277/ProxyPilot"


def _version(value: str) -> tuple[tuple[int,int,int],tuple[int,int]|None]:
    match=VERSION_PATTERN.fullmatch(value.strip())
    if not match:raise ValueError("Release tag is not a supported version")
    core=(int(match.group(1)),int(match.group(2)),int(match.group(3)))
    semver_stage,semver_number,python_number,dev_number=match.group(4,5,6,7)
    if semver_stage:
        rank={"alpha":0,"beta":1,"rc":2}[semver_stage]
        return core,(rank,int(semver_number))
    if python_number:
        marker=value.strip().removeprefix("v")
        rank=0 if "a" in marker else 1 if "b" in marker else 2
        return core,(rank,int(python_number))
    if dev_number:
        return core,(-1,int(dev_number))
    return core,None


def _is_newer(latest: str,current: str) -> bool:
    latest_core,latest_pre=_version(latest)
    current_core,current_pre=_version(current)
    if latest_core!=current_core:return latest_core>current_core
    if latest_pre is None:return current_pre is not None
    if current_pre is None:return False
    return latest_pre>current_pre


def check(repository: str|None=None,current_version: str|None=None) -> dict:
    current_version=current_version or __version__
    repository=(repository or os.environ.get("PROXYPILOT_GITHUB_REPOSITORY") or DEFAULT_REPOSITORY).strip()
    result={"schema_version":1,"configured":bool(repository),"repository":repository or None,
            "current_version":current_version,"latest_version":None,"update_available":None,
            "compatible":None,"release_url":None,"published_at":None,"release_notes":"",
            "assets":[],"integrity_model":"not checked","error":None}
    if not repository:
        result["message"]="Set PROXYPILOT_GITHUB_REPOSITORY to owner/repository to enable release checks."
        return result
    if not REPOSITORY_PATTERN.fullmatch(repository) or any(part in (".","..") for part in repository.split("/")):
        result["error"]="Repository must use the owner/name form."
        result["message"]=result["error"]
        return result
    endpoint=f"https://api.github.com/repos/{repository}/releases/latest"
    request=Request(endpoint,headers={"Accept":"application/vnd.github+json",
                    "X-GitHub-Api-Version":"2022-11-28",
                    "User-Agent":f"ProxyPilot/{current_version}"})
    try:
        try:
            with urlopen(request,timeout=8) as response:
                raw=response.read(1_048_577)
            release=json.loads(raw.decode("utf-8"))
        except HTTPError as exc:
            _,current_prerelease=_version(current_version)
            if exc.code!=404 or current_prerelease is None:raise
            prerelease_endpoint=f"https://api.github.com/repos/{repository}/releases?per_page=20"
            prerelease_request=Request(prerelease_endpoint,headers={"Accept":"application/vnd.github+json",
                    "X-GitHub-Api-Version":"2022-11-28",
                    "User-Agent":f"ProxyPilot/{current_version}"})
            with urlopen(prerelease_request,timeout=8) as response:
                raw=response.read(1_048_577)
            releases=json.loads(raw.decode("utf-8"))
            if not isinstance(releases,list):raise ValueError("GitHub release list must be an array")
            release=next((item for item in releases if isinstance(item,dict) and not item.get("draft")),None)
            if release is None:
                result["error"]="No published GitHub release is available."
                result["message"]=result["error"]
                return result
        if len(raw)>1_048_576:raise ValueError("GitHub release metadata is too large")
        if not isinstance(release,dict):raise ValueError("GitHub release metadata must be an object")
        tag=str(release.get("tag_name", ""))
        _version(tag)
        release_url=str(release.get("html_url", ""))
        if not release_url.startswith(f"https://github.com/{repository}/releases/tag/"):
            raise ValueError("GitHub returned an unexpected release URL")
        assets=[]
        for asset in release.get("assets",[]):
            name=str(asset.get("name", ""))
            url=str(asset.get("browser_download_url", ""))
            if not name or not url.startswith(f"https://github.com/{repository}/releases/download/"):
                continue
            assets.append({"name":name,"url":url,"size":int(asset.get("size",0) or 0)})
        version=tag.removeprefix("v")
        expected_archive=f"proxypilot-{version}-source.tar.gz"
        result.update({"latest_version":version,
                       "update_available":_is_newer(tag,current_version),
                       "compatible":any(a["name"]==expected_archive for a in assets),
                       "release_url":release_url,"published_at":release.get("published_at"),
                       "release_notes":str(release.get("body", ""))[:12000],"assets":assets,
                       "integrity_model":"not checked; release metadata only"})
        result["message"]=("A compatible source archive is available." if result["compatible"]
                           else "Release found, but no compatible source archive was listed.")
    except HTTPError as exc:
        result["error"]=f"GitHub returned HTTP {exc.code}."
    except (URLError,TimeoutError,OSError) as exc:
        result["error"]=f"GitHub release lookup failed: {type(exc).__name__}."
    except (UnicodeError,json.JSONDecodeError,ValueError,TypeError,AttributeError) as exc:
        result["error"]=f"Invalid GitHub release metadata: {type(exc).__name__}."
    if result["error"]:
        result["message"]=result["error"]
    return result
