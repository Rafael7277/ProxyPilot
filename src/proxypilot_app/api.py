"""Shared, side-effect-conscious application API for GUI and CLI clients."""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Any


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import appstatus
import diagnostics
import manager
import netobserve
import proxypilot as bridge
import traffic
from . import updates


def _command(args: list[str], timeout: float = 4.0) -> dict[str, Any]:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "returncode": None, "error": type(exc).__name__}
    return {"available": result.returncode == 0, "returncode": result.returncode,
            "stdout": result.stdout.strip(), "error": result.stderr.strip()[:300]}


def _parse_properties(raw: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)


def _service_status(unit: str) -> dict[str, Any]:
    result = _command(["systemctl", "--user", "show", unit, "-p", "LoadState",
                       "-p", "ActiveState", "-p", "SubState", "-p", "MainPID",
                       "-p", "NRestarts"])
    if not result["available"]:
        return {"available": False, "error": result.get("error") or "systemd user manager unavailable"}
    props = _parse_properties(result["stdout"])
    return {"available": True, "load_state": props.get("LoadState", "unknown"),
            "active_state": props.get("ActiveState", "unknown"),
            "sub_state": props.get("SubState", "unknown"),
            "main_pid": int(props.get("MainPID", "0") or 0),
            "restart_count": int(props.get("NRestarts", "0") or 0)}


def _user_manager_status() -> dict[str, Any]:
    result = _command(["systemctl", "--user", "show-environment"])
    linger = _command(["loginctl", "show-user", str(os.getuid()), "-p", "Linger"])
    linger_value = None
    if linger["available"]:
        linger_value = _parse_properties(linger["stdout"]).get("Linger") == "yes"
    return {"available": result["available"], "linger": linger_value,
            "runtime_dir": bool(os.environ.get("XDG_RUNTIME_DIR") and
                                Path(os.environ["XDG_RUNTIME_DIR"]).is_dir()),
            "error": result.get("error") if not result["available"] else None}


def _tcp_listener(host: str, port: int, timeout: float = 0.15) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError, TypeError):
        return False


def _group_summary(group: dict[str, Any]) -> dict[str, Any]:
    apps = group.get("apps", [])
    return {
        "id": group["id"], "name": group["name"], "policy": group.get("mode", "unmanaged"),
        "process_count": group.get("process_count", 0), "bridged_count": group.get("bridged_count", 0),
        "memory_mb": group.get("memory_mb", 0), "cpu_percent": group.get("cpu_percent", 0.0),
        "has_supported_launch_method": bool(apps or group.get("services")),
        "launchers": [{"id": app["id"], "managed": bool(app.get("managed")),
                       "dbus_activatable": bool(app.get("dbus_activatable")),
                       "actions": list(app.get("actions", []))} for app in apps],
        "services": list(group.get("services", [])),
    }


def groups() -> list[dict[str, Any]]:
    """Return the same-user app/service/process inventory used by both clients."""
    return manager.inventory()


def find_group(query: str, inventory: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    groups_ = groups() if inventory is None else inventory
    key = query.casefold().strip()
    exact = [g for g in groups_ if g["id"].casefold() == key or g["name"].casefold() == key
             or any(a["id"].casefold() == key or a["name"].casefold() == key for a in g.get("apps", []))]
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        raise ValueError("Ambiguous app name: " + ", ".join(g["id"] for g in exact))
    matches = [g for g in groups_ if key in g["id"].casefold() or key in g["name"].casefold()
               or any(key in a["id"].casefold() or key in a["name"].casefold()
                      for a in g.get("apps", []))]
    if len(matches) == 1:
        return matches[0]
    if matches:
        raise ValueError("Ambiguous app name; matches: " + ", ".join(g["id"] for g in matches[:12]))
    raise ValueError(f"No app or process group matches {query!r}")


def status() -> dict[str, Any]:
    """Read configuration and local runtime state; never probes public hosts."""
    cfg = bridge.load()
    proxy = diagnostics.system_snapshot(cfg, probe=False)
    service = _service_status("proxypilot.service")
    user = _user_manager_status()
    listeners = {
        "auto": _tcp_listener("127.0.0.1", cfg["auto_port"]),
        "proxy_only": _tcp_listener("127.0.0.1", cfg["proxy_port"]),
        "upstream": _tcp_listener(cfg["upstream_host"], cfg["upstream_port"]),
    }
    return {"schema_version": 1, "version": _version(), "service": service,
            "user_manager": user, "listeners": listeners,
            "policy": {"global": cfg.get("global_mode", "off"),
                       "allow_direct_fallback": bool(cfg.get("allow_direct_fallback", True))},
            "configured_upstream": f"{cfg['upstream_host']}:{cfg['upstream_port']}",
            "system_proxy": {"gnome_mode": proxy["gnome_mode"], "gnome": proxy["gnome"],
                             "systemd": proxy["systemd"], "notes": proxy["notes"]}}


def _version() -> str:
    from . import __version__
    return __version__


def doctor(probe_upstream: bool = False) -> dict[str, Any]:
    report = status()
    checks = []
    service = report["service"]
    checks.append({"id": "user_systemd", "ok": report["user_manager"]["available"],
                   "detail": "User systemd manager is available" if report["user_manager"]["available"]
                   else "No systemd user bus; install/start cannot manage the user service"})
    checks.append({"id": "linger", "ok": report["user_manager"]["linger"] is True,
                   "detail": "User manager persists across logouts" if report["user_manager"]["linger"] is True
                   else "Linger is disabled or could not be checked; persistence after logout is not assured"})
    checks.append({"id": "service", "ok": service.get("active_state") == "active",
                   "detail": f"ProxyPilot service state: {service.get('active_state', service.get('error', 'unknown'))}"})
    for name, ok in report["listeners"].items():
        checks.append({"id": f"listener_{name}", "ok": ok,
                       "detail": "Listening on loopback" if ok else "Expected loopback listener is unavailable"})
    if probe_upstream:
        cfg = bridge.load()
        ok = bridge.upstream_ok(cfg)
        checks.append({"id": "socks5_handshake", "ok": ok,
                       "detail": "SOCKS5 negotiation succeeded" if ok else "SOCKS5 negotiation failed"})
    for note in report["system_proxy"]["notes"]:
        checks.append({"id": "system_proxy_configuration", "ok": True,
                       "severity": "warning", "detail": note})
    blocking = [c for c in checks if c.get("severity") != "warning"]
    return {"schema_version": 1, "version": _version(), "ok": all(c["ok"] for c in blocking),
            "checks": checks, "status": report}


def app_list(query: str | None = None) -> list[dict[str, Any]]:
    inventory = groups()
    if query:
        key = query.casefold()
        inventory = [g for g in inventory if key in g["id"].casefold() or key in g["name"].casefold()
                     or any(key in a["id"].casefold() or key in a["name"].casefold()
                            for a in g.get("apps", []))]
    return [_group_summary(g) for g in inventory]


def inspect(query: str) -> dict[str, Any]:
    cfg = bridge.load()
    inventory = groups()
    group = find_group(query, inventory)
    live_sockets = netobserve.observe(cfg)
    reader = traffic.TrafficReader()
    events = reader.poll()
    evidence = appstatus.group_evidence(group, live_sockets, reader.connections())
    env = diagnostics.process_proxies([p["pid"] for p in group.get("processes", [])]) \
        if group.get("processes") else {"status": "App not running", "detail": "—", "sampled": 0}
    overrides = diagnostics.service_override_info(group.get("services", []))
    summary = _group_summary(group)
    warnings = list(evidence["lines"])
    if group.get("mode") != "unmanaged" and group.get("process_count") and not group.get("bridged_count"):
        warnings.append("A saved route is not active in the observed running process environment.")
    app_modes = {cfg.get("apps", {}).get(a["id"]) for a in group.get("apps", [])
                 if cfg.get("apps", {}).get(a["id"]) is not None}
    service_modes = {cfg.get("services", {}).get(u) for u in group.get("services", [])
                     if cfg.get("services", {}).get(u) is not None}
    if app_modes and service_modes and app_modes != service_modes:
        warnings.append("Desktop app and user-service policies differ.")
    if overrides:
        warnings.extend(overrides)
    return {"schema_version": 1, "version": _version(), "app": summary,
            "requested_policy": {"group": group.get("mode", "unmanaged"),
                                 "apps": {a["id"]: cfg.get("apps", {}).get(a["id"], "unmanaged")
                                          for a in group.get("apps", [])},
                                 "services": {u: cfg.get("services", {}).get(u, "unmanaged")
                                              for u in group.get("services", [])}},
            "effective_configuration": {"integrated_launchers": [a["id"] for a in group.get("apps", [])
                                                                    if a.get("managed")],
                                        "process_proxy_environment": env,
                                        "service_overrides": overrides},
            "observed_connections": evidence["connections"],
            "verification": {"result": evidence["title"], "level": evidence["level"],
                             "explanation": evidence["explanation"], "evidence": warnings,
                             "observed_at": time.time()}}


def connections(limit: int = 200) -> dict[str, Any]:
    cfg = bridge.load()
    reader = traffic.TrafficReader()
    reader.poll()
    events = reader.connections()[:max(1, min(limit, 5000))]
    sockets = netobserve.observe(cfg)
    return {"schema_version": 1, "version": _version(), "bridge_events": events,
            "live_socket_observations": sockets,
            "notice": "TCP observations and bridge events are partial evidence, not full traffic capture."}


def process_list(review_only: bool = False) -> list[dict[str, Any]]:
    inventory = groups()
    reviews = {g["id"]: r for r in manager.cleanup_candidates(inventory)}
    try:sockets=netobserve.observe(bridge.load())
    except Exception:sockets=[]
    by_process={}
    for item in sockets:
        by_process.setdefault((item.get("pid"),item.get("start")),[]).append({
            "peer":f"{item.get('remote_ip')}:{item.get('remote_port')}",
            "kind":item.get("kind"),"observed_at":item.get("ts")})
    result = []
    for group in inventory:
        if not group.get("process_count"):
            continue
        review = reviews.get(group["id"])
        if review_only and not review:
            continue
        process_rows=[]
        reviewed=set(review.get("auto_pids",[])) if review else set()
        for process in group.get("processes",[]):
            protected=manager.protected_process(process)
            pid=process.get("pid")
            start=process.get("start")
            process_rows.append({"pid":pid,"parent_pid":process.get("ppid"),
                "command":process.get("cmd"),"state":process.get("state"),
                "age_seconds":process.get("age_s"),
                "cpu_percent":process.get("cpu_percent",0.0),
                "memory_mb":round(process.get("rss_kb",0)/1024,1),
                "protected":protected,
                "category":"Protected" if protected else
                    "Review recommended" if pid in reviewed else "Background/active",
                "connections":by_process.get((pid,start),[])})
        result.append({"id": group["id"], "name": group["name"],
                       "process_count": group["process_count"], "memory_mb": group["memory_mb"],
                       "cpu_percent": group["cpu_percent"],
                       "protected": bool(process_rows) and all(x["protected"] for x in process_rows),
                       "review": review["reasons"] if review else [],
                       "process_tree":process_rows})
    return result


def update_check(repository: str | None=None) -> dict[str, Any]:
    return updates.check(repository=repository,current_version=_version())


def set_route(query: str, mode: str, *, apply: bool = False,
              manage_launchers: bool = False, restart_services: bool = False) -> dict[str, Any]:
    inventory = groups()
    group = find_group(query, inventory)
    if not group.get("apps") and not group.get("services"):
        raise ValueError("This process-only group has no supported managed launch method.")
    plan = {"app": group["name"], "id": group["id"], "current_policy": group.get("mode", "unmanaged"),
            "requested_policy": mode, "manage_launchers": manage_launchers,
            "restart_services": restart_services, "processes_affected_now": False,
            "requires_apply": True}
    if not apply:
        return {"schema_version":1,"version":_version(),
                "applied": False, "dry_run": True, "plan": plan}
    result = manager.set_group_mode(group["id"], mode, manage_launchers=manage_launchers,
                                   restart_services=restart_services)
    return {"schema_version":1,"version":_version(),
            "applied": not bool(result.get("errors")), "dry_run": False,
            "plan": plan, "result": result}
