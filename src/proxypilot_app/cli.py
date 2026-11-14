"""Headless CLI for local and SSH administration."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import socket
import subprocess
import sys
import time
from typing import Any

from . import __version__
from . import api


def _emit(data: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(data, ensure_ascii=False, sort_keys=True))
    elif isinstance(data, str):
        print(data)
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="proxypilot", description="ProxyPilot Linux proxy manager")
    parser.add_argument("--version", action="version", version=f"ProxyPilot {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("status", help="Read current service, proxy, and listener status")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("doctor", help="Run local read-only diagnostics")
    p.add_argument("--json", action="store_true")
    p.add_argument("--probe-upstream", action="store_true", help="Negotiate SOCKS5 with the local upstream; no public host probe")

    p = sub.add_parser("apps", help="List installed apps, services, and process groups")
    p.add_argument("query", nargs="?")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("inspect", help="Compare requested policy, effective configuration, and observed evidence")
    p.add_argument("app")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("connections", help="Read ProxyPilot bridge events and current same-user TCP observations")
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--follow", action="store_true")
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--json", action="store_true")

    route = sub.add_parser("route", help="Read or change an app policy")
    route_sub = route.add_subparsers(dest="route_command", required=True)
    p = route_sub.add_parser("get")
    p.add_argument("app");p.add_argument("--json", action="store_true")
    p = route_sub.add_parser("set")
    p.add_argument("app");p.add_argument("mode", choices=("direct", "proxy", "auto", "unmanaged"))
    p.add_argument("--apply", action="store_true", help="Apply the change; without this flag only show the plan")
    p.add_argument("--dry-run", action="store_true", help="Explicitly show the plan without changing configuration")
    p.add_argument("--manage-launchers", action="store_true")
    p.add_argument("--restart-services", action="store_true")
    p.add_argument("--yes", action="store_true", help="Required together with --apply for non-interactive confirmation")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("run", help="Run one command with a selected proxy environment")
    p.add_argument("--mode", choices=("direct", "proxy", "auto", "system"), required=True)
    p.add_argument("command_args", nargs=argparse.REMAINDER)

    processes = sub.add_parser("processes", help="Review same-user processes without terminating them")
    processes_sub = processes.add_subparsers(dest="process_command")
    p = processes_sub.add_parser("review")
    p.add_argument("--json", action="store_true")
    p = processes_sub.add_parser("list")
    p.add_argument("--json", action="store_true")
    processes.set_defaults(process_json=False)
    processes.add_argument("--json", action="store_true")

    system = sub.add_parser("system", help="Inspect Linux system proxy state")
    system_sub = system.add_subparsers(dest="system_command", required=True)
    p = system_sub.add_parser("status");p.add_argument("--json", action="store_true")

    update = sub.add_parser("update", help="Check for a public release")
    update_sub = update.add_subparsers(dest="update_command", required=True)
    p = update_sub.add_parser("check");p.add_argument("--repository")
    p.add_argument("--json", action="store_true")

    return parser


def _text_status(report: dict[str, Any]) -> str:
    service = report["service"]
    user = report["user_manager"]
    listeners = report["listeners"]
    lines = [f"ProxyPilot {report['version']}",
             f"Service: {service.get('active_state', service.get('error', 'unknown'))}",
             f"User systemd: {'available' if user['available'] else 'unavailable'}; linger: "
             f"{'yes' if user['linger'] is True else 'no/unknown'}",
             f"ProxyPilot global policy: {report['policy']['global']}",
             f"AUTO direct fallback: {'allowed' if report['policy']['allow_direct_fallback'] else 'disabled'}",
             f"Upstream: {report['configured_upstream']} ({'listening' if listeners['upstream'] else 'unavailable'})",
             f"Bridge AUTO: {'listening' if listeners['auto'] else 'unavailable'}; "
             f"Proxy only: {'listening' if listeners['proxy_only'] else 'unavailable'}"]
    for note in report["system_proxy"]["notes"]:
        lines.append("Warning: " + note)
    return "\n".join(lines)


def _text_apps(items: list[dict[str, Any]]) -> str:
    if not items:return "No matching apps or process groups."
    return "\n".join(f"{x['name']} [{x['id']}] policy={x['policy']} processes={x['process_count']} "
                     f"bridged={x['bridged_count']}" for x in items)


def _text_inspect(item: dict[str, Any]) -> str:
    app=item["app"];ver=item["verification"]
    lines=[f"{app['name']} [{app['id']}]",f"Requested: {item['requested_policy']}",
           f"Effective: {item['effective_configuration']}",
           f"Observed: {ver['result']} — {ver['explanation']}" ]
    if ver["evidence"]:lines.extend("Evidence: "+x for x in ver["evidence"])
    return "\n".join(lines)


def _proxy_env(mode: str) -> dict[str, str]:
    env=os.environ.copy()
    names=("HTTP_PROXY","HTTPS_PROXY","ALL_PROXY","NO_PROXY","http_proxy","https_proxy","all_proxy","no_proxy")
    if mode=="system":return env
    for name in names:env.pop(name,None)
    if mode=="direct":return env
    import proxypilot as bridge
    cfg=bridge.load()
    port=int(cfg["auto_port"] if mode=="auto" else cfg["proxy_port"])
    try:
        with socket.create_connection(("127.0.0.1",port),timeout=0.2):pass
    except OSError as exc:
        raise RuntimeError(f"ProxyPilot bridge port {port} is unavailable; command not started.") from exc
    env.update(bridge.credentials_env(mode,cfg))
    return env


def _run_command(args: argparse.Namespace) -> int:
    command=args.command_args
    if command and command[0]=="--":command=command[1:]
    if not command:
        raise ValueError("Provide a command after --, for example: proxypilot run --mode proxy -- curl https://example.com")
    try:
        return subprocess.run(command,env=_proxy_env(args.mode),check=False).returncode
    except FileNotFoundError:
        raise ValueError(f"Command not found: {command[0]}")


def main(argv: list[str] | None = None) -> int:
    parser=_parser()
    args=parser.parse_args(argv)
    try:
        if args.command=="status":
            report=api.status();_emit(report if args.json else _text_status(report),args.json);return 0
        if args.command=="doctor":
            report=api.doctor(args.probe_upstream);_emit(report if args.json else report,args.json);return 0 if report["ok"] else 1
        if args.command=="apps":
            items=api.app_list(args.query)
            payload={"schema_version":1,"version":__version__,"apps":items}
            _emit(payload if args.json else _text_apps(items),args.json);return 0
        if args.command=="inspect":
            item=api.inspect(args.app);_emit(item if args.json else _text_inspect(item),args.json);return 0
        if args.command=="connections":
            if not args.follow:
                item=api.connections(args.limit);_emit(item,args.json);return 0
            if args.interval<0.25:raise ValueError("--interval must be at least 0.25 seconds")
            last=None
            while True:
                item=api.connections(args.limit)
                key=(tuple(x.get("id") for x in item["bridge_events"]),
                     tuple((x.get("pid"),x.get("inode"),x.get("remote_ip"),
                            x.get("remote_port"),x.get("kind"))
                           for x in item["live_socket_observations"]))
                if key!=last:
                    _emit(item,args.json);last=key
                time.sleep(args.interval)
        if args.command=="route":
            if args.route_command=="get":
                item=api.inspect(args.app)
                payload={"schema_version":1,"version":__version__,"app":item["app"],
                         "requested_policy":item["requested_policy"]}
                _emit(payload if args.json else item["requested_policy"],args.json);return 0
            if args.apply and args.dry_run:raise ValueError("--apply and --dry-run cannot be used together")
            if args.apply and not args.yes:raise ValueError("For non-interactive safety, --apply requires --yes")
            if args.restart_services and not args.apply:raise ValueError("Service restart requires --apply --yes")
            item=api.set_route(args.app,args.mode,apply=args.apply,
                               manage_launchers=args.manage_launchers,
                               restart_services=args.restart_services)
            _emit(item,args.json);return 0 if item.get("applied",True) else 2
        if args.command=="run":return _run_command(args)
        if args.command=="processes":
            review=args.process_command=="review"
            items=api.process_list(review_only=review)
            as_json=args.json or args.process_json
            payload={"schema_version":1,"version":__version__,"processes":items}
            _emit(payload if as_json else items,as_json);return 0
        if args.command=="system" and args.system_command=="status":
            payload={"schema_version":1,"version":__version__,
                     "system_proxy":api.status()["system_proxy"]}
            _emit(payload,args.json);return 0
        if args.command=="update" and args.update_command=="check":
            result=api.update_check(args.repository)
            _emit(result,args.json);return 0 if not result.get("error") else 2
        parser.error("unsupported command")
    except KeyboardInterrupt:
        return 130
    except (OSError,RuntimeError,ValueError,KeyError) as exc:
        if getattr(args,"json",False):_emit({"error":type(exc).__name__,"message":str(exc)},True)
        else:print(f"proxypilot: {exc}",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
