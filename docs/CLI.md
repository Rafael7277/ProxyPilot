# CLI command reference

The CLI is designed to work without GTK, X11, or a running desktop session. JSON outputs are UTF-8 and include `schema_version` on structured results. The CLI and GTK app call the same `proxypilot_app.api` service layer.

## Commands

| Command | Behavior |
| --- | --- |
| `proxypilot status [--json]` | Read config, system proxy state, user manager, service state, and loopback listeners. No public network probe. |
| `proxypilot doctor [--json] [--probe-upstream]` | Diagnose local service/configuration. The optional probe performs only a SOCKS5 greeting to the configured local listener. |
| `proxypilot apps [query] [--json]` | List installed launchers, user services, and same-user process groups. |
| `proxypilot inspect APP [--json]` | Show requested policy, effective config, live evidence, and verification. |
| `proxypilot connections [--limit N] [--json]` | Read bridge metadata and current TCP observations. |
| `proxypilot connections --follow` | Refresh connection evidence until interrupted. |
| `proxypilot route get APP [--json]` | Read app and service policy records. |
| `proxypilot route set APP MODE` | Show a dry-run plan. |
| `proxypilot route set APP MODE --apply --yes` | Apply an explicitly reviewed policy change. |
| `proxypilot run --mode MODE -- COMMAND...` | Start a command with a selected proxy environment. |
| `proxypilot processes [list|review] [--json]` | Review process groups; this command never stops processes. |
| `proxypilot system status [--json]` | Read GNOME and systemd proxy state. |
| `proxypilot update check [--json] [--repository OWNER/REPO]` | Read the latest stable GitHub Release if a repository is configured. No release is downloaded or installed. |
| `proxypilot-uninstall [--dry-run]` | Preview or confirm removal of the user-local install; keeps settings and backups. |

## JSON stability

JSON keys are additive within schema version 1. Breaking changes require a schema version increase. Consumers should ignore unknown keys. Error output has `error` and `message` keys and exits with code 2. A successful dry-run route plan exits with code 2 to distinguish “not applied” from success; callers should inspect `applied` and `dry_run` in the output.

## Route safety

Route changes do not mutate already-running process environments. Menu-launch integration and user-service restarts are separate, explicit options. `--restart-services` requires both `--apply` and `--yes`. The CLI rejects process-only groups with no supported launch method.

`run --mode proxy` and `run --mode auto` refuse to start the child if the corresponding loopback bridge is not listening. They never fall back by starting the child with a direct environment. AUTO fallback policy is enforced inside the bridge and is controlled by `allow_direct_fallback`.
