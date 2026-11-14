# ProxyPilot baseline and migration audit

The initial source baseline lacked a repository history and automated Linux release pipeline. The application used a legacy JSON configuration format and a user-level bridge service; the 1.0 migration retains both while introducing a shared CLI/GUI service layer.

## Confirmed behavior and gaps

1. The bridge exposes loopback HTTP proxy endpoints and connects to a configured SOCKS5 upstream. Unit tests cover forwarding and AUTO fallback.
2. The initial desktop-only administration path did not support SSH. The new CLI works without `DISPLAY` and does not import GTK.
3. Process and socket discovery uses Linux `/proc`, is scoped to the current user, and reports best-effort evidence.
4. Per-app route settings do not affect arbitrary already-running processes. Control paths are managed desktop launchers and user services.
5. Desktop-entry handling preserves supported field codes and refuses launchers it cannot safely manage.
6. Process cleanup uses conservative review candidates and protects SSH shells and multiplexers.
7. The system proxy integration manages GNOME GSettings and the systemd user environment. It is not a universal Linux proxy API and does not route all TCP/UDP.

## Migration requirements

- Preserve existing JSON keys and unknown values during schema migration; write updates atomically.
- Leave unrelated launchers, service drop-ins, environment files, desktop settings, and proxy configuration unchanged.
- Keep bridge ports and the legacy `proxypilot.py serve` entry point compatible with existing user units.
- Back up only files owned by ProxyPilot. Never overwrite an unknown destination or follow a symlink during install, update, or rollback.
- Public documentation and artifacts must not include host-specific proxy state or application inventory.
