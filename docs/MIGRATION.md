# Migration plan to ProxyPilot 1.0

## Data and system files

- Preserve `~/.config/proxypilot/config.json`, including unrecognized keys.
- Keep current bridge ports and the legacy service invocation working.
- Back up the ProxyPilot service unit and its owned desktop launcher before an upgrade.
- Leave unrelated desktop applications, user services, environment.d, GNOME, and proxy settings unchanged unless the user separately requests an explicit operation.
- Never silently enable or disable systemd linger. Report its state and provide a user-reviewed instruction.

## Upgrade strategy

1. Inventory existing ProxyPilot-owned files and validate that destinations are not symlinks or unknown files.
2. Stage new code and generated units in a private temporary directory.
3. Verify package contents and configuration readability before changing the active install.
4. Create a timestamped code/unit backup with restrictive permissions.
5. Install atomically, reload the user manager, and restart only ProxyPilot when the user explicitly runs the installer.
6. Check service health and expected loopback listeners.
7. Roll back ProxyPilot-owned files if health verification fails. Do not roll back unrelated user settings.

## Development constraints

Installation and upgrade tests must run in a temporary HOME with a mocked systemd command. They must never touch the developer's active service or real application settings.
