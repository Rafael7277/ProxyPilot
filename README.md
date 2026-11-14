# ProxyPilot

**Linux proxy manager for proxy-aware desktop and CLI applications.** ProxyPilot combines a local HTTP proxy bridge, SOCKS5 upstream support, per-app policy controls, process/socket evidence, and headless administration over SSH.

> **Pre-release status:** this checkout reports `1.0.0-alpha.3`; it is not a stable release. The project uses the MIT License. The canonical repository is [Rafael7277/ProxyPilot](https://github.com/Rafael7277/ProxyPilot).

## What it does

- Provides loopback HTTP and HTTPS `CONNECT` proxy endpoints backed by a SOCKS5 upstream.
- Supports `DIRECT`, `PROXY ONLY`, `AUTO`, and `USE SYSTEM SETTINGS` policies.
- Lets AUTO direct fallback be enabled or disabled. PROXY ONLY fails closed for requests that use the bridge.
- Reports the requested policy, effective launcher/service configuration, observed connections, and verification result separately.
- Includes a command-line interface suitable for local terminals and SSH sessions without `DISPLAY`.
- Includes a GTK 4 desktop client that uses the same application API as the CLI.
- Inspects same-user Linux processes, TCP sockets, GNOME settings, and systemd user environment without root.
- Preserves legacy ProxyPilot JSON configuration and the existing `proxypilot.py serve` entry point.

## Scope and limits

ProxyPilot does **not** implement a TUN device or transparent packet interception. It cannot force arbitrary applications, UDP traffic, or every TCP connection through a proxy. Applications must use the configured system proxy, inherit proxy environment variables, or be launched through an integrated ProxyPilot entry point.

Process and socket attribution is best-effort and limited to information visible to the current Linux user. A connection to local Xray proves contact with that listener; it does not prove all application requests used it or establish final internet egress. Missing evidence is reported as unverified.

The system-proxy adapter currently manages GNOME GSettings and the systemd user environment. Other desktop environments are not yet declared supported for system-proxy changes.

## Requirements

- Linux with Python 3.11 or newer.
- systemd user manager for the background bridge service.
- GTK 4 and PyGObject for the graphical client (`python3-gi` and `gir1.2-gtk-4.0` on Debian-family distributions).
- An optional SOCKS5 service such as Xray.

Headless users can install the CLI and service without GTK:

```bash
bash install.sh --cli-only
```

## Install and inspect

### Install a published Debian release

Download the current preview release from [GitHub Releases](https://github.com/Rafael7277/ProxyPilot/releases). With GitHub CLI installed, download its assets and verify their checksums before installing:

```bash
release_dir="$(mktemp -d)"
release_tag="$(gh release list --repo Rafael7277/ProxyPilot --limit 100 --json tagName,isDraft --jq '[.[] | select(.isDraft == false)][0].tagName')"
test -n "$release_tag"
gh release download "$release_tag" --repo Rafael7277/ProxyPilot --dir "$release_dir"
(cd "$release_dir" && sha256sum --check SHA256SUMS)
for artifact in "$release_dir"/*; do
  test "${artifact##*/}" = SHA256SUMS || gh attestation verify "$artifact" --repo Rafael7277/ProxyPilot
done
sudo apt install "$release_dir"/proxypilot_*_amd64.deb
```

The Debian package installs ProxyPilot for all users; its user service is not enabled automatically. To install only for your account without root, use the source installer below.

### Install from source for your account

```bash
git clone https://github.com/Rafael7277/ProxyPilot.git
cd ProxyPilot
```

Review the destinations first:

```bash
bash install.sh --dry-run
```

Install interactively:

```bash
bash install.sh
```

The installer backs up ProxyPilot-owned files, asks before starting or restarting its user service, and leaves unrelated browser, service, GNOME, Xray, and environment files unchanged. To stage files without contacting systemd:

```bash
bash install.sh --no-start
```

For unattended installation, pass `--yes` only after reviewing the dry run. Linger is inspected but never enabled automatically. Add `~/.local/bin` to `PATH` if necessary.

Preview removal with `proxypilot-uninstall --dry-run`, then run `proxypilot-uninstall` to confirm interactively. It preserves settings and refuses to remove the bridge while ProxyPilot-managed app launchers, service overrides, or a global profile still depend on it. The source checkout also provides `bash uninstall.sh --dry-run`.

## CLI examples

```bash
proxypilot status
proxypilot doctor
proxypilot apps
proxypilot apps --json
proxypilot inspect sample-app
proxypilot inspect background-gateway --json
proxypilot connections
proxypilot connections --follow
proxypilot route get sample-app
proxypilot route set sample-app auto                 # preview only
proxypilot route set sample-app auto --apply --yes   # explicit change
proxypilot run --mode proxy -- curl https://example.com
proxypilot processes review
proxypilot system status
```

`route set` previews by default. Applying a route requires `--apply --yes`. Restarting related services also requires the explicit `--restart-services` flag. Process inventory and diagnostics do not terminate anything.

`proxypilot run --mode proxy` requires the local ProxyPilot bridge. `--mode system` preserves the current environment. Direct mode clears inherited proxy variables for the child command only.

The Updates page and `proxypilot update check` read the latest stable release from `Rafael7277/ProxyPilot` by default. An alpha build can discover the latest published pre-release when no stable release exists. `PROXYPILOT_GITHUB_REPOSITORY=owner/repo` can override the repository. This is a read-only check; download and installation are not implemented.

For JSON automation, each command provides a versioned JSON object or list with a `schema_version` field where applicable. The JSON contract is documented in [`docs/CLI.md`](docs/CLI.md).

## GUI

Launch with:

```bash
proxypilot-gui
```

The GTK client contains Dashboard, Applications, Live Network, Process Manager, System Proxy, Diagnostics, Settings, Updates, and About pages. Scans run off the UI thread. Changes to app or system routes require a confirmation dialog.

## Configuration and migration

Legacy configuration remains at `~/.config/proxypilot/config.json` unless `XDG_CONFIG_HOME` is set. Application data, state, launchers, and user units follow XDG locations. Unknown configuration keys are preserved. Installation and upgrade tests run under a temporary HOME; the development installer must not be run against a production user account during CI.

See [`docs/BASELINE_AUDIT.md`](docs/BASELINE_AUDIT.md), [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/MIGRATION.md`](docs/MIGRATION.md), and [`docs/ACCEPTANCE_STATUS.md`](docs/ACCEPTANCE_STATUS.md).

## Development

```bash
python3 -m unittest discover -s tests -v
PYTHONPATH=src python3 -m proxypilot_app status --json
python3 scripts/check_public_tree.py
```

Build a wheel without network access when local build dependencies are installed:

```bash
python3 -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
```

CI runs unit and isolated installer/upgrade/uninstaller tests, headless CLI checks, a GTK smoke test under Xvfb, and builds and validates source archives, a wheel, a Debian package, and checksums. Runtime validation on this host still does not replace a real SSH login or a full desktop acceptance run. Current support claims are tracked in [`docs/SUPPORT.md`](docs/SUPPORT.md).

## Security and privacy

- Normal operation does not require root.
- Bridge listeners bind to loopback.
- Logs store destination metadata and route evidence, never request bodies, TLS content, or URL paths.
- Proxy URLs displayed by diagnostics have credentials and paths removed.
- See [`SECURITY.md`](SECURITY.md) before reporting a vulnerability.

## Contributing and releases

Read [`CONTRIBUTING.md`](CONTRIBUTING.md), [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md), and [`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md). Releases use Semantic Versioning and Conventional Commits. `1.0.0-alpha.3` is the current preview; stable `1.0.0` waits for the open acceptance checks to pass.
