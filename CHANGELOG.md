# Changelog

Changes are tracked using Semantic Versioning. Release notes are reviewed before publication.

## [1.0.0-alpha.7](https://github.com/Rafael7277/ProxyPilot/compare/v1.0.0-alpha.6...v1.0.0-alpha.7) (2026-11-14)


### Features

* **ssh:** add two-pane file manager and independent terminals ([#16](https://github.com/Rafael7277/ProxyPilot/issues/16)) ([3017975](https://github.com/Rafael7277/ProxyPilot/commit/30179758cd37fc9a36e3b2648ed38abd4dab8065))

## [1.0.0-alpha.6](https://github.com/Rafael7277/ProxyPilot/compare/v1.0.0-alpha.5...v1.0.0-alpha.6) (2026-11-14)


### Features

* **ssh:** add proxied SSH and SFTP workspace ([#14](https://github.com/Rafael7277/ProxyPilot/issues/14)) ([b6256ec](https://github.com/Rafael7277/ProxyPilot/commit/b6256ec84af6b67fca476f965d5f593cd093625c))

## [1.0.0-alpha.5](https://github.com/Rafael7277/ProxyPilot/compare/v1.0.0-alpha.4...v1.0.0-alpha.5) (2026-11-14)


### Documentation

* refresh preview and acceptance status ([#12](https://github.com/Rafael7277/ProxyPilot/issues/12)) ([cb9a42e](https://github.com/Rafael7277/ProxyPilot/commit/cb9a42eebeeed32871f4614910965ee769941772))

## [1.0.0-alpha.4](https://github.com/Rafael7277/ProxyPilot/compare/v1.0.0-alpha.3...v1.0.0-alpha.4) (2026-11-14)


### Documentation

* select published releases and record alpha3 ([#9](https://github.com/Rafael7277/ProxyPilot/issues/9)) ([c5d946b](https://github.com/Rafael7277/ProxyPilot/commit/c5d946bcc653ab805183de4d94d0d855ee12bf3d))

## [1.0.0-alpha.3](https://github.com/Rafael7277/ProxyPilot/compare/v1.0.0-alpha.2...v1.0.0-alpha.3) (2026-11-14)


### Bug Fixes

* sync package version with release tag ([#6](https://github.com/Rafael7277/ProxyPilot/issues/6)) ([7ba9591](https://github.com/Rafael7277/ProxyPilot/commit/7ba9591d93a92901df1f2011e63df280d25dd138))

## [1.0.0-alpha.2](https://github.com/Rafael7277/ProxyPilot/compare/v1.0.0-alpha.1...v1.0.0-alpha.2) (2026-11-14)


### Bug Fixes

* use GitHub-safe Debian artifact names ([#4](https://github.com/Rafael7277/ProxyPilot/issues/4)) ([66936a3](https://github.com/Rafael7277/ProxyPilot/commit/66936a38d999afd738606abe2cec25b36bf47df2))

## [Unreleased]

### Added

- Separate two-pane SSH/SFTP file manager with independently selectable local or SSH endpoints, including transfers between two servers.
- Drag-and-drop move, multi-item Copy/Cut/Paste, new files and folders, rename, safe delete, overwrite confirmation, progress, and cancellation.
- Independent SSH terminal windows; each New Terminal action opens a fresh verified SSH session and PTY.
- Explicit saved-profile list selection, post-save reselection, and selected-profile deletion state.
- Per-connection ProxyPilot routing for SSH, SFTP, and shell channels. The strict CONNECT route ignores bypass rules and never falls back to a direct connection.
- In-process transfer tests and a GTK display smoke test for profile selection/deletion, two file panes, and multiple terminal windows.

### Security

- Keep SSH passwords out of saved profiles, reject unknown server keys until explicit fingerprint review, and store accepted host keys in a private per-user file.
- Disable the SSH encrypt-then-MAC and CBC algorithm pair on Paramiko builds older than 3.4 as a Terrapin mitigation.

### Changed

- Add Paramiko and GTK 4 VTE runtime dependencies to project metadata and Debian packaging.
- Prepare MIT-licensed source and `1.0.0-alpha.1` GitHub release artifacts.

## [1.0.0-alpha.1] — 2026-11-14

### Added

- Local-only Git feature branch and baseline, architecture, and migration documentation.
- Shared application API for CLI and GTK desktop clients.
- Headless CLI commands for status, diagnostics, app discovery, inspection, connection evidence, route preview/apply, process review, and wrapped command launch.
- GTK 4 desktop client with non-blocking scans and confirmation dialogs for route changes.
- XDG-aware configuration, application, and state paths.
- Explicit AUTO direct-fallback configuration, preserving legacy AUTO behavior by default.
- SOCKS5 IPv4/IPv6 address encoding and local-only SOCKS health handshake.
- Desktop-entry field-code forwarding, correct Desktop Entry quoting, and safe refusal of unsupported D-Bus/action launchers.
- TCP half-close relay support and SSH/shell process cleanup protections.
- User-local installer with dry-run, private backups, ownership checks, rollback, CLI-only mode, and no automatic linger changes.
- Manifest-backed user uninstaller that preserves configuration and refuses removal while managed launchers, service overrides, or global proxy state still depend on the bridge.
- Python packaging metadata, Debian package builder, source archive builder, public-tree check, CI, security check, provenance attestation, and release workflow scaffolding.
- Read-only latest-stable GitHub release lookup, versioned JSON envelopes, process tree/socket details, and process table pagination.

### Fixed

- The health indicator no longer creates repeated outbound connections to a public host; it negotiates only with the configured SOCKS5 listener.
- AUTO can be configured to fail closed instead of silently using direct access.
- IPv6 literal destinations are encoded as IPv6 SOCKS5 requests.
- A client TCP half-close no longer causes the relay to discard the server response.
- Process cleanup protects SSH sessions, shells, and terminal multiplexers.
- Process termination uses pidfds where available and refuses unknown service drop-ins, configuration symlinks, and unknown installer destinations.
- Wayland sessions are not evaluated with X11-only window tools.

### Pending before a stable v1.0.0 release

- Full GUI, package install/upgrade/rollback, SSH, desktop-entry, Flatpak/Snap, and resource benchmark validation.
- Update download/signature verification and rollback implementation.

## 0.8.0 — legacy baseline

- Added read-only Linux proxy diagnostics, bridge evidence, service drop-in inspection, and connection observations.
- Maintained the no-root, no-TUN product boundary.
- Existing user configuration and unrelated application settings were intentionally preserved by the legacy installer.
