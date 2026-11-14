# Linux support matrix

Status reflects tested implementation, not aspiration.

| Environment / feature | Current status | Notes |
| --- | --- | --- |
| Ubuntu 26.04, XFCE, X11 | Development target | Runtime inspection and a two-second GTK startup/shutdown smoke passed; the host GTK3-era theme emitted GTK4 CSS warnings. Full interaction QA remains open. |
| GNOME proxy settings | Implemented, integration tests pending | Uses `gsettings` plus user systemd environment. |
| KDE Plasma proxy settings | Unsupported | System proxy adapter does not write KDE settings. |
| Wayland window attribution | Conservative / unknown | X11 window tools are skipped for Wayland; process and TCP scans remain best-effort. |
| Headless SSH CLI | Local headless smoke passed | JSON status works with `DISPLAY` removed and without importing GTK. A separate remote SSH login was not available. |
| SSH / SFTP workspace | Local protocol tests and GTK window smoke pass | The separate two-pane manager supports local/remote and remote/remote transfers; saved profile selection/deletion and opening multiple terminal windows are smoke-tested. Physical drag/drop and a live login to a separately configured server still need manual interoperability acceptance. |
| Embedded SSH terminal | Implemented with GTK 4 VTE | Requires `gir1.2-vte-3.91` and a supported GTK 4 PyGObject environment. SFTP does not require VTE. |
| User systemd bridge service | Implemented | Requires an active user manager; linger is detected but never enabled automatically. |
| Non-systemd distributions | Unsupported for service integration | CLI diagnostics and direct process inspection may work; service install does not. |
| Per-app desktop launching | Partial | `%U` forwarding is tested. D-Bus-activatable entries and entries with desktop actions are rejected instead of being falsely marked managed. |
| Debian package | Built and payload-validated | The package is extracted into a temporary directory and its CLI version command is exercised; it was not installed through `dpkg` on the real host. |
| GitHub update check | Implemented for the canonical repository | Reads latest stable release metadata, with a pre-release fallback for alpha builds; download/install is not available. |
| Flatpak / Snap | Discovery best-effort | Sandbox environment and app-to-process correlation need dedicated tests. |
| TUN / all-packet routing | Not implemented | No claim of universal TCP/UDP coverage. |

Do not mark an environment Supported until its CI and manual test plan passes.
