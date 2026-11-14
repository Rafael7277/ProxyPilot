# ProxyPilot 1.0 acceptance status

Status for the current ProxyPilot 1.0 preview source. “Pass” means an isolated automated check or a bounded local smoke test passed. It does not imply that a stable release is ready.

| # | Acceptance criterion | Status and evidence |
| --- | --- | --- |
| 1 | GUI and CLI report the same state | Partial. Both call `proxypilot_app.api`; headless CLI and GTK startup pass independently. A value-by-value GUI/CLI integration assertion is not implemented. |
| 2 | SSH without `DISPLAY` | Pass for headless mode. `test_status_json_runs_without_display_or_gui_import`; no separate remote SSH login was available. |
| 3 | Per-app route evidence | Partial. `test_live_local_proxy_socket_owner`, `test_xray_socket_is_observation_not_end_to_end_proof`, and process/PID correlation tests pass. A real application transaction through an isolated proxy was not run. |
| 4 | Desktop/service policy mismatch | Partial. `api.inspect` compares app and service policies. A deterministic service-specific fixture test is still needed. |
| 5 | Bridge through SOCKS5 | Pass against a local mock SOCKS5 endpoint. `test_proxy_only_bridge_uses_configured_socks5_upstream` verifies negotiation, destination, request, and response without an external service. |
| 6 | AUTO direct fallback policy | Pass. `test_http_forward_via_auto_direct_fallback`, `test_auto_fails_closed_when_direct_fallback_is_disabled`, and `test_proxy_upstream_fallback`. |
| 7 | PROXY ONLY does not fall back directly | Pass. `test_proxy_only_does_not_fall_back_to_direct` receives 502 and confirms the direct listener received no connection. |
| 8 | Route changes affect new connections | Pass at bridge level. `test_route_changes_live_on_new_connections`. Existing TCP connections are not migrated. |
| 9 | Desktop file/URL launching | Partial. `%U` argument forwarding and managed-launcher restore are tested. Actual file-manager activation, `%f/%F`, Snap/Flatpak, and supported D-Bus activation remain open; unsupported D-Bus/action launchers are refused. |
| 10 | Cleaner protects SSH | Pass for signal protection and PID reuse. `test_protects_ssh_and_shell_processes_from_cleanup_signals`, `test_refuses_to_kill_reused_pid`. |
| 11 | Install/uninstall preserve user settings | Partial. Isolated tests preserve unrelated launchers, environment.d, and config files and verify dry-run/rollback. Service-specific files and live GNOME preservation have not been exercised end-to-end. |
| 12 | Upgrade from current version | Pass in temporary HOME fixtures for legacy config and old source modules. The real installation has not been upgraded. |
| 13 | Debian package build | Partial. `build_release.py` creates amd64 `.deb`, checks metadata/checksums, extracts it, and runs the packaged CLI version. Root-level `dpkg -i` install/upgrade was deliberately not run. |
| 14 | GitHub Actions | Pass. GitHub run `43588096509` passed the unit/integration suite, GTK smoke under Xvfb, artifact build, CodeQL, and Python 3.11/3.14 matrix; security checks passed in `43588096558`. |
| 15 | Release artifact generation | Pass for `1.0.0-alpha.4`: source `.tar.gz`, source `.zip`, amd64 `.deb`, wheel, and `SHA256SUMS` were built and published. Downloaded assets pass `sha256sum --check`; Debian metadata and architecture were inspected. Release workflow `43587771541` verified build provenance for every asset before publication. |
| 16 | Update discovery and installation | Partial. Latest-stable release metadata lookup is implemented and mock-tested. Download/install and update rollback are not implemented; GitHub build provenance is provided for release artifacts. |
| 17 | Rollback | Partial. Isolated installer test `test_service_failure_rolls_back_code_and_unit_files` verifies restoration after a mocked service failure. In-place update rollback is not implemented. |
| 18 | Errors are reported honestly | Partial. Proxy errors, missing service state, proxy mismatch warnings, and unverified evidence have tests. Broader real-network/system failure coverage remains open. |

## Stable-release blockers

- Update installation and rollback are missing.
- The 1.0 GTK UI has only startup/shutdown smoke coverage, not full interaction QA.
- The live installation and system proxy settings were not changed or restarted during development.
- Real SSH, desktop-entry, Flatpak/Snap, resource benchmark, and full system-package install/upgrade checks remain open.
