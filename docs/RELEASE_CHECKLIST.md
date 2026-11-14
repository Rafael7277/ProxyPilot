# Release readiness checklist

The canonical source is https://github.com/Rafael7277/ProxyPilot. The project uses MIT; release artifacts carry GitHub build provenance attestations and SHA256 checksums.

For subsequent updates, Conventional Commits drive a Release Please PR. CI and CodeQL run before that PR can be reviewed. After it is merged, Actions creates a draft alpha release, rebuilds and verifies the artifacts, attaches provenance, and publishes the draft through the `release` environment. The release channel is intentionally alpha until all stable-release checks below pass; change the release-please prerelease settings in a reviewed PR before starting stable releases.

Before a stable `v1.0.0` tag:

- [x] Headless CLI status tested with `DISPLAY` unset; a remote SSH login remains untested.
- [ ] GUI smoke test under Xvfb; a local XFCE/X11 start/stop smoke passed, but full interaction QA remains open.
- [x] Install, legacy upgrade, rollback-on-service-failure, and uninstall dry-run tested under temporary HOME fixtures with mocked services.
- [ ] App/service mismatch reporting has a real-system baseline; deterministic service fixture coverage remains open.
- [ ] `%U` forwarding and safe D-Bus/action refusal are tested; full file-manager activation and Flatpak/Snap coverage remain open.
- [x] PROXY ONLY fail-closed and AUTO fallback behavior tested with local mock listeners.
- [x] SSH process cleanup protections and pidfd signaling tested.
- [x] `.deb`, source archives, wheel, checksums, metadata, and extracted CLI payload are validated locally.
- [x] Public-tree check covers tracked and unignored untracked files; local configuration and the private audit remain ignored.
- [x] License, maintainer metadata, and repository URL are configured.
- [ ] Private vulnerability reporting is enabled on the GitHub repository.
- [ ] Initial public source push and `1.0.0-alpha.1` release complete successfully in GitHub Actions.
