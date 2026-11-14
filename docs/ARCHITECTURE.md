# Architecture and support contract

## Product boundary

ProxyPilot 1.0 manages proxy-aware applications and services. Its HTTP bridge sends supported HTTP/HTTPS proxy requests to a SOCKS5 upstream. AUTO may use direct fallback only when the user enables it. PROXY ONLY fails closed for requests that actually use the bridge. The product does not claim to intercept arbitrary sockets, UDP, or all system traffic.

## Shared application core

The GUI and CLI call the same service layer for configuration, app discovery, policy evaluation, diagnostics, connection observations, and route changes. Legacy user configuration at `~/.config/proxypilot/config.json` is migrated atomically to schema version 1, with a private pre-migration backup and unknown keys preserved.

## Evidence model

Each app view reports four separate fields: requested policy, effective configuration, observed connections, and verification result. Evidence must include source and time. A socket to Xray is evidence of a local proxy connection, not proof that all app traffic or final egress used the proxy. Missing evidence means unable to verify.

## Privilege model

Normal operation and user-service integration run without root. Any future TUN or transparent-routing helper is a separate, optional component with a narrow interface and its own security review.

## Runtime adapters

- Linux process and socket observation: `/proc`, scoped to the current UID and subject to kernel visibility limits.
- User services: `systemctl --user`, with clear diagnostics for an unavailable user manager or D-Bus.
- Desktop launchers: FreeDesktop desktop-entry syntax, including D-Bus activation, field codes, actions, and sandbox limitations.
- System proxy: GNOME GSettings and systemd user environment are separate adapters; unsupported desktop settings are reported as unsupported.
- SSH/headless: CLI is first-class and cannot require `DISPLAY` or GTK.

## Components

The first 1.0 development slice keeps the tested legacy bridge modules in place while introducing a shared API package for the new CLI and GTK UI. A later move to a `src/` layout must retain legacy module entry points and be completed only with migration and install tests.

## Remote access

`proxypilot_app.remote_access` owns SSH profiles, host-key trust, the optional loopback HTTP CONNECT tunnel, authenticated SSH transports, and SFTP operations. `remote_ui` manages profiles and opens windows; `remote_windows` provides the two-endpoint file manager and one-shell-per-window terminal. Passwords remain in process memory only for the profile page or file-manager window lifetime so a lost transport can reconnect; they are excluded from profile serialization and logs. SSH keys are checked against the operating-system known-hosts database and ProxyPilot's mode-0600 per-user known-hosts file. A new key is rejected until the user reviews its SHA256 fingerprint.

The SSH profile page owns the primary verified connection and its Connect/Disconnect control. File-manager panes auto-connect when a profile is selected; the initial pane gets its own SFTP channel on a reference-counted SSH transport. Terminal windows establish independent SSH transports and shells automatically, without an in-window connect control. The file-manager toolbar keeps only Cancel transfer; other file actions live in a right-click menu.

SFTP transport loss triggers up to three reconnect attempts with bounded backoff. Transfers use unique hidden staging paths, compare the source size and modification time before resuming, and continue regular files from the existing partial offset. Staged directory copies retain completed children and resume their current partial file. Unknown host keys, authentication failures, changed source metadata, and permission errors stop the retry loop; a new host key is never trusted automatically.

The profile page offers a masked password field instead of an identity-file path. A supplied password is retained only in application memory for the current run, passed to newly opened SFTP and terminal sessions, cleared when the page shuts down, and excluded from logs and the on-disk profile JSON. Leaving it blank retains the interactive authentication prompt.

PyPI installs require Paramiko 3.4 or newer. Older distro-maintained builds are accepted for compatibility, with the affected encrypt-then-MAC and CBC algorithms disabled during SSH negotiation.

When the profile's proxy option is enabled, the client connects only to ProxyPilot's loopback proxy listener and requests a strict proxy route. That request ignores ordinary bypass entries and cannot use AUTO direct fallback. The SSH shell and SFTP channels share the verified SSH transport, so the checkbox applies to both. A proxy failure is reported as a failed connection; it never triggers a second direct SSH attempt.

The file manager has two independent endpoints, each either local or backed by its own saved SSH profile and verified session. Files and directories can be copied or moved between local storage and two servers. File replacement uses a temporary sibling and rename; directory copies are staged and published only when complete. Overwrites require UI confirmation, symlinks are refused, and directory deletion is limited to empty directories. Transfers run on worker threads with cancellation checks. Every terminal window owns a separate verified SSH session and PTY; VTE provides terminal rendering and input, while shell I/O runs off the GTK thread.
