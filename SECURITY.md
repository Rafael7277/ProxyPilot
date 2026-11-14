# Security policy

ProxyPilot handles proxy configuration and process metadata. Do not file a public issue containing credentials, proxy URLs with passwords, private hostnames, full process environments, or traffic logs.

Report suspected vulnerabilities privately using GitHub's **Report a vulnerability** feature on the [ProxyPilot security page](https://github.com/Rafael7277/ProxyPilot/security/advisories/new). Do not open a public issue for an unpatched vulnerability. Include the affected version, reproduction steps with secrets removed, and impact. Do not attach real user configuration unless it has been sanitized.

Security-sensitive areas include desktop-entry rewriting, user-service overrides, configuration migration, process termination, proxy URL redaction, local listener binding, update verification, and package installation/rollback.

SSH-related security properties: profile files are stored with owner-only permissions and contain no passwords; private key material is referenced by path and never copied. Unknown host keys are rejected until a user confirms the displayed fingerprint. Existing key mismatches are not silently replaced. SSH/SFTP traffic marked to use ProxyPilot goes through the loopback proxy-only listener and fails closed if that route is unavailable. Connection logs never record SSH payloads or terminal content.

PyPI installations require Paramiko 3.4 or newer. On older distribution-managed builds, the client disables the affected encrypt-then-MAC and CBC algorithms during negotiation.
