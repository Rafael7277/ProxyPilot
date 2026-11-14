# Contributing

Thanks for helping improve ProxyPilot. The project is distributed under the MIT License from [Rafael7277/ProxyPilot](https://github.com/Rafael7277/ProxyPilot). The current release is a pre-release; consult `docs/ACCEPTANCE_STATUS.md` before describing functionality as stable.

## Development setup

- Python 3.11 or newer.
- GTK 4/PyGObject for GUI work.
- systemd user manager for runtime integration tests.
- Xvfb and a D-Bus session for GUI smoke tests.

Run the existing suite before submitting changes:

```bash
python3 -m unittest discover -s tests -v
python3 scripts/check_public_tree.py
```

Tests that write configuration or install files must use a temporary HOME. Never test the installer against a developer's active ProxyPilot service.

## Change process

- Use Conventional Commit subjects: `feat:`, `fix:`, `docs:`, `test:`, `build:`, `refactor:`, `security:`.
- Keep route policy and evidence in the shared API layer; do not duplicate behavior between CLI and GUI.
- Add a regression test for each behavior change.
- Keep network tests local and deterministic. Avoid public endpoints in required tests.
- State evidence and limits accurately. A setting saved to disk is not proof that an app uses it.
- Never include real environment files, tokens, user logs, private machine audit data, or application secrets.

## Pull requests

Explain the user-visible change, migration impact, tests run, platforms tested, and any unsupported cases. Do not claim a feature works on a desktop environment that has not been tested.
