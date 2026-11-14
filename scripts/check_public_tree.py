#!/usr/bin/env python3
"""Reject obvious local-machine artifacts from the public source tree."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT=Path(__file__).resolve().parents[1]
FORBIDDEN_NAMES={"config.json", ".env", ".env.local", "LOCAL_AUDIT.private.md"}
PRIVATE_FRAGMENTS=(b"/home/"+b"rafael/", b"SSH_"+b"CONNECTION=",
                   b"api_"+b"key=", b"access_"+b"token=")


def main() -> int:
    tracked=subprocess.run(["git","-C",str(ROOT),"ls-files","--cached","--others",
                            "--exclude-standard","-z"],capture_output=True)
    if tracked.returncode:
        print("Public-tree check requires a Git worktree.",file=sys.stderr);return 2
    bad=[]
    for raw in tracked.stdout.split(b"\0"):
        if not raw:continue
        rel=Path(raw.decode("utf-8","replace"))
        if rel.name in FORBIDDEN_NAMES:
            bad.append(f"sensitive filename: {rel}");continue
        path=ROOT/rel
        try:data=path.read_bytes()
        except OSError:continue
        for fragment in PRIVATE_FRAGMENTS:
            if fragment.lower() in data.lower():
                bad.append(f"private-value pattern {fragment.decode('ascii','replace')!r}: {rel}")
                break
    if bad:
        print("Public source tree check failed:",file=sys.stderr)
        print("\n".join(f"- {x}" for x in bad),file=sys.stderr)
        return 1
    print("Public source tree check passed (tracked and unignored untracked files).")
    return 0


if __name__=="__main__":raise SystemExit(main())
