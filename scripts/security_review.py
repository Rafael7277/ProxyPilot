#!/usr/bin/env python3
"""Small deterministic source checks for unsafe dynamic execution patterns."""
from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
FORBIDDEN_CALLS={"eval","exec"}


def main() -> int:
    files=list(ROOT.rglob("*.py"))
    failures=[]
    for path in files:
        if any(part in {".git","__pycache__","build","dist"} for part in path.parts):continue
        try:tree=ast.parse(path.read_text(encoding="utf-8"),filename=str(path))
        except (OSError,SyntaxError) as exc:
            failures.append(f"cannot parse {path.relative_to(ROOT)}: {exc}");continue
        for node in ast.walk(tree):
            if not isinstance(node,ast.Call):continue
            name=(node.func.id if isinstance(node.func,ast.Name) else
                  node.func.attr if isinstance(node.func,ast.Attribute) else "")
            if name in FORBIDDEN_CALLS:
                failures.append(f"dynamic {name} at {path.relative_to(ROOT)}:{node.lineno}")
            if isinstance(node.func,ast.Attribute) and node.func.attr=="system" and \
                    isinstance(node.func.value,ast.Name) and node.func.value.id=="os":
                failures.append(f"os.system at {path.relative_to(ROOT)}:{node.lineno}")
            if isinstance(node.func,ast.Attribute) and node.func.attr in {"run","Popen","call","check_call","check_output"}:
                if any(k.arg=="shell" and isinstance(k.value,ast.Constant) and k.value.value is True
                       for k in node.keywords):
                    failures.append(f"shell=True at {path.relative_to(ROOT)}:{node.lineno}")
    if failures:
        print("Security source review failed:",file=sys.stderr)
        print("\n".join("- "+x for x in failures),file=sys.stderr)
        return 1
    print(f"Security source review passed ({len(files)} Python files parsed).")
    return 0


if __name__=="__main__":raise SystemExit(main())
