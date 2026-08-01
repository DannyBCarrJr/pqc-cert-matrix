#!/usr/bin/env python3
"""Shared JSON emitter for runners. See CONTRACT.md.

Usage:
  emit.py CLIENT VERSION parse RC FILE verify RC FILE handshake RC FILE

RC is an integer return code, or the literal `skip`, in which case FILE is the
skip reason instead of a path.
"""
import json
import sys


def cell(rc: str, arg: str) -> dict:
    if rc == "skip":
        return {"status": "skip", "detail": arg}
    try:
        out = open(arg, errors="replace").read().strip()
    except OSError:
        out = ""
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    ok = int(rc) == 0
    detail = (lines[-1] if lines else "") if ok else " | ".join(lines[-2:])
    return {"status": "ok" if ok else "fail", "detail": detail[:400]}


def main() -> None:
    client, version = sys.argv[1], sys.argv[2]
    rest = sys.argv[3:]
    tests = {}
    for i in range(0, len(rest), 3):
        name, rc, arg = rest[i], rest[i + 1], rest[i + 2]
        tests[name] = cell(rc, arg)
    print(json.dumps({"client": client, "client_version": version, "tests": tests}))


if __name__ == "__main__":
    main()
