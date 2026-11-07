#!/usr/bin/env python3
"""Require every native SQL file to execute: no whole-file or statement skips.

The pinned upstream runner's --fail-require-skip scans stdout while this host
reports skips on stderr. Consume its structured terminal events on both streams
instead. Community build/test entrypoints are not changed.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def verify(output, expected):
    completed = {}
    for line in output.splitlines():
        if "[TEST_EVENT] " not in line:
            continue
        event = json.loads(line.split("[TEST_EVENT] ", 1)[1])
        if event.get("event") != "end":
            continue
        name = event["name"]
        if name in completed:
            raise ValueError(f"Duplicate terminal test event: {name}")
        completed[name] = event
        if (event.get("status") != "ok" or event.get("fails") != 0
                or event.get("skip-mode") != 0 or event.get("partial-skip-reasons")
                or not isinstance(event.get("passes"), int) or event["passes"] <= 0):
            raise ValueError(f"Native SQL test failed, skipped or empty: {name}: {event.get('status')}")
    if set(completed) != set(expected):
        raise ValueError(f"Native SQL inventory mismatch: expected {sorted(expected)}, got {sorted(completed)}")
    return sum(event["passes"] for event in completed.values())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default="build/release/test/unittest")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    expected = {p.relative_to(root).as_posix() for p in (root / "test/sql").glob("*.test")}
    if not expected:
        raise ValueError("No native SQL tests found")
    result = subprocess.run([str((root / args.binary).resolve()), "test/sql/*", "--emit-test-events"],
                            cwd=root, capture_output=True, text=True, timeout=180)
    output = result.stdout + "\n" + result.stderr
    try:
        if result.returncode:
            raise ValueError(f"Native unittest exited {result.returncode}")
        assertions = verify(output, expected)
    except (ValueError, KeyError):
        print(output, file=sys.stderr)
        raise
    print(f"PASS {len(expected)} native SQL files, {assertions} assertions, zero skips")


if __name__ == "__main__":
    main()
