"""Check faithful SQL results/errors and connection isolation without a server."""

import json
import os
import subprocess
import sys


def main():
    driver, httpfs, quack, extension = sys.argv[1:]
    commands = [
        {"httpfs": httpfs, "quack": quack, "extension": extension},
        {"op": "connect"},
        {"op": "query", "connection": 1, "sql": "SELECT version() AS version"},
        {"op": "query", "connection": 1, "sql": "SELECT 'a' || chr(0) || 'b' AS value, NULL AS absent"},
        {"op": "query", "connection": 1, "sql": "CREATE TEMP TABLE only_owner AS SELECT 42 AS value"},
        {"op": "connect"},
        {"op": "query", "connection": 2, "sql": "SELECT * FROM only_owner"},
        {"op": "query", "connection": 1, "sql": "SELECT * FROM only_owner"},
        {"op": "query", "connection": 2, "sql": "SELECT 'healthy' AS value"},
        {"op": "close", "connection": 1},
        {"op": "close", "connection": 2},
        {"op": "quit"},
    ]
    result = subprocess.run(
        [driver],
        input="".join(json.dumps(command) + "\n" for command in commands),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(replies) == len(commands), "Driver dropped or duplicated a reply"
    assert replies[0] == {"ready": True}
    assert replies[1] == {"connection": 1} and replies[5] == {"connection": 2}
    assert replies[2] == {"rows": [{"version": "v2.0.0"}]}
    assert replies[3] == {"rows": [{"value": "a\x00b", "absent": None}]}, "Lossy SQL result encoding"
    assert "does not exist" in replies[6]["error"], "Sibling inherited a temporary table"
    assert replies[7] == {"rows": [{"value": "42"}]}
    assert replies[8] == {"rows": [{"value": "healthy"}]}, "Expected error poisoned healthy connection"
    print("Native SQL adapter: exact values, NULL, errors and connection isolation PASS")


if __name__ == "__main__":
    main()
