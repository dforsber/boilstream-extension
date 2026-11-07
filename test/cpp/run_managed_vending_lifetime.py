"""Held actual managed GETs with independent response HMAC and owner controls."""
import datetime
import http.server
import json
import os
import queue
import subprocess
import sys
import threading
import urllib.parse

from run_required_response_signature import now, sign

CATALOG = "9a927d1b-30f5-48da-91eb-af1492bf31c0"


class Authority(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path != "/secrets/quack/credentials" or query.get("catalog_id") != [CATALOG]:
            self.send_error(400)
            return
        server = self.server
        with server.lock:
            server.count += 1
            number = server.count
            server.sequences.append(self.headers.get("X-Boilstream-Sequence"))
        if number == 1:
            server.first_arrived.set()
            if not server.release_first.wait(10):
                return
        elif number != 2:
            self.send_error(409)
            return
        body = json.dumps(
            {
                "token": "synthetic-old-token" if number == 1 else "synthetic-fresh-token",
                "expires_at": (
                    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "endpoint": "server.example:443",
                "catalog_id": CATALOG,
                "storage_owner_tenant_id": 42,
                "catalog_group": CATALOG.replace("-", "_"),
                "server_ca_pem": "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n",
            },
            separators=(",", ":"),
        )
        headers = {"x-boilstream-date": now()}
        headers["x-boilstream-response-signature"] = sign(body, 200, headers)
        self.send_response(200)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())
        self.wfile.flush()


def run_case(lane, mode):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Authority)
    server.daemon_threads = False
    server.lock = threading.Lock()
    server.count = 0
    server.sequences = []
    server.first_arrived = threading.Event()
    server.release_first = threading.Event()
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    process = None
    reader = None
    output = queue.Queue()
    try:
        process = subprocess.Popen(
            [sys.argv[1], f"http://127.0.0.1:{server.server_port}/secrets", lane, mode],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env=dict(os.environ, QUERY_FARM_TELEMETRY_OPT_OUT="1"),
        )

        def read_output():
            for line in process.stdout:
                output.put(line.strip())

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        assert output.get(timeout=10) == "READY", "fixture admission failed"
        assert server.first_arrived.wait(10), "actual managed GET did not arrive"
        process.stdin.write("mutate-held\n")
        process.stdin.flush()
        assert output.get(timeout=10) == "HELD_MUTATION_APPLIED", "held mutation not observed"
        server.release_first.set()
        code = process.wait(timeout=15)
        reader.join(timeout=2)
        assert not reader.is_alive(), "fixture output did not drain"
        rows = []
        while not output.empty():
            rows.append(output.get_nowait())
        expected = [f"CASE held_{lane}_{mode} PASS", f"CASE fresh_owner_{lane}_{mode} PASS"]
        assert code == 0 and rows == expected, "exact managed native oracles failed"
        assert server.count == 2 and server.sequences == ["0", "0"], "managed owner/HTTP count changed"
        for row in rows:
            print(row)
        print(f"CASE signed_managed_requests_{lane}_{mode} PASS")
        return 0
    except Exception:
        print(f"CASE managed_lifetime_{lane}_{mode} FAIL")
        return 1
    finally:
        server.release_first.set()
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if reader:
            reader.join(timeout=2)
        server.shutdown()
        server.server_close()
        serving.join(timeout=2)


if __name__ == "__main__":
    outcomes = [
        run_case(lane, mode)
        for lane in ("vend", "named")
        for mode in ("normal", "generation", "replaced", "cancelled", "expired", "logout")
    ]
    raise SystemExit(int(any(outcomes)))
