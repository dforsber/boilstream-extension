"""Real loopback /match responses; no production credentials or external service."""

import http.server
import json
import os
import queue
import subprocess
import sys
import threading

from run_required_response_signature import now, sign


class Authority(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        server = self.server
        request = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        if self.path != "/secrets/match" or request.get("type") != "owned_test":
            self.send_error(400)
            return
        if not server.fixture_ready.wait(10):
            return
        with server.lock:
            server.count += 1
            number = server.count
            server.active += 1
            server.maximum_active = max(server.maximum_active, server.active)
            server.sequences.append(self.headers.get("X-Boilstream-Sequence"))
        response_finished = False
        try:
            if number == 1:
                server.first_arrived.set()
                if not server.release_first.wait(10):
                    return
            body = server.fixture
            headers = {"x-boilstream-date": now()}
            headers["x-boilstream-response-signature"] = sign(body, 200, headers)
            # Hold accounting lock through final flush/decrement so a correctly
            # serialized next request cannot race the handler's bookkeeping.
            with server.lock:
                try:
                    self.send_response(200)
                    for key, value in headers.items():
                        self.send_header(key, value)
                    self.send_header("Content-Length", str(len(body.encode())))
                    self.end_headers()
                    self.wfile.write(body.encode())
                    self.wfile.flush()
                finally:
                    server.active -= 1
                    response_finished = True
        finally:
            if not response_finished:
                with server.lock:
                    server.active -= 1


def run_case(mode):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Authority)
    server.daemon_threads = True
    server.lock = threading.Lock()
    server.count = server.active = server.maximum_active = 0
    server.sequences = []
    server.fixture_ready = threading.Event()
    server.first_arrived = threading.Event()
    server.release_first = threading.Event()
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    process = None
    output = queue.Queue()
    try:
        process = subprocess.Popen(
            [sys.argv[1], f"http://127.0.0.1:{server.server_port}/secrets", mode],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env={**os.environ, "QUERY_FARM_TELEMETRY_OPT_OUT": "1"},
        )

        def read_output():
            for line in process.stdout:
                output.put(line.rstrip("\n"))
            output.put(None)

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        first = output.get(timeout=15)
        assert first and first.startswith("FIXTURE "), "fixture unavailable"
        server.fixture = first.removeprefix("FIXTURE ")
        assert json.loads(server.fixture)["expires_at"] is None
        server.fixture_ready.set()
        assert server.first_arrived.wait(10), "first request unavailable"
        process.stdin.write("start-second\n")
        process.stdin.flush()
        second = output.get(timeout=5)
        assert second in ("SECOND_RETURNED", "SECOND_PENDING"), "second lookup unavailable"
        server.release_first.set()
        result = process.wait(timeout=20)
        reader.join(timeout=2)
        while not output.empty():
            line = output.get_nowait()
            if line and line.startswith("CASE "):
                print(line)
        expected = ["0", "1"] if mode == "normal" else ["0"]
        serial = server.count == len(expected) and server.maximum_active == 1 and server.sequences == expected
        print("CASE signed_requests_" + mode, "PASS" if serial else "FAIL")
        print("HTTP_REQUESTS", mode, server.count)
        return result or int(not serial)
    except Exception:
        print("CASE concurrent_lookup_harness FAIL")
        return 1
    finally:
        server.fixture_ready.set()
        server.release_first.set()
        if process and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        server.shutdown()
        server.server_close()
        serving.join(timeout=2)


if __name__ == "__main__":
    results = [
        run_case(mode) for mode in ("normal", "expired", "replaced", "generation", "cancelled", "cancelled_cached")
    ]
    raise SystemExit(int(any(results)))
