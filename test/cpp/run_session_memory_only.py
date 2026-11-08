"""Run the memory-only session regression with a rejecting loopback authority."""

import http.server
import os
import subprocess
import sys
import threading


class RejectLogin(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_POST(self):
        self.server.requests += 1
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.server.handshakes.append(body)
        if (
            self.path != "/auth/api/protocol/v2/handshake"
            or self.headers.get("Cookie")
            or self.headers.get("Authorization")
            or any(
                value in body for value in (b"synthetic-access-token", b"synthetic-bootstrap-identity", bytes([9]) * 32)
            )
        ):
            self.server.invalid = True
        body = b'{"error":"fixture rejection"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    server = http.server.HTTPServer(("127.0.0.1", 0), RejectLogin)
    server.requests = 0
    server.handshakes = []
    server.invalid = False
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = subprocess.run(
            [sys.argv[1], f"http://127.0.0.1:{server.server_port}/secrets"],
            timeout=60,
            check=False,
            env={**os.environ, "QUERY_FARM_TELEMETRY_OPT_OUT": "1"},
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    # Only the valid, connection-owned refresh credential may reach the network.
    print(f"HTTP_REQUESTS {server.requests}")
    return (
        result.returncode
        if result.returncode
        else int(server.requests != 2 or server.invalid or len(set(server.handshakes)) != 2)
    )


if __name__ == "__main__":
    raise SystemExit(main())
