"""Synthetic loopback responses; output only case outcomes and request counts."""
import http.server
import os
import subprocess
import sys
import threading
from run_required_response_signature import sign, now

class Reply(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass
    def do_DELETE(self):
        self.reply()
    def do_GET(self):
        self.reply()
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.reply()
    def reply(self):
        scenario = self.path.split("/")[1]
        key = self.command + " " + self.path
        self.server.requests[key] = self.server.requests.get(key, 0) + 1
        status = 200
        marker = "private_diagnostic_marker_A7"
        body = '{"error":"' + marker + '"}'
        cookie = False
        if scenario.isdigit():
            status = int(scenario)
        elif self.path.endswith("/auth/csrf"):
            if scenario in ("csrf-invalid", "register-csrf-invalid"): body = marker
            elif scenario in ("csrf-http", "register-csrf-http"): status = 403
            elif scenario != "csrf-missing": body = '{"csrf_token":"' + marker + '"}'
        elif self.path.endswith("/auth/email/signup"):
            body = '{"success":false,"error":"' + marker + '"}'
        elif self.path.endswith("/auth/email/login"):
            if scenario == "login-http": status = 403
            elif scenario != "login-cookie": cookie = True
        elif "/mfa/" in self.path:
            if scenario == "mfa-invalid": body = marker
            elif scenario == "bootstrap-invalid": body = '{"success":true}'
            else: body = '{"success":false,"error":"' + marker + '"}'
        else:
            body = marker
        body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookie: self.send_header("Set-Cookie", ("unexpected=" if scenario == "login-malformed-cookie" else "session=") + marker + "; HttpOnly")
        if self.command == "GET" and status == 200:
            headers = {"x-boilstream-date": now()}
            headers["x-boilstream-response-signature"] = sign(body.decode(), status, headers, bytes([9]) * 32)
            for name, value in headers.items(): self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

def main():
    server = http.server.HTTPServer(("127.0.0.1", 0), Reply)
    server.requests = {}
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        result = subprocess.run([sys.argv[1], f"http://127.0.0.1:{server.server_port}"],
                                env={**os.environ, "QUERY_FARM_TELEMETRY_OPT_OUT": "1"}, timeout=30)
    finally:
        server.shutdown(); server.server_close(); worker.join()
    counts = {}
    for path, count in server.requests.items():
        scenario = path.split("/")[1]
        counts[scenario] = counts.get(scenario, 0) + count
    print(f"HTTP_REQUESTS {counts}")
    expected = {"200":2,"403":3,"400":1,"429":4,"501":1,"csrf-invalid":1,"csrf-missing":1,"csrf-http":2,
                "login-http":2,"login-cookie":2,"login-malformed-cookie":2,"mfa-invalid":3,"mfa-rejected":3,"bootstrap-invalid":4,"register-csrf-invalid":1,"register-csrf-http":1,"register-signup-rejected":2}
    return result.returncode or int(counts != expected)

if __name__ == "__main__":
    raise SystemExit(main())
