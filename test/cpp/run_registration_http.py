"""Exercise real registration handlers against a bounded synthetic loopback server."""
import collections
import http.server
import json
import os
import subprocess
import sys
import threading

class Reply(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args): pass
    def do_GET(self): self.reply({})
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.reply(json.loads(body))
    def reply(self, data):
        route = self.path
        email = data.get("email", "")
        cookie = self.headers.get("Cookie", "")
        with self.server.lock:
            self.server.counts[route] += 1
            if route == "/auth/email/signup" and email == "failure@example.com":
                self.server.failure_signups += 1
                reject = self.server.failure_signups == 1
            else: reject = False
            if route == "/auth/api/mfa/verify-enrollment":
                self.server.verification_cookies.append(cookie)
        status = 400 if reject else 200
        headers = {}
        if route == "/auth/csrf": result = {"csrf_token":"synthetic-csrf"}
        elif route == "/auth/email/signup": result = {"success":not reject}
        elif route == "/auth/email/login":
            result = {"success":True}
            headers["Set-Cookie"] = "session=synthetic-" + email.split("@")[0] + "; HttpOnly"
        elif route == "/auth/api/mfa/enroll/totp":
            result = {"secret":"JBSWY3DPEHPK3PXP"}
        elif route == "/auth/api/mfa/verify-enrollment":
            ok = data.get("code") == "123456" and cookie == "session=synthetic-b"
            result = {"success":ok,"backup_codes":["backup-b"] if ok else []}
        else:
            status=404;result={"error":"unexpected synthetic route"}
        payload = json.dumps(result).encode()
        self.send_response(status)
        for key, value in headers.items(): self.send_header(key,value)
        self.send_header("Content-Length",str(len(payload)))
        self.send_header("Content-Type","application/json")
        self.end_headers();self.wfile.write(payload)

def main():
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),Reply)
    server.lock=threading.Lock();server.counts=collections.Counter();server.failure_signups=0;server.verification_cookies=[]
    worker=threading.Thread(target=server.serve_forever,daemon=True);worker.start()
    try:
        result=subprocess.run([sys.argv[1],f"http://127.0.0.1:{server.server_port}"],env={**os.environ,"QUERY_FARM_TELEMETRY_OPT_OUT":"1"},timeout=30)
    finally:
        server.shutdown();server.server_close();worker.join()
    expected={"/auth/csrf":5,"/auth/email/signup":5,"/auth/email/login":4,"/auth/api/mfa/enroll/totp":4,"/auth/api/mfa/verify-enrollment":2}
    counts_ok=dict(server.counts)==expected
    owners_ok=server.verification_cookies==["session=synthetic-b","session=synthetic-b"]
    print("HTTP_COUNTS", "PASS" if counts_ok else "FAIL",dict(server.counts))
    print("HTTP_COOKIE_OWNERS", "PASS" if owners_ok else "FAIL")
    return result.returncode or int(not(counts_ok and owners_ok))
if __name__=="__main__":raise SystemExit(main())
