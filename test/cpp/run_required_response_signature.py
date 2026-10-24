"""Independent protocol signatures, no real credentials or external services."""

import base64
import datetime
import hashlib
import hmac
import http.server
import json
import os
import subprocess
import sys
import threading


def sign(body, status, headers, key=bytes([7]) * 64):
    prk = hmac.new(b"boilstream-session-v1", key, hashlib.sha256).digest()
    integrity = hmac.new(prk, b"response-integrity-v1\x01", hashlib.sha256).digest()
    fields = sorted(
        (k.lower(), v)
        for k, v in headers.items()
        if k.lower().startswith("x-boilstream-") and k.lower() != "x-boilstream-response-signature"
    )
    canonical = (
        str(status)
        + "\n"
        + "".join(k + ":" + v + "\n" for k, v in fields)
        + "\n"
        + ";".join(k for k, v in fields)
        + "\n"
        + hashlib.sha256(body.encode()).hexdigest()
    )
    return base64.b64encode(hmac.new(integrity, canonical.encode(), hashlib.sha256).digest()).decode()


def now(offset=0):
    return (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=offset)).strftime(
        "%Y%m%dT%H%M%SZ"
    )


def fixtures():
    rows = []

    def add(name, date=None, reject=False, headers=None, mutate=None, wrong_key=False):
        h = dict(headers or {})
        if date is not None:
            h["x-boilstream-date"] = date
        body = "synthetic-result"
        status = 200
        h["x-boilstream-response-signature"] = sign(body, status, h)
        row = dict(
            name=name,
            headers=h,
            body=body,
            status=status,
            reject=reject,
            wrong_key=wrong_key,
        )
        if mutate:
            mutate(row)
        rows.append(row)

    add("valid_current_signature", now())
    add("valid_recent_signature", now(-30))
    add("valid_near_future_signature", now(30))
    add(
        "missing_signature_rejected",
        now(),
        True,
        mutate=lambda r: r["headers"].pop("x-boilstream-response-signature"),
    )
    add(
        "empty_signature_rejected",
        now(),
        True,
        mutate=lambda r: r["headers"].update({"x-boilstream-response-signature": ""}),
    )
    add(
        "request_signature_is_not_response_signature",
        now(),
        True,
        mutate=lambda r: r["headers"].update(
            {"x-boilstream-signature": r["headers"].pop("x-boilstream-response-signature")}
        ),
    )
    add("missing_signed_timestamp_rejected", None, True)
    for label, date in [
        ("malformed", "not-a-date"),
        ("embedded_nul", now() + "\0ignored"),
        ("leading_space", " " + now()),
        ("trailing_space", now() + " "),
        ("invalid_minute", "20261017T126000Z"),
        ("invalid_second", "20261017T120060Z"),
        ("wrong_width", "20261017T120000ZZ"),
        ("non_digit", "20261017Txx0000Z"),
        ("invalid_calendar", "20260230T120000Z"),
        ("invalid_hour", "20261017T990000Z"),
        ("stale", now(-120)),
        ("future", now(120)),
    ]:
        add("signed_" + label + "_timestamp_rejected", date, True)
    add("wrong_session_key_rejected", now(), True, wrong_key=True)
    add(
        "body_tampering_rejected",
        now(),
        True,
        mutate=lambda r: r.update(body="modified"),
    )
    add("status_tampering_rejected", now(), True, mutate=lambda r: r.update(status=201))
    add(
        "signed_header_tampering_rejected",
        now(),
        True,
        headers={"x-boilstream-encrypted": "false"},
        mutate=lambda r: r["headers"].update({"x-boilstream-encrypted": "true"}),
    )
    return rows


class Reply(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.reply()

    def do_DELETE(self):
        self.reply()

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.reply()

    def reply(self):
        _, method, mode = self.path.split("/")
        with self.server.lock:
            self.server.count += 1
        body = "synthetic-result"
        headers = {
            "x-boilstream-date": (now(-120) if mode == "stale" else "not-a-date" if mode == "bad-date" else now())
        }
        if mode != "missing":
            headers["x-boilstream-response-signature"] = sign(
                body, 200, headers, bytes([9 if mode == "wrong-key" else 7]) * 64
            )
        if mode == "malformed":
            headers["x-boilstream-response-signature"] = "invalid"
        if mode == "tampered":
            body = "modified"
        self.send_response(200)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())


def main():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Reply)
    server.lock = threading.Lock()
    server.count = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        r = subprocess.run(
            [sys.argv[1], f"http://127.0.0.1:{server.server_port}"],
            input=json.dumps(fixtures()),
            text=True,
            env={**os.environ, "QUERY_FARM_TELEMETRY_OPT_OUT": "1"},
            timeout=30,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    print("HTTP_REQUESTS", server.count)
    return r.returncode or int(server.count != 33)


if __name__ == "__main__":
    raise SystemExit(main())
