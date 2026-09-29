"""The e2e workspace's one application: just enough HTTP to be asserted against.

    /          200 "hello from the workspace" — the thing an owner may open and a stranger may not
    /healthz   200 "ok" — the path a `rules` entry opens to anonymous callers
    /headers   200, the request's headers as JSON — how a test sees what crossed the gate
    /login     POST: a form login, 200 + Set-Cookie session=<token> for the right credential
    /private   200 with a valid session cookie, 401 without — what preauth-proxy logs into
    /expire    POST: forget every session, so the next /private is a 401 and the proxy renews

Standard library only: the image stays small, and nothing here needs more.
"""

import json
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

SESSIONS = set()
USER = os.environ.get("E2E_LOGIN_USER", "robot")
SECRET = os.environ.get("E2E_LOGIN_SECRET", "robot-secret")


def session_of(cookie_header):
    for part in (cookie_header or "").split(";"):
        name, _, value = part.strip().partition("=")
        if name == "session":
            return value
    return None


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body, content_type="text/plain", cookie=None):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/":
            self.reply(200, "hello from the workspace\n")
        elif self.path == "/healthz":
            self.reply(200, "ok\n")
        elif self.path == "/headers":
            self.reply(200, json.dumps(dict(self.headers.items())), "application/json")
        elif self.path == "/private":
            if session_of(self.headers.get("Cookie")) in SESSIONS:
                # A rotated session on every answer: preauth-proxy must not hand it to callers.
                self.reply(200, "private data\n", cookie="session=rotated; Path=/; HttpOnly")
            else:
                self.reply(401, "no session\n")
        else:
            self.reply(404, "not found\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode())
        if self.path == "/login":
            if form.get("email") == [USER] and form.get("password") == [SECRET]:
                token = secrets.token_hex(16)
                SESSIONS.add(token)
                self.reply(200, "welcome\n", cookie=f"session={token}; Path=/; HttpOnly")
            else:
                self.reply(401, "bad credential\n")
        elif self.path == "/expire":
            SESSIONS.clear()
            self.reply(200, "expired\n")
        else:
            self.reply(404, "not found\n")

    def log_message(self, fmt, *args):
        sys.stderr.write("serve.py: " + (fmt % args) + "\n")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
