#!/usr/bin/env python3
"""fake_telegram.py - a stand-in for Telegram's Bot API, for the tests only.

It listens on 127.0.0.1 and answers POST /bot<token>/sendMessage the way
api.telegram.org does, as far as auto-sec-detect looks at the answer. No
message ever leaves this machine. The tests of auto_sec never call the real
Telegram.

Usage: fake_telegram.py --dir DIR [--port N]
  DIR/port       the port it listens on (written at start; --port 0 picks one)
  DIR/messages   one JSON object per accepted message:
                 {"n": <message id>, "t": <epoch>, "chat_id": ..., "text": ..., "token_ok": true|false}
  DIR/requests   one line per request: "<epoch> <what it answered>"
  DIR/mode       how to answer; read at every request. One line:
                   ok              200 {"ok": true, "result": {"message_id": n}}
                   429 <s> <k>     the next k requests: 429 with retry_after s, then ok
                   500 <k>         the next k requests: 500, then ok
                   hang <s> <k>    the next k requests: no answer for s seconds
                   401             every request: 401 (a wrong token)
A token other than the test token 12345678:TEST-TOKEN-ONLY-for-the-fake-sink
is answered with 401, like a wrong token.
"""
import argparse
import http.server
import json
import os
import re
import threading
import time

TEST_TOKEN = "12345678:TEST-TOKEN-ONLY-for-the-fake-sink"
LOCK = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    store = "."
    count = [0]

    def log_message(self, *_args):
        pass

    def _note(self, what):
        with open(os.path.join(self.store, "requests"), "a", encoding="utf-8") as fh:
            fh.write("%.3f %s\n" % (time.time(), what))

    def _mode(self):
        path = os.path.join(self.store, "mode")
        try:
            with open(path, encoding="utf-8") as fh:
                words = fh.read().split()
        except OSError:
            words = []
        if not words or words[0] == "ok":
            return ["ok"]
        if words[0] in ("429", "500", "hang"):
            left = int(words[-1]) if len(words) > 1 else 0
            if left <= 0:
                return ["ok"]
            words[-1] = str(left - 1)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(" ".join(words) + "\n")
        return words

    def _answer(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802 - the name http.server asks for
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(length, 1 << 20))
        m = re.fullmatch(r"/bot([^/]+)/sendMessage", self.path)
        with LOCK:
            mode = self._mode()
            if not m:
                self._note("404")
                self._answer(404, {"ok": False, "error_code": 404, "description": "Not Found"})
                return
            if mode[0] == "hang":
                self._note("hang")
                time.sleep(float(mode[1]))
                return
            if mode[0] == "429":
                self._note("429")
                self._answer(429, {"ok": False, "error_code": 429,
                                   "description": "Too Many Requests: retry after %s" % mode[1],
                                   "parameters": {"retry_after": int(mode[1])}})
                return
            if mode[0] == "500":
                self._note("500")
                self._answer(500, {"ok": False, "error_code": 500, "description": "Internal Server Error"})
                return
            if mode[0] == "401" or m.group(1) != TEST_TOKEN:
                self._note("401")
                self._answer(401, {"ok": False, "error_code": 401, "description": "Unauthorized"})
                return
            try:
                msg = json.loads(raw.decode("utf-8"))
            except ValueError:
                self._note("400")
                self._answer(400, {"ok": False, "error_code": 400, "description": "Bad Request"})
                return
            self.count[0] += 1
            n = self.count[0]
            with open(os.path.join(self.store, "messages"), "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"n": n, "t": time.time(), "chat_id": msg.get("chat_id"),
                                     "text": msg.get("text"), "token_ok": True}) + "\n")
            self._note("200")
            self._answer(200, {"ok": True, "result": {"message_id": n, "chat": {"id": msg.get("chat_id")}}})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True)
    ap.add_argument("--port", type=int, default=0)
    a = ap.parse_args()
    os.makedirs(a.dir, exist_ok=True)
    Handler.store = a.dir
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    with open(os.path.join(a.dir, "port"), "w", encoding="ascii") as fh:
        fh.write("%d\n" % srv.server_address[1])
    for name in ("messages", "requests"):
        with open(os.path.join(a.dir, name), "a", encoding="utf-8"):
            pass
    srv.serve_forever()


if __name__ == "__main__":
    main()
