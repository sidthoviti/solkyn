#!/usr/bin/env python3
"""In-Kali OOB callback catcher.

A self-contained HTTP server that runs INSIDE the Kali container during
a Solkyn engagement. The agent hands targets a URL like
``http://<kali-ip>:8888/cb/<correlation-id>`` and any request to that
path is logged. The agent then polls the local catcher API to see whether
the target made the callback.

Why not Interactsh / oast.live:

- XBOW challenges run on the same Docker host; the agent's Kali container
  is auto-connected to each challenge's compose network at start time
  (see ``scripts/run_challenges.py::_connect_to_challenge_networks``),
  so the target can already reach the agent by IP.
- Self-hosting Interactsh requires a publicly resolvable domain we don't
  have, plus RSA + AES wire-format crypto.
- Public OAST (oast.live) leaks engagement traffic to a third party.

Endpoints:

  GET/POST /cb/<token>...     — record a hit. Returns 200 with empty body.
  GET      /api/poll/<token>  — JSON list of hits for that token.
  GET      /api/list          — JSON list of all tokens with hit counts.
  POST     /api/clear/<token> — drop hits for a token (idempotent).
  GET      /healthz           — liveness probe.

Hits include: timestamp (UTC ISO), method, full path (including query
string), headers (subset: Host, User-Agent, X-Forwarded-*, Referer),
remote IP, body (truncated to 4 KiB).

Usage (inside Kali):

    python3 -m solkyn.tools.oob_catcher serve --port 8888 &
    # ... agent uses http://<kali-ip>:8888/cb/<token> in payloads ...
    python3 -m solkyn.tools.oob_catcher poll <token>

Usage (from the agent's bash_exec, recommended):

    # Register a fresh token and embed it in a payload
    TOKEN=$(python3 -m solkyn.tools.oob_catcher new-token)
    URL="http://<kali-ip>:8888/cb/$TOKEN"
    curl "http://target/?url=$URL"
    sleep 2
    python3 -m solkyn.tools.oob_catcher poll "$TOKEN"
"""

from __future__ import annotations

import argparse
import json
import secrets
import socket
import sys
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

DEFAULT_PORT = 8888
MAX_BODY_BYTES = 4096
MAX_HITS_PER_TOKEN = 256
MAX_TOTAL_TOKENS = 1024
STATE_DIR = Path("/tmp/solkyn-oob")  # noqa: S108 — Kali sandbox, ephemeral
STATE_FILE = STATE_DIR / "hits.json"
LOCK_FILE = STATE_DIR / "lock"

_RECORDED_HEADERS = (
    "host",
    "user-agent",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "referer",
    "origin",
    "content-type",
)

# Process-local cache of hits, keyed by token. Each value is a list of
# hit records. Persisted to STATE_FILE on every write so the `poll` and
# `serve` subcommands (which can run in different processes) see the
# same state.
_state_lock = threading.Lock()


def _ensure_state_dir() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def _read_state() -> dict[str, list[dict[str, Any]]]:
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())  # type: ignore[no-any-return]
    except (json.JSONDecodeError, OSError):
        return {}


def _write_state(state: dict[str, list[dict[str, Any]]]) -> None:
    _ensure_state_dir()
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(STATE_FILE)


def _record_hit(token: str, hit: dict[str, Any]) -> None:
    with _state_lock:
        state = _read_state()
        if len(state) >= MAX_TOTAL_TOKENS and token not in state:
            return
        bucket = state.setdefault(token, [])
        if len(bucket) >= MAX_HITS_PER_TOKEN:
            return
        bucket.append(hit)
        _write_state(state)


def _get_hits(token: str) -> list[dict[str, Any]]:
    with _state_lock:
        return _read_state().get(token, [])


def _clear_token(token: str) -> bool:
    with _state_lock:
        state = _read_state()
        had = token in state
        state.pop(token, None)
        _write_state(state)
        return had


def _list_tokens() -> dict[str, int]:
    with _state_lock:
        return {tok: len(hits) for tok, hits in _read_state().items()}


class OobHandler(BaseHTTPRequestHandler):
    """HTTP handler that records every /cb/<token>... request."""

    # Quiet — we have our own log via state file; printing to stderr per
    # request would pollute the agent's tool output if anything reads
    # the catcher's stderr.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def _record_request(self) -> None:
        path = self.path
        if not path.startswith("/cb/"):
            return
        token_with_path = path[len("/cb/") :]
        # Token is the first path segment; the rest is opaque to us
        # (some payloads embed extra structure after the token).
        token = token_with_path.split("/", 1)[0].split("?", 1)[0]
        if not token:
            return

        # Read body (best-effort, capped).
        body_bytes = b""
        length = self.headers.get("content-length")
        if length:
            try:
                n = min(int(length), MAX_BODY_BYTES)
                if n > 0:
                    body_bytes = self.rfile.read(n)
            except (ValueError, OSError):
                pass

        try:
            body = body_bytes.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            body = repr(body_bytes)

        headers = {
            k: self.headers.get(k, "")
            for k in _RECORDED_HEADERS
            if self.headers.get(k) is not None
        }

        hit = {
            "timestamp": datetime.now(UTC).isoformat(),
            "method": self.command,
            "path": path,
            "remote": self.client_address[0],
            "headers": headers,
            "body": body,
        }
        _record_hit(token, hit)

    def _serve_api(self, method: str) -> None:
        path = self.path
        if path == "/healthz":
            self._json(200, {"status": "ok"})
            return
        if path == "/api/list" and method == "GET":
            self._json(200, _list_tokens())
            return
        if path.startswith("/api/poll/") and method == "GET":
            token = path[len("/api/poll/") :].split("?", 1)[0]
            self._json(200, {"token": token, "hits": _get_hits(token)})
            return
        if path.startswith("/api/clear/") and method == "POST":
            token = path[len("/api/clear/") :].split("?", 1)[0]
            existed = _clear_token(token)
            self._json(200, {"token": token, "cleared": existed})
            return
        self._json(404, {"error": "not found"})

    def _json(self, code: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _handle(self, method: str) -> None:
        path = self.path
        if path.startswith("/cb/"):
            self._record_request()
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        # Anything else is the catcher's own admin API.
        self._serve_api(method)

    def do_GET(self) -> None:  # noqa: N802
        self._handle("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    def do_PUT(self) -> None:  # noqa: N802
        self._handle("PUT")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle("DELETE")

    def do_HEAD(self) -> None:  # noqa: N802
        self._handle("HEAD")


def serve(port: int) -> None:
    _ensure_state_dir()
    # Wipe state on serve so each engagement starts clean.
    _write_state({})
    server = ThreadingHTTPServer(("0.0.0.0", port), OobHandler)  # noqa: S104
    print(f"oob_catcher listening on 0.0.0.0:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


def new_token() -> str:
    """Generate a fresh URL-safe token."""
    return secrets.token_urlsafe(12)


def cli_serve(args: argparse.Namespace) -> int:
    serve(args.port)
    return 0


def cli_new_token(_args: argparse.Namespace) -> int:
    print(new_token())
    return 0


def cli_poll(args: argparse.Namespace) -> int:
    deadline = time.time() + args.wait
    while True:
        hits = _get_hits(args.token)
        if hits or time.time() >= deadline:
            print(json.dumps({"token": args.token, "hits": hits}, indent=2))
            return 0 if hits else 1
        time.sleep(min(0.5, max(0.1, args.wait / 10)))


def cli_list(_args: argparse.Namespace) -> int:
    print(json.dumps(_list_tokens(), indent=2))
    return 0


def cli_clear(args: argparse.Namespace) -> int:
    existed = _clear_token(args.token)
    print(json.dumps({"token": args.token, "cleared": existed}))
    return 0


def cli_kali_ip(_args: argparse.Namespace) -> int:
    """Print the IP of this Kali container that targets can reach.

    Used by the agent inside the container to know what URL to embed
    in a payload. Picks the first non-loopback, non-link-local IPv4.
    """
    # Prefer the IP advertised by the host OS as 'reachable'
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connect doesn't actually send packets for UDP; just resolves
        # the local end's outbound interface IP.
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        print(ip)
        return 0
    except OSError:
        # Fall back: scan interfaces.
        host = socket.gethostbyname(socket.gethostname())
        print(host)
        return 0
    finally:
        s.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="oob_catcher")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help="Run the catcher HTTP server")
    p_serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    p_serve.set_defaults(fn=cli_serve)

    p_new = sub.add_parser("new-token", help="Print a fresh callback token")
    p_new.set_defaults(fn=cli_new_token)

    p_poll = sub.add_parser("poll", help="Print hits for a token")
    p_poll.add_argument("token")
    p_poll.add_argument(
        "--wait",
        type=float,
        default=0.0,
        help="Seconds to wait for a hit (polls every 0.5s). Default 0 = instant.",
    )
    p_poll.set_defaults(fn=cli_poll)

    p_list = sub.add_parser("list", help="List all tokens with hit counts")
    p_list.set_defaults(fn=cli_list)

    p_clear = sub.add_parser("clear", help="Drop hits for a token")
    p_clear.add_argument("token")
    p_clear.set_defaults(fn=cli_clear)

    p_ip = sub.add_parser(
        "kali-ip", help="Print the Kali container's reachable IP"
    )
    p_ip.set_defaults(fn=cli_kali_ip)

    args = parser.parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    sys.exit(main())
