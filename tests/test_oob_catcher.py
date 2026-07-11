"""Tests for the in-Kali OOB callback catcher."""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.request
from contextlib import closing
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from solkyn.tools import oob_catcher


@pytest.fixture(autouse=True)
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Per-test scratch dir so concurrent tests don't share /tmp/solkyn-oob."""
    scratch = tmp_path / "oob"
    scratch.mkdir()
    monkeypatch.setattr(oob_catcher, "STATE_DIR", scratch)
    monkeypatch.setattr(oob_catcher, "STATE_FILE", scratch / "hits.json")
    monkeypatch.setattr(oob_catcher, "LOCK_FILE", scratch / "lock")


def _free_port() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _start_server(port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), oob_catcher.OobHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    # Give it a beat to bind.
    time.sleep(0.05)
    return server


def test_new_token_is_url_safe_and_unique() -> None:
    a = oob_catcher.new_token()
    b = oob_catcher.new_token()
    assert a != b
    assert all(c.isalnum() or c in "-_" for c in a)
    assert len(a) >= 12


def test_record_and_get_hits() -> None:
    oob_catcher._record_hit(  # type: ignore[attr-defined]
        "tok1",
        {
            "timestamp": "2026-05-21T00:00:00+00:00",
            "method": "GET",
            "path": "/cb/tok1",
            "remote": "127.0.0.1",
            "headers": {},
            "body": "",
        },
    )
    hits = oob_catcher._get_hits("tok1")  # type: ignore[attr-defined]
    assert len(hits) == 1
    assert hits[0]["method"] == "GET"
    assert oob_catcher._get_hits("nope") == []  # type: ignore[attr-defined]


def test_clear_token_removes_hits() -> None:
    oob_catcher._record_hit(  # type: ignore[attr-defined]
        "tok2", {"method": "GET", "path": "/cb/tok2"}
    )
    assert oob_catcher._clear_token("tok2") is True  # type: ignore[attr-defined]
    assert oob_catcher._get_hits("tok2") == []  # type: ignore[attr-defined]
    assert oob_catcher._clear_token("tok2") is False  # type: ignore[attr-defined]


def test_max_hits_per_token_capped() -> None:
    for i in range(oob_catcher.MAX_HITS_PER_TOKEN + 5):
        oob_catcher._record_hit(  # type: ignore[attr-defined]
            "flood",
            {"method": "GET", "path": f"/cb/flood/{i}"},
        )
    assert len(oob_catcher._get_hits("flood")) == oob_catcher.MAX_HITS_PER_TOKEN  # type: ignore[attr-defined]


def test_max_total_tokens_capped() -> None:
    for i in range(oob_catcher.MAX_TOTAL_TOKENS):
        oob_catcher._record_hit(  # type: ignore[attr-defined]
            f"tok-{i}",
            {"method": "GET", "path": f"/cb/tok-{i}"},
        )
    overflow = "overflow-token"
    oob_catcher._record_hit(  # type: ignore[attr-defined]
        overflow, {"method": "GET", "path": "/cb/overflow"}
    )
    assert oob_catcher._get_hits(overflow) == []  # type: ignore[attr-defined]


def test_http_callback_records_get(tmp_path: Path) -> None:
    port = _free_port()
    server = _start_server(port)
    try:
        url = f"http://127.0.0.1:{port}/cb/abc?leak=value"
        urllib.request.urlopen(url, timeout=2).read()  # noqa: S310

        # Poll API
        poll = json.loads(
            urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{port}/api/poll/abc", timeout=2
            ).read()
        )
        assert poll["token"] == "abc"
        assert len(poll["hits"]) == 1
        hit = poll["hits"][0]
        assert hit["method"] == "GET"
        assert hit["path"] == "/cb/abc?leak=value"
        assert "timestamp" in hit
    finally:
        server.shutdown()


def test_http_callback_records_post_with_body() -> None:
    port = _free_port()
    server = _start_server(port)
    try:
        body = b'{"data":"FLAG{abc}"}'
        req = urllib.request.Request(  # noqa: S310
            f"http://127.0.0.1:{port}/cb/post1",
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=2).read()  # noqa: S310

        poll = json.loads(
            urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{port}/api/poll/post1", timeout=2
            ).read()
        )
        hit = poll["hits"][0]
        assert hit["method"] == "POST"
        assert "FLAG{abc}" in hit["body"]
        assert hit["headers"].get("content-type") == "application/json"
    finally:
        server.shutdown()


def test_healthz() -> None:
    port = _free_port()
    server = _start_server(port)
    try:
        body = json.loads(
            urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{port}/healthz", timeout=2
            ).read()
        )
        assert body == {"status": "ok"}
    finally:
        server.shutdown()


def test_list_endpoint_returns_counts() -> None:
    port = _free_port()
    server = _start_server(port)
    try:
        for tok in ("a", "b", "b", "c"):
            urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{port}/cb/{tok}", timeout=2
            ).read()
        body = json.loads(
            urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{port}/api/list", timeout=2
            ).read()
        )
        assert body == {"a": 1, "b": 2, "c": 1}
    finally:
        server.shutdown()


def test_clear_endpoint() -> None:
    port = _free_port()
    server = _start_server(port)
    try:
        urllib.request.urlopen(  # noqa: S310
            f"http://127.0.0.1:{port}/cb/del", timeout=2
        ).read()
        clear = urllib.request.Request(  # noqa: S310
            f"http://127.0.0.1:{port}/api/clear/del", method="POST"
        )
        body = json.loads(urllib.request.urlopen(clear, timeout=2).read())  # noqa: S310
        assert body == {"token": "del", "cleared": True}
        # Now empty
        poll = json.loads(
            urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{port}/api/poll/del", timeout=2
            ).read()
        )
        assert poll["hits"] == []
    finally:
        server.shutdown()


def test_unknown_admin_path_404s() -> None:
    port = _free_port()
    server = _start_server(port)
    try:
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{port}/api/unknown", timeout=2
            ).read()
        assert ei.value.code == 404
    finally:
        server.shutdown()


def test_callback_with_extra_path_segments_uses_first_token() -> None:
    """Some payloads embed structure after the token (e.g. /cb/<tok>/leak)."""
    port = _free_port()
    server = _start_server(port)
    try:
        urllib.request.urlopen(  # noqa: S310
            f"http://127.0.0.1:{port}/cb/onlyfirst/extra/path", timeout=2
        ).read()
        poll = json.loads(
            urllib.request.urlopen(  # noqa: S310
                f"http://127.0.0.1:{port}/api/poll/onlyfirst", timeout=2
            ).read()
        )
        assert len(poll["hits"]) == 1
        assert poll["hits"][0]["path"] == "/cb/onlyfirst/extra/path"
    finally:
        server.shutdown()


def test_kali_ip_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    rc = oob_catcher.main(["kali-ip"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    parts = out.split(".")
    assert len(parts) == 4
    assert all(p.isdigit() for p in parts)


def test_new_token_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    rc = oob_catcher.main(["new-token"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    assert len(out) >= 12


def test_poll_cli_returns_1_when_no_hits(capsys: pytest.CaptureFixture[str]) -> None:
    rc = oob_catcher.main(["poll", "noexist"])
    assert rc == 1


def test_poll_cli_returns_0_when_hits_recorded(capsys: pytest.CaptureFixture[str]) -> None:
    oob_catcher._record_hit("hashits", {"method": "GET", "path": "/cb/hashits"})  # type: ignore[attr-defined]
    rc = oob_catcher.main(["poll", "hashits"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "hashits" in out


def test_poll_cli_with_wait_returns_quickly_on_match() -> None:
    oob_catcher._record_hit("waittok", {"method": "GET", "path": "/cb/waittok"})  # type: ignore[attr-defined]
    started = time.time()
    rc = oob_catcher.main(["poll", "waittok", "--wait", "5"])
    elapsed = time.time() - started
    assert rc == 0
    assert elapsed < 1  # already there, no wait
