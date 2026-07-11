#!/usr/bin/env python3
"""JSFuck generator — uses headless Chromium (via Playwright) to invoke
jsfuck.com's reference encoder and print the result.

This is the most reliable way to produce a JSFuck payload because the
encoder is a non-trivial JS algorithm. We download `jsfuck.js` once into
a local file, then evaluate it inside a real browser context.

Usage:
    python3 /tools/jsfuck_gen.py 'alert("XSS")'
        → prints the JSFuck-encoded form to stdout

The output uses only []()!+ characters and evaluates to the same JS as
the input string when placed inside a JS context (e.g. `eval(<output>)`
or simply executed as a statement).

Notes:
- Requires Playwright + Chromium (already installed in the Solkyn Kali image).
- First run downloads jsfuck.js (~10KB) from jsfuck.com to /tmp/jsfuck.js.
- Internet access is required ONLY on first invocation.
"""
from __future__ import annotations

import sys
from pathlib import Path

JSFUCK_JS = Path("/tmp/jsfuck.js")
JSFUCK_URL = "https://www.jsfuck.com/jsfuck.js"


def _ensure_jsfuck_js() -> str:
    if JSFUCK_JS.exists():
        return JSFUCK_JS.read_text()
    import urllib.request
    js = urllib.request.urlopen(JSFUCK_URL, timeout=10).read().decode()
    JSFUCK_JS.write_text(js)
    return js


def encode(target: str) -> str:
    js = _ensure_jsfuck_js()
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        page = browser.new_page()
        page.goto("about:blank")
        page.add_script_tag(content=js)
        # JSFuck.encode is the entry point exposed by jsfuck.js
        result = page.evaluate("(t) => JSFuck.encode(t)", target)
        browser.close()
        return result


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 1
    print(encode(sys.argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
