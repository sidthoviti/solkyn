#!/usr/bin/env python3
"""Browser helper — Playwright-based headless browser for the Solkyn agent.

The agent calls this script via bash_exec to interact with web pages
using a real browser (Chromium). Useful for:
- Rendering JavaScript-heavy pages to see actual DOM content
- Filling forms and clicking buttons
- Executing JavaScript in page context
- Testing XSS payloads (checking if alert/confirm/prompt fires)
- Taking screenshots for debugging
- Extracting content that requires JS rendering

Usage:
    python3 /tools/browser_helper.py navigate URL
    python3 /tools/browser_helper.py get_html URL
    python3 /tools/browser_helper.py execute_js URL 'document.cookie'
    python3 /tools/browser_helper.py fill URL 'input[name=q]' 'search term'
    python3 /tools/browser_helper.py click URL 'button[type=submit]'
    python3 /tools/browser_helper.py screenshot URL /tmp/page.png
    python3 /tools/browser_helper.py test_xss URL
    python3 /tools/browser_helper.py full URL  # navigate + get HTML + check alerts + console

Output: JSON with {"success": bool, "result": str, ...}
"""

from __future__ import annotations

import json
import sys
import traceback


def _output(success: bool, **kwargs) -> None:
    """Print JSON output and exit."""
    print(json.dumps({"success": success, **kwargs}))
    sys.exit(0 if success else 1)


def main() -> None:
    if len(sys.argv) < 3:
        _output(False, error="Usage: browser_helper.py <action> <url> [args...]")

    action = sys.argv[1]
    url = sys.argv[2]

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _output(False, error="Playwright not installed. Run: pip3 install playwright && playwright install chromium")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
            context = browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1280, "height": 720},
            )
            page = context.new_page()

            # Collect console messages and dialog events
            console_msgs: list[str] = []
            dialogs: list[dict] = []

            page.on("console", lambda msg: console_msgs.append(f"[{msg.type}] {msg.text}"))

            def handle_dialog(dialog):
                dialogs.append({
                    "type": dialog.type,
                    "message": dialog.message,
                })
                dialog.accept()

            page.on("dialog", handle_dialog)

            if action == "navigate":
                resp = page.goto(url, wait_until="networkidle", timeout=15000)
                title = page.title()
                status = resp.status if resp else None
                _output(True, title=title, status=status, url=page.url,
                        console=console_msgs, dialogs=dialogs)

            elif action == "get_html":
                page.goto(url, wait_until="networkidle", timeout=15000)
                html = page.content()
                # Truncate for large pages
                if len(html) > 50000:
                    html = html[:50000] + "\n... [truncated at 50KB]"
                _output(True, html=html, title=page.title(),
                        console=console_msgs, dialogs=dialogs)

            elif action == "execute_js":
                if len(sys.argv) < 4:
                    _output(False, error="Usage: browser_helper.py execute_js URL 'js_code'")
                js_code = sys.argv[3]
                page.goto(url, wait_until="networkidle", timeout=15000)
                result = page.evaluate(js_code)
                _output(True, result=str(result) if result is not None else None,
                        console=console_msgs, dialogs=dialogs)

            elif action == "fill":
                if len(sys.argv) < 5:
                    _output(False, error="Usage: browser_helper.py fill URL 'selector' 'value'")
                selector = sys.argv[3]
                value = sys.argv[4]
                page.goto(url, wait_until="networkidle", timeout=15000)
                page.fill(selector, value)
                _output(True, result=f"Filled {selector} with value",
                        console=console_msgs, dialogs=dialogs)

            elif action == "click":
                if len(sys.argv) < 4:
                    _output(False, error="Usage: browser_helper.py click URL 'selector'")
                selector = sys.argv[3]
                page.goto(url, wait_until="networkidle", timeout=15000)
                page.click(selector)
                page.wait_for_load_state("networkidle", timeout=10000)
                _output(True, result=f"Clicked {selector}", url=page.url,
                        title=page.title(), console=console_msgs, dialogs=dialogs)

            elif action == "screenshot":
                if len(sys.argv) < 4:
                    output_path = "/tmp/screenshot.png"
                else:
                    output_path = sys.argv[3]
                page.goto(url, wait_until="networkidle", timeout=15000)
                page.screenshot(path=output_path, full_page=True)
                _output(True, result=f"Screenshot saved to {output_path}",
                        console=console_msgs, dialogs=dialogs)

            elif action == "test_xss":
                # Navigate and check if any alert/confirm/prompt fired
                page.goto(url, wait_until="networkidle", timeout=15000)
                # Also trigger focus events on autofocus elements (like PhantomJS does)
                page.evaluate("""() => {
                    document.querySelectorAll('[autofocus], [onfocus]').forEach(el => {
                        el.dispatchEvent(new Event('focus', {bubbles: true}));
                    });
                }""")
                page.wait_for_timeout(1000)  # Wait for event handlers
                xss_detected = any(d["message"] == "XSS" for d in dialogs)
                _output(True, xss_detected=xss_detected, dialogs=dialogs,
                        console=console_msgs, title=page.title())

            elif action == "full":
                # Full page analysis: navigate, get HTML, check alerts, console
                resp = page.goto(url, wait_until="networkidle", timeout=15000)
                # Trigger focus events
                page.evaluate("""() => {
                    document.querySelectorAll('[autofocus], [onfocus]').forEach(el => {
                        el.dispatchEvent(new Event('focus', {bubbles: true}));
                    });
                }""")
                page.wait_for_timeout(500)
                html = page.content()
                if len(html) > 30000:
                    html = html[:30000] + "\n... [truncated at 30KB]"
                title = page.title()
                status = resp.status if resp else None
                # Extract visible text
                text = page.inner_text("body")
                if len(text) > 5000:
                    text = text[:5000] + "\n... [truncated]"
                _output(True, title=title, status=status, url=page.url,
                        html=html, text=text, console=console_msgs, dialogs=dialogs)

            else:
                _output(False, error=f"Unknown action: {action}. "
                        "Available: navigate, get_html, execute_js, fill, click, screenshot, test_xss, full")

            browser.close()

    except Exception as e:
        _output(False, error=f"{type(e).__name__}: {e}", traceback=traceback.format_exc())


if __name__ == "__main__":
    main()
