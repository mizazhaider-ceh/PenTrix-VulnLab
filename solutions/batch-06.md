# Batch 06 solutions - LFI + Misconfiguration (new labs)

## lfi - Path Traversal / LFI

**1. Absolute Path Read** - `PENTRIX{lfi_absolute}`
Request: `GET /lfi/abs?page=/etc/passwd`
The page prints `/etc/passwd` (look for `root:x:0:0`) and the flag box appears.
Why it works: the reader uses absolute paths verbatim instead of confining reads to the docs folder, so no `../` traversal is needed at all.

**2. Double-Encoding Bypass** - `PENTRIX{lfi_double-encode}`
Request: `GET /lfi/double?page=%252e%252e%252fdocs%252fsecret.txt`
The filter decodes once, sees no `..`, and lets it through; the value is decoded a second time on use, becoming `../docs/secret.txt`, and the secret (`LFI-SECRET-8830`) is printed with the flag.
Why it works: single-decode-then-check is defeated when the application decodes again after the check; `%252e` survives the first decode as `%2e` and becomes `.` on the second.

**3. Deep Nesting Bypass** - `PENTRIX{lfi_nested-deep}`
Request: `GET /lfi/nested?page=....///docs/secret.txt`
The filter strips every `../` in one pass, turning `....///` into `..//`, which normalizes to `../`; the secret is printed with the flag. (`...//docs/secret.txt` works too.)
Why it works: a one-pass strip never re-inspects its own output, so nested dots regenerate a fresh traversal sequence after filtering.

**4. Language Parameter Traversal** - `PENTRIX{lfi_lang}`
Request: `GET /lfi/lang?lang=../secret`
The viewer reads `docs/lang/../secret.txt`, which resolves to `docs/secret.txt`; the secret is printed with the flag.
Why it works: the `lang` parameter is concatenated into a filesystem path with zero validation, so it is just another filename input.

**5. Log Poisoning Chain** - `PENTRIX{lfi_log-poison}`
Step 1, poison the log: `curl -A "PENTRIX-LOG-MARKER pwned" http://localhost:3000/lfi/log-demo`
Step 2, read the log back through the LFI: `GET /lfi/view?file=../lfi_access.log`
Your marker appears in the file content returned by the viewer, and the flag is awarded.
Why it works: the access log stores the raw User-Agent with no filtering (log injection), and the document viewer reads that log file via traversal, chaining the two flaws.

**6. Process Environ Leak** - `PENTRIX{lfi_proc-self}`
Request: `GET /lfi/procinfo?f=environ`
The page prints the raw `/proc/self/environ` (NUL-separated `KEY=value` entries, including `PATH=`) and the flag is awarded.
Why it works: the filename is appended to `/proc/self/` with no validation, and `environ` exposes the whole process environment, secrets included.

**7. Encoded Separator Bypass** - `PENTRIX{lfi_enc-slash}`
Request: `GET /lfi/enc?page=%2e%2e%2fdocs%2fsecret.txt`
The filter rejects literal `..` and `/` but checks before decoding; `%2e%2e%2f` passes the check and decodes to `../` afterwards. The secret is printed with the flag.
Why it works: validating the still-encoded input is useless once a decode happens after the check.

**8. Secret Config Read** - `PENTRIX{lfi_config-read}`
Request: `GET /lfi/config?file=../lfi_secret.conf`
The planted config one directory above docs is printed (contains `LFI-CONFIG-SECRET-5521`) and the flag is awarded.
Why it works: the config viewer applies no validation at all, and a secret file was left within traversal reach.

## misconfig - Security Misconfiguration

**1. Exposed .git Directory** - `PENTRIX{misconfig_git}`
Walk the chain:
`GET /misconfig/.git/HEAD` gives `ref: refs/heads/main`
`GET /misconfig/.git/refs/heads/main` gives the commit hash `a1b2c3d4...`
`GET /misconfig/.git/objects/` lists `a1/`, `GET /misconfig/.git/objects/a1/` lists the object file
`GET /misconfig/.git/objects/a1/b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4` prints the commit, whose diff leaks `ADMIN_BACKUP_TOKEN`, and the flag is awarded.
Why it works: version-control metadata served over HTTP lets anyone resolve refs and read objects, and this commit's diff contains a production secret.

**2. Vim Swap File Leak** - `PENTRIX{misconfig_swp}`
Request: `GET /misconfig/app.js.swp`
The recovered editor backup prints dev notes with a database password, a Stripe key, and the backup token flag.
Why it works: the swap artifact was left in the web-accessible tree and is served to anyone who guesses its name.

**3. HTTP TRACE Enabled (XST)** - `PENTRIX{misconfig_trace}`
Request: `curl -X TRACE http://localhost:3000/misconfig/trace -H "X-Custom: hello"`
The server reflects the full request (your headers come back in the page) and the flag is awarded.
Why it works: TRACE is enabled and echoes the entire request, which is the primitive behind cross-site tracing attacks that steal reflected `Cookie`/`Authorization` headers.

**4. Exposed .env File** - `PENTRIX{misconfig_env}`
Request: `GET /misconfig/.env`
The file prints `DB_URL`, `STRIPE_SECRET_KEY`, `SESSION_SECRET`, and the admin API token flag.
Why it works: the environment file with production secrets sits where the web server serves it to anyone who asks.

**5. Debug Mode via Query Param** - `PENTRIX{misconfig_debug-param}`
Request: `GET /misconfig/info?debug=1`
The page renders a stack trace plus a config dump containing the debug token flag. (Plain `/misconfig/info` shows nothing.)
Why it works: a query-string switch flips on verbose debug output, leaking internals to any visitor who guesses the parameter.

**6. Default Credentials** - `PENTRIX{misconfig_manager}`
Request: `curl -u admin:admin http://localhost:3000/misconfig/manager`
Without credentials the panel returns 401; with `admin:admin` (HTTP Basic) it opens and the flag is awarded.
Why it works: the management panel is protected only by the vendor default credential, which was never changed.

**7. Robots.txt Disclosure** - `PENTRIX{misconfig_robots}`
`GET /misconfig/robots.txt` shows `Disallow: /misconfig/backup.zip`
`GET /misconfig/backup.zip` downloads a valid ZIP; `unzip -p backup.zip backup.txt` prints admin credentials and the backup token flag.
Why it works: robots.txt advertises the sensitive path, and the backup archive itself is downloadable.

**8. Unauthenticated HTTP PUT** - `PENTRIX{misconfig_put}`
Upload: `curl -X PUT -H "Content-Type: text/plain" --data-binary 'hello' http://localhost:3000/misconfig/files/pwn.txt` (201 Created)
Read back: `GET /misconfig/files/pwn.txt` prints the uploaded bytes and the flag is captured on the scoreboard.
Why it works: the endpoint accepts arbitrary file writes with no authentication, and the written file is served back raw, proving the write.
