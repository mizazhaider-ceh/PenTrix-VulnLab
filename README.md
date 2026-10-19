![PenTrix VulnLab](docs/assets/hero.svg)

![modules](https://img.shields.io/badge/modules-29-7C3AED?style=for-the-badge)
![challenges](https://img.shields.io/badge/challenges-235-DB2777?style=for-the-badge)
![node](https://img.shields.io/badge/node-20%2B-10B981?style=for-the-badge)
![status](https://img.shields.io/badge/status-intentionally%20vulnerable-F59E0B?style=for-the-badge)

An intentionally vulnerable web application for learning **real-world web security**, built by **The PenTrix**. Every challenge behaves like a small genuine website, a shop, a login portal, a blog, an API, and every flag is earned by genuine multi-step exploitation. Nothing is handed to you, and nothing leaks from the source.

> ⚠️ **WARNING: This application is intentionally vulnerable.**
> Never deploy it to a public server or expose it to the internet.
> Run it only on your own machine or an isolated lab network.

## Quick start

```bash
docker compose up --build
# open http://localhost:3000
```

The compose file binds to `127.0.0.1` only, ships a healthcheck, drops Linux capabilities, and caps CPU and memory. The database persists in `./data` (gitignored).

Or without Docker (Node 20+):

```bash
npm install
npm start
```

Set `SESSION_SECRET` to a private value for any graded or shared use. The app falls back to an insecure dev secret when it is unset, which is fine for local labs only.

## How a session goes

1. **Pick a module** on the home page. 29 to choose from, with search and difficulty filters.
2. **Read the briefing**, then open a challenge. Each one looks and behaves like a real little website. The vulnerability is there to be discovered, not announced.
3. **Find the bug.** Exploit it the way a real attacker would, with real tools: curl, Burp, your browser.
4. **Capture the flag.** Progress lands on the scoreboard.
5. **Stuck?** Reveal the hint. Still stuck? `SOLUTIONS.md` walks the technique, never the flag.

## Flags are born on your machine, not in this repo

![Flag lifecycle](docs/assets/flags.svg)

- On first boot the app generates its own **235 flags**: `PENTRIX{` + 32 random hex characters.
- They live only in the local SQLite database (`data/vulnlab.db`), which is gitignored and mounted as a Docker volume.
- **No flag literal exists in any tracked file.** Reading the source on GitHub reveals nothing.
- Delete the database and reboot for a fresh set. Your flags and everyone else's are different, so sharing them proves nothing.

## Shortcuts earn nothing

![Verification integrity](docs/assets/verification.svg)

Flags are awarded only when the exploit genuinely works:

| Real exploitation | Result |
|---|---|
| SQLi login bypass with a working payload | Flag awarded |
| Reflected XSS that actually fires in the victim context | Flag awarded |
| Blind extraction, character by character | Flag awarded |

| Shortcut | Result |
|---|---|
| Bare curl beacon with no exploit behind it | `400`, no flag |
| Replaying a stolen token | `400`, no flag |
| Just visiting a demo page | Nothing |

Every challenge is paired with tests proving the real path works and the fakes fail.

## Architecture

![Architecture](docs/assets/architecture.svg)

- **Express + SQLite**, zero build step, plain CSS and JS. Clone it, read it, run it.
- **29 module routers** (`/sqli`, `/xss`, `/idor`, …). Each of the **235 challenges lives in its own file** under `modules/<id>/challenges/`, owning its page, its routes, and its vulnerability.
- **`lib/flags.js`** looks up the per-deployment flag and verifies the exploit before awarding. Challenge code never touches flag values.
- **Scoreboard** tracks progress from session state. It never displays secrets.
- Every vulnerability is marked in the source with `// VULN:` comments (280 across the codebase) so you can study the code *after* solving.

## The lab catalog

235 intentionally vulnerable challenges across 29 modules:

| Module | Highlights |
|--------|------------|
| **xss** – Cross-Site Scripting (11) | Reflected · Stored (guestbook, profile bio, SVG upload) · DOM XSS · Attribute and JS-string breakouts · DOM clobbering · Naive Markdown links |
| **sqli** – SQL Injection (12) | Auth bypass · UNION injection · Blind boolean · Error-based · ORDER BY · Second-order · LIKE wildcards · LIMIT/OFFSET · INSERT injection |
| **auth** – Broken Authentication (11) | No rate limiting · JWT `alg=none` · Predictable reset tokens · Username enumeration · Remember-me tampering · OTP brute force · API key in HTML comment |
| **idor** – Broken Access Control (11) | Profile and order IDOR · Invoice download · Cart and address IDOR · API key regeneration · Forced browsing · Comment deletion |
| **ssrf** – Server-Side Request Forgery (10) | Basic SSRF · Blocklist bypasses (decimal, hex, octal, integer IP, userinfo) · Open-redirect chain · Cloud metadata · `file://` |
| **upload** – File Upload (10) | Stored XSS via SVG/HTML · Extension blacklist bypasses (double ext, case, strip-once) · MIME spoofing · Path traversal · Polyglot |
| **cmdi** – Command Injection (10) | Unfiltered ping gadget · Blacklist-bypass series (`$IFS`, `${IFS}`, newline, backticks, glob wildcards, tab, pipe) |
| **xxe** – XXE Injection (8) | File read · SSRF via XXE · Billion laughs · External DTD exfiltration · XXE in SVG/SOAP · XInclude · Parameter-entity OOB |
| **ssti** – Server-Side Template Injection (10) | Basic `{{7*7}}` · Filter-bypass series (words, underscores, brackets, dots, braces, quotes) · SSTI to RCE |
| **lfi** – Path Traversal / LFI (10) | Basic traversal · Filter bypasses (nested, double-encoded) · Absolute paths · Log poisoning · `/proc/self/environ` · Config read |
| **csrf** – CSRF & Open Redirect (11) | State-changing GETs · Login CSRF · JSON CSRF via `text/plain` · Referer/Content-Type bypasses · Method override · 2FA disable via GET |
| **api** – API Security Flaws (11) | Mass assignment · Excessive data exposure · BOLA · Rate-limit bypass via `X-Forwarded-For` · Version bypass · ID enumeration |
| **misconfig** – Security Misconfiguration (11) | Verbose errors · Exposed `.git`/`.env`/backup/swap files · Directory listing · HTTP TRACE · Debug param · Default creds · HTTP PUT |
| **jwt** – JWT Attacks (8) | `alg=none` · Weak HMAC secret · `kid` SQL injection · Untrusted `jku` · RS256/HS256 confusion · Missing expiry/audience checks |
| **session** – Session Management (6) | Fixation · Logout without destruction · Predictable IDs · Session ID in URL · Never-expiring sessions · IDs in debug logs |
| **race** – Race Conditions (8) | Double coupon redeem · Double-spend · Double vote/registration · AV-scan TOCTOU · Rate-limit burst · Stock oversell |
| **bizlogic** – Business Logic Flaws (8) | Negative quantity · Price tampering · Coupon stacking · Client-side OTP · Workflow skipping · Currency confusion · Refund tampering |
| **redirect** – Open Redirect (6) | Protocol-relative `//evil.com` · `javascript:`/`data:` schemes · Backslash bypass · OAuth code theft · Parameter pollution |
| **hostheader** – Host Header Injection (6) | Reset-link poisoning · Cache poisoning · SSRF via Host · `X-Forwarded-Host`/`X-Host-Override` trust |
| **cors** – CORS Misconfiguration (6) | Reflected origin with credentials · `null` origin · Regex bypass · Wildcard on sensitive data · Exposed headers |
| **proto** – Prototype Pollution (6) | Query-string pollution · JSON body pollution · `constructor` bypass · `toString` DoS · Unicode-escape bypass |
| **crypto** – Cryptographic Failures (8) | Predictable PIN · ECB decryption oracle · CBC bit-flipping · Hash length extension · MD5 cracking · XOR crib dragging |
| **oauth** – OAuth Flaws (8) | Redirect-URI bypass · Code leakage · Missing `state` (login CSRF) · Implicit flow · Scope tampering · Code replay · PKCE skip |
| **postmsg** – postMessage Flaws (5) | Missing origin check · Wildcard `targetOrigin` leak · Unsanitized data to HTML · Substring origin bypass · Forged actions |
| **csti** – Client-Side Template Injection (5) | Basic `{{7*7}}` evaluation · Delimiter filter bypass · Constructor breakout · Attribute context · Stored template |
| **http** – HTTP Layer Flaws (6) | CRLF log injection · Method override · Verb tampering · `X-Forwarded-For` trust · Cache deception · Referer auth |
| **jsonp** – JSONP Injection (5) | Callback XSS · JSONP data theft · Callback filter bypass · Array-constructor hijack · MIME sniffing |
| **formula** – CSV Formula Injection (4) | Classic `=cmd` · DDE execution · `HYPERLINK` exfiltration · Pipe prefix |
| **redos** – ReDoS (4) | Catastrophic email/URL regexes · Nested-quantifier username · Regex-injection search |

## What we built

This repo went through a full engineering transformation:

- **Phase Zero, audit.** Live exploitation of the original app, feature inventory, architecture and risk analysis, documented in `docs/audit/`.
- **Phase One, planning.** Lab quality matrix (every challenge graded), design brief, motion system, platform research, architecture assessment, and a 10-milestone implementation plan in `docs/roadmap/`.
- **Safety groundwork.** Localhost-only container binding, healthcheck, resource limits, non-root image, loader validation, env-based session secret, database untracked.
- **Claymorphism redesign.** A light-only, candy-colored, soft-3D interface: super-rounded cards, squishy buttons, floating blobs, Nunito + DM Sans.
- **Verification integrity.** Every fake flag award removed. Bare beacons, token replays, and visit-only claims are rejected; only genuine exploits earn flags.
- **Per-deployment random flags.** Flag values are generated at first boot into a gitignored database. GitHub reveals nothing.
- **One file per challenge.** Each of the 235 challenges owns its file, its page, and its code. No monolithic module files.
- **In progress:** real-website feel for every challenge page, motion polish, and a curriculum depth pass. The roadmap lives in `docs/roadmap/IMPLEMENTATION_PLAN.md`.

## Project layout

```
PenTrix-VulnLab/
├── app.js                  # Express app, module mounting, scoreboard, about
├── lib/
│   ├── db.js               # SQLite setup, seed, flags table
│   ├── flags.js            # flagFor() lookup, award() with exploit verification
│   └── page.js             # shared page shell, nav, scoreboard components
├── modules/
│   ├── sqli/
│   │   ├── index.js        # module contract: id, name, briefing, challenge registry
│   │   └── challenges/
│   │       ├── login.js    # one file per challenge
│   │       └── ...
│   └── ...                 # 28 more modules, same shape
├── public/                 # claymorphism CSS, client JS
├── data/                   # SQLite database (gitignored, created on boot)
├── docs/
│   ├── assets/             # diagrams used in this README
│   ├── audit/              # Phase Zero findings
│   ├── curriculum/         # lab quality matrix
│   ├── design/             # design brief, motion system
│   ├── research/           # platform benchmarks, skills research
│   └── roadmap/            # architecture assessment, decisions, plan, progress
├── SOLUTIONS.md            # technique walkthroughs (never flags)
└── docker-compose.yml      # localhost-only, healthchecked, resourced-limited
```

## Rules

1. Attack **only** this application.
2. Flags prove exploitation. Share write-ups, not just flags.
3. Built for learning. If you find an *unintended* vulnerability, that is a bonus flag in spirit.

## License

Educational use only. Built by The PenTrix.
