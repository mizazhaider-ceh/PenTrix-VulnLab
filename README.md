![PenTrix VulnLab](docs/assets/hero.svg)

![modules](https://img.shields.io/badge/modules-29-7C3AED?style=for-the-badge)
![challenges](https://img.shields.io/badge/challenges-201-DB2777?style=for-the-badge)
![node](https://img.shields.io/badge/node-20%2B-10B981?style=for-the-badge)
![status](https://img.shields.io/badge/status-intentionally%20vulnerable-F59E0B?style=for-the-badge)

An intentionally vulnerable web application for learning **real-world web security**, built by **The PenTrix**. Every challenge behaves like a small genuine website, a shop, a login portal, a blog, an API, and every flag is earned by genuine multi-step exploitation. Nothing is handed to you, and nothing leaks from the source.

> ⚠️ **WARNING: This application is intentionally vulnerable.**
> Never deploy it to a public server or expose it to the internet.
> Run it only on your own machine or an isolated lab network.

## Why I built this

I am a cybersecurity student, and I learn by breaking things.

When I started learning web security, I tried the existing labs. Some handed me the flag just for opening a page. Some taught the theory and skipped the part where you actually exploit something. Some felt nothing like the real websites I wanted to learn to test.

So I built the lab I wished existed.

Every challenge in PenTrix VulnLab is a small, believable website with a real bug in it. No hand-holding, no fake flags, no shortcuts. You either exploit it for real, or you get nothing. That is how the real world works, and that is how this lab works.

I built it for students like me: people who learn by doing, late at night, with curl and Burp and too much coffee. If that is you, welcome. Break everything.

*Muhammad Izaz Haider ([@mizazhaider-ceh](https://github.com/mizazhaider-ceh))*

## Who this is for

- **Students** meeting web security for the first time and wanting real practice, not slides.
- **Self-learners** grinding toward pentesting certifications or their first CTF.
- **CTF players** who want 201 warm-up challenges with honest, uncheatable flags.
- **Instructors** who need a one-command lab for a classroom (event mode is on the way).
- **Career switchers** who want proof of skill: solve paths, earn certificates, show your work.

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

Run the regression suite (boots the app on a throwaway database; needs Node 20 and the installed dependencies, or run it in the container with `docker compose run --rm vulnlab npm test`):

```bash
npm test
```

## How a session goes

1. **Pick a module** on the home page. 29 to choose from, with search and difficulty filters.
2. **Read the briefing**, then open a challenge. Each one looks and behaves like a real little website. The vulnerability is there to be discovered, not announced.
3. **Find the bug.** Exploit it the way a real attacker would, with real tools: curl, Burp, your browser.
4. **Capture the flag.** Progress lands on the scoreboard.
5. **Stuck?** Reveal the hint. Still stuck? `SOLUTIONS.md` walks the technique, never the flag.

## Flags are born on your machine, not in this repo

![Flag lifecycle](docs/assets/flags.svg)

- On first boot the app generates its own **201 flags**: `PENTRIX{` + 32 random hex characters.
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

## The three pillars

![The three pillars](docs/assets/pillars.svg)

Most labs stop at "find the bug". PenTrix is being built to train complete security engineers:

1. **Break-then-fix.** After you capture a flag, patch the vulnerable code yourself. The lab re-runs the original exploit against your fix in an isolated sandbox. If the exploit fails and the app still works, you earn a fix badge. Offense and defense, in one place. *(In active development: framework plus full SQLi and XSS coverage first.)*
2. **Kill-chain scenarios.** Multi-stage attacks that tell one story: recon a target, exploit it, pivot, escalate, exfiltrate. Single challenges teach techniques; scenarios teach how attackers actually think. *(In active development: Shop Takeover, API Heist, Ghost in the CMS.)*
3. **Guided career paths.** Ordered journeys like "Zero to Web Pentester" and "API Hacker", with prerequisites, skill tracking, and a verifiable certificate when you finish. *(In active development.)*

## Why PenTrix

| | **PenTrix VulnLab** | Juice Shop | WebGoat | PortSwigger Academy |
|---|---|---|---|---|
| Challenges | 201 | 100+ | Lesson-based | Extensive |
| Flags random per install | Yes | No | No | N/A |
| Shortcut exploits rejected | Yes | Partial | No | Yes |
| Break-then-fix mode | In development | No | No | No |
| Kill-chain scenarios | In development | No | No | Partial |
| Guided career paths | In development | No | Lessons | Yes |
| One-command local setup | Yes | Yes | Yes | Browser only |
| Fully open source | Yes | Yes | Yes | No |

## Architecture

![Architecture](docs/assets/architecture.svg)

- **Express + SQLite**, zero build step, plain CSS and JS. Clone it, read it, run it.
- **29 module routers** (`/sqli`, `/xss`, `/idor`, …). Each module is split one file per challenge: `modules/<id>/challenges/<vuln-id>.js` holds a single challenge, `modules/<id>/index.js` is a thin aggregator, and `modules/<id>/shared.js` holds module helpers.
- **`lib/flags.js`** looks up the per-deployment flag and verifies the exploit before awarding. Challenge code never touches flag values.
- **Scoreboard** tracks progress per browser session. Sessions are stored in `data/sessions.db` (separate from the vulnerable app's database), so progress survives restarts and is cleared only by deleting `data/`. It never displays secrets.
- Every vulnerability is marked in the source with `// VULN:` comments (281 across the codebase) so you can study the code *after* solving.

## The lab catalog

201 intentionally vulnerable challenges across 29 modules:

| Module | Highlights |
|--------|------------|
| **xss** – Cross-Site Scripting (9) | Reflected · Stored (guestbook, profile bio, SVG upload) · DOM XSS · Attribute and JS-string breakouts · DOM clobbering · Naive Markdown links |
| **sqli** – SQL Injection (11) | Auth bypass · UNION injection · Blind boolean · Error-based · ORDER BY · Second-order · LIKE wildcards · LIMIT/OFFSET · INSERT injection |
| **auth** – Broken Authentication (8) | No rate limiting · JWT `alg=none` · Predictable reset tokens · Username enumeration · Remember-me tampering · OTP brute force · API key in HTML comment |
| **idor** – Broken Access Control (7) | Profile and order IDOR · Invoice download · Cart and address IDOR · API key regeneration · Forced browsing · Comment deletion |
| **ssrf** – Server-Side Request Forgery (9) | Basic SSRF · Blocklist bypasses (decimal, hex, octal, integer IP, userinfo) · Open-redirect chain · Cloud metadata · `file://` |
| **upload** – File Upload (8) | Stored XSS via SVG/HTML · Extension blacklist bypasses (double ext, case, strip-once) · MIME spoofing · Path traversal · Polyglot |
| **cmdi** – Command Injection (9) | Unfiltered ping gadget · Blacklist-bypass series (`$IFS`, `${IFS}`, newline, backticks, glob wildcards, tab, pipe) |
| **xxe** – XXE Injection (8) | File read · SSRF via XXE · Billion laughs · External DTD exfiltration · XXE in SVG/SOAP · XInclude · Parameter-entity OOB |
| **ssti** – Server-Side Template Injection (9) | Basic `{{7*7}}` · Filter-bypass series (words, underscores, brackets, dots, braces, quotes) · SSTI to RCE |
| **lfi** – Path Traversal / LFI (9) | Basic traversal · Filter bypasses (nested, double-encoded) · Absolute paths · Log poisoning · `/proc/self/environ` · Config read |
| **csrf** – CSRF & Open Redirect (5) | State-changing GETs · Login CSRF · JSON CSRF via `text/plain` · Referer/Content-Type bypasses · Method override · 2FA disable via GET |
| **api** – API Security Flaws (5) | Mass assignment · Excessive data exposure · BOLA · Rate-limit bypass via `X-Forwarded-For` · Version bypass · ID enumeration |
| **misconfig** – Security Misconfiguration (10) | Verbose errors · Exposed `.git`/`.env`/backup/swap files · Directory listing · HTTP TRACE · Debug param · Default creds · HTTP PUT |
| **jwt** – JWT Attacks (8) | `alg=none` · Weak HMAC secret · `kid` SQL injection · Untrusted `jku` · RS256/HS256 confusion · Missing expiry/audience checks |
| **session** – Session Management (6) | Fixation · Logout without destruction · Predictable IDs · Session ID in URL · Never-expiring sessions · IDs in debug logs |
| **race** – Race Conditions (8) | Double coupon redeem · Double-spend · Double vote/registration · AV-scan TOCTOU · Rate-limit burst · Stock oversell |
| **bizlogic** – Business Logic Flaws (8) | Negative quantity · Price tampering · Coupon stacking · Client-side OTP · Workflow skipping · Currency confusion · Refund tampering |
| **redirect** – Open Redirect (5) | Protocol-relative `//evil.com` · `javascript:`/`data:` schemes · Backslash bypass · OAuth code theft · Parameter pollution |
| **hostheader** – Host Header Injection (5) | Reset-link poisoning · Cache poisoning · SSRF via Host · `X-Forwarded-Host`/`X-Host-Override` trust |
| **cors** – CORS Misconfiguration (6) | Reflected origin with credentials · `null` origin · Regex bypass · Wildcard on sensitive data · Exposed headers |
| **proto** – Prototype Pollution (6) | Query-string pollution · JSON body pollution · `constructor` bypass · `toString` DoS · Unicode-escape bypass |
| **crypto** – Cryptographic Failures (8) | Predictable PIN · ECB decryption oracle · CBC bit-flipping · Hash length extension · MD5 cracking · XOR crib dragging |
| **oauth** – OAuth Flaws (8) | Redirect-URI bypass · Code leakage · Missing `state` (login CSRF) · Implicit flow · Scope tampering · Code replay · PKCE skip |
| **postmsg** – postMessage Flaws (5) | Missing origin check · Wildcard `targetOrigin` leak · Unsanitized data to HTML · Substring origin bypass · Forged actions |
| **csti** – Client-Side Template Injection (5) | Basic `{{7*7}}` evaluation · Delimiter filter bypass · Constructor breakout · Attribute context · Stored template |
| **http** – HTTP Layer Flaws (3) | CRLF log injection · Method override · Verb tampering · `X-Forwarded-For` trust · Cache deception · Referer auth |
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
- **One file per challenge.** Each of the 201 challenges owns its file, its page, and its code. No monolithic module files.
- **Break-then-fix mode.** The sandboxed fix runner is in-tree (`lib/fixmode.js`): pilot blocks for sqli and xss let you repair the vulnerable code and prove the exploit is blocked. Kill-chain scenarios and career paths are next. The roadmap lives in `docs/roadmap/IMPLEMENTATION_PLAN.md`.

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
├── scenarios/              # kill-chain scenarios (in development)
├── paths/                  # guided career paths (in development)
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
└── docker-compose.yml      # localhost-only, healthchecked, resource-limited
```

## FAQ

**Is it safe to run?**
Yes, on your own machine. The container binds to `127.0.0.1` only, drops Linux capabilities, and is resource-limited. It is still intentionally vulnerable software, so keep it off shared networks.

**Can I deploy it to the internet so friends can play?**
No. Never. It is a practice target, not a hardened app. If you want a shared event, run it on an isolated lab network you fully control.

**How do flags work?**
Every install generates its own 201 random flags on first boot, stored in a gitignored local database. The source on GitHub contains zero flags, so nothing can be spoiled by reading code.

**I solved a challenge but got no flag. Why?**
Because the lab only awards flags for genuine exploitation. A request that does not actually trigger the vulnerability earns nothing. Re-read the briefing, check the hint, and make the exploit real.

**I found an unintended vulnerability in the lab itself.**
That is a bonus flag in spirit. Open an issue and tell the story.

**Can I add my own challenges?**
A simple challenge-builder format is in development. Until then, issues and pull requests with new challenge ideas are welcome.

**Do I need Burp Suite?**
No. Everything is solvable with curl and a browser. Burp just makes some challenges faster.

**Where do I start if I am brand new?**
Open the app and follow the "Start here" card. It points to the gentlest module first. Then follow the career paths as they land.

## Rules

1. Attack **only** this application.
2. Flags prove exploitation. Share write-ups, not just flags.
3. Built for learning. If you find an *unintended* vulnerability, that is a bonus flag in spirit.

## License

Educational use only. Built by The PenTrix.
