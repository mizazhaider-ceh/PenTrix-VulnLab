# 🧪 PenTrix VulnLab

An intentionally vulnerable web application for learning web security, built by **The PenTrix**.

> ⚠️ **WARNING: This application is intentionally vulnerable.**
> Never deploy it to a public server or expose it to the internet.
> Run it only on your own machine or an isolated lab network.

## Quick start

```bash
docker compose up --build
# open http://localhost:3000
```

Or without Docker (Node 20+):

```bash
npm install
npm start
```

## How it works

- Pick a module on the home page (XSS, SQLi, IDOR, SSRF, and more).
- Each module briefs you on what to attack, with hints when you're stuck.
- Exploit the vulnerability for real, capture the flag (`PENTRIX{...}`).
- Track your progress on the **Scoreboard** page.
- Full walkthroughs live in `SOLUTIONS.md`. Try without them first.
- Every vulnerability is marked in the source with `// VULN:` comments so you can study the code after solving.

## Vulnerability inventory

34 intentionally vulnerable challenges across 13 modules:

| Module | Vulnerabilities |
|--------|-----------------|
| **xss** – Cross-Site Scripting | Reflected XSS · Stored XSS (guestbook) · DOM XSS |
| **sqli** – SQL Injection | Auth bypass · UNION injection · Blind boolean injection · Error-based injection |
| **auth** – Broken Authentication | No rate limiting (brute force) · JWT `alg=none` · Password reset token forgery |
| **idor** – Access Control | Profile IDOR · Order IDOR · Unprotected admin panel |
| **ssrf** – Server-Side Request Forgery | Basic SSRF · Blocklist bypass (decimal IP) |
| **upload** – File Upload | Stored XSS via SVG/HTML upload · Extension blacklist bypass |
| **cmdi** – Command Injection | Ping gadget (no filtering) · Ping gadget v2 (weak `;` blacklist) |
| **xxe** – XML External Entities | XXE file read · SSRF via XXE |
| **ssti** – Template Injection | Basic SSTI (`{{7*7}}`) · SSTI to RCE |
| **lfi** – Path Traversal | Basic traversal (`../`) · Filter bypass (`....//`) |
| **csrf** – Cross-Site Request Forgery | State-changing GET (email change) · Open redirect · Clickjacking (no frame headers) |
| **api** – API Abuse | Mass assignment · Excessive data exposure · Missing rate limiting |
| **misconfig** – Security Misconfiguration | Verbose debug errors · Exposed backup file · Directory listing |

## Rules

1. Attack **only** this application.
2. Flags prove exploitation. Share write-ups, not just flags.
3. Built for learning. If you find an *unintended* vulnerability, that's a bonus flag in spirit.

## License

Educational use only. Built by The PenTrix.
