<p align="center">
  <img src="https://img.shields.io/badge/Flags-197+-red?style=for-the-badge&logo=hackthebox&logoColor=white" alt="Flags"/>
  <img src="https://img.shields.io/badge/Chapters-18-blue?style=for-the-badge&logo=owasp&logoColor=white" alt="Chapters"/>
  <img src="https://img.shields.io/badge/Linux%20CTF-10%20Flags-green?style=for-the-badge&logo=linux&logoColor=white" alt="Linux CTF"/>
  <img src="https://img.shields.io/badge/Docker-4%20Services-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License"/>
</p>

# PenTrix — Vulnerable Web Application Pentesting Lab

A **professional-grade**, deliberately vulnerable web application lab for practicing penetration testing, API exploitation, SSRF chains, and Linux privilege escalation — inside a segmented Docker network.

> **You're not solving CTF puzzles. You're breaching PenTrix Corp — a fictional company with sloppy DevOps, internal drama, and broken security at every layer.**

---

## Why PenTrix?

| | PenTrix | DVWA | Juice Shop | WebGoat |
|--|---------|------|------------|---------|
| **Total Challenges** | 197+ flags + 10 secrets | ~14 | ~100 | ~30 |
| **Multi-Service Architecture** | 4 Docker services, 2 networks | Single app | Single app | Single app |
| **Network Segmentation** | DMZ + Internal (enterprise-style) | None | None | None |
| **Linux Privesc Machine** | 10-flag dedicated CTF box | None | None | None |
| **SSRF to Internal Pivot** | Full chain (Web to API to Redis) | None | Basic | None |
| **Corporate Narrative** | Emails, chat, wiki, audit checklists | None | Juice Shop story | Lesson-based |
| **Attack Scenarios** | 3 guided multi-step chains | None | Challenges only | Lessons only |
| **Hint System** | 522+ narrative hints (3-tier, organic) | On/off toggle | Hints | Lessons |
| **Red Herrings** | Educational decoy endpoints | None | None | None |

---

## Architecture

```
                     +------------------------------+
                     |      ATTACKER MACHINE         |
                     +--------+-----------+----------+
                         :5000|           |:8888/:2222
+============================|===========|============+
|  DMZ Network (10.10.1.0/24)|           |            |
|  +---------------------+   |  +--------+----------+ |
|  |  pentrix_web         |<--+  | pentrix_linux_ctf | |
|  |  Flask + SQLite      |      | Debian + Apache   | |
|  |  197 Vuln Flags      |      | SSH + 10 Flags    | |
|  +----------+-----------+      +-------------------+ |
+==============|======================================+
               | SSRF
+==============|======================================+
|  Internal Network (10.10.2.0/24) -- NOT EXPOSED      |
|  +----------+----------+  +-----------------------+  |
|  |  pentrix_internal    |  |    pentrix_redis      |  |
|  |  SSRF Target + RCE  |  |    No Auth (6379)     |  |
|  |  AWS Metadata Mock   |  |    Gopher Exploit     |  |
|  +----------------------+  +-----------------------+  |
+======================================================+
```

| Service | IP | Exposed Ports | Role |
|---------|------|------|------|
| **Web App** | 10.10.1.10 | 5000 | Primary attack surface — all web vulns |
| **Linux CTF** | 10.10.1.20 | 8888 (HTTP), 2222 (SSH) | Privilege escalation machine |
| **Internal API** | 10.10.2.20 | 8080 (internal only) | SSRF target, AWS metadata mock, RCE |
| **Redis** | 10.10.2.30 | 6379 (internal only) | SSRF to Redis exploitation via Gopher |

> See [ARCHITECTURE.md](ARCHITECTURE.md) for full network topology, attack paths, and database schema.

---

## Quick Start

```bash
# Clone
git clone https://github.com/mizazhaider-ceh/PenTrix-VulnLab.git
cd PenTrix-VulnLab

# Launch (builds all 4 services)
docker compose up --build -d

# Verify
docker compose ps
```

| What | Where |
|------|-------|
| Main Application | http://localhost:5000 |
| Challenge Hub | http://localhost:5000/challenges |
| Scoreboard | http://localhost:5000/scoreboard |
| Linux CTF (HTTP) | http://localhost:8888 |
| Linux CTF (SSH) | `ssh -p 2222 localhost` |

```bash
# Stop
docker compose down

# Full reset (wipes database)
docker compose down -v
```

---

## Challenge Chapters

<table>
<tr><th>#</th><th>Chapter</th><th>Category</th><th>Flags</th><th>Difficulty</th><th>OWASP</th></tr>
<tr><td>01</td><td>First Contact</td><td>Reconnaissance</td><td>10</td><td>*</td><td>--</td></tr>
<tr><td>02</td><td>Know Your Target</td><td>Fingerprinting</td><td>10</td><td>*</td><td>--</td></tr>
<tr><td>03</td><td>Doors Without Locks</td><td>Broken Access Control</td><td>10</td><td>**</td><td>A01</td></tr>
<tr><td>04</td><td>Secrets in the Open</td><td>Sensitive Data Exposure</td><td>10</td><td>**</td><td>A02</td></tr>
<tr><td>05</td><td>Breaking Boundaries</td><td>Directory Traversal</td><td>10</td><td>**</td><td>A01</td></tr>
<tr><td>06</td><td>Keys Under the Mat</td><td>Broken Authentication</td><td>10</td><td>**</td><td>A07</td></tr>
<tr><td>07</td><td>Mapping the Unknown</td><td>Fuzzing and Discovery</td><td>10</td><td>**</td><td>A05</td></tr>
<tr><td>08</td><td>Injecting Reality</td><td>Cross-Site Scripting</td><td>10</td><td>***</td><td>A03</td></tr>
<tr><td>09</td><td>The Client is Lying</td><td>DOM Vulnerabilities</td><td>10</td><td>***</td><td>A03</td></tr>
<tr><td>10</td><td>Trust No Request</td><td>CSRF</td><td>10</td><td>***</td><td>A01</td></tr>
<tr><td>11</td><td>Total Control</td><td>Remote Code Execution</td><td>10</td><td>****</td><td>A03</td></tr>
<tr><td>12</td><td>Invisible Hands</td><td>Clickjacking</td><td>10</td><td>**</td><td>A05</td></tr>
<tr><td>13</td><td>Broken by Design</td><td>Insecure Design and Logic</td><td>10</td><td>**</td><td>A04</td></tr>
<tr><td>14</td><td>The Machine Speaks</td><td>API Vulnerabilities</td><td>10</td><td>***</td><td>A06</td></tr>
<tr><td>15</td><td>Trusted by Mistake</td><td>CORS Misconfiguration</td><td>10</td><td>***</td><td>A05</td></tr>
<tr><td>16</td><td>The Database Obeys</td><td>SQL Injection</td><td>10</td><td>***</td><td>A03</td></tr>
<tr><td>B1</td><td>Reaching the Unreachable</td><td>SSRF (Bonus)</td><td>10</td><td>****</td><td>A10</td></tr>
<tr><td>B2</td><td>The XML Weapon</td><td>XXE (Bonus)</td><td>10</td><td>****</td><td>A05</td></tr>
<tr><td>17</td><td>Red Team Operator</td><td>Advanced Exploitation</td><td>14</td><td>****</td><td>Multi</td></tr>
</table>

### Attack Scenarios

| Scenario | Codename | Difficulty | Description |
|----------|----------|------------|-------------|
| **A** | The Insider | Medium | Fingerprinting then Default Creds then IDOR then Admin |
| **B** | Data Heist | Hard | Fuzzing then CORS Exploit then IDOR then SQLi then Exfil |
| **C** | Full Compromise | Expert | Recon then Traversal then SQLi then Auth Bypass then SSRF then RCE then Privesc |

### Linux CTF Flags (10 flags)

| # | Technique | Difficulty |
|---|-----------|------------|
| 1 | Web Page Source Inspection | * |
| 2 | Directory Enumeration | * |
| 3 | Weak SSH Credentials | ** |
| 4 | File Permission Misconfiguration | ** |
| 5 | SUID Binary Exploitation | *** |
| 6 | Cron Job Abuse | *** |
| 7 | Sudo to Root (Final Flag) | *** |
| 8 | Linux Capabilities Abuse | **** |
| 9 | SSH Key Backup + Password Reuse | *** |
| 10 | Internal Network Pivot | **** |

---

## Implemented Vulnerabilities

<details>
<summary><b>Reconnaissance and Discovery</b></summary>

- Technology fingerprinting via response headers and error messages
- Sensitive data in HTML comments, robots.txt, sitemap.xml
- Debug endpoints and stack trace leakage
- Hidden path discovery and directory listing
- API endpoint enumeration

</details>

<details>
<summary><b>Injection</b></summary>

- SQL Injection — Union, Error-based, Blind Boolean, Blind Time-based, Second-order
- Cross-Site Scripting — Reflected, Stored, DOM-based, via SVG upload
- Server-Side Template Injection (Jinja2)
- OS Command Injection (multiple vectors)
- XML External Entity (XXE) — Classic, Blind OOB, Error-based, XInclude, SOAP
- YAML deserialization and Pickle deserialization

</details>

<details>
<summary><b>Authentication and Session</b></summary>

- Default and weak credentials
- JWT algorithm confusion (RS256 to HS256), algorithm=none bypass
- Session fixation and predictable token generation
- Brute-forceable password reset mechanisms
- Missing session expiration and invalidation
- Account takeover via security questions

</details>

<details>
<summary><b>Access Control and Business Logic</b></summary>

- IDOR (read to write to delete chains)
- Broken function-level authorization and admin bypass
- Path traversal with encoding bypasses
- Privilege escalation via mass assignment
- Race conditions (TOCTOU double-spend, coupon abuse)
- Client-side price manipulation and negative quantity exploits
- HTTP verb tampering, type juggling, parameter pollution

</details>

<details>
<summary><b>Server-Side Attacks</b></summary>

- SSRF — Internal service access, AWS metadata mock, blind SSRF
- SSRF to Redis command injection via Gopher protocol
- Remote Code Execution via deserialization (Pickle, YAML)
- SSRF chaining through internal microservices to RCE

</details>

<details>
<summary><b>Client-Side Attacks</b></summary>

- Cross-Site Request Forgery (no CSRF tokens anywhere)
- DOM manipulation and prototype pollution
- CORS misconfiguration (origin reflection, null origin, wildcard credentials)
- Clickjacking (no X-Frame-Options, no CSP)

</details>

<details>
<summary><b>Linux Privilege Escalation</b></summary>

- Web recon then hidden directory then SSH credentials
- File permission misconfiguration (world-readable secrets)
- SUID binary exploitation (custom binary)
- Cron job abuse (writable root script)
- Linux capabilities (cap_setuid on Python)
- SSH key backup discovery + password reuse
- Network pivot and internal service discovery
- Full privesc chain to root

</details>

---

## Testing Guide

### By Skill Level

**Beginner**  Start with Chapters 1-2 (Recon, Fingerprinting). Use browser DevTools exclusively.

**Intermediate**  Chapters 3-7 (Access Control, Traversal, Auth, Fuzzing). Add Burp Suite/ZAP.

**Advanced**  Chapters 8-16 (XSS, RCE, SQLi, API, SSRF). Script your exploits.

**Expert**  Chapter 17 (Race Conditions, JWT Confusion, IDOR Chains), Linux CTF, and Attack Scenarios.

### Recommended Tools

| Tool | Use Case |
|------|----------|
| Browser DevTools | Source inspection, cookie editing, network analysis |
| Burp Suite / ZAP | Request interception, parameter fuzzing |
| curl / httpie | API testing, header manipulation |
| sqlmap | Automated SQL injection |
| ffuf / gobuster | Directory and endpoint brute-forcing |
| nmap | Linux CTF network discovery |
| John / Hashcat | Credential cracking |
| Python / Bash | Custom exploit scripting |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.11, Flask 2.3.3, Jinja2 |
| Database | SQLite (intentionally plaintext passwords) |
| Cache | Redis 7 Alpine (no authentication) |
| Auth | Flask Sessions + PyJWT (HS256 + algorithm=none) |
| API | REST (v1/v2) + GraphQL (introspection enabled) |
| XML | lxml 4.9.3 (external entities enabled) |
| Serialization | PyYAML (unsafe load), Pickle |
| Containers | Docker Compose — 4 services, 2 segmented networks |
| Linux CTF | Debian Stable, Apache, OpenSSH, Cron |
| Frontend | Glassmorphism CSS, Vanilla JS |

---

## Common Issues

| Problem | Solution |
|---------|----------|
| Port 5000 in use | Change PORT in .env or docker-compose.yml |
| Containers won't start | Run `docker compose logs` to see errors |
| Database is empty | Run `docker compose down -v` and rebuild |
| Build fails | Check internet connectivity; Docker pulls base images |
| Need full reset | `docker compose down -v && docker compose up --build -d` |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding vulnerabilities, flags, and documentation.

## Security Policy

See [SECURITY.md](SECURITY.md)  all vulnerabilities in this project are **intentional by design**.

---

## Disclaimer

> **This application is INTENTIONALLY VULNERABLE.** It contains real security flaws for educational purposes.
>
> **DO NOT** deploy on public networks, use with real data, or run outside isolated Docker environments.
>
> The author assumes no liability for misuse. **Authorized testing only.**

---

## License

[MIT License](LICENSE.md) — Free for educational use.

---

<p align="center">
  <em>"Not every path leads somewhere. The skill isn't just finding things — it's knowing which findings matter."</em>
  <br/><br/>
  <strong>Built for the security community.</strong>
</p>
