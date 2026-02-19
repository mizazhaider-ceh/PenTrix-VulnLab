# The PenTrix — Vulnerable Web App Pentesting Lab 🔺
A comprehensive, deliberately vulnerable web application for practicing penetration testing, web security, API exploitation, and Linux privilege escalation — all inside Docker.

⚠️ **WARNING:** This application is intentionally vulnerable and should only be used for educational purposes in isolated environments.

<!-- Add a screenshot here -->
<!-- ![PenTrix Dashboard](screenshots/dashboard.png) -->

## Overview
This project is a full-scale vulnerable web application pentesting lab that simulates a **realistic corporate environment**. Unlike simple CTF boxes, PenTrix provides an **immersive narrative experience** — you're not solving abstract puzzles, you're penetrating *PenTrix Corp*, a fictional company with sloppy DevOps, exposed secrets, and broken security at every layer. It's designed to help security engineers, pentesters, developers, interns, QA analysts and DevSecOps practitioners learn about:

- Common web application vulnerabilities (OWASP Top 10)
- API security testing (REST & GraphQL)
- Linux privilege escalation techniques
- Server-Side Request Forgery (SSRF) & XXE
- Secure coding practices & code review
- Security testing automation

## Features & Vulnerabilities
### Core Features
- 🔍 **183 Web Challenges** across 16 progressive chapters + 2 bonus categories
- 🔐 **10 CTF Secrets** — elite-difficulty secrets hidden in unconventional places
- 🐧 **7 Linux Privilege Escalation Flags** — full privesc chain from web to root
- 🎬 **3 Multi-Step Attack Scenarios** — real-world attack chains combining multiple vulnerabilities
- 📊 **Built-in Scoreboard** — per-chapter progress tracking, global rankings, milestone messages
- 💡 **480 Narrative Hints** — 3-tier hint system that feels like discovering clues, not reading instructions
- 🏢 **Corporate Simulation** — internal emails, chat, notes, wiki, audit checklists
- 🚩 **Meaningful Flag Names** — every flag reinforces the vulnerability you exploited
- 🔗 **Challenge Linkage** — completing certain challenges reveals clues for others
- 🎭 **Red Herrings** — decoy endpoints with educational lessons about real pentesting

### Implemented Vulnerabilities

**Reconnaissance & Information Disclosure**
- Technology fingerprinting via headers, responses, and error messages
- Sensitive data exposure in HTML comments, headers, robots.txt
- Debug information and stack trace leakage
- Directory listing and hidden path discovery
- Information disclosure through API responses

**Broken Access Control**
- Insecure Direct Object References (IDOR)
- Broken function-level authorization
- Path traversal / directory traversal
- Privilege escalation via role manipulation
- Unprotected admin endpoints
- Clickjacking / UI redressing

**Injection Vulnerabilities**
- SQL Injection (Union, Error-based, Blind, Time-based, Second-order)
- Cross-Site Scripting — Reflected, Stored, DOM-based
- Server-Side Template Injection (SSTI) via Jinja2
- OS Command Injection (multiple vectors)
- XML External Entity (XXE) Injection
- Log injection and header injection

**Authentication & Session Flaws**
- Weak credential policies and default credentials
- JWT manipulation and weak signing keys
- Session fixation and token prediction
- Brute-forceable reset mechanisms
- Missing session expiration and invalidation

**API Security**
- REST API endpoint enumeration
- GraphQL introspection and query abuse
- Mass assignment and excessive data exposure
- Broken Object Level Authorization (BOLA)
- API key leakage and misuse

**Server-Side Attacks**
- Server-Side Request Forgery (SSRF) — hitting internal services & Redis
- Remote Code Execution via deserialization (Pickle, YAML)
- SSRF chaining through internal microservices
- Redis protocol exploitation via SSRF

**Client-Side Attacks**
- Cross-Site Request Forgery (CSRF)
- DOM manipulation and prototype pollution
- CORS misconfiguration exploitation
- Clickjacking with frame injection

**Linux Privilege Escalation (Dedicated CTF Container)**
- Web page source code inspection
- Directory enumeration and hidden paths
- Weak SSH credentials
- File permission misconfigurations
- SUID binary exploitation
- Cron job abuse
- User pivoting and sudo escalation

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          HOST MACHINE                                    │
│                                                                          │
│  ┌─────────────────────┐  ┌──────────────────┐  ┌────────────────────┐  │
│  │   pentrix_web        │  │ pentrix_internal  │  │  pentrix_linux_ctf │  │
│  │   Flask 2.3.3        │  │ Flask Microservice│  │  Debian + Apache   │  │
│  │   Python 3.11        │  │                   │  │  + SSH + 7 Flags   │  │
│  │   SQLite + Jinja2    │  │ SSRF Demo Target  │  │                    │  │
│  │                       │  │                   │  │  HTTP → :8888      │  │
│  │   :5000 ←────────── │  │                   │  │  SSH  → :2222      │  │
│  │                       │  │                   │  │                    │  │
│  │  183 Web Challenges  │  │  :8080 (internal) │  │  Privesc Chain:    │  │
│  │  10 CTF Secrets      │──│  (not exposed)    │  │  Web → SSH →       │  │
│  │  3 Attack Scenarios  │  │                   │  │  SUID → Cron →     │  │
│  │  16 Chapters         │  │                   │  │  Root              │  │
│  └──────────┬───────────┘  └────────┬──────────┘  └────────────────────┘  │
│             │                        │                                     │
│             │    pentrix_net (bridge network)                              │
│             └────────────┬───────────┘                                     │
│                          │                                                 │
│              ┌───────────┴──────────┐                                      │
│              │    pentrix_redis     │                                      │
│              │    Redis 7 Alpine    │                                      │
│              │    :6379 (internal)  │                                      │
│              └──────────────────────┘                                      │
└──────────────────────────────────────────────────────────────────────────┘
```

### Services

| Service | Container | Port | Purpose |
|---------|-----------|------|---------|
| **Web App** | `pentrix_web` | `5000` | Main vulnerable Flask application with all challenges |
| **Internal API** | `pentrix_internal` | `8080` (internal only) | Microservice for SSRF exploitation targets |
| **Redis** | `pentrix_redis` | `6379` (internal only) | Cache — discover and exploit via SSRF |
| **Linux CTF** | `pentrix_linux_ctf` | `8888` (HTTP), `2222` (SSH) | Debian box with 7 privilege escalation flags |

---

## 🎯 Challenge Chapters

<table>
<tr><th>#</th><th>Chapter</th><th>Vulnerability Category</th><th>Challenges</th><th>Difficulty</th><th>OWASP</th></tr>
<tr><td>01</td><td>🔍 First Contact</td><td>Initial Reconnaissance</td><td>10</td><td>⭐</td><td>—</td></tr>
<tr><td>02</td><td>🔎 Know Your Target</td><td>Technology Fingerprinting</td><td>10</td><td>⭐</td><td>—</td></tr>
<tr><td>03</td><td>🔓 Doors Without Locks</td><td>Broken Access Control</td><td>10</td><td>⭐⭐</td><td>A01:2021</td></tr>
<tr><td>04</td><td>📂 Secrets in the Open</td><td>Sensitive Data Exposure</td><td>10</td><td>⭐⭐</td><td>A02:2021</td></tr>
<tr><td>05</td><td>📁 Breaking Boundaries</td><td>Directory Traversal</td><td>10</td><td>⭐⭐</td><td>A01:2021</td></tr>
<tr><td>06</td><td>🔑 Keys Under the Mat</td><td>Broken Authentication</td><td>10</td><td>⭐⭐</td><td>A07:2021</td></tr>
<tr><td>07</td><td>🎯 Mapping the Unknown</td><td>Fuzzing & Discovery</td><td>10</td><td>⭐⭐</td><td>A05:2021</td></tr>
<tr><td>08</td><td>💉 Injecting Reality</td><td>Cross-Site Scripting (XSS)</td><td>10</td><td>⭐⭐⭐</td><td>A03:2021</td></tr>
<tr><td>09</td><td>🌐 The Client is Lying</td><td>DOM Vulnerabilities</td><td>10</td><td>⭐⭐⭐</td><td>A03:2021</td></tr>
<tr><td>10</td><td>🎭 Trust No Request</td><td>CSRF</td><td>10</td><td>⭐⭐⭐</td><td>A01:2021</td></tr>
<tr><td>11</td><td>💀 Total Control</td><td>Remote Code Execution</td><td>10</td><td>⭐⭐⭐⭐</td><td>A03:2021</td></tr>
<tr><td>12</td><td>🖱️ Invisible Hands</td><td>Clickjacking</td><td>10</td><td>⭐⭐</td><td>A05:2021</td></tr>
<tr><td>13</td><td>⚠️ Broken by Design</td><td>Insecure Design & Logic Flaws</td><td>10</td><td>⭐⭐</td><td>A04:2021</td></tr>
<tr><td>14</td><td>🔌 The Machine Speaks</td><td>API Vulnerabilities (REST & GraphQL)</td><td>10</td><td>⭐⭐⭐</td><td>A06:2021</td></tr>
<tr><td>15</td><td>🌍 Trusted by Mistake</td><td>CORS Misconfiguration</td><td>10</td><td>⭐⭐⭐</td><td>A05:2021</td></tr>
<tr><td>16</td><td>💾 The Database Obeys</td><td>SQL Injection</td><td>10</td><td>⭐⭐⭐</td><td>A03:2021</td></tr>
<tr><td>17</td><td>🔗 Reaching the Unreachable</td><td>SSRF (Bonus)</td><td>10</td><td>⭐⭐⭐⭐</td><td>A10:2021</td></tr>
<tr><td>18</td><td>📄 The XML Weapon</td><td>XXE (Bonus)</td><td>10</td><td>⭐⭐⭐⭐</td><td>A05:2021</td></tr>
</table>

### 🎬 Attack Scenarios

Multi-step, real-world attack chains that combine vulnerabilities across chapters:

| Scenario | Name | Difficulty | Steps | Attack Chain |
|----------|------|------------|-------|--------------|
| **A** | The Insider | 🟢 Easy | 3 | Fingerprinting → Default Creds → IDOR to Admin |
| **B** | Data Heist | 🟡 Medium | 5 | Fuzzing → CORS Exploit → IDOR → Data Exposure → SQLi |
| **C** | Full Compromise | 🔴 Hard | 9 | Recon → Traversal → SQLi → Auth Bypass → XSS → CSRF → RCE → SSRF → Privesc |

---

## Installation & Setup 🚀
### Prerequisites
- Docker and Docker Compose
- A modern web browser with Developer Tools
- *Optional:* Burp Suite, OWASP ZAP, curl, Python, or any proxy/scripts you prefer
- Git

### Option 1: Using Docker Compose (Recommended)
Clone the repository:
```bash
git clone https://github.com/mizazhaider-ceh/PenTrix-VulnLab.git
cd PenTrix-VulnLab
```

Start the application:
```bash
docker compose up --build -d
```

Verify all services are running:
```bash
docker compose ps
```

The application will be available at http://localhost:5000

### Option 2: Using Docker Only (Web App)
Clone the repository:
```bash
git clone https://github.com/mizazhaider-ceh/PenTrix-VulnLab.git
cd PenTrix-VulnLab
```

Build the Docker image:
```bash
docker build -t pentrix-web .
```

Run the container:
```bash
docker run -p 5000:5000 pentrix-web
```

> **Note:** Running with Docker only will not include the internal microservice, Redis, or the Linux CTF container. Use Docker Compose for the full experience.

### Accessing the Application
| Service | URL |
|---------|-----|
| **Main Application** | http://localhost:5000 |
| **Challenge Hub** | http://localhost:5000/challenges |
| **Scoreboard** | http://localhost:5000/scoreboard |
| **Linux CTF (HTTP)** | http://localhost:8888 |
| **Linux CTF (SSH)** | `ssh -p 2222 localhost` |

### Stopping the Lab
```bash
# Stop all containers
docker compose down

# Stop and remove all data (full reset)
docker compose down -v
```

### Common Issues & Solutions

**Windows**
- If you get "docker not found": Ensure Docker Desktop is installed and running
- Port 5000 already in use: Change the port mapping in `docker-compose.yml` (e.g., `5001:5000`)
- Permission issues: Run terminal as administrator

**Linux/Mac**
- Port 5000 already in use:
```bash
sudo lsof -i:5000
sudo kill <PID>
```
- Permission denied on Docker:
```bash
sudo usermod -aG docker $USER
# Then log out and back in
```

**Docker Issues**
- Containers not starting: Check Docker daemon is running with `docker info`
- Build failures: Ensure you have internet access for pulling base images
- Out of disk space: Run `docker system prune -a` to clean up

---

## Testing Guide 🎯
### Reconnaissance Testing
- Inspect HTTP response headers for technology fingerprints
- Examine HTML source for hidden comments and metadata
- Check for common files: `robots.txt`, `sitemap.xml`, `.well-known/`
- Enumerate error pages for framework disclosure
- Analyze response timing and behavior differences

### Access Control Testing
- Test for IDOR by manipulating object IDs in URLs and parameters
- Attempt horizontal and vertical privilege escalation
- Access admin functionality as a regular user
- Test path traversal in file operations
- Verify authorization on every API endpoint

### Injection Testing
- SQL injection in form fields, URL parameters, and headers
- XSS payloads in all user input fields (reflected, stored, DOM)
- Template injection via Jinja2 syntax
- Command injection in tool/utility endpoints
- XXE in XML-accepting endpoints
- YAML deserialization in import/config features

### Authentication Testing
- Test for default and weak credentials
- Analyse JWT tokens for weak signing and claim manipulation
- Attempt session fixation and token prediction
- Test password reset mechanisms for weaknesses
- Check for missing session expiration

### API Security Testing
- Enumerate REST API endpoints (v1, v2)
- Test GraphQL for introspection and query manipulation
- Check for mass assignment in POST/PUT requests
- Analyse error responses for information disclosure
- Test CORS headers with different origins

### SSRF Testing
- Attempt to reach internal services from the web application
- Chain SSRF to interact with Redis
- Access internal microservice endpoints via SSRF
- Test for blind vs in-band SSRF
- Explore the internal network via the web app

### Client-Side Testing
- CSRF attacks against state-changing operations
- CORS exploitation to exfiltrate data cross-origin
- Clickjacking via frame injection
- DOM-based vulnerabilities through URL fragments and client-side routing

### Linux Privilege Escalation
- Start from the web interface and work your way to SSH
- Enumerate the filesystem for misconfigurations
- Look for SUID binaries and writable scripts
- Monitor scheduled tasks and exploit them
- Pivot between users to reach root

### CTF Secrets (Bonus)
- Don't just look at page content — look at *everything*: headers, cookies, timing, errors, redirects
- Some secrets require chaining multiple techniques
- The application has 10 secrets — all in `SECRET{...}` format
- Think like a real attacker: what would you overlook?

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **Backend** | Python 3.11, Flask 2.3.3 | Web framework with intentional vulnerabilities |
| **Templating** | Jinja2 3.1.2 | Server-side rendering (SSTI target) |
| **Database** | SQLite | SQL injection targets |
| **Cache** | Redis 7 | SSRF/exploitation target |
| **Auth** | Flask Sessions + PyJWT 2.8.0 | Session management & JWT attacks |
| **API** | REST (v1/v2) + GraphQL | API vulnerability surface |
| **XML** | lxml 4.9.3 | XXE exploitation targets |
| **Serialization** | PyYAML 6.0.1, Pickle | Deserialization attacks |
| **HTTP** | Requests 2.31.0, Flask-CORS 4.0.0 | SSRF & CORS misconfiguration |
| **Linux CTF** | Debian stable, Apache2, OpenSSH | Privilege escalation environment |
| **Container** | Docker Compose (4 services) | Network isolation & realistic infra |

---

## 📚 Skills Covered

### OWASP Top 10 (2021) Mapping

| OWASP Category | PenTrix Chapters |
|----------------|------------------|
| **A01** Broken Access Control | CH03, CH05, CH10, CH12 |
| **A02** Cryptographic Failures | CH04 |
| **A03** Injection | CH08, CH09, CH11, CH16 |
| **A04** Insecure Design | CH13 |
| **A05** Security Misconfiguration | CH07, CH15, Bonus-XXE |
| **A06** Vulnerable Components | CH14 |
| **A07** Authentication Failures | CH06 |
| **A08** Software Integrity Failures | Deserialization in CH11 |
| **A09** Logging & Monitoring Failures | Log injection & exposure |
| **A10** SSRF | Bonus-SSRF |

### Hands-On Skills

<table>
<tr>
<td width="50%" valign="top">

**Offensive Security**
- Web application reconnaissance & fingerprinting
- HTTP header analysis & cookie manipulation
- SQL injection (Union, Error, Blind, Time-based, Second-order)
- Cross-Site Scripting (Reflected, Stored, DOM-based)
- Server-Side Template Injection (SSTI)
- Remote Code Execution via OS command injection
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE) attacks
- Cross-Site Request Forgery (CSRF)
- CORS exploitation
- Clickjacking / UI redressing
- Directory traversal / path manipulation
- Authentication bypass (JWT, session, brute-force)
- IDOR / privilege escalation
- API enumeration (REST, GraphQL introspection)
- Insecure deserialization (Pickle, YAML)

</td>
<td width="50%" valign="top">

**Linux & Infrastructure**
- SSH brute-forcing & credential guessing
- SUID binary exploitation
- Cron job abuse for privilege escalation
- File permission enumeration
- Linux user pivoting (su → sudo chain)
- Web server directory enumeration
- Internal service discovery

**Tools & Methodology**
- Burp Suite / OWASP ZAP proxy usage
- curl & scripting for automation
- Browser Developer Tools mastery
- Directory brute-forcing (dirb, gobuster, ffuf)
- Docker container analysis
- Redis protocol exploitation
- Network pivoting between services

</td>
</tr>
</table>

---

## 🎨 Design Highlights

- **Glassmorphism UI** — Modern dark theme with frosted glass effects and smooth animations
- **Narrative-Driven** — Corporate simulation with internal emails, chat, notes, wiki, audit checklists
- **Red Herrings** — Decoy endpoints that teach real pentesting lessons about false positives
- **Challenge Linkage** — Completing certain challenges reveals clues for others, simulating real attack chains
- **AJAX Flag Submission** — Submit flags inline without page reloads
- **Progress Tracking** — Per-chapter completion percentages, global scoreboard, milestone messages
- **Meaningful Flags** — Every flag name reinforces the vulnerability you just exploited

---

## Contributing 🤝
Contributions are welcome! Feel free to:

- Add new vulnerabilities and challenges
- Improve existing features
- Document testing scenarios
- Enhance documentation
- Fix bugs (that aren't intentional vulnerabilities)

---

## ⚠️ Disclaimer

This application contains **intentional security vulnerabilities** for educational purposes. **DO NOT:**

- Deploy in production
- Use with real personal data
- Run on public networks
- Use for malicious purposes
- Store sensitive information

The author assumes no liability for misuse of this software.

Ethical hacking only. Scope respected. Coffee consumed. ☕

---

## 📄 License

This project is licensed under the [MIT License](LICENSE.md).

---

<p align="center">
  <strong>Made with ❤️ for Security Education</strong><br/>
  <em>"Not every path leads somewhere. The skill isn't just finding things — it's knowing which findings matter."</em>
</p>
