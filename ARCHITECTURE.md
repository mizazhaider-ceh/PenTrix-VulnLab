# Architecture Overview

> Enterprise-style network topology designed for realistic penetration testing training.

## Network Topology

```
                     ┌─────────────────────────────────────┐
                     │           ATTACKER MACHINE           │
                     │       (Kali / Parrot / Host OS)      │
                     └───────────┬───────────┬──────────────┘
                                 │           │
                          :5000  │           │  :8888 (HTTP)
                          (HTTP) │           │  :2222 (SSH)
                                 │           │
╔════════════════════════════════╪═══════════╪═══════════════╗
║  pentrix_dmz (10.10.1.0/24)   │           │               ║
║  ┌─────────────────────────┐  │  ┌────────┴────────────┐  ║
║  │    pentrix_web           │◄─┘  │  pentrix_linux_ctf  │  ║
║  │    10.10.1.10:5000       │     │  10.10.1.20         │  ║
║  │                          │     │                     │  ║
║  │  Flask App + SQLite      │     │  Apache + SSH       │  ║
║  │  13 Route Blueprints     │     │  10 CTF Flags       │  ║
║  │  197+ Vuln Flags         │     │  SUID / Cron /      │  ║
║  │  OWASP Top 10 Coverage   │     │  Capabilities /     │  ║
║  │                          │     │  Network Pivot      │  ║
║  └────────────┬─────────────┘     └─────────────────────┘  ║
╚═══════════════╪════════════════════════════════════════════╝
                │
                │  SSRF / Internal API
                │
╔═══════════════╪════════════════════════════════════════════╗
║  pentrix_internal (10.10.2.0/24) — NOT exposed to host    ║
║               │                                            ║
║  ┌────────────┴────────────┐  ┌─────────────────────────┐ ║
║  │    pentrix_internal      │  │     pentrix_redis       │ ║
║  │    10.10.2.20:8080       │  │     10.10.2.30:6379     │ ║
║  │                          │  │                         │ ║
║  │  Python Microservice     │  │  Redis 7 (Alpine)      │ ║
║  │  AWS Metadata Mock       │  │  No Authentication     │ ║
║  │  Admin Panel / RCE       │  │  SSRF → Redis Target   │ ║
║  │  10 SSRF Flags           │  │  Gopher Protocol       │ ║
║  └──────────────────────────┘  └─────────────────────────┘ ║
╚════════════════════════════════════════════════════════════╝
```

## Service Details

| Service | Container | IP | Ports | Technology | Purpose |
|---------|-----------|------|-------|------------|---------|
| Web App | `pentrix_web` | 10.10.1.10 | 5000 (exposed) | Flask 2.3.3 + SQLite | Primary attack surface |
| Internal API | `pentrix_internal` | 10.10.2.20 | 8080 (internal) | Python HTTP Server | SSRF target, AWS metadata mock |
| Redis | `pentrix_redis` | 10.10.2.30 | 6379 (internal) | Redis 7 Alpine | Cache, SSRF→Redis exploitation |
| Linux CTF | `pentrix_linux_ctf` | 10.10.1.20 | 80, 22 (exposed) | Debian + Apache + SSH | Privilege escalation machine |

## Attack Paths

### Path 1: Web → Internal Service (SSRF Chain)
```
Attacker → Web App (:5000)
              │
              ├─ /tools/fetch (SSRF)
              │     └─ http://10.10.2.20:8080/admin     → Internal admin panel
              │     └─ http://10.10.2.20:8080/metadata   → AWS IAM credentials
              │     └─ http://10.10.2.20:8080/exec       → Remote code execution
              │
              └─ /api/webhook/test (Blind SSRF)
                    └─ gopher://10.10.2.30:6379/...      → Redis command injection
```

### Path 2: Linux CTF Privilege Escalation Chain
```
Web Recon (Flag 1)
    └─ Directory Enum (Flag 2)
        └─ Weak SSH Creds (Flag 3)
            ├─ File Permission Misconfig  (Flag 4)  ← sysadmin creds leaked
            ├─ SUID Binary Exploitation   (Flag 5)  ← read as root
            ├─ Cron Job Exploitation      (Flag 6)  ← code exec as root
            ├─ Capability Abuse           (Flag 8)  ← python3 cap_setuid
            ├─ SSH Key from Backup        (Flag 9)  ← /var/backups/old-keys
            ├─ Network Pivot              (Flag 10) ← discover web app internally
            └─ Root Flag                  (Flag 7)  ← su sysadmin → sudo su
```

### Path 3: Full Compromise (Multi-Service)
```
1. Recon           → Map attack surface (robots.txt, sitemap, headers)
2. SQLi            → Dump credentials from database
3. SSRF            → Reach internal service, extract secrets
4. JWT Forgery     → Impersonate admin using leaked SECRET_KEY
5. RCE             → Command injection via /tools/ping or SSTI
6. Lateral Move    → Pivot from web container to Linux CTF
7. Priv Esc        → Escalate to root on Linux machine
8. Data Exfil      → Extract all sensitive data across services
```

## Database Schema (SQLite)

```sql
users            ─── Core user table (plaintext passwords, PII)
sessions         ─── Session management (short IDs, no expiry)
posts            ─── User content (stored XSS target)
comments         ─── Post comments (stored XSS target)
messages         ─── Private messages (IDOR target)
files            ─── File metadata (path traversal target)
tickets          ─── Support tickets (XSS target)
flags            ─── CTF flag registry
submissions      ─── Flag submission tracking
hints            ─── Tiered hint system
hint_unlocks     ─── Hint purchase tracking
api_keys         ─── API authentication keys
coupons          ─── Discount codes (race condition target)
access_logs      ─── Request logging (UA injection target)
approval_requests ── Workflow approvals (self-approval target)
```

## Vulnerability Coverage by OWASP Category

| OWASP 2021 | Chapters |  Flags |
|------------|----------|--------|
| A01: Broken Access Control | CH03, CH05, CH17 | 24 |
| A02: Cryptographic Failures | CH04, CH06 | 20 |
| A03: Injection | CH08, CH11, CH16 | 30 |
| A04: Insecure Design | CH13, CH17 | 24 |
| A05: Security Misconfiguration | CH01, CH02, CH07, CH12, CH15 | 50 |
| A06: Vulnerable Components | CH11 | 10 |
| A07: Auth Failures | CH06, CH17 | 24 |
| A08: Data Integrity Failures | CH10, CH11 | 20 |
| A09: Logging Failures | CH02, CH04 | 10 |
| A10: SSRF | BONUS-SSRF, CH17 | 11 |

## Technology Stack

```
Frontend:    HTML5 / CSS3 (Glassmorphism) / Vanilla JS
Backend:     Python 3.11 / Flask 2.3.3 / Jinja2
Database:    SQLite 3 (intentionally plaintext storage)
Cache:       Redis 7 (no authentication)
Auth:        JWT (HS256, algorithm=none bypass)
Container:   Docker / Docker Compose 3.8
Networks:    Bridge (DMZ + Internal segregation)
Linux CTF:   Debian Stable / Apache / OpenSSH / Cron
```
