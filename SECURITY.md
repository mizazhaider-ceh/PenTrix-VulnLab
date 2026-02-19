# Security Policy

## ⚠️ Important Notice

**PenTrix Vuln Lab is an INTENTIONALLY VULNERABLE application** designed for cybersecurity education and penetration testing practice. Every vulnerability in this project exists by design.

## Scope

### In Scope (By Design — Not Bugs)
- SQL Injection, XSS, CSRF, SSRF, XXE, RCE
- Broken authentication and access control
- Insecure deserialization
- Business logic flaws
- All 197+ flags and 10 CTF secrets

### Out of Scope
- Vulnerabilities in Docker itself
- Issues in base images (Python, Redis, Debian)
- Network-level attacks outside the Docker environment

## Reporting Actual Bugs

If you find a **unintentional** bug that breaks the lab functionality (not a security vulnerability — those are features), please:

1. Open a GitHub Issue with the `bug` label
2. Include steps to reproduce
3. Specify your Docker and OS version

## Responsible Use

- **NEVER** deploy this application on a public-facing server
- **NEVER** use techniques learned here against systems without explicit written authorization
- **ALWAYS** run in an isolated Docker environment
- This project is intended for local development and isolated lab environments only

## Contact

For questions about this project: [GitHub Issues](https://github.com/mizazhaider-ceh/PenTrix-VulnLab/issues)
