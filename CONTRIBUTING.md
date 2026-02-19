# Contributing to PenTrix Vuln Lab

Thank you for your interest in contributing! PenTrix is a community-driven vulnerable web application designed for learning penetration testing.

## How to Contribute

### Adding New Vulnerabilities

1. **Choose a category** — Pick an OWASP Top 10 category or propose a new chapter
2. **Create a route** — Add a new endpoint in `app/routes/` following the existing pattern
3. **Add a flag** — Register the flag in `app/flags.py` with a meaningful name
4. **Write hints** — Add 3-tier narrative hints in the `_build_hints()` function
5. **Label it** — Comment the vuln with `# [VULN: CH##-C##]`

### Vulnerability Naming Convention

```
# [VULN: CH{chapter}-C{challenge_number}]
# Chapter 01-17: Main challenges
# BONUS-SSRF-C##: SSRF bonus flags
# BONUS-XXE-C##: XXE bonus flags
# SCENARIO-{A,B,C}: Multi-step attack scenarios
```

### Flag Format

```python
# In MEANINGFUL_FLAGS dict:
'CH##-C##': 'flag{descriptive_name_of_what_was_exploited}'

# Flag names should reinforce the lesson learned
# Good: flag{race_condition_double_spend}
# Bad:  flag{challenge_17_flag_1}
```

### Adding Linux CTF Flags

1. Edit `linux_ctf/setup.sh`
2. Add the flag creation in the numbered sequence
3. Include clear comments explaining the intended attack path
4. Add breadcrumbs and hints for discoverability
5. Update the MOTD flag count

## Development Setup

```bash
git clone https://github.com/mizazhaider-ceh/PenTrix-VulnLab.git
cd PenTrix-VulnLab
docker-compose build
docker-compose up -d
```

## Code Style

- Python: Follow PEP 8
- Every vulnerability must have a `# [VULN: CH##-C##]` comment
- Use descriptive function names and docstrings
- Keep route functions focused on one vulnerability concept

## Pull Request Guidelines

1. Fork the repo and create a feature branch
2. Add or modify vulnerabilities with proper labeling
3. Ensure Docker build succeeds: `docker-compose build`
4. Include a description of the vulnerability and its educational value
5. Update documentation if adding new chapters

## Reporting Issues

- Use GitHub Issues for bug reports
- Label with `bug`, `enhancement`, or `vulnerability-request`
- Include Docker version and OS in bug reports

## Code of Conduct

- This project is for **educational purposes only**
- Do not use techniques learned here against systems without authorization
- Be respectful in all interactions
- Help others learn — we all started somewhere

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
