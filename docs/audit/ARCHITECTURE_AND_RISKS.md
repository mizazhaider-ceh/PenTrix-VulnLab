# ARCHITECTURE_AND_RISKS: PenTrix VulnLab (Phase Zero)

## Architecture (observed)

```
browser -> Express 4 (app.js) -> auto-mounted module routers (29x)
                                 -> better-sqlite3 (data/vulnlab.db)
                                 -> express-session MemoryStore (flags in session)
static: public/style.css, /uploads served statically
```

- Request flow is simple and readable. Module isolation is by convention
  (MODULE_CONTRACT rule 4), enforced only by code review, not by the loader.
- No layers: routers talk to SQLite directly, render HTML directly.
- 15k lines of template-string HTML across 29 routers; no shared components
  beyond `page/esc/flagBox/hintBox/brief`.

## Risks, ranked

### Intended vulnerabilities (by design, must stay contained)

1. The app is deliberately vulnerable (SQLi, RCE via cmdi, SSTI, file upload,
   etc.). Container has g++ and python3 installed (build-time need) which
   widens post-exploit capability inside the container. Acceptable for a local
   lab; must never be exposed beyond localhost / isolated lab net.
2. `docker-compose.yml` binds `3000:3000` on all interfaces by default. On a
   shared network this exposes the vulnerable app to the LAN. Recommend
   `127.0.0.1:3000:3000` in the default compose file (reversible, documented).
3. `./data:/app/data` mount with `chmod 777` on data/uploads inside the image.
   Fine for local single-user; document that multi-user deployments need real
   isolation (separate containers or per-student DBs).

### Unintended weaknesses (candidates for fixing)

4. `express-session` MemoryStore: leaks memory under load, loses all progress on
   restart. For a local lab this is tolerable, but a tiny sqlite-backed or
   file-backed store would make progress durable. Low priority.
5. No rate limiting anywhere (some auth labs intentionally lack it, but the
   session/scoreboard layer has none either).
6. `data/vulnlab.db` is committed to git while `.gitignore` lists `data/`.
   Contradictory; every clone carries a stale DB and local runs dirty it.
   Recommend: gitignore the DB properly, seed on first boot (already supported).
7. No healthcheck, no resource limits, no restart policy in compose.
8. `npm ci` needs build tools; better-sqlite3@11 has no Node 24 prebuild, so
   contributors on newer Node hit the node-gyp path (worked here with a nodedir
   workaround; v12 has prebuilds). Recommend bumping to better-sqlite3@12 after
   testing, or pinning Node 20 in README/CONTRIBUTING.
9. 29 routers duplicate HTML patterns; no shared form/table/pagination
   components. Any redesign must introduce components without breaking the
   module contract.
10. `// VULN:` markers (280) are great for study-after-solving, but they also
    mean solutions are grep-able. That is a deliberate pedagogical tradeoff;
    keep, but do not put flags or full payloads in comments.

### Hypotheses (not yet verified)

- H1: Some of the 235 vulns may be shallow (flag via one click) or duplicated
  across modules. Needs the lab quality matrix (Phase Five).
- H2: The `race` module may behave nondeterministically under load. Needs testing.
- H3: Session fixation / cookie flags are intentionally weak for cookie-stealing
  demos; confirm each is marked VULN and covered by a lab.

## Change-safety notes (Rule 1)

- Working tree was clean at discovery. No checkpoint commit made yet; first
  structural change will be preceded by a `phase-zero-baseline` tag/branch.
- Loader contract (`{id, name, tagline, description, difficulty, vulns[], router}`)
  is the compatibility surface. Frontend redesign must keep it stable.
- Test strategy: keep a live instance running during changes; curl the home,
  scoreboard, and every module index after each milestone (scriptable).
