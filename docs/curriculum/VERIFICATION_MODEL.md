# Verification Model: what the server observes before awarding

Date: 2026-10-19 (Milestone 5, verification integrity). Every flag in the lab is
awarded only on server-observable evidence that the exploit succeeded. This
document records, per changed module, what that evidence is, and lists the
awards that were left unchanged because they were already sound.

Rule: a forged request that never executed the vulnerability earns no flag.
Tokens are per-session, single-use, and rotated on award. Nothing here adds
CAPTCHAs or rate limits on the exploit path; every challenge stays solvable
with a browser, curl, or Burp-style manual requests.

## Changed modules

### csrf / clickjacking (was: award on page visit)
The server now observes the full framing chain before awarding: (1) the framing
demo `/csrf/framedemo` issues a one-time frame token, (2) the victim page
`/csrf/vip-action` is actually loaded inside the frame carrying that token, and
(3) the framed form is submitted back with the token. Visiting the demo alone,
or POSTing without the token, earns nothing.

### xss (was: beacon honored from any client)
Each challenge page renders a per-session, per-vuln token as `window.__px`.
The beacon `/xss/collect` awards only when it arrives with non-empty data, a
known vuln id, and the token for that vuln (single-use). The SVG lab carries
the token in the file link's `?n=` query string instead, read from
`location.search` by the script running inside the opened SVG. Applies to:
reflected, stored, dom, stored-xss-profile, xss-attr-breakout, xss-js-context,
xss-svg-upload, xss-markdown, xss-hash-write, xss-backtick.

### postmsg (was: prefix-match beacons for no-check, data-xss, substring)
The three victim pages render a per-session, per-vuln token (`PM_NONCE`) and
their beacon scripts echo it back. The beacon awards only on prefix match plus
a valid single-use token. `wildcard` (session secret in the beacon) and
`csrf-action` (server-side `pm_deleted` state) were already evidence-bound and
are unchanged.

### csti (was: beacon honored from any client)
Each lab page renders a per-session, per-vuln token (`CSTI_NONCE`). Auto-beacon
labs echo it in the beacon fetch; the constructor lab's manual payload must echo
it too. The beacon awards only on the expected result data plus a valid
single-use token.

### jsonp
- `callback-xss`, `filter-bypass`, `mimetype` (were: input-pattern awards): each
  JSONP endpoint embeds a per-session token in its response data. The injected
  script must echo the token back to `/jsonp/beacon-xss`, proving it executed
  with the response data. `filter-bypass` additionally requires the taught
  payload shape (string concatenation beating the `alert` filter) to have been
  attempted; `mimetype` additionally requires an HTML-shaped callback attempt.
- `csrf-data` (was: module-constant secret): the feed now serves a per-session
  secret; the beacon accepts only the secret this session's feed served
  (single-use, rotates on award).
- `array-hijack` (was: constant feed items): the legacy feed appends a
  per-session token element; the beacon must carry the hijacked items including
  that token (single-use, rotates on award).

### cmdi (was: input-pattern awards for basic and bypass)
`basic` and `bypass` now award only when the shell output contains evidence a
second command ran (`uid=`, `gid=`, `root:`, `daemon:`, `total `). The student's
own input is scrubbed from the output first, so echoing a marker without
injection cannot award. The v3-v10 gadgets already required output evidence
(pattern plus output marker) and are unchanged.

## Awards left unchanged (already sound)

- `xss/xss-dom-clobber`: server inspects the stored markup for the genuine
  clobbering shape (form id=settings plus named isAdmin input) before awarding.
- `postmsg/wildcard`: beacon must carry the per-session secret the victim page
  broadcast. `postmsg/csrf-action`: beacon requires server-side deleted state.
- `cmdi` v3-v10 (cmdi-ifs, cmdi-braces, cmdi-newline, cmdi-backtick,
  cmdi-wildcard, cmdi-pipe, cmdi-tab, cmdi-env): each already required the
  injected command's output (`root:` / `uid=`) in addition to the taught
  payload shape.
- Everything else in the curriculum: outcome/state-based awards (secret matched,
  state changed, file actually read), marker-in-response awards, timing awards,
  and config-checker harnesses were out of scope for this milestone. The cors
  config-checker rebuild and the http/crlf-log input-pattern award remain open
  items for Milestone 7.
