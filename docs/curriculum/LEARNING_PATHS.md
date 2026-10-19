# PenTrix VulnLab Learning Paths

This document defines the curriculum structure: tracks, prerequisites, tool mapping, and the scoring model. It is the source of truth for the learning path metadata surfaced on module index pages.

## Tracks

The 29 modules are organized into four tracks. Each module declares its track and prerequisites in its `module.exports` (`track`, `prerequisites`). The index page renders a banner via `trackBanner(mod)` from `lib/page.js`.

### Foundations
Start here. These modules teach the core web security model: how browsers, servers, and HTTP interact, and what goes wrong when developers trust user input.

| Module | Difficulty | Prerequisites | Tools |
|--------|-----------|---------------|-------|
| misconfig | Beginner | none | Browser, curl |
| idor | Beginner | misconfig | Browser, curl |
| xss | Beginner | misconfig | Browser |
| csrf | Beginner | xss | Browser |
| redirect | Beginner | misconfig | Browser, curl |
| http | Beginner | misconfig | curl |
| formula | Beginner | xss | Browser |

### Injection
Server-side injection flaws. You will send payloads that change the meaning of queries, commands, templates, and file paths.

| Module | Difficulty | Prerequisites | Tools |
|--------|-----------|---------------|-------|
| sqli | Intermediate | Foundations track | Browser, curl |
| cmdi | Intermediate | sqli | Browser, curl |
| ssti | Intermediate | sqli, xss | Browser, curl |
| xxe | Intermediate | sqli | Browser, curl |
| lfi | Intermediate | sqli | Browser, curl |
| upload | Intermediate | xss | curl |
| csti | Intermediate | xss, ssti | Browser |

### Auth and Sessions
Identity, sessions, tokens, and the browser security model. These modules teach how authentication breaks and how cross-origin attacks work.

| Module | Difficulty | Prerequisites | Tools |
|--------|-----------|---------------|-------|
| auth | Intermediate | Foundations track | Browser, curl, Python |
| session | Intermediate | auth | Browser, devtools |
| jwt | Intermediate | auth | Browser, node, wordlist |
| oauth | Intermediate | auth, jwt | Browser, curl |
| cors | Intermediate | xss | Browser |
| hostheader | Intermediate | auth | curl |

### Advanced
Challenging labs that combine multiple primitives or target subtle logic flaws. Attempt after completing the earlier tracks.

| Module | Difficulty | Prerequisites | Tools |
|--------|-----------|---------------|-------|
| ssrf | Advanced | Injection track | curl |
| crypto | Advanced | Injection track | Python, curl |
| race | Advanced | Auth and Sessions track | Python, curl |
| proto | Advanced | xss, sqli | Browser, curl |
| bizlogic | Intermediate | Foundations track | Browser, Burp/ZAP |
| postmsg | Intermediate | xss, cors | Browser, devtools |
| jsonp | Intermediate | xss, cors | Browser |
| redos | Intermediate | Injection track | Browser, curl |
| api | Intermediate | Auth and Sessions track, Injection track | curl |

## Tool Legend

- **B** (Browser): the challenge is solvable with a normal browser and address bar.
- **DT** (devtools): browser developer tools (console, network, application/storage).
- **C** (curl): command-line HTTP client for raw requests.
- **P** (Python): scripting for automation, brute force, or crypto.
- **BZ** (Burp/ZAP): intercepting proxy for request tampering.
- **N** (node): Node.js for JWT crafting and token manipulation.
- **W** (wordlist): dictionary attacks (passwords, secrets).

Each vulnerability entry carries a `tools` field (e.g. `tools: "B, C"`), rendered on the index page via `toolsPill(v)` from `lib/page.js`.

## Hint Ladders

Every vulnerability has a 3-step progressive hint ladder (`hints: [...]`), rendered via `hintLadder(v)`:

1. **Step 1 (nudge):** points at the right area without naming the technique.
2. **Step 2 (technique):** teaches the underlying technique or concept.
3. **Step 3 (explicit):** gives the concrete payload or action.

The original single `hint` field is preserved for backwards compatibility but superseded by the ladder on index pages. Solutions remain gated behind solving: hints teach, they do not hand over flags.

## Remediation Panels

After each flag capture, a "The Fix" panel appears (via `fixPanel(mod, vulnId)` from `lib/page.js`). It contains 2-4 sentences explaining the remediation and a link to the relevant OWASP Cheat Sheet. The content is original; it does not copy cheat-sheet text.

The fix database lives in `lib/page.js` as the `FIXES` table, keyed by `"<module>:<vulnId>"`. If a key is missing, `fixPanel` renders nothing (fail-safe).

## Scoring Model

Difficulty-weighted scoring: **Easy = 1 point, Medium = 2 points, Hard = 3 points.**

### Implementation

The `scoreFor(difficulty)` helper in `lib/page.js` maps difficulty strings to points:

```js
function scoreFor(difficulty) {
  const d = String(difficulty || '').toLowerCase();
  if (d === 'easy') return 1;
  if (d === 'hard') return 3;
  return 2; // Medium and anything else
}
```

### app.js Integration Point (for the coordinator)

The scoreboard page template lives in `app.js` (not in M7's files). To apply difficulty-weighted scoring:

1. In `app.js`, locate the scoreboard computation: the `totals()` function and the `moduleProgress()` function, plus the scoreboard template's `got/total` accumulation loop.
2. Where the scoreboard sums captured flags (currently 1 point per flag), replace the increment with `scoreFor(vuln.difficulty)`.
3. The `scoreChipHtml` helper (if present) should display the weighted total.
4. `lib/page.js` already exports `scoreFor`; `app.js` can `require('./lib/page').scoreFor` (or `require('../lib/page')` depending on path).

Example integration:
```js
const { scoreFor } = require('./lib/page');
// ... in the scoreboard loop:
total += scoreFor(vuln.difficulty);
if (captured) got += scoreFor(vuln.difficulty);
```

This keeps the weighting logic in one place (`lib/page.js`) while `app.js` owns the presentation.

## Module Metadata Reference

Each module's `module.exports` includes:
- `id`: stable module identifier (never changes; used by the flag system).
- `name`, `tagline`, `description`: display metadata.
- `difficulty`: `Beginner`, `Intermediate`, or `Advanced` (honest, not "Mixed").
- `track`: one of `Foundations`, `Injection`, `Auth and Sessions`, `Advanced`.
- `prerequisites`: array of module ids or track names (e.g. `['sqli']`, `['Foundations track']`).
- `vulns`: array of vulnerability entries, each with `id` (stable), `name`, `difficulty` (`Easy`/`Medium`/`Hard`), `hint`, `hints` (3-step ladder), `tools`, `how`, `link`.

## Verification

The curriculum changes preserve the M5 verification model:
- All award flows use `award(req, mod, vulnId)` with evidence checks intact.
- No flags are hardcoded; `flagFor()` does DB lookup.
- Dedupe kept every remaining vuln's id stable.
- See `docs/curriculum/VERIFICATION_MODEL.md` for the full guarantee list.
