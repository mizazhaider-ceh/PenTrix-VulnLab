# CHALLENGE SPLIT CONTRACT: one file per challenge

Date: 2026-10-19. Owner directive: split every monolithic `modules/<id>/router.js`
into one file per challenge. Same routes, same vulnerabilities, same flags,
zero behavior change, only file organization.

## Target layout

```
modules/<id>/
  index.js                 # aggregator, keeps the module contract
  shared.js                # OPTIONAL: module-scoped helpers, table seeding, constants
  challenges/
    <vuln-id>.js          # one file per vuln, e.g. login-bypass.js
    ...
```

## Challenge file shape (`modules/<id>/challenges/<vulnId>.js`)

```js
'use strict';
// <Vuln name>: one line describing the vulnerability.
const express = require('express');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured, flagFor } = require('../../lib/flags');
const shared = require('../shared'); // only if this module has one

const router = express.Router();

// ALL routes belonging to this vuln, and nothing else.

module.exports = {
  vuln: {
    id: '<vuln-id>',       // exact id from the old VULNS array, never rename
    name: '...',           // exact name, never rename
    difficulty: 'Easy',    // exact difficulty, never change
    hint: '...',           // exact hint text (M7 may have revised it; keep M7's)
    how: '...',            // exact how text
    link: '/<id>/...',     // exact link
  },
  router,
};
```

Rules:
- One vuln per file. A vuln may own MULTIPLE routes (e.g. blind has GET
  `/product` and POST `/blind-submit`); move all of them together.
- The file must contain ONLY that challenge's code: its routes, its
  vuln-specific helpers. Nothing else.
- Shared code (table creation, `adminSecret()`, constants used by 2+ challenges)
  goes in `shared.js`, required by the challenge files that need it.
- `shared.js` must not define routes or export a vuln.
- Keep every `// VULN:` marker with the code it describes.
- Never hardcode a flag (MODULE_CONTRACT.md rule 8). Use `award()`/`flagFor()`.

## Aggregator shape (`modules/<id>/index.js`)

```js
'use strict';
const express = require('express');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const shared = require('./shared'); // only if the module has one
const challenges = [
  require('./challenges/<vuln-a>'),
  require('./challenges/<vuln-b>'),
  // ... in the SAME order as the old VULNS array
];

const router = express.Router();

// Module index page (the old router.get('/') handler), unchanged in behavior.
router.get('/', (req, res) => { /* brief + vuln table */ });

for (const c of challenges) router.use(c.router);

module.exports = {
  id: '<id>',              // unchanged
  name: '...',             // unchanged
  tagline: '...',          // unchanged
  description: '...',      // unchanged
  difficulty: '...',       // unchanged
  vulns: challenges.map((c) => c.vuln),
  router,
};
```

Rules:
- The aggregator holds ONLY: requires, the index page, the challenge loop,
  and module.exports. No challenge routes, no challenge helpers.
- Challenge order must match the old VULNS array order (scoreboard and
  index pages list them in order).

## UI styling (owner: fix ALL unstyled controls)

Every challenge page must use full claymorphism styling. No native-looking
controls ship. Apply while splitting:
- Forms: wrap in `.clay-card` or use M4 form patterns; labels with `.clay-field`.
- Inputs: `class="clay-input"` on text/password/url/email inputs; `class="clay-select"` on selects; `class="clay-input"` on textareas (or the textarea rule in style.css).
- Buttons: `class="clay-btn clay-btn-primary"` for submit/primary, `class="clay-btn clay-btn-secondary"` for secondary actions.
- Code/payload blocks: use the `payloadBlock(label, code)` helper from lib/page.js (includes copy button).
- Tables: use the `.tbl` class (existing) or M4's table pattern.
- Flag display: `flagBox(flag)` or `flagBanner(flag)` only.
- Hints: `hintBox(hint)` only.
- Do not invent new CSS classes. Do not add `<style>` blocks. If a needed
  pattern is missing, note it for the coordinator instead of inventing one.

## Loader

`app.js` tries `modules/<id>/index.js` first, falls back to `modules/<id>/router.js`
during migration. After all 29 modules are migrated, the fallback is removed.

## Verification (per challenge, by the verifier agents)

(a) Route returns 200 and the desktop-width screenshot renders clean clay UI
    with no unstyled controls.
(b) The documented exploit still awards the flag end to end (M5 standard:
    real exploit earns it, fake/pattern shortcuts do not).
(c) Zero em dashes anywhere in the new files.
(d) The challenge file contains only that challenge's code (no strays from
    sibling challenges).
Plus: `node --check` on every new file, and the route-dump script
(`scripts/dump-routes.js`) must show the identical route list before/after
for the module.
