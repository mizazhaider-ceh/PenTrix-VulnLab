# MODULE CONTRACT: read this before writing any module

You are implementing ONE module of the PenTrix VulnLab. The app shell, database,
styling, flag system, and scoreboard already exist. Your module lives in
`modules/<id>/`: one file per challenge in `modules/<id>/challenges/<vuln-id>.js`,
a thin aggregator at `modules/<id>/index.js`, and shared helpers in
`modules/<id>/shared.js`. It is auto-mounted at `/<id>`.

## What you must export

Each `modules/<id>/challenges/<vuln-id>.js` must export `{ vuln, router }`, and
`modules/<id>/index.js` must aggregate them:

```js
module.exports = {
  id: '<id>',                 // URL prefix, lowercase, e.g. 'xss'
  name: 'Cross-Site Scripting',
  tagline: 'One line shown on the home-page card.',
  description: 'Longer text shown at the top of the module page.',
  difficulty: 'Beginner',     // Beginner | Intermediate | Mixed
  vulns: [
    { id: '<vuln-id>', name: 'Reflected XSS', difficulty: 'Easy',   // Easy | Medium | Hard
      hint: 'Hint shown on the module page.',
      hints: ['Level 1 nudge.', 'Level 2 technique.', 'Level 3 payload shape.'],
      tools: 'B, C', how: 'One line: what the attacker must do.',
      link: '/<id>/<vuln-id>', start: 'Starting command shown on the module page.' },
  ],
  router, // an express.Router() with routes relative to '/<id>'
};
```

## Available helpers

```js
const { getDb } = require('../../lib/db');       // better-sqlite3 singleton (already seeded)
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, flagFor, captured } = require('../../lib/flags');
```

- `page(title, bodyHtml)` wraps your HTML in the site layout. Always use it.
- `esc(s)` escapes HTML. Use it on ALL user input you reflect, EXCEPT where the
  vulnerability itself requires reflecting raw input (mark those spots `// VULN:`).
- `award(req, '<id>', '<vuln-id>')` marks the flag captured in the session and
  RETURNS the flag string `PENTRIX{<32 hex>}` (random per deployment, issued by
  the flag system). Show it with `flagBox(flag)`.
- `brief(title, html)` renders the module briefing box. Use it at the top of your index page.

## Rules

1. **Real vulnerabilities only.** No fake "type the flag here" gates, no theatrics.
   Every vuln must be genuinely exploitable with real technique.
2. **Award on success, never before.** Call `award()` only when the exploit actually
   succeeded (e.g. bypass worked, query returned the secret, file was read).
   Never render a flag on a normal page view.
3. **Mark every vuln** in code with `// VULN: <one-line explanation of the flaw>`.
4. **Self-contained.** All logic lives in your challenge files. Do not add app-level
   middleware, do not touch `app.js`, `lib/*`, `public/*`, or other modules'
   directories. Do not add npm dependencies.
5. **Module index page** at `GET /<id>` (i.e. `router.get('/')`) must show:
   `brief()` + a list/table of its vulns with difficulty, hint (`hintBox`), and
   links to each challenge page.
6. **Provide attack surface.** Every vuln needs a visible form, link, or endpoint
   to attack. No hidden routes the user can't discover from your pages.
7. **Session flags only.** Do not invent your own flag strings. Flag format is fixed.
8. **Never hardcode a flag.** Flags are randomly generated per install at
   first boot on the student's own machine, no flag literal exists in any
   tracked file, and only genuine exploits earn flags. Use `award(req, '<id>', '<vuln-id>')` to award and
   `flagFor('<id>', '<vuln-id>')` to display an already-captured flag. Never
   write a literal `PENTRIX{...}` value in code (format examples like
   `PENTRIX{...}` in docs are fine).
8. **Keep it robust:** validate your files with `node --check` on every
   `modules/<id>/challenges/<vuln-id>.js` and `modules/<id>/index.js`.
   The coordinator will boot the app and curl your pages; broken modules get fixed
   or cut.
9. **Difficulty honesty:** Easy = a beginner with the hint solves it in minutes.
   Medium = needs real technique. Hard = needs chaining or creative bypass.
10. **No emojis in code comments.** UI emojis are fine.

## Module-level endpoint files

A module MAY keep endpoint files at module level (alongside `index.js` and
`shared.js`) when one endpoint serves multiple challenges or when a route
placed in a challenge file would be duplicated and shadowed by Express.
The existing examples (`modules/oauth/idp.js`, `modules/oauth/client.js`, and
`modules/xxe/importer.js`) are the reference pattern.

Rules for such files:

a. **Award conditions stay identical.** Award conditions inside an endpoint
   file must be identical to the award conditions the served challenges
   specify, never weakened, and evidence checks (D19) apply in full.
b. **Challenge files stay the source of vuln metadata.** The `{ vuln, router }`
   exports and `// VULN:` markers stay in the challenge files. An intentionally
   empty router export must carry a comment pointing at the endpoint file.
c. **Load through the aggregator only.** Endpoint files are loaded only
   through the module's `index.js` aggregator, never mounted by `app.js`
   directly.
d. **Header names the served challenges.** Each endpoint file carries a
   one-line header comment naming the challenges it serves.
e. **New endpoint files need the same justification.** A new endpoint file
   beyond the three reference examples needs the same justification
   (multi-challenge endpoint or shadowed-route defect), recorded in the
   file header.

## Seeded data you can use

- `users`: admin/admin123 (role admin, secret = random `PENTRIX{...}` per
  deployment), alice/alice123, bob/bob123 (role user). Read the admin secret
  from the DB at request time via `getDb()`; never hardcode it.
- `products`, `orders`, `comments` tables exist. Add your own tables if needed,
  but prefix them clearly (e.g. `xss_notes`) and create them with IF NOT EXISTS.
