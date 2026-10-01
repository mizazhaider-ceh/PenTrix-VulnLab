# MODULE CONTRACT — read this before writing any module

You are implementing ONE module of the PenTrix VulnLab. The app shell, database,
styling, flag system, and scoreboard already exist. Your module lives in
`modules/<id>/router.js` and is auto-mounted at `/<id>`.

## What you must export

`modules/<id>/router.js` must export:

```js
module.exports = {
  id: '<id>',                 // URL prefix, lowercase, e.g. 'xss'
  name: 'Cross-Site Scripting',
  tagline: 'One line shown on the home-page card.',
  description: 'Longer text shown at the top of the module page.',
  difficulty: 'Beginner',     // Beginner | Intermediate | Mixed
  vulns: [
    { id: '<vuln-id>', name: 'Reflected XSS', difficulty: 'Easy',   // Easy | Medium | Hard
      hint: 'Hint shown on the module page.', how: 'One line: what the attacker must do.' },
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
  RETURNS the flag string `PENTRIX{<id>_<vuln-id>}`. Show it with `flagBox(flag)`.
- `brief(title, html)` renders the module briefing box. Use it at the top of your index page.

## Rules

1. **Real vulnerabilities only.** No fake "type the flag here" gates, no theatrics.
   Every vuln must be genuinely exploitable with real technique.
2. **Award on success, never before.** Call `award()` only when the exploit actually
   succeeded (e.g. bypass worked, query returned the secret, file was read).
   Never render a flag on a normal page view.
3. **Mark every vuln** in code with `// VULN: <one-line explanation of the flaw>`.
4. **Self-contained.** All logic lives in your router. Do not add app-level
   middleware, do not touch `app.js`, `lib/*`, `public/*`, or other modules'
   directories. Do not add npm dependencies.
5. **Module index page** at `GET /<id>` (i.e. `router.get('/')`) must show:
   `brief()` + a list/table of its vulns with difficulty, hint (`hintBox`), and
   links to each challenge page.
6. **Provide attack surface.** Every vuln needs a visible form, link, or endpoint
   to attack. No hidden routes the user can't discover from your pages.
7. **Session flags only.** Do not invent your own flag strings. Flag format is fixed.
8. **Keep it robust:** validate your file with `node --check modules/<id>/router.js`.
   The coordinator will boot the app and curl your pages; broken modules get fixed
   or cut.
9. **Difficulty honesty:** Easy = a beginner with the hint solves it in minutes.
   Medium = needs real technique. Hard = needs chaining or creative bypass.
10. **No emojis in code comments.** UI emojis are fine.

## Seeded data you can use

- `users`: admin/admin123 (role admin, secret = `PENTRIX{sqli_union}`),
  alice/alice123, bob/bob123 (role user).
- `products`, `orders`, `comments` tables exist. Add your own tables if needed,
  but prefix them clearly (e.g. `xss_notes`) and create them with IF NOT EXISTS.
