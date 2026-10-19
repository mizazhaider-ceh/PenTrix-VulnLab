# M11: Break-Then-Fix Mode

Break-then-fix mode teaches the defensive half of security. First the student
breaks a challenge by exploiting it. Then they see the vulnerable code, write a
fix, and the platform checks the fix automatically. When the fix passes, they
earn a badge for that challenge.

## The loop

1. **Exploit.** The student solves the challenge the usual way (exploit to a
   flag). This proves they understand the attack.
2. **View code.** The challenge page shows a "Fix mode" section with a small,
   self-contained copy of the vulnerable code.
3. **Submit fix.** The student edits the code in the browser and submits it.
4. **Runner verdict.** The sandboxed runner runs the two tests against the
   student's code and reports the result with a friendly message.
5. **Badge.** When both tests pass, the student earns a fix badge for that
   challenge, shown on the challenge page and in their progress.

## The fix block contract

Each fix exercise is one file at `modules/<module>/fixes/<vulnId>.js`. It
exports this object:

```js
module.exports = {
  module: 'sqli',                 // module id (directory name)
  vulnId: 'login-bypass',         // challenge id (file name without .js)
  title: 'SQLi Login Bypass: fix it', // shown on the challenge page
  language: 'javascript',         // language of the code samples
  vulnerableCode: '...',          // vulnerable code the student starts from
  fixedCode: '...',               // reference fix shown after success
  testExploit: '...',             // JS expression: true when the exploit WORKS
  testLegit: '...',               // JS expression: true when normal use WORKS
  exploitDescription: '...',      // plain-English description of the attack
  fixHint: '...',                 // hint shown when the fix fails
};
```

Rules for writing a block:

- `vulnerableCode` must define a function named `vulnFn`. The runner refuses
  anything that does not define it.
- `vulnerableCode` must be a minimal, self-contained reproduction of the bug.
  No database, no framework, no `require`. For SQLi blocks the code uses a
  tiny in-memory users table and a mini SQL evaluator that behaves like the
  challenge's real WHERE clause. For XSS blocks the code models the escaping
  behavior directly.
- `testExploit` and `testLegit` are plain synchronous JS expressions evaluated
  against the sandbox context after the code runs. Keep them one-liners.
- `fixedCode` is only revealed after the student passes. It must pass both
  tests itself (see the runner checks below).
- Never put real flag literals in a fix block file. Like everything tracked in
  git, fix blocks must never contain a real flag.

## The runner (lib/fixmode.js)

The runner is sandboxed and server-side. The student never runs their own
server; they paste code into a form and the server checks it.

Exported API:

- `listFixBlocks()` - scan all `modules/*/fixes/*.js`, return
  `[{ module, vulnId, title }]`. Cached; call `resetFixCache()` to rescan.
- `hasFixBlock(module, vulnId)` - true when a block loads for the challenge.
- `getFixBlock(module, vulnId)` - the block object, or null. Malformed ids
  (anything outside `[a-z0-9_-]`) and broken files return null, never throw.
- `validateBlock(block)` - sanity check on a block: `vulnerableCode` must
  define `vulnFn`, `testExploit` must be true against it, `testLegit` must be
  true against it. Returns `{ valid, error }`.
- `testFix(module, vulnId, studentCode)` - the main verdict. Returns
  `{ ok, exploitBlocked, legitWorks, error }`.

### The four checks

`validateBlock` and `testFix` together run four combinations of code and test:

| # | Code | Test | Required result | Meaning |
|---|------|------|-----------------|---------|
| 1 | vulnerable | testExploit | true | the exploit really works on the vulnerable code |
| 2 | vulnerable | testLegit | true | normal use really works on the vulnerable code |
| 3 | student fix | testExploit | false | the exploit is blocked by the fix |
| 4 | student fix | testLegit | true | normal use still works after the fix |

Check 1 and 2 run inside `validateBlock` against the block author's code. If
the vulnerable code is not actually exploitable, or breaks normal use on its
own, the block is rejected before any student can attempt it. Checks 3 and 4
run inside `testFix` against the student's code. A fix only passes when the
exploit fails (check 3) AND legitimate input still works (check 4). A fix that
blocks the exploit by breaking everything is not a fix; check 4 catches it.

### Sandbox safety rules

Student code is untrusted. The runner executes it in a bare `node:vm` context:

- **Timeout:** 2 seconds per run. Infinite loops are killed; the student sees
  a friendly "your code took too long" message, not a stack trace.
- **No require, no process.** The sandbox only exposes plain JS builtins
  (Math, JSON, String, Array, Object, Map, Set, RegExp, typed arrays, and
  friends). No file system, no network, no environment variables.
- **Console is neutered.** `console.log` and friends are no-ops inside the
  sandbox, so noisy code cannot flood the server logs.
- **Size limit:** 50 KB per code submission. Keeps fixes short and runs cheap.
- **No async tricks:** a test that returns a Promise is rejected. Everything
  is synchronous.
- **Friendly errors:** syntax errors, runtime errors, stack overflows, and
  timeouts are converted into plain-English messages for the student. The
  server never leaks internal paths or raw errors to the browser.

### Badge storage (lib/fixbadges.js)

Badges are per-user and persistent. The table `fix_badges` lives in the same
SQLite database as the flags table:

- `user_key` - the express session id, the same identity the flag system uses
- `module`, `vuln_id` - which challenge the badge is for
- `awarded_at` - timestamp

Awards are idempotent (`INSERT OR IGNORE`): a student who re-submits a passing
fix does not get a duplicate badge. Badge queries (`listFixBadges`,
`hasFixBadge`, `fixBadgeCount`) follow the same API shape as the flag
equivalents in `lib/flags.js`.

## Pilot scope: 20 blocks

The pilot ships fix blocks for two modules, the ones students attack first:

- **sqli:** 11 blocks (blind, error, groupby-having, insert-inject,
  like-wildcard, limit-offset, login-bypass, order-by, second-order, union,
  union-filter-bypass)
- **xss:** 9 blocks (dom, reflected, stored, xss-attr-breakout, xss-backtick,
  xss-dom-clobber, xss-js-context, xss-markdown, xss-svg-upload)

Twenty blocks is enough to prove the loop end to end: both server-side
injection and client-side injection, both easy and hard challenges. These
blocks are the quality reference for everything that follows. A new block is
only accepted when `validateBlock` passes on it, which is the automatic
quality gate.

## The "fix mode coming soon" rule

The other 181 challenges do not have fix blocks yet. On their pages the Fix
mode section shows an honest "fix mode coming soon" note. It is never faked:
no fake code, no fake tests, no fake badges. A block appears on a page only
when the file exists and `validateBlock` passes on it. This keeps the feature
honest while the rollout continues.

## Rollout plan for the remaining modules

1. **Keep the pilot green.** Any change to the runner must keep all 20 pilot
   blocks passing `validateBlock`. This is the regression gate.
2. **One module at a time, server-side first.** Modules whose bugs reduce to
   pure JS reproduce well in the sandbox: cmdi, ssti, lfi, ssrf, upload,
   xxe, misconfig, jwt, session, race, bizlogic, proto, crypto, redirect,
   hostheader, cors, postmsg, csti, http, jsonp, formula, redos.
3. **Per-block quality bar.** Each new block needs: a minimal vulnerable
   reproduction that defines `vulnFn`, a `testExploit` that is true on the
   vulnerable code, a `testLegit` that is true on it too, a reference
   `fixedCode` that passes both, a plain-English `exploitDescription`, and a
   helpful `fixHint`. `validateBlock` enforces the first four automatically;
   a human reviewer checks the last two.
4. **Difficulty ordering.** Easy challenges first inside each module so
   students meet fix mode early, hard ones later.
5. **Badge parity.** When a module is fully covered, its badge set is complete
   and the "coming soon" note disappears from that module's pages.
6. **Docs stay in sync.** This file is the contract. If the runner API or the
   block shape changes, update this doc in the same change.

## Open questions

- Do fix badges count toward the public scoreboard, or stay as a separate
  "defender" track? (Open: needs izaz's call.)
- Should the reference `fixedCode` be shown immediately on success, or only
  after a cooldown so students sit with their own fix? (Open.)
- Do we want multiple accepted fix patterns (for example, escaping vs.
  parameterized queries) graded differently, or is one binary pass enough for
  the pilot? (Open for the full rollout.)
