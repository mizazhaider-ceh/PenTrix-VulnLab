# CHALLENGE-SPLIT SWARM: agent brief templates

Scale-up per owner order 2026-10-19. Waves: writers (43) -> verifiers (29) ->
fixers (pool of 20) -> professor demo sweep. Coordinator commits per wave on
main. No agent pushes, no GitHub API, no em dashes anywhere, ever.

## Shared context (prepend to every brief)

Work in ~/workspace/pentrix-vulnlab on branch main. DO NOT push. DO NOT use
any GitHub API. Commit nothing; leave changes in the working tree (the
coordinator commits). No new npm dependencies. No build step. Read
docs/roadmap/CHALLENGE_SPLIT_CONTRACT.md first and follow it exactly. No em
dashes in any file or report (use commas, colons, parentheses).

## WRITER brief (one per module; 2 writers for modules with 9+ challenges)

Your module: <id>. You own these vuln ids: <list>. (On 2-writer modules the
other writer owns <list>; writer A additionally writes index.js and shared.js
and deletes router.js at the end. The require list in index.js is
deterministic from the vuln ids below, so write all requires upfront.)

Vuln ids and their challenge file names:
<id> -> modules/<id>/challenges/<vuln-id>.js
...

Steps:
1. Dump routes BEFORE: `DB_PATH=/tmp/dump-<id>.db node scripts/dump-routes.js <id> > /tmp/routes-<id>-before.txt`
2. Read modules/<id>/router.js fully. Identify shared code (table seeding,
   helpers used by 2+ challenges) -> shared.js (writer A). Group every route
   by its vuln id.
3. Write your challenge files per the contract (vuln metadata copied EXACTLY:
   same id, name, difficulty, hint, how, link; same routes; same flags via
   award()/flagFor(); never hardcode a flag).
4. UI defect fix (owner order): every form, input, button, select, textarea,
   table, and code block on your challenge pages gets full claymorphism
   styling. Inputs: class="clay-input". Selects: class="clay-select".
   Buttons: class="clay-btn clay-btn-primary" (submit) or
   class="clay-btn clay-btn-secondary". Code/payloads: payloadBlock() helper.
   Flags: flagBox()/flagBanner(). Hints: hintBox(). Tables: existing .tbl
   class. Do NOT invent new CSS classes. Do NOT add <style> blocks. No
   native-looking controls may remain.
5. Writer A: write index.js (aggregator per contract, challenges in the same
   order as the old VULNS array) and shared.js, then delete router.js ONLY
   after every challenge file passes node --check.
6. `node --check` every new file.
7. Dump routes AFTER and diff: `diff /tmp/routes-<id>-before.txt <(DB_PATH=/tmp/dump-<id>.db node scripts/dump-routes.js <id>)`. Must be identical.
8. `grep -rn $'\u2014' modules/<id>/` must print nothing.
9. Report: files created, route-diff result (paste it), clay elements fixed
   per challenge, any deviation or blocker. Do not claim what you did not run.

## VERIFIER brief (one per module)

Your module: <id> (challenges: <list>). The writers are done and the
coordinator has synced their files to ~/workspace/pentrix-verify.

Setup (do NOT edit files in pentrix-verify; it is your live test bed):
`cd ~/workspace/pentrix-verify && DB_PATH=/tmp/verify-<id>.db PORT=<port> nohup node app.js > /tmp/verify-<id>.log 2>&1 &`
Wait for `[ok] mounted` x29 in the log, then curl one route to confirm.

Per challenge, prove ALL FOUR:
(a) Route returns 200 AND the desktop-width screenshot renders clean clay UI
    with zero unstyled controls. Screenshot: `bash docs/qa/screenshot.sh
    http://localhost:<port>/<id>/<route> docs/qa/shots/split-<id>-<vuln>.png`
    (run from the repo). Open each PNG and actually look at it.
(b) The documented exploit still awards the flag end to end (M5 paired
    standard): run the REAL exploit from the challenge hints/SOLUTIONS.md and
    confirm the flag is captured (scoreboard or claim-status shows captured;
    NEVER print or report flag values). Then run the trivial bypass
    (pattern match, token-less beacon, direct URL) and confirm NO flag.
(c) Zero em dashes: `grep -rn $'\u2014' modules/<id>/` empty.
(d) Each challenge file contains only that challenge's code (read it; no
    strays from siblings, no duplicated helpers that belong in shared.js).

Extra for the xss module: verify the "How to claim this flag" box and the
claim-status widget. Token-less beacon must still 400 and show not-captured;
the documented payload must earn the flag and flip the widget.

For every FAIL, file a fixer ticket: module, challenge, which check failed,
exact evidence (URL, curl output, screenshot path). For every PASS, keep the
evidence paths. Report per-challenge PASS/FAIL with evidence. Never fabricate
a test you did not run.

## FIXER brief (pool of 20, on demand)

You receive fixer tickets (module, challenge, failed check, evidence). Work in
the repo on main. Fix ONLY what the ticket names; do not refactor, do not
touch sibling challenges, do not change routes/flags/vuln metadata. After the
fix, re-run the exact failing check from the ticket and confirm it passes
(paste the evidence). If the fix needs a verifier re-check beyond your scope,
say so. No em dashes. Commit nothing. Report per ticket: fixed (with
evidence) or still broken (with reason).

## PROFESSOR DEMO SWEEP brief (after the split verifies; separate wave)

You are a journey verifier. Hardware: desktop width only. Walk the ENTIRE
user journey and screenshot every step to docs/qa/shots/demo-<nn>-<step>.png:
home -> module index -> challenge page -> run the exploit -> flag captured ->
scoreboard -> next module. Cover all 29 modules. Every page must be
demo-quality: zero broken pages, zero unstyled controls, zero placeholder
text, zero broken links, zero console-visible errors. Anything imperfect
becomes a fixer ticket with the screenshot attached. Nothing ships with known
defects. Report: steps covered, screenshots, tickets filed.
