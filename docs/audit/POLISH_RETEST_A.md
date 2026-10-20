# Polish-wave retest, team A (D18 compliant, no flag literals)

Retest coordinator report. Target: the polished working tree of
`~/workspace/pentrix-vulnlab` (232 changed files vs `main`, uncommitted),
served from a synced verify copy at `~/workspace/pentrix-verify` on
`PORT=19701` with a throwaway DB. Server killed after the run. No product
code edited, nothing committed or pushed.

Goal: prove the P1 fixes did not break honest solves and the old cheats
still fail. Three simulated students, each with its own cookie jar
(progress lives in the session cookie). Verdicts: HONEST WORKS,
CHEAT FAILS, REGRESSION.

## Student 1, beginner, upload module (10/10)

Honest path per challenge: read the per-challenge beacon token from the
module page, upload file bytes carrying the beacon snippet for that
challenge id (token embedded), serve the file, fire POST /upload/beacon,
flag captured. All eight solved:

- stored-xss: POST /upload?filename=s1-xss.html, raw HTML bytes. Served
  200 as text/html. Beacon 200, flag captured. HONEST WORKS.
- upload-case: POST /upload/ext-blacklist?filename=s1case.SVG (case
  variant beats the case-sensitive blacklist). Served as image/svg+xml
  via /upload/view/. Beacon 200, flag captured. HONEST WORKS.
- upload-double-ext: POST /upload/ext-blacklist?filename=s1double.svg.jpg
  (final .jpg passes, viewer guesses .svg). Served image/svg+xml. Beacon
  200, flag captured. HONEST WORKS.
- upload-ctype: POST /upload/mime-check?filename=s1ctype.html with
  `Content-Type: image/png` (header-only validation). Beacon 200, flag
  captured. HONEST WORKS.
- upload-traversal: POST /upload/traverse?filename=../s1-escape.txt, then
  GET /upload/traverse-prove?f=../s1-escape.txt (read-back proof, no
  beacon for this one). 200, flag captured. HONEST WORKS.
- upload-strip-once: POST /upload/filter?filename=s1strip.s.svgvg (one
  strip rebuilds s1strip.svg). Response names the stored file; served via
  /upload/view/s1strip.svg. Beacon 200, flag captured. HONEST WORKS.
- upload-overwrite: POST /upload/avatar?user=bob with bytes starting with
  `<` (served as text/html) carrying the beacon snippet. Beacon with
  file=bob, 200, flag captured. HONEST WORKS.
- upload-polyglot: POST /upload/polyglot?filename=s1poly.gif, bytes start
  `GIF89a` then scriptable HTML with token. Rendered at /upload/poly/ as
  text/html. Beacon 200, flag captured. HONEST WORKS.

Old cheats:

- One-byte .html upload (1 byte body, token baked in but no script):
  upload 200, no flag at upload time; beacon 403 ("the stored file
  contains no executable script"). CHEAT FAILS.
- One POST trying to win two challenge ids: one upload of
  s1cheat2.svg.SVG (satisfies both the case and double-ext bypass
  shapes) with only the upload-case token embedded. No flag at upload
  time. The upload-case beacon won (correct: genuine evidence for that
  id). The upload-double-ext beacon with its own session token returned
  403, "the beacon token is not inside the stored file", no flag.
  CHEAT FAILS. The per-challenge evidence gate holds: a sibling id
  cannot be claimed off one artifact unless its own token is in the
  bytes.

## Student 2, intermediate, postmsg + race + cheat battery (13/13)

Honest csrf-action, the real way: fetched /postmsg/csrf-action, extracted
the victim page's inline script, ran it in a Node vm with a fetch shim
pointed at the live lab (same session cookie), fired the forged message
`{action:'delete-account'}` the way the attacker page does. The victim
script drove the delete POST with its page-bound token
(`pm_msg_deleted` set server-side) and fired the beacon, which carried
the flag. Status text confirmed "account deleted (lab only)",
/postmsg/claim-status reported captured, and the reloaded victim page
showed the DELETED pill. HONEST WORKS.

Race challenges via parallel bursts (the module ships 8, not 5; all 8
were burst-solved, superset of the brief): coupon (20x redeem), balance
(20x transfer), vote (6x), referral (10x code REF2026), register (5x),
ratelimit (20x hit), stock (10x qty 5), upload-scan (upload then 20x GET
inside the 2s scan window). Every burst carried exactly one flag and the
scoreboard captured each challenge once. HONEST WORKS for all 8.

Old cheats:

- Bare curl delete + beacon, no token: delete 200, beacon 400, no flag,
  claim-status false. CHEAT FAILS.
- Same with forged Origin and Referer headers: delete 200, beacon 400,
  no flag. CHEAT FAILS (header forgery changes nothing, as the brief
  says the token is the evidence, not the headers).
- XXE marker-typing on xxe/file: POST /xxe/import with the literal
  marker typed into the XML, 200, no flag. Honest control (real
  file:// entity read of the secret file) won the flag on the same
  endpoint, so the rejection is the cheat failing, not a broken
  endpoint. CHEAT FAILS.
- LFI bare-percent on lfi/double: GET /lfi/double?page=%73ecret.txt,
  200, the secret read back, zero flags. Honest control
  (page=%252e%252e%252fdocs%252fsecret.txt) won the flag. CHEAT FAILS.

## Student 3, CTF player, banner-once (4/4)

- 20-parallel GET burst on /race/files/s3secret.txt (burst-friendly
  award endpoint): exactly 1 flag banner across all 20 responses,
  exactly 1 response carried the flag, scoreboard exactly 1. PASS.
- Same award request repeated sequentially 3 times: 0 new banners,
  scoreboard still 1. PASS.
- Second, different challenge (race-coupon 20x burst): its own banner
  rendered exactly once, scoreboard 2. PASS.
- Re-solve of an already-captured challenge (/lfi/view traversal):
  first hit showed the banner, the repeat page showed no new award
  banner but the flag stayed viewable and copyable via the captured
  display (flagFor path), including on a benign page view. PASS.

Repo regression suites run against the same polished tree:
tests/polish-banner-once.test.js 5/5 pass,
tests/polish-upload-quota.test.js 1/1 pass (per-session quota: a
flooding session never evicts another session's files).

## Anything broken or confusing after the polish

1. Re-firing a beacon for an already-captured challenge returns 200
   "Payload executed" with no flag box (banner renders once per
   capture). Correct by design, but a learner re-running a working
   exploit will see a success page with no flag and may think it broke;
   the flag is still viewable on the module page's captured display.
   A one-line hint on the re-award page ("already captured, see the
   module page") would close the confusion gap.
2. One POST to /upload/ext-blacklist whose name satisfies both bypass
   shapes arms BOTH pending records (case and double-ext). The beacon
   then correctly gates each id on its own embedded token, so this is
   not a cheat hole, but a student uploading "evil.svg.SVG" and seeing
   two "stored" messages might expect one upload to earn two flags.
   It does not, and the 403 reason is clear.
3. Count note: the race module mounts 8 challenges, not 5
   (coupon, balance, vote, referral, register, upload-scan, ratelimit,
   stock). All 8 honest-burst, so the brief's "5" is covered either way.
4. /race/reset is POST-only now (GET 404s). Intended P1-2 behavior;
   anyone with an old bookmarked GET reset link will hit a 404.

## Coordinator verdict on the P1 stream, from a learner's seat

The polish stream holds. Nothing honest broke: all 8 upload beacons,
the postmsg victim-script flow, all 8 race bursts, and the traversal
prove path award on the documented techniques with clear module-page
guidance (per-challenge tokens and snippets are right where a student
looks). Every old cheat fails at the gate with a specific reason:
no-executable-script, token-not-in-bytes, unknown/mismatched token,
no-flag. The banner-once behavior is exactly right under bursts,
repeats, second challenges, and re-solves. The evidence-gated model
is strict without being brittle: it rejected the shortcuts and accepted
every genuine exploit my three students ran, 27/27 green plus the
repo's own polish suites 6/6. Ship it.
