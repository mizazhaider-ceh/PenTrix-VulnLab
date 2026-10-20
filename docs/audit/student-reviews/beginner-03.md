# Student Review: Day-One Priya (beginner-03)

- Modules tested: CSRF & Clickjacking (5/5 challenges: change-email GET, clickjacking, JSON text/plain CSRF, referer bypass, method override) and JWT Attacks (8/8 challenges: alg=none, weak HMAC secret, kid SQLi, jku key server, RS256/HS256 confusion, no-expiry, audience bypass, missing-kid default key). I tested with curl simulating Burp Proxy/Repeater/Intruder flows, one unique cookie jar for the whole pass. NOTE ON TIMING: the shared pool VM rebooted mid-test (~01:37 UTC). A first pass had already confirmed 5 CSRF flags (scoreboard 5/201) plus 4 JWT flags via "Flag captured" responses, then the reboot wiped all progress (scoreboard back to 0/201). I re-ran every exploit on the live instance afterwards. Final verified scoreboard for my session: 13/201 (CSRF 5/5, JWT 8/8). Everything below describes the live post-reboot instance unless noted.

- What worked well:
  - Every challenge awarded its flag only after a genuine exploit, and the scoreboard count rose immediately, so success was unambiguous. All 13 flags were captured this way, each confirmed in the response text and on the scoreboard.
  - CSRF challenge 1 is the perfect first ten minutes for a day-one student: one request, immediate flag, and I understood the lesson (state-changing GET with no token). I felt like a hacker within two minutes of logging in as alice.
  - The challenge pages' scenario text is genuinely readable. The Postbox webmail story, the "P Postbox / E evil.example" two-column framing, and the plain-English "what happened" hint boxes after success taught the concept at the moment I cared most.
  - The JWT module intro is a good mini-primer: header.payload.signature, what alg and kid mean, and the clear goal "get the panel to accept a token with role admin". I knew what to break before touching anything.
  - Reference tokens with Copy buttons on every JWT challenge page meant I could test every flow without setting up tooling first. Lowering the setup bar is the right call for this module.
  - Anti-cheat held everywhere I probed. Change-email with no login showed a login prompt, not a flag. Posting the vip-action form with a random unissued frame token gave an explicit "No flag" message explaining the one-time token rule. Replaying the already-successful vip-action POST gave "No flag" and the scoreboard did not move. The nickname POST with a non-matching Referer got 403 with no change. POSTing the account form with _method=PUT got "Nothing to do: a plain POST does not close the account". The no-login and bare-POST cases were re-verified on the post-reboot instance.

- Bugs found (with reproduction):
  1. Stale port in every JWT challenge card's starting point. Reproduction: open /jwt, copy any "Starting point" URL (for example http://localhost:3000/jwt/none), fetch it: connection refused. The lab is actually served on 127.0.0.1:18403 in this setup, and the challenge pages themselves say :18403, so the module cards contradict the challenges. (beginner-01 saw the same localhost:3000 copy on the API module, so it looks systemic.)
  2. The alg-confusion challenge rejects a correctly signed HS256 token with a bare 403 and no explanation unless the public-key string ends with a newline. Reproduction: fetch /jwt/confusion-pubkey, extract the PEM, sign an HS256 admin token with the PEM bytes minus the trailing newline, POST it: 403. Sign with the identical bytes plus the trailing newline, POST: the lab awarded the flag. Nothing in the hints mentions byte-exactness; a beginner copying the PEM from the page will hit this depending on their copy method. The server should normalize whitespace or the hint should say the newline matters.
  3. POST /jwt/aud returns 404. Reproduction: POST a token field to /jwt/aud: 404. The page actually carries two forms (/jwt/aud/mint and /jwt/aud/login), and the page URL itself is GET-only. I hit this before noticing the second form action; a beginner will too.
  4. The pool reboot wiped all progress with no warning: mid-test the instance stopped responding (connection refused) for minutes, then the scoreboard showed 0/201, down from 5/201, and I was logged out everywhere. All work had to be redone. (This was the ~01:37 UTC VM reboot, not something I caused.) Losing everything to a silent restart was the worst moment of the session.
  5. Minor: the attacker-keys register POST returns 302, and following that redirect with curl landed on a 404 page even though the key WAS registered (the JWKS endpoint showed it). The success signal looks like a failure; a beginner will think registration broke and retry.

- Friction/confusion points:
  - The homepage and the scoreboard both call CSRF the "Start here" module, but the CSRF learning track says "Prerequisites: xss". As a day-one beginner that line told me I was in the wrong place and I hesitated for several minutes before clicking in. It should say none.
  - Every starting point assumes Burp Proxy/Repeater fluency ("send it to Repeater", "find the request in Proxy history"), yet neither module page gives a 60-second Burp primer. I simulated everything with curl, which worked for all 13 challenges, but a beginner who follows the instructions literally has to learn Burp on the spot with no on-ramp.
  - The module card text for every CSRF challenge (and most JWT cards) contains the full exploit recipe, so the hint ladders had nothing left to do: I never opened a hint on CSRF because the card above the challenge already told me the attack. The challenge pages themselves are better balanced (scenario plus ladder).
  - CSRF challenge 4 (referer): the starting point says to submit the nickname form once so the POST lands in proxy history, but the form is rejected with 403 even when used legitimately, because the app runs on localhost instead of pentrix.lab. The challenge page explains why, but following the literal first step and failing feels broken until you read the fine print.
  - CSRF challenge 3 (JSON): the page's attack form does the whole trick for you; I could have solved it by pressing the on-page button. It teaches CSRF-as-concept more than JSON-CSRF craft, and a beginner might think pressing the button was the exploit.
  - JWT intro: "jsonwebtoken is installed, so you can mint and verify tokens locally with node -e one-liners" is only true from the repo root. From my home directory, require('jsonwebtoken') failed with "Cannot find module". I lost time before trying cd into the repo. The page should say "run node from the repo root".
  - jku: the register form's fields are labeled by placeholder text only ("key id, e.g. evil", "your HMAC secret"); a beginner scanning the page can miss what goes where.
  - aud: two same-styled forms (Mint token, Submit a token) on one page; the task is to submit the partner token at the login form, which I only got right after the 404 dead end.
  - confusion: the public key page returns an HTML document, not the PEM text; copying from the browser works, but scripting against it needs HTML parsing. A raw text/plain link would help curl-first testers.
  - My first guess at the CSRF module URL (/modules/csrf) 404'd; the real path is /csrf and only the homepage link leads there. Minor, but it cost me a confused minute in my first 15 minutes.

- Hint quality (helpful? spoilery? useless?):
  - CSRF change-email: spoilery. The card text is the complete solution; the ladder is redundant. On the challenge page itself, the single hint box is honest and teaches the concept without handing over the request.
  - CSRF clickjacking: spoilery. The card gives the exact three-request chain (frame GET with token, then form POST with the same token). I never needed the ladder.
  - CSRF JSON: helpful. H1 asks the right question (why does text/plain matter for CSRF), H2 teaches simple requests, H3 gives the body shape. I understood it at H2; the module card had already pre-solved it though.
  - CSRF referer: helpful. The scenario names the domain, H2 unlocked it ("substring match, and you control the Referer"), H3 is explicit but fair.
  - CSRF method override: H1 is spoilery ("The app honors _method=DELETE on a POST"), so the challenge becomes one request. Fine for an introductory challenge.
  - JWT none: helpful. The page's sample token plus "try changing the role" was enough; H3 is explicit exactly as advertised.
  - JWT weak: helpful but misdirecting. H1 ("a classic default, what are the usual suspects") is good, but H2/H3 push only the Intruder sniper route (many requests, slow). The professional move, verifying candidate secrets offline against the leaked sample token, is never mentioned; that is how I solved it, with a 25-word list in one local script. Rung 2 taught nothing about cracking.
  - JWT kid: spoilery by design (the page prints the SQL query). H2 unlocked the UNION idea, H3 explicit. A good ladder for a Medium.
  - JWT jku: the challenge page text is a complete recipe (register, point jku at the JWKS URL, sign). The ladder is consistent and H3 explicit. It felt like Medium, not Hard.
  - JWT confusion: helpful, but the byte-exact newline trap is unhinted and cost me several bare 403s. H3 names the trick plainly. Good ladder, missing one detail.
  - JWT noexpiry: H3 is a pure spoiler ("It does not. Replay the leaked token as-is"), but the challenge is Easy and one step; fair enough.
  - JWT aud: helpful. H1/H2 teach the concept (the aud claim is never compared); the page prints the partner token. Solved at H2.
  - JWT kiddefault: the best ladder in the set. H2 ("what tiny guessable key would a developer hardcode while testing") plus H3 ("A 403 means wrong guess, so try the next one") built a clean guess loop; the 4th guess won. Helpful without being spoilery; the other ladders should copy this shape.

- Difficulty fairness:
  - CSRF labels are fair overall. Clickjacking is the hardest CSRF flow (a three-step token dance) but the card spoils the chain, so Easy is fair in practice.
  - JWT: none and noexpiry are fairly Easy. Weak is fairly Medium if you know the offline trick (Easy in practice); the hints' Intruder route would make it Medium for the wrong reasons. kid is fairly Medium. aud is labeled Medium but is Easy in practice (the partner token is printed on the page and submitted as-is), so slightly overrated. kiddefault is fairly Medium. jku and confusion are labeled Hard; with the page recipes they feel like Medium, and confusion's Hard comes partly from the newline trap rather than the concept.

- Burp-first feasibility:
  - All 5 CSRF challenges: fully doable in Burp Community Repeater (single requests, no extensions needed). One caveat: challenge 1's Hint 3 points at Burp's "Generate CSRF PoC" tool; I could not verify in this curl-based pass whether that button exists in the free Community edition, and my understanding is it may be Professional-only, so a Community beginner could find that rung dead. Worth a check by the Burp tester.
  - JWT none, noexpiry, aud, kiddefault: Repeater plus pasting a token, trivially Community-feasible; kiddefault's guess loop is a few manual Repeater resends or a small Intruder run.
  - JWT weak: an Intruder sniper run works in Community, but the fast route is offline signing with node plus the repo's jsonwebtoken (run from the repo root).
  - JWT kid, jku, confusion: need local token crafting (node plus jsonwebtoken), then paste the token into Repeater. Feasible for a beginner who can run node; the Burp JWT extension would help but is not required.

- Suggestions (concrete):
  1. Replace localhost:3000 with the real base URL (or use relative links) in all JWT card starting points; audit the other modules for the same stale port.
  2. On the CSRF track, change "Prerequisites: xss" to "none" and add a 60-second "New to Burp: Proxy, Repeater, Intruder" box, since every starting point assumes that fluency.
  3. Move full exploit recipes out of the module card bodies into Hint 3; keep card text to scenario plus goal so the hint ladders have a job to do.
  4. Confusion: normalize public-key whitespace server-side (or hint that the PEM must include the trailing newline); also serve the key as text/plain for scripted testers.
  5. Weak secret: add a hint rung teaching offline candidate verification against the sample token (the real workflow), instead of only the slow Intruder route.
  6. aud page: label the Mint vs Login forms distinctly; make POST /jwt/aud return a helpful redirect or message instead of a bare 404.
  7. attacker-keys: give the kid and secret inputs visible labels, not placeholders only.
  8. JWT intro: add "run node from the repo root" to the jsonwebtoken one-liner note.
  9. Persist captured flags across pool reboots, or warn on the home page that a restart wipes progress.

- Rating: 4/5
