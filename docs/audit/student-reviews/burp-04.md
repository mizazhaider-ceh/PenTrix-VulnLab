# Student Review: Decoder Dan (burp-04)
- Modules tested: xss (9 challenges: reflected, stored, dom, xss-attr-breakout, xss-js-context, xss-backtick, xss-markdown, xss-svg-upload, xss-dom-clobber) and crypto (8 challenges: crypto-rand-pin, crypto-md5-crack, crypto-b64-cookie, crypto-key-in-js, crypto-xor-crib, crypto-cbc-bitflip, crypto-hash-ext, crypto-ecb-oracle). Tested only against http://127.0.0.1:18409 with a unique cookie jar, curl standing in for Burp Repeater. The VM rebooted mid-session (per-boot secrets rotated), so every flag except the PIN was re-earned and re-verified after the reboot. Final scoreboard: 16/201 (all 9 XSS flags plus 7 crypto flags). Only crypto-rand-pin was not captured; the brute force did not finish in-session.

Per-challenge Burp flows I ran (curl equivalents executed, flag confirmed unless noted):
XSS (beacon model: each challenge page issues a per-session, per-vuln nonce as window.__px; the beacon is GET /xss/collect?c=<stolen data>&v=<id>&n=<nonce>; nonces are single-use):
1. reflected: Proxy the search, send GET /xss/search to Repeater, reshape q into a script tag, confirm the reflection inside "Results for:" in the response, load the URL in the Burp browser, watch /xss/collect land in Proxy history. The lab awarded the flag.
2. stored: Proxy, POST /xss/guestbook in Repeater with a beacon comment, GET the page to confirm it is stored and rendered raw, reload in the browser. The lab awarded the flag.
3. dom: read the page source in the Burp browser to find the location.hash to innerHTML sink, build a /xss/dom# URL with an <img onerror> fragment (a script tag via innerHTML never runs, the hint teaches this), open it in the browser. The lab awarded the flag.
4. xss-attr-breakout: Repeater on GET /xss/attr, set n to close the value="..." attribute and open a script tag, confirm the breakout markup in the response, load in the browser. The lab awarded the flag.
5. xss-js-context: Repeater, break out of var q = '...' with a quote, run the beacon statement, comment out the tail with //, confirm the reflected line reads as valid JS, load in the browser. The lab awarded the flag.
6. xss-backtick: Repeater, inject a ${...} expression into m, confirm it lands inside the template literal in the response, load in the browser. The lab awarded the flag.
7. xss-markdown: Repeater POST /xss/markdown with md=[x](javascript:...), confirm <a href="javascript:..."> in the response, open the rendered note in the browser and click the link. The lab awarded the flag.
8. xss-svg-upload: Repeater POST /xss/svg with a script-bearing SVG inside a CDATA section, follow the redirect to /xss/uploads/<file>?n=<token>, open the file link in the browser. The token comes from the URL query (the SVG is its own document, no window.__px), served as image/svg+xml. The lab awarded the flag.
9. xss-dom-clobber: Repeater POST /xss/clobber with markup that rebuilds window.settings.isAdmin from DOM elements alone (form id=settings plus an input named isAdmin; no script tags, the filter strips those), confirm it renders raw, then open /xss/clobber-admin. No beacon needed; the server re-verifies the stored markup itself. The lab awarded the flag.

Crypto:
1. crypto-rand-pin: Proxy, POST /crypto/pin/generate, send POST /crypto/pin/verify to Intruder with a null payload generating 000000-999999. NOT completed in-session (see Burp-first feasibility). Mechanics verified: wrong guesses return 401, no rate limiting, one 200 awards the flag.
2. crypto-md5-crack: Repeater GET /crypto/md5/wordlist.txt, hash candidates offline in Python until one matches the leaked hash, POST /crypto/md5/login as demo with the cracked password. The lab awarded the flag.
3. crypto-b64-cookie: Repeater POST /crypto/b64/login, send the vlab_b64 value to Burp Decoder, decode as Base64, edit role to admin in the JSON, re-encode, POST /crypto/b64/check. The lab awarded the flag.
4. crypto-key-in-js: Repeater GET /crypto/keyjs/app.js, read the hardcoded key constant, decrypt the hex note offline (AES-128-CBC, IV prepended), POST /crypto/keyjs/solve. The lab awarded the flag.
5. crypto-xor-crib: copy the ciphertext hex from the page via Repeater, crib-drag offline in Python with the known {"user":" header, trying key lengths 1-12 and keeping the one that decrypts to valid JSON, POST /crypto/xor/solve. The lab awarded the flag.
6. crypto-cbc-bitflip: POST /crypto/cbc/login, send the cookie to Decoder, Base64 decode, XOR the IV bytes sitting over "guest" (bytes 9-13) with ("guest" xor "admin"), re-encode, POST /crypto/cbc/check. The lab awarded the flag.
7. crypto-hash-ext: Repeater GET /crypto/mac/sign?msg=role=user, rebuild the glue padding for the 16-byte secret in a script, restore the digest as SHA-256 compression state, continue the hash with ;admin=1, POST /crypto/mac/verify with the full message as hex plus the forged MAC. The lab awarded the flag.
8. crypto-ecb-oracle: Repeater probing to find the block size (16) and confirm ECB with a repeated block, then byte-at-a-time decryption (align prefix so the unknown byte lands at end of block, try all 256 values, keep the match; scripted loop, about 28 bytes), POST /crypto/ecb/solve. The lab awarded the flag.

- What worked well:
  - The XSS beacon model is excellent for a Burp learner: every challenge page shows the exact payload shape in a claim box plus a live claim-status widget, and the hint ladders teach the nonce mechanism (window.__px, params c/v/n) instead of assuming it. Level 3 hints name the exact Burp surface (Proxy history, Repeater, the Burp browser) without handing over a copy-paste payload.
  - The cheat-resistant verification held up in every test I tried: bare /xss/collect with no nonce, wrong nonce, unknown vuln id, empty c with a valid nonce, and replaying a consumed nonce all returned 400 with no flag awarded. The clobber challenge correctly awards nothing via beacon (it never issues a token) and re-verifies the stored markup server-side.
  - Crypto hints are unusually honest about tool limits: hash-ext hint 2 says "Burp Decoder will not do this step for you", xor-crib says "Do the crib-drag offline in Python", and the tools pills (BZ/Browser/DevTools/curl/Python/Wordlist) match the realistic path for each challenge. The CBC page even tells you the plaintext layout and which IV bytes to flip.
  - The SVG challenge's beaconInfo is a model of good guidance: it explains why window.__px is unavailable in the SVG document, how to read the token from ?n=, and the CDATA requirement for XML parsing.

- Bugs found (with reproduction):
  1. Pool instance 127.0.0.1:18409 stopped listening mid-session (connection refused instantly, ~03:10 CEST, before the announced reboot window). My /tmp scratch was wiped at the same time. Reproduction: curl --max-time 10 http://127.0.0.1:18409/ returned 000, exit code 7; ss showed nothing listening on 18409 until the infra brought it back. (Context: another tester was running a 32-thread PIN brute force against a different pool port, 18407, so that was not the cause on my port. The later infra notice confirmed a VM reboot around 01:37 UTC.)
  2. /xss/clobber-admin access-denied branch returns HTTP 200 instead of 403. Reproduction: fresh cookie jar, GET /xss/clobber-admin with no custom profile HTML saved; response is HTTP 200 containing the "Access denied" page. Cause visible in the deny branch: it calls res.send(page(..., errorPage(403, ...))) without setting the status. Impact: a learner cannot tell success from failure by status code.
  3. crypto-rand-pin state is global to the whole pool instance: anyone clicking "Generate reset PIN" resets the active PIN for every tester, which silently invalidates someone else's in-progress 1M brute force. The challenge page gives no warning about this.
  4. Misleading guidance: crypto-ecb-oracle's "how" says "then decrypt the secret byte-at-a-time (Repeater for single bytes, Intruder for the full loop)". Intruder cannot chain dependent byte-by-byte iterations (each byte's payload set depends on the previous byte's result), so "Intruder for the full loop" is not real. The honest path is a script (Python is in the tools pill) or manual Repeater iteration per byte.
  5. crypto-rand-pin hint 3 ("Use a null payload generating 000000-999999. Watch for a 200 among the 401s.") never mentions that Burp Community throttles Intruder attacks, making a 1M-request attack infeasible in Community edition (it would take days). No alternative is suggested.

- Friction/confusion points:
  - "Watch for a 200 among the 401s": the lab never tells the learner how to spot one different response among thousands in Intruder (sort the results table by the Status column). A Burp-first learner will not know this.
  - ECB byte matching: all 256 Intruder responses for one byte have identical length, so the "different" response is invisible unless you compare response bodies (Intruder's compare or a grep match). No guidance on this.
  - crypto-md5-crack hint 3 ("Hash every wordlist entry with MD5 until one matches the leak, then log in with it through Burp Proxy") implies doing this in Repeater tabs, but Burp has no native way to MD5-hash a 48-word list; the real step is Python or hashcat, which the hint never names outright (the tools pill lists Python, but the hint should say it).
  - The PIN page's "Generate reset PIN" button resets the shared PIN with no warning; re-clicking it mid-attack restarts your whole brute force and there is no indication of that.
  - My own length-extension script initially used the wrong final padding length (suffix length instead of total message length); the lab page's note describing the attack was correct, so this was my bug, not the lab's. Worth noting because the verify page's "MAC valid: false / contains ;admin=1: true" feedback made the mistake easy to diagnose.

- Hint quality (helpful? spoilery? useless?):
  - XSS hints: helpful and well-paced. Level 1 orients ("what happens if your search term is not text?"), level 2 names the sink and the Burp surface, level 3 gives the beacon shape and the exact click path. They teach the concept without giving a paste-ready payload. The beaconInfo blurbs on dom/markdown/svg are genuinely instructive.
  - Crypto hints: helpful and honest about technique (ECB block equality, glue padding, crib-dragging). Not spoilery: they describe the shape of the attack but you still have to build it. Weak spots: rand-pin (no Community throttling warning, no sort-by-status tip), ecb (overclaims Intruder's role), md5 (hashing step hand-waved).

- Difficulty fairness:
  - Labels felt fair across both modules. XSS Easy challenges (reflected, stored) are genuinely easy; the Mediums (attr, jsctx, backtick, markdown, svg, dom) each teach one new context; clobber Hard is fair because the hints teach DOM clobbering from scratch.
  - Crypto Easy (md5, b64, key-in-js) fair; xor Medium fair; cbc/hash-ext/ecb Hard fair and well scaffolded. The rand-pin Easy label is fair on technique (brute force) but misleading on effort in Burp Community (see feasibility).

- Burp-first feasibility:
  - 15 of 17 challenges are fully doable in Burp Community plus a proxied browser and Python (which the lab itself sanctions in the tools pills). The right tool is named in the guidance for nearly every step: Proxy for capture, Repeater for crafting, Decoder (Base64, Hex editor, XOR, Encode) for the CBC cookie, DevTools/page source for the DOM sink.
  - crypto-rand-pin is NOT feasible in Burp Community: Community throttles Intruder attacks, so a 1,000,000-request null-payload attack would take days. Even scripted outside Burp I only reached about 177 requests/second against the local instance (roughly 47 minutes average to hit), and I stopped the run before completion. The lab names Intruder as the tool with no throttling warning and no scripted alternative.
  - crypto-ecb-oracle is only semi-feasible in pure Burp: Intruder works per byte (256 payloads), but chaining 28 dependent bytes needs manual iteration each round. The realistic path is a Python loop, which the tools pill allows.

- Suggestions (concrete):
  1. Set the 403 status on the clobber-admin deny branch (res.status(403).send(...)) so learners can distinguish success from failure by status.
  2. rand-pin hint 3: add "sort the Intruder results by the Status column to find the 200", warn that Burp Community throttles Intruder (1M requests is not practical there), and suggest the scripted alternative the page already hints at ("script it").
  3. ecb "how": replace "Intruder for the full loop" with "script the byte loop (Python) or iterate manually in Repeater", and add a tip for spotting the matching block among 256 same-length responses (compare response bodies or add a grep match).
  4. md5 hint 3: name the hashing step explicitly ("hash each wordlist entry with MD5 in Python or hashcat"), since Repeater cannot do it.
  5. Scope the reset PIN per session instead of globally, or at least warn on the PIN page that generating a new PIN resets it for everyone on a shared instance.
  6. Keep the honest "Decoder will not do this step for you" style of hint; it is the best guidance in the module and should be the template for the md5/ecb/pin gaps above.

- Rating: 4
