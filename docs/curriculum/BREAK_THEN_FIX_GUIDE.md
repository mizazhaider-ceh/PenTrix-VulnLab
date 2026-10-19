# Break-Then-Fix Guide

Attacking teaches you how things break. This mode teaches you how to fix them.
Break-then-fix is the defensive half of PenTrix: first you exploit a
challenge, then you repair the vulnerable code so the exploit no longer works.
Real security work is exactly this loop, attack, then defend.

## What break-then-fix is

Every security bug has two sides. The attacker side is what you already
practice in the challenges: find the weakness, build the exploit, capture the
flag. The defender side asks the harder question: how do you change the code
so the attack fails but normal users never notice?

Break-then-fix makes that the game:

1. **Break it.** Solve a challenge the normal way, exploit to flag. This
   proves you understand the attack.
2. **Read the code.** Open the fix view for that challenge. You get a small,
   self-contained copy of the vulnerable code.
3. **Fix it.** Edit the code right in your browser and submit your fix.
4. **Get the verdict.** A sandboxed runner tests your fix automatically.
5. **Earn the badge.** When your fix passes both tests, you earn a fix badge
   for that challenge.

## How to open a fix view

On any challenge page that supports fix mode, you will see a button labeled
**"Try to fix this"**. Click it and the fix view opens below the challenge.

The fix view shows three things:

- **The vulnerable code.** A minimal copy of the buggy logic, small enough to
  read in one screen. You do not need the whole application, just this piece.
- **What the attack does.** A short plain-English description of the exploit,
  so you know exactly what you have to stop.
- **An editor.** A text box where you write your fixed version of the code.

When you are ready, press **Submit fix**. The runner tests your code and
reports the result within seconds. There is no limit on attempts, so iterate
until it passes.

Challenges that do not have a fix block yet show an honest **"fix mode
coming soon"** note instead. The pilot covers the SQLi and XSS modules (20
blocks). More modules are added over time, and a fix view only appears when
the fix block behind it is real and verified.

## How to write a fix

Think like the developer who wrote the bug, not like the attacker who used
it. Your goal is to change as little as possible while closing the hole
completely.

A good fix follows three rules:

1. **Stop the attack.** The exact exploit from the challenge must fail
   against your code. Not mostly fail, completely fail.
2. **Keep normal use working.** A fix that blocks the attack by breaking
   everything is not a fix. Legitimate input must still work exactly as
   before.
3. **Fix the cause, not the symptom.** Blocking one payload string is not a
   fix if a slightly different payload still gets through. Aim for the root
   cause: untrusted input reaching a dangerous operation without the right
   protection.

A useful workflow:

1. Read the vulnerable code line by line. Find where untrusted input enters
   (the source) and where it does damage (the sink).
2. Decide on the right fix pattern for this bug class (see the patterns
   below).
3. Apply the pattern with the smallest change that covers all inputs, not
   just the one you used to exploit it.
4. Submit, read the runner feedback, and adjust.

## What the runner checks

Your submitted code is executed in a sandboxed runner on the server. You
never run your own server, you just paste code into the form and the server
checks it.

The runner performs two checks on your fix:

| Check | Question it answers | Your fix must... |
|-------|---------------------|------------------|
| 1. Exploit test | Does the old attack still work? | Make the attack **fail** |
| 2. Legit test | Does normal use still work? | Make normal use **pass** |

Both checks must pass. Here is why both matter:

- If only check 1 passed, you could "fix" anything by deleting all the
  code or rejecting all input. That is not security, that is denial of
  service.
- If only check 2 passed, your code is just the vulnerable code again.

Only when the exploit fails **and** legitimate input still works has the bug
actually been fixed.

A few facts about the sandbox, so nothing surprises you:

- Your code runs with a **2 second time limit**. An infinite loop is stopped
  and reported as a timeout, so be careful with loops.
- The sandbox exposes only plain JavaScript (strings, arrays, objects, Math,
  JSON, and friends). There is no file system, no network, no database.
- Submissions are limited to **50 KB**, which is far more than any fix
  needs. Keep it short.
- `console.log` inside the sandbox does nothing, so do not rely on it for
  debugging. Test your logic in your head or in your own scratch file.
- Errors (syntax errors, crashes, timeouts) are converted into plain-English
  messages. If your fix fails, the message plus the challenge's fix hint
  will point you in the right direction.

## What the badges mean

A fix badge is proof that you both broke **and** repaired a vulnerability.
Earning one means:

- You exploited the challenge and understood the attack.
- You read the vulnerable code and found the root cause.
- You wrote a fix that blocks the exploit without breaking normal use.
- The fix passed automatic checks in a sandbox, so the verdict is
  objective, not opinion.

Badges are per challenge and shown on the challenge page and in your
progress. They are separate from flags: a flag proves you can attack, a
fix badge proves you can defend. Collecting both for a challenge means you
understand the vulnerability from both sides, which is the whole point of
this platform.

## Tips and common fix patterns

Most vulnerabilities in this course fall into a few families. Each family
has a standard fix. Learn these patterns and most fix views become easy.

### Parameterized queries (fixes SQL injection)

Never build SQL by gluing strings together. The dangerous pattern looks
like this: user input is concatenated directly into a query string, so the
database cannot tell data from commands.

The fix is to separate the two: send the query structure with placeholders
and the user input as separate parameters. The database then treats the
input as pure data, always. There is no input value that can escape the
data role and become code.

Tip: ask yourself, "does any user-controlled text end up inside the SQL
string itself?" If yes, parameterize it. This one pattern kills the entire
SQL injection class.

### Output encoding (fixes cross-site scripting)

Cross-site scripting happens when untrusted data is placed into a page
where the browser executes it as code. The fix depends on where the data
lands:

- **In HTML text:** encode the special characters (`<`, `>`, `&`, quotes)
  so the browser renders them as text, not tags.
- **In an attribute:** encode quotes and angle brackets, and keep the
  attribute quoted.
- **In JavaScript:** never drop raw input into script. Encode for the JS
  context, or better, keep user data in the DOM and read it from there
  instead of from inline script.

The key insight is context: encoding must match where the data is used.
HTML encoding does not protect a JavaScript context, and vice versa. Look
at where the sink is, then pick the encoding for that context.

### Allowlists (fixes path traversal, open redirect, SSRF-style bugs)

When input picks a file, a URL, a command, or any resource, the safest fix
is an allowlist: define the exact set of values that are acceptable and
reject everything else.

- For file access: map input to a fixed list of allowed files, or resolve
  the path and verify it stays inside the intended directory.
- For redirects: allow only relative paths or a short list of trusted
  destinations, reject absolute URLs to other sites.
- For anything similar: validate against a strict pattern (letters and
  digits only, fixed length) when an allowlist of values is impractical.

Allowlists beat denylists because attackers are creative: blocking
`../` does nothing against encoded variants, but "only these ten files
exist" has no variants to sneak through.

### More patterns you will meet

- **Type and range checks:** if a value should be a number between 1 and
  100, enforce exactly that. Never trust the client to send sane values.
- **Least privilege in the sink:** when you cannot fully sanitize,
  constrain the dangerous operation itself (read-only queries, sandboxed
  evaluation, restricted commands).
- **Fail closed:** if validation is uncertain, reject the input. A fix
  that guesses is a fix that can be bypassed.

### General debugging tips

- Read the runner's feedback carefully. It tells you which check failed:
  exploit still works, or legit use broke.
- If the exploit still works, your fix missed a path. Trace every way
  input reaches the sink, not just the one you exploited.
- If legit use broke, your fix is too aggressive. Narrow it: block the
  malicious shape of input, not all input.
- If you are stuck, re-read the exploit description in the fix view. It
  describes exactly what must fail.
- After your fix passes, compare it with the reference fix that is
  revealed. There is often more than one valid approach, and seeing the
  reference teaches you the idiomatic one.

## Why this matters beyond the course

In a real job, "I found the bug" is only half the work. The other half is
writing the patch, proving it works, and proving it breaks nothing. That
is what break-then-fix trains: you learn to think like a developer under
pressure, not just like an attacker with free time.

Students who collect both flags and fix badges graduate with the rarest
skill in security: the ability to break something and then build it better.
