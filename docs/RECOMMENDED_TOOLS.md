# Recommended Tools for PenTrix VulnLab

**Step-by-step install instructions for every tool on this page:** [docs/TOOL_SETUP_GUIDE.md](TOOL_SETUP_GUIDE.md)

You do not need a big toolbox for this lab. You need one main tool, a
few helpers, and the patience to actually understand the bug in front
of you. This page tells you exactly that, nothing more.

## 1. The short version

**Burp Suite is the first-class tool of this lab.**

Install it, point your browser through its proxy, and learn four
things: Proxy, Repeater, Intruder, Decoder. Every one of the 201
challenges is solvable with that workflow: see the traffic, replay
the request, change one thing at a time, watch what the app does.

If you take nothing else from this page, take this: stop guessing in
the browser and start reading the traffic. The vulnerability always
shows up in the request/response pair before it shows up anywhere else.

## 2. Burp Suite, the one that matters

Four features, in the order you will actually use them.

**Proxy.** Sits between your browser and the lab. Every request your
browser sends and every response the app returns passes through here
and gets logged. This is where you find the interesting requests: the
login POST, the API call, the redirect with a suspicious cookie. Turn
intercept on, click through the challenge site once, and read what you
captured.

**Repeater.** Sends a captured request again, exactly as it was, and
lets you tweak anything before resending: a username field, a price
field, a cookie value, a header. This is your workbench. The workflow
for most challenges is: find the interesting request in the Proxy
history, send it to Repeater, change one field, send it, and compare
the new response to the old one. Repeat until the app does something
it should not.

**Intruder.** Takes a request and fires it many times with different
values in marked positions. Think guessing passwords against the login
form, or trying many IDs against an endpoint. Community Edition is
throttled, it sends requests slowly. That is fine for this lab, the
targets are small and the answer spaces are small. Mark a position,
give it a wordlist, start the attack, and watch for the one response
that looks different from the rest.

**Decoder.** Translates between encodings: base64, URL encoding, hex,
hash formats. When a cookie or token looks like gibberish, paste it
into Decoder and see what it really says. It will not tell you the
answer, it just removes the wrapping paper.

### Community vs Pro

**Community Edition is enough for all 201 challenges.** Nothing in
this lab requires the paid version.

What Pro adds, honestly: an automated **Scanner** that hunts for common
bugs for you, and **Collaborator** for out-of-band testing (detecting
things like blind SSRF, where the vulnerable server has to call back
to you). Interesting, but not needed here. If you ever test a real
target where blind vulnerabilities matter, that is when Pro earns its
price.

### Setup

1. Install Burp Suite Community Edition from the PortSwigger website.
2. Start Burp. The proxy listener runs on `127.0.0.1:8080` by default.
3. Configure your browser to use that proxy. Firefox with a separate
   profile for lab work is the common choice, so your normal browsing
   stays untouched. FoxyProxy makes switching profiles painless.
4. Open the lab at `http://localhost:3000` in that proxied browser
   and confirm requests show up in Burp's Proxy history.

One thing you do **not** need here: the Burp CA certificate. That cert
is for intercepting HTTPS traffic. This lab is plain HTTP on localhost,
so there is nothing to decrypt. Skip that step entirely for this lab.

## 3. The supporting cast

One line each, and where each one fits in this lab.

| Tool | What it is | Fits these modules |
| ---- | ---------- | ------------------ |
| OWASP ZAP | Free, open-source alternative to Burp with its own proxy and scanner | Any module, if you prefer it over Burp |
| sqlmap | Automates SQL injection: finds the injection, extracts the data | sqli |
| ffuf | Fast fuzzer: throws wordlists at URLs, parameters, headers | lfi, ssrf, api |
| gobuster | Discovers hidden paths and files on a server | misconfig |
| nmap | Maps what is listening on a target: ports, services | recon in method only (the lab is localhost, so you already know the target) |
| hashcat | Cracks hashes with wordlists and rules, uses your GPU | crypto (md5-crack), auth (brute-force) |
| Node with jsonwebtoken | Lets you forge and inspect JWTs from a script | jwt |

The pattern is the same everywhere: understand the bug by hand in
Burp first, then reach for the automation to do the boring part
faster. If you start with the automation, you skip the part where
you learn.

## 4. What not to reach for

**Raw curl one-liners as your default.** They still work, and you will
use curl plenty. But if every challenge is a curl command you pasted
together by trial and error, you are training your memory, not your
understanding. Do it in Repeater first, where you can see the full
request and the full response side by side. Graduate to curl when you
know exactly what you are sending and why.

**Raw sockets.** Nothing in this lab needs them. If you are writing
socket code to talk to this lab, you have wandered off the path. Come
back to Repeater.

## 5. Honest limits

- Burp Community's Intruder is throttled. It is slow on purpose. For
  this lab that is fine, the guessable spaces are small. If you find
  yourself waiting an hour on an attack, the approach is wrong, not
  the tool.
- No tool here replaces understanding the vulnerability. sqlmap can
  extract a database, but it cannot tell you *why* the query was
  injectable. If you cannot explain the bug in one sentence, you have
  not finished the challenge, even with the flag in hand.
- The best tool in this lab is still your own attention. Read the
  responses. All of them. The app tells you more than you think.
