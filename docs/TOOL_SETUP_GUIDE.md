# Tool Setup Guide: Burp Suite and the Web Hacking Toolkit

This is the full setup guide for the PenTrix-VulnLab pentesting toolkit. It is written for students starting the lab from zero: it installs Burp Suite (the lab's primary tool), connects a browser through the proxy, and adds the supporting tools you will use alongside it. Work through it once, in order, and you will be ready to attack every module.

## Table of contents

- [1. Burp Suite: What It Is and How to Install It](#1-burp-suite-what-it-is-and-how-to-install-it)
- [2. Connecting Your Browser to Burp: Proxy, HTTPS Certificate, and Scope](#2-connecting-your-browser-to-burp-proxy-https-certificate-and-scope)
- [3. The Burp Workflow You Will Use for Every Challenge](#3-the-burp-workflow-you-will-use-for-every-challenge)
- [4. ZAP (the Free Burp Alternative) and sqlmap (the SQLi Machine)](#4-zap-the-free-burp-alternative-and-sqlmap-the-sqli-machine)
- [5. ffuf, gobuster, and nmap (the Recon Trio)](#5-ffuf-gobuster-and-nmap-the-recon-trio)
- [6. More Tools Worth Knowing, Which Tool for Which Module, and the Methodology](#6-more-tools-worth-knowing-which-tool-for-which-module-and-the-methodology)

---

## 1. Burp Suite: What It Is and How to Install It

## What is Burp Suite?

Burp Suite is an intercepting proxy built for web security testing. In plain words: it sits between your browser and a web application, and it lets you see, stop, and change every request and response that passes through. You browse the site like normal, but Burp quietly captures all the HTTP traffic so you can inspect it, tamper with it, and resend it with changes.

It is made by **PortSwigger**, and it is the number one tool for this lab for one simple reason: almost every PenTrix challenge runs through HTTP requests. Login forms, hidden parameters, cookies, API calls, file uploads, everything goes through the browser, and Burp gives you full control over all of it. If you can see the request, you can test it. That is how the challenges are meant to be solved.

You will spend most of your time in four tools inside Burp:

- **Proxy**: the interception point. This is where you watch traffic flow and decide which requests to pause and inspect.
- **Repeater**: send the same request again and again with small changes, and watch how the server answers. This is your main testing playground.
- **Intruder**: send many requests automatically with different values (payloads) in chosen spots. Great for fuzzing inputs and finding where something interesting happens.
- **Decoder**: encode and decode data (base64, URL encoding, hashes) when a challenge hides values in plain sight.

## Community vs Pro: which one do you need?

Good news: the **Community Edition is free, and it is enough for every single one of the 201 PenTrix challenges**. Proxy, Repeater, Intruder, and Decoder are all included. You can complete the entire lab without paying anything.

| | Community Edition | Professional |
|---|---|---|
| Price | Free, forever | Around $449/year |
| Proxy (intercept + inspect traffic) | Yes | Yes |
| Repeater (manual request tampering) | Yes | Yes |
| Intruder (automated payloads) | Yes (rate-limited) | Yes (faster, full speed) |
| Decoder (encoding tools) | Yes | Yes |
| Automated Scanner | No | Yes (scans for vulnerabilities automatically) |
| Burp Collaborator (out-of-band detection) | No | Yes |
| Save projects and reports | Limited | Full |

Professional is genuinely useful in real-world pentesting jobs because the automated Scanner finds issues for you, but for learning and for this lab, you do not need it. The Community Edition forces you to understand the requests yourself, which is exactly the skill PenTrix is here to teach. Start free, upgrade later if you ever do client work.

## Download Burp Suite Community Edition

The official download page is:

```
https://portswigger.net/burp/communitydownload
```

(Verified: this URL returns HTTP 200 directly, no redirects. Download only from this page, never from a random mirror. Free tools with bundled installers are a classic malware trap.)

Pick the installer for your operating system:

- **Windows**: `.exe`
- **macOS**: `.dmg`
- **Linux**: `.sh` script (64-bit system required)

## Install Burp Suite

### Windows

1. Download the `.exe` installer from the page above.
2. Double-click the `.exe` and follow the installation wizard (keep the default options, they are fine).
3. When it finishes, launch **Burp Suite Community Edition** from the Start menu.

### macOS

1. Download the `.dmg` file from the page above.
2. Open the `.dmg`, then drag the Burp Suite icon into your **Applications** folder.
3. On first launch, macOS may block the app because it was downloaded from the internet. If that happens, right-click (or Control-click) the app and choose **Open**, then confirm. This bypasses Gatekeeper once; after that it launches normally.

### Linux

1. Download the `.sh` installer from the page above (you need a 64-bit system).
2. Make the installer executable:
   ```bash
   chmod +x burpsuite_community_linux_*.sh
   ```
3. Run the installer:
   ```bash
   sudo ./burpsuite_community_linux_*.sh
   ```
   (You can also run it as a normal user without `sudo` if you install into your home directory; `sudo` gives you a system-wide install.)
4. Follow the installer's prompts. When it finishes, you can start Burp from your application menu or by running the installed binary.

### One less thing to worry about

Modern Burp Suite ships with its own bundled Java runtime. You do **not** need to install Java separately. If you see old tutorials telling you to install a JDK first, ignore them, that advice is outdated.

## First launch: getting past the welcome screens

When you open Burp for the first time, it asks a few setup questions. Here is what to pick:

1. **Project**: choose **Temporary project**. This means Burp keeps nothing when you close it. For learning that is perfect: you always start clean, and there is nothing important to lose yet. (You can create saved projects later once you do longer assessments.)
2. **Configuration**: choose **Use Burp defaults**. The default settings are fine for everything you will do in this lab.
3. Click **Start Burp**.

Burp opens on the **Dashboard** tab. This is your home screen. Right now it looks a bit empty, which is normal: it shows a task list, an event log, and an issue activity panel. Once you start browsing through the proxy, the Dashboard will fill up with the requests you have captured. For now, just get comfortable with the layout. The tabs along the top (Target, Proxy, Intruder, Repeater, Decoder) are the tools you will learn one by one in the next sections.

You have Burp installed and running. Next, we will make your browser talk to it.

---

## 2. Connecting Your Browser to Burp: Proxy, HTTPS Certificate, and Scope

## What is actually happening here

Think of Burp as a post office that sits between your browser and the lab. Every request your browser makes to `http://localhost:3000` is first handed to Burp, which logs it, lets you pause and edit it, and then forwards it to the lab. Responses travel back through the same route. Burp listens for this traffic on **127.0.0.1 port 8080** by default (check Proxy > Options / Proxy settings if you ever change it). Your browser does not know about Burp on its own, so you have to tell it: "send your traffic through the proxy at 127.0.0.1:8080". There are two ways to do that, manual or with an extension. Method 2 is recommended.

## Method 1: Manual proxy configuration

### Chrome / Edge

Chrome and Edge use your operating system's proxy settings, so you are really configuring the OS:

1. In Chrome, go to **Settings > System > Open your computer's proxy settings** (in Edge the wording is nearly identical). This opens the OS proxy panel.
2. Turn on **manual proxy setup** and enter:
   - Proxy server address: `127.0.0.1`
   - Port: `8080`
3. **Windows:** this is under Settings > Network > Proxy. **macOS:** System Settings > Network > Wi-Fi > Details > Proxies, then enable **Web Proxy (HTTP)** and **Secure Web Proxy (HTTPS)**, both pointing at `127.0.0.1:8080`.
4. Save. Now browse to `http://localhost:3000` and watch the traffic appear in Burp under Proxy > HTTP history.

**Localhost gotcha:** on many systems, `localhost` and `127.0.0.1` are in the proxy bypass/exception list by default. If that is the case, your browser talks straight to the lab and Burp sees nothing, which is the classic "why is nothing being intercepted" moment. Fix: make sure `localhost` and `127.0.0.1` are **NOT** in the bypass or exception list.

### Firefox

Firefox has its own independent proxy settings, which is handy because it does not touch the rest of your system:

1. Go to **Settings**, scroll to **Network Settings**, and click **Settings**.
2. Select **Manual proxy configuration**.
3. In the **HTTP Proxy** field, enter `127.0.0.1` and set **Port** to `8080`.
4. Check **"Also use this proxy for HTTPS"**.
5. **Firefox-specific gotcha:** the **"No proxy for"** box usually contains `localhost, 127.0.0.1`. Clear those entries (or uncheck the relevant option) so localhost traffic goes through Burp. Leave the box empty for this lab.

## Method 2: FoxyProxy extension (RECOMMENDED)

FoxyProxy is an open-source proxy management extension available as both **FoxyProxy Basic** (simplified) and **FoxyProxy Standard** (full featured) on the Chrome Web Store and on Firefox Add-ons. You are installing it from the official store for your browser, so you can verify the name yourself in the store search before installing. Either edition works fine for the lab.

Setup:

1. Install FoxyProxy Basic (or Standard) from the Chrome Web Store / Firefox Add-ons.
2. Click the FoxyProxy icon in the toolbar and open its options. Add a new proxy:
   - Host: `127.0.0.1`
   - Port: `8080`
3. Add a URL pattern so only lab traffic uses the proxy: pattern `*localhost*` (add `*127.0.0.1*` too). URL patterns use wildcards, so `*localhost*` matches `http://localhost:3000` and anything else with localhost in it.
4. Save. Now click the FoxyProxy toolbar icon and select your new proxy to turn it on. Click again to turn it off and go back to direct browsing.

**Why this is better:** it is one click on, one click off. Manual config affects everything you browse while it is enabled (and forgetting to turn it off means your normal browsing breaks whenever Burp is closed). FoxyProxy with a `*localhost*` pattern sends only lab traffic through Burp, so your normal browsing is completely untouched, and you always know at a glance from the toolbar icon whether the proxy is active.

## Installing the Burp CA certificate (so HTTPS works without errors)

Your lab runs on plain HTTP, but the moment Burp needs to handle HTTPS traffic it has to generate certificates on the fly. Your browser will reject those with errors unless it trusts Burp's certificate authority (CA). So you install Burp's CA once per browser:

1. Make sure Burp is running and the proxy is switched on in your browser (Method 1 or Method 2 above).
2. In the browser, visit **`http://burp/cert`**. This is Burp's built-in endpoint for this; the browser will download a file called `cacert.der`.
3. Install it as a trusted root CA:
   - **Firefox:** Settings > Privacy & Security > Certificates > View Certificates > Authorities tab > Import, select `cacert.der`, and check **"Trust this CA to identify websites"**.
   - **Chrome / Edge on Windows:** import the file into the Windows certificate store under **Trusted Root Certification Authorities**. You can do this via `certlm.msc` (import into Trusted Root Certification Authorities > Certificates), or via Chrome's Settings > Privacy and security > Security > Manage certificates, which opens the same store.
   - **macOS:** open **Keychain Access**, import `cacert.der` into the **System** keychain, then double-click the new "PortSwigger CA" entry, expand Trust, and set "When using this certificate" to **Always Trust**.
   - **Linux:** it varies by distro and browser. Firefox uses its own certificate store (follow the Firefox steps above). For Chromium-based browsers, import the cert into the OS trust store for your distro (for example with the distro's CA update tooling) or consult your distro's docs.

**If you skip this:** HTTPS sites through Burp will show **"Your connection is not private"** or `NET::ERR_CERT_AUTHORITY_INVALID`. That error means exactly one thing: the browser does not trust the certificate Burp generated, because the Burp CA is not in its trusted store yet. Go back and install the CA.

**One caveat:** this CA lets Burp decrypt HTTPS traffic routed through it. Only install it in a browser profile you use for lab work, not your main daily browser, and only ever trust it on your own machine.

## Setting up the target scope for PenTrix

With the proxy connected, tell Burp which site is in scope so you can filter out noise:

1. In Burp, go to the **Target** tab, then the **Scope** sub-tab.
2. Under "Include in scope", click **Add** and enter `http://localhost:3000`. Add `http://127.0.0.1:3000` as well, since both addresses reach the same lab.
3. Now browse the lab normally in your browser. The **Target > Site map** fills in automatically, showing every page, endpoint, and parameter you have visited, organized like a tree.
4. Everything you do is also logged in **Proxy > HTTP history**, which is the full chronological record of every request and response, in scope or not. Use the scope filter there to show only lab traffic.

From here on, the Site map is your map of the lab's attack surface: every new page you click through adds to it, and that is exactly where you start looking for interesting functionality to test.

---

## 3. The Burp Workflow You Will Use for Every Challenge

Nearly every PenTrix-VulnLab challenge follows the same rhythm: intercept a request, replay it, change one thing, observe what changes in the response. You do not need to master all of Burp. You need six tools and the habit of repeating this loop until it feels natural.

## 1. Proxy: your window into the traffic

The Proxy sits between your browser and the lab server. Every request passes through it, and you can hold, inspect, forward, or drop each one.

- **Intercept on/off:** In the Proxy tab, open the **Intercept** sub-tab. The **Intercept is on/off** button (it toggles, and the status bar shows the state) decides whether requests pause in front of you. With intercept **on**, each request waits for you to act. With it **off**, traffic flows straight through but is still logged.
- **Forward vs Drop:** When a request is paused, **Forward** sends it on to the server exactly as you see it (edit it first if you like, then forward). **Drop** throws it away without sending it to the server, and the browser sees the request fail.
- **HTTP history:** In the Proxy tab, open **HTTP history**. This is your log of everything: every request your browser made, every response that came back, status codes, methods, parameters. When you wonder "what did I actually send?", the answer is here.

Typical use in the lab: turn intercept **off** most of the time (so browsing feels normal), open HTTP history to find the request you care about, then work with it.

## 2. Repeater: your workbench

Repeater is where nearly every challenge gets solved. It lets you take one request and resend it again and again, changing one thing at a time.

1. In HTTP history (or in the Intercept tab), right-click any request and choose **Send to Repeater** (shortcut: **Ctrl+R**).
2. Switch to the **Repeater** tab. Your request is now in its own numbered tab.
3. Edit anything you want: the method (GET, POST), the path, a header, or a value in the body.
4. Click **Send**. The response appears on the right.
5. Change one more thing, click Send again, and **compare the two responses**.

The power of Repeater is iteration speed. You can send twenty variations of a request in a minute and watch exactly how the server reacts. Every tab keeps its own history of what you sent and what came back, so you can scroll up and compare.

## 3. Intruder: automated repetition

Intruder does what you do in Repeater, but automatically: it takes a request and repeats it with different values in chosen positions.

1. Right-click a request and choose **Send to Intruder** (shortcut: **Ctrl+I**).
2. In the **Positions** tab, the attack type is **Sniper** (the default and the one you want for this lab). Mark your payload positions: select a value in the request and click **Add §**. The value now sits between two § symbols.
3. Switch to the **Payloads** tab. For this lab, simple lists are enough: numbers (1, 2, 3) or short word lists you type in or paste.
4. Click **Start attack**. A results table appears with one row per payload value, showing the response length and status code.

One honest note: **Burp Community Edition throttles Intruder** (it inserts a delay between requests), so attacks run slower than in the paid version. For this lab the lists are small, so the throttle is only mildly annoying, not a blocker. Keep your payload lists short and focused.

## 4. Decoder: reading and writing encodings

Servers and browsers constantly encode text (URL encoding, Base64, HTML entities). Decoder translates between the encoded and readable forms.

- Paste any text into the Decoder tab.
- Choose a transform: **Decode as URL**, **Decode as Base64**, **Decode as HTML**, or the matching **Encode as** versions.
- You can chain transforms (decode URL, then decode Base64) by stacking them.

You will use this constantly when reading responses. If a response contains a blob that looks like random characters, paste it into Decoder and try Base64 or URL decoding before assuming it is meaningless.

## 5. Comparer: spot the difference

When two responses look identical but the server behaves differently, Comparer shows you the exact difference.

1. Right-click any request in HTTP history or Repeater and choose **Send to Comparer** (request or response, whichever you want to compare).
2. Send a second response the same way.
3. In the Comparer tab, select both items and click **Compare by words** (or **Compare by bytes**).
4. The view highlights exactly which bytes changed.

Typical lab use: send the same request twice with one value changed, send both responses to Comparer, and find the one field that differs. That difference is often the clue.

## 6. Logger: the full story

Logger (in newer Burp versions it replaces the old Target scope logging) is the always-on record of everything Burp sees, Proxy traffic included, with powerful filtering. If you ever need to reconstruct "what exactly did I do in the last ten minutes", Logger has the full traffic story. Make sure it is enabled (Proxy and platform traffic logging switched on in Logger settings) so the record exists when you need it.

## Worked mini-example: intercepting a login (mechanics only)

This example uses no real challenge route, no flags, and no payloads. It is only about the mechanics: intercept, replay, modify, observe.

1. In Burp, go to the Proxy tab, Intercept sub-tab, and click the **Intercept is off** button so it now reads **Intercept is on**.
2. In your proxied browser, open the lab and submit the login form with any values you like (for example, a test username and a test password).
3. Burp now holds the request. You will see a **POST** request to the login path, with the username and password visible in the body of the request. Nothing has reached the server yet.
4. Click **Forward**. The request goes to the server, the browser shows the result of your login attempt.
5. Back in Burp, open **Proxy > HTTP history**. Find the POST request you just forwarded (it is the most recent POST to the login path).
6. Right-click it and choose **Send to Repeater** (or press **Ctrl+R**).
7. In the Repeater tab, find the username value in the request body and change it to something else (another plain username, nothing special).
8. Click **Send**. Read the response on the right.
9. Now change the username again to a third value, click Send again, and compare the two responses. Notice what changed and what stayed the same.

That loop (intercept, find in history, send to Repeater, change one thing, send, compare responses) is the entire Burp workflow for this lab. Every challenge is a variation of it.

## Troubleshooting

| Problem | Cause | Fix |
|---|---|---|
| Port 8080 already in use when starting Burp | Another program (another Burp instance, a local server, Docker) is already listening on 8080 | In Burp: **Proxy > Proxy settings** (the gear icon in the Proxy tab), edit the listener on 127.0.0.1:8080 and change the port to 8081. Then update your browser proxy config (or FoxyProxy) to use 127.0.0.1:8081 so both sides match. |
| Certificate errors on every HTTPS page in the browser | Burp's CA certificate is not installed or not trusted in that browser (see Section B, step 4) | Redo the CA install: export the CA from Burp (Proxy settings > Import/export CA certificate), import it into the browser's certificate store, and restart the browser. |
| Localhost traffic not appearing in Burp | The browser is bypassing the proxy for localhost (many browsers do this by default) | Remove localhost (and 127.0.0.1) from the browser's proxy bypass or exceptions list. In FoxyProxy, check your URL pattern and make sure it covers the lab's URL instead of excluding it. |
| Burp feels slow, pages hang halfway through loading | Intercept is **on** and holding a request that Burp is waiting for you to act on | Look at the Intercept tab. If a request is waiting, click **Forward** (or **Drop**). Then turn intercept off if you do not need to pause traffic right now. |
| Proxy configured but the browser ignores it | Firefox and Chrome/Edge handle proxy settings differently | **Firefox** has its own proxy settings and its own certificate store: configure both inside Firefox (Settings > Network Settings for the proxy, Settings > Privacy & Security > Certificates for the CA). **Chrome and Edge** use the operating system's proxy and certificate settings, so configure them at OS level (or use FoxyProxy in either browser to keep things simple). |
| Burp will not start at all | Incompatible Java runtime or a non-executable installer on Linux | Burp needs a **64-bit** operating system and a compatible Java runtime (the bundled installer usually handles this). On Linux, if you downloaded the .sh installer, make it executable first: `chmod +x burpsuite_community_linux*.sh`, then run it. If it still fails, run it from a terminal so you can read the actual error message. |

---

## 4. ZAP (the Free Burp Alternative) and sqlmap (the SQLi Machine)

Two more tools for your belt. ZAP is your free second opinion and site mapper. sqlmap is the automated SQL injection tester for the sqli modules. Neither one replaces your brain: they find things, you understand them.

---

## 1. OWASP ZAP (Zed Attack Proxy)

**What it is:** a free, open-source intercepting proxy and security scanner from OWASP, the same people who publish the Top 10. Think of it as Burp's free sibling: it proxies your browser traffic, lets you spider a site, and runs an automated scan. Site: https://www.zaproxy.org (verified live, Oct 2026).

### Install

Pick one for your OS:

- **Windows:** download the installer from the ZAP download page on zaproxy.org (verify the URL responds before downloading).
- **macOS:** installers on the site, or via Homebrew:

  ```bash
  brew install --cask owasp-zap
  ```

- **Linux (Debian/Ubuntu):** download the Linux installer from the site, or check your distro's repo (Kali ships ZAP preinstalled).

Sanity check after install: launch ZAP, open the Options > Network > Local Servers/Proxies panel, and confirm the proxy address is **127.0.0.1:8080**.

**Important: the port clash.** ZAP's default proxy port is also 127.0.0.1:8080, same as Burp. Run only one of them at a time, or change one tool's proxy port (in ZAP: Tools > Options > Network; in Burp: Proxy settings > change the listener port, e.g. 8081). If your browser suddenly stops loading pages after switching tools, a port clash is the first thing to check.

### Essential use (4 steps)

1. **Set the browser proxy to ZAP.** Same idea as Burp: point your browser's proxy settings (or FoxyProxy) at 127.0.0.1:8080 while ZAP is running. Click around http://localhost:3000 and watch the Sites tree in ZAP fill up. Every page you visit gets mapped.

2. **Run the Automated Scan.** In the Quick Start tab, paste your target (http://localhost:3000) and hit **Attack**. ZAP spiders the lab automatically and runs a passive scan on everything it finds, reporting issues in the Alerts tab. This gives you a baseline map of every page, parameter, and form in the lab.

3. **Manual explore.** Spidering only finds what the spider can reach. Browse the lab yourself through the proxy, especially the sqli, xss, idor, auth, ssrf, upload, and jwt module pages, so ZAP's site tree reflects the real app, not just the crawler's guess.

4. **(Optional) Try the HUD.** ZAP can inject a Heads-Up Display into your browser so you see scan results overlaid on the page while you browse. It is off by default; enable it from the HUD tab if you like working in-page.

### How it fits PenTrix-VulnLab

- **Any module, as a second opinion after Burp.** Two tools, two opinions: if both flag the same thing, it is worth your time; if only one does, investigate before trusting it.
- **Best at spidering.** Run the Automated Scan early in a module to map every page and parameter before you start testing by hand, so you do not miss a hidden corner of the lab.

---

## 2. sqlmap (the SQL injection tester)

**What it is:** the standard automatic SQL injection testing tool. You point it at a URL or form, it figures out if the input is injectable, and (with the right options) can read the database structure and data. It is a confirmation and exploration machine for the sqli modules. Site: https://sqlmap.org (verified live, Oct 2026).

### Install

- **Kali Linux:** already installed. Run `sqlmap --version` to check.
- **Anywhere with Python 3:**

  ```bash
  git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
  cd sqlmap
  python sqlmap.py --version
  ```

- **Windows:** install Python 3 first, then clone the repo as above and run `python sqlmap.py`. Same commands, just from PowerShell or cmd.

Sanity check: `python sqlmap.py --version` (or `sqlmap --version` on Kali) should print a version banner without errors.

### Essential commands (against the lab only)

sqlmap's options form an escalation ladder: find the injection, list the databases, list the tables, dump the data. Each step needs the previous one to succeed.

1. **Test a form endpoint for injectable parameters:**

   ```bash
   python sqlmap.py -u "http://localhost:3000/<form-endpoint>" --forms --dbs --batch
   ```

   Replace `<form-endpoint>` with a form page in the lab, e.g. a login or search form (keep it generic, the point is the pattern). `--forms` makes sqlmap test the page's forms automatically, `--dbs` lists the databases if injection works, `--batch` answers all prompts with the default so the run does not stop and wait for you.

2. **Escalation ladder, step by step:**
   - `--dbs` : list the database names (your proof the injection is real).
   - `--tables -D <database>` : list the tables inside one database (replace `<database>` with a name from step 1).
   - `--dump -D <database> -T <table>` : dump the contents of one table (replace `<table>` with a table from step 2). Dump only what you need; full dumps of big tables are slow and noisy.

3. **Stay safe on the lab:** keep `--level` and `--risk` at their defaults (1). Higher values mean more requests and more aggressive payloads; the defaults are enough for this lab and keep things fast. Add `--batch` to every run so you are never stuck at a prompt mid-session.

### How it fits PenTrix-VulnLab

- **sqli modules.** After you find a suspicious input by hand (Burp or ZAP), let sqlmap confirm the injection and map the database for you. It is also a great way to double-check a page you thought was clean.
- **Golden rule: tools confirm, you understand.** Always take sqlmap's finding back to Burp Repeater and reproduce it by hand before you believe it. If you cannot explain the injection in your own words, you have not learned it yet, you have just watched a tool work.

---

## Quick recap

| Tool | Job in this lab | Remember |
|------|-----------------|----------|
| ZAP | Free proxy, spider, and baseline scan; second opinion after Burp | Same default port as Burp (8080); run one at a time or change a port |
| sqlmap | Automatic SQL injection testing; the `--dbs` > `--tables` > `--dump` ladder | Keep `--level`/`--risk` at defaults; always confirm findings by hand in Repeater |

Both tools' official sites were verified live as of this writing. Install once, use them on every module.

---

## 5. ffuf, gobuster, and nmap (the Recon Trio)

You now have Burp running and the lab loading. These three tools handle the
next job: **reconnaissance**, which is the fancy word for poking around before
you start attacking. In real pentests, recon is where most vulnerabilities are
found. The habit is simple: enumerate first, attack second.

All examples below target the lab at `http://localhost:3000`. Swap in the URL
you are actually working on when you move to other targets.

## E.1 ffuf (fast web fuzzer)

**What it is:** ffuf is a fast web fuzzer written in Go. "Fuzzing" here just
means throwing many inputs at a target and watching the responses. Its main
job for us is **content discovery**: guessing hidden paths, pages, and
parameters on the lab (things like `/secret-panel` that no link points to).
It replaces the old-school tool `dirb`, which you may see in older writeups.
Repo: https://github.com/ffuf/ffuf

**Install:**

- **Kali Linux:** preinstalled. Type `ffuf -V` to check.
- **Any system with Go:** run `go install github.com/ffuf/ffuf/v2@latest`.
  You need Go installed first. Make sure your Go bin
  folder is in your PATH afterwards, or the `ffuf` command will not be found.
- **Windows without Go:** grab a prebuilt binary from the releases page
  linked from the ffuf repo above and drop it somewhere in your PATH.

You also need **wordlists**, which are big text files full of common directory
and parameter names. The standard set is SecLists, a community wordlist
collection. Clone it once and reuse it forever:

```bash
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists
```

**Essential commands:**

```bash
# 1. Fuzz for hidden directories and pages.
# FUZZ is the keyword: ffuf swaps in one wordlist line per request.
ffuf -u http://localhost:3000/FUZZ -w ~/SecLists/Discovery/Web-Content/common.txt -mc 200,301,302,403
```

The `-mc` flag (match codes) keeps only responses with those HTTP status
codes, so noise like 404s is hidden. 403 (Forbidden) is worth keeping: a
forbidden page still proves something exists there.

```bash
# 2. Same scan, but also follow into found directories (one level deep).
ffuf -u http://localhost:3000/FUZZ -w ~/SecLists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -recursion -recursion-depth 1
```

Recursion re-fuzzes every directory it finds. Keep the depth low at first:
depth 2 or 3 on a big wordlist can explode into thousands of requests.

```bash
# 3. Fuzz for hidden GET parameters: http://localhost:3000/page?FUZZ=value
ffuf -u "http://localhost:3000/page?FUZZ=value" -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt -mc 200
```

```bash
# 4. Fuzz for hidden POST parameters.
ffuf -u http://localhost:3000/page -X POST -d 'param=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -w ~/SecLists/Discovery/Web-Content/burp-parameter-names.txt -mc 200
```

With `-X POST`, ffuf sends each wordlist line as the value of `param`.
Change `param` to any parameter name you already know from the lab forms.

**How it fits PenTrix:** run a directory fuzz before you start a challenge.
Found pages become new Burp targets: visit them in the browser, add them to
scope, and inspect how they behave. Found parameters become injection points
to test later. One fuzzing run often hands you the next two or three things
to investigate.

## E.2 gobuster (directory and DNS brute forcer)

**What it is:** gobuster is the classic directory/DNS brute forcing tool, also
written in Go. It does the same content discovery job as ffuf but with a
different, simpler interface that many people find easier to read. Knowing
both is useful because writeups and teammates will use either one.
Repo: https://github.com/OJ/gobuster

**Install:**

- **Kali Linux:** preinstalled.
- **Debian/Ubuntu:** `sudo apt install gobuster`.
- **Any system with Go:** `go install github.com/OJ/gobuster/v3@latest`.
- **Windows/macOS:** prebuilt binaries are on the releases page linked from
  the gobuster repo above.

**Essential commands:**

```bash
# 1. Directory scan with file extension guessing.
gobuster dir -u http://localhost:3000 -w ~/SecLists/Discovery/Web-Content/common.txt -x php,txt,html
```

`dir` mode is the one you want for web labs. The `-x` flag makes gobuster
also try each word with those extensions appended (so `admin` becomes
`admin.php`, `admin.txt`, `admin.html` too). This catches backup and config
files that plain directory guessing misses.

```bash
# 2. Only show interesting status codes.
gobuster dir -u http://localhost:3000 -w ~/SecLists/Discovery/Web-Content/common.txt -s 200,204,301,302,307,401,403
```

`-s` is gobuster's version of ffuf's `-mc`: a whitelist of status codes to
display.

```bash
# 3. Blacklist noisy codes instead (for example, hide 404s explicitly).
gobuster dir -u http://localhost:3000 -w ~/SecLists/Discovery/Web-Content/common.txt -b 404
```

`-b` hides responses with those codes. Use whichever of `-s` and `-b` gives
you a cleaner screen for the target at hand.

```bash
# 4. Slower, quieter scan (useful if the lab ever rate-limits you).
gobuster dir -u http://localhost:3000 -w ~/SecLists/Discovery/Web-Content/common.txt -t 10 --delay 200ms
```

`-t` sets the thread count (default 10) and `--delay` pauses between
requests. Slower scans are also better practice for real targets, where
hammering a server gets you blocked.

**How it fits PenTrix:** gobuster and ffuf overlap, so pick one as your daily
driver and keep the other in your back pocket. A common workflow: quick
gobuster `dir` run with `-x` extensions for a first pass, then ffuf with
recursion if the first pass turned up directories worth digging into. Feed
everything you find back into Burp as new scope.

## E.3 nmap (service recon)

**What it is:** nmap is the network scanner. It answers the question "what is
listening, and what is it?" by probing ports and fingerprinting services. You
will use it on every real engagement, usually as step zero.
Homepage: https://nmap.org

**Install:**

- **Kali Linux:** preinstalled.
- **Debian/Ubuntu:** `sudo apt install nmap`.
- **Windows:** download the installer from the nmap download page
  (install Npcap when it asks, otherwise scanning will not work properly).
- **macOS:** download the dmg from the nmap download page.

**Essential commands:**

```bash
# 1. Check what is listening on the lab host, with service versions.
nmap -sV localhost -p 3000
```

`-sV` probes the open port and guesses the service and version (for example,
"Node.js" or "Express"). `-p 3000` limits the scan to the lab's port. The
output tells you what software stack you are dealing with, which guides what
attacks are even plausible.

```bash
# 2. Add default scripts: safe, useful extra checks.
nmap -sV -sC localhost -p 3000
```

`-sC` runs nmap's default script set against the port. These scripts grab
banners, titles, and common misconfigurations. They are non-intrusive and
safe to run on the lab.

```bash
# 3. Aggressive scan (version detection, scripts, OS detection, traceroute).
nmap -A localhost -p 3000
```

`-A` is the "everything" button: OS detection, version detection, script
scanning, and traceroute in one go. It is **noisy** (loud on the network,
easy to spot in logs) and slower. Fine against your own lab, but on real
targets you only use `-A` when you have permission and a reason.

```bash
# 4. Quick check: is the port even open, no frills.
nmap localhost -p 3000
```

When the lab will not load in the browser, this is faster than guessing: if
the port shows `closed`, the lab container is not running. Start it and try
again.

**How it fits PenTrix:** the lab is a single local port, so nmap will not
find much here beyond "port 3000 is open, here is the stack." That is fine:
its real value in this guide is building the habit. Every future target,
multi-container lab, or HackTheBox-style box starts the same way: nmap first,
understand the attack surface, then point the web tools at what you found.

## E.4 Putting the trio together (your recon loop)

For each PenTrix challenge, run this loop before you start attacking:

1. `nmap -sV -sC localhost -p 3000` to confirm the service and stack.
2. `gobuster dir` (or ffuf) for hidden paths and files.
3. Visit every interesting find in the browser through Burp, add it to scope.
4. ffuf for hidden parameters on the pages that take input.
5. Now attack, with Burp Repeater and Intruder doing the heavy lifting.

Recon is not a one-time step. Every new page you discover restarts the loop
on that page. The people who find the most bugs are usually just the people
who enumerated the most.

---

## 6. More Tools Worth Knowing, Which Tool for Which Module, and the Methodology

You already have your core kit. These extra tools deserve a quick mention so you recognize their names when you see them in writeups.

## Quick mentions

**Nikto** (https://github.com/sullo/nikto) is a web server scanner that checks a target for thousands of known misconfigurations, outdated software versions, and dangerous default files. Install it with `sudo apt install nikto`. Use it for a quick automated health check of a server you are allowed to test, then dig into the interesting findings yourself in Burp.

**dirsearch** (https://github.com/maurosoria/dirsearch) is a path and file brute forcer: you give it a wordlist, it asks the server for every name on the list, and reports the ones that exist. Install it with `pip install dirsearch` or `sudo apt install dirsearch`. Use it when you suspect a site hides admin pages, backups, or forgotten directories.

**wfuzz** (https://github.com/xmendez/wfuzz) is a flexible fuzzer that replaces placeholders in requests with wordlist entries, useful for finding parameters, values, and hidden endpoints. Install it with `pip install wfuzz`. Use it when dirsearch or ffuf feel too simple and you want custom fuzzing of headers, parameters, or POST bodies.

**Sublist3r** (https://github.com/aboul3la/Sublist3r) and **amass** (https://github.com/owasp-amass/amass) are subdomain enumeration tools: they find subdomains like `api.target.com` that you would never guess by hand. Install Sublist3r with `pip install -r requirements.txt` inside its folder, amass with `sudo snap install amass` or from its releases page. These two matter for real bug hunting more than for this localhost lab, because PenTrix-VulnLab runs on one local host and has no subdomains to discover; on a real program, subdomain enum is often step one.

## Which tool for which module type

Burp Suite is your primary tool for almost everything. The supporting tools below speed up specific jobs, they do not replace understanding the bug.

| Module type | Primary tool | Supporting tools |
|---|---|---|
| SQL injection | Burp Suite (Repeater) | sqlmap, Burp Intruder |
| XSS | Burp Suite (Repeater, Proxy) | Burp Decoder for encodings |
| IDOR / broken access | Burp Suite (Repeater) | Burp Comparer, Autorize extension |
| Authentication attacks | Burp Suite (Intruder) | Hydra, custom wordlists (SecLists) |
| SSRF | Burp Suite (Repeater) | Burp Collaborator for out-of-band checks |
| File upload | Burp Suite (Repeater) | file command, exiftool for file inspection |
| JWT | Burp Suite (Repeater) | Burp Decoder, jwt.io style offline checkers |
| LFI / path traversal | Burp Suite (Repeater) | ffuf for file name fuzzing |
| Command injection | Burp Suite (Repeater) | Burp Collaborator for time-based and out-of-band checks |
| CSRF | Burp Suite (Proxy) | generate the PoC with Burp's built-in generator |
| XXE | Burp Suite (Repeater) | Burp Collaborator for out-of-band data theft |
| Crypto | Burp Suite (Decoder, Repeater) | CyberChef, Python for custom scripts |
| Race conditions | Burp Suite (Repeater, Intruder) | Turbo Intruder extension for parallel requests |
| Directory discovery | ffuf or gobuster | dirsearch, wfuzz |
| Recon / mapping | Burp Suite (Proxy, Target site map) | nikto, browser dev tools |

## The methodology: how to hunt bugs like a pro

Tools find things, methodology finds bugs. Follow this order every time you open a new challenge.

1. **Recon: know the target.** Spider the app and click through it like a normal user first. Let Burp's Target site map fill up so you can see the whole attack surface before you touch anything.
2. **Mapping: list every input, endpoint, and parameter.** For each request, write down where user input goes: URL parameters, form fields, headers, cookies, file uploads. If an input exists, it is a candidate.
3. **Testing: one variable at a time in Repeater.** Send the interesting request to Repeater, change exactly one thing, and watch the response. One variable at a time is how you learn what the server actually does with your input.
4. **Exploiting: prove impact, capture the flag.** Once you understand the bug, build the request that proves it. A bug you cannot demonstrate is a guess, not a finding.
5. **Documenting: write what you did so you can repeat it.** Save the request, the response, and the steps. Future you will thank present you during the report and the exam.

### Order of operations for a new challenge

1. Proxy on, browser routed through Burp.
2. Click through the challenge normally, like a real user.
3. Read the Proxy history and the site map.
4. Pick the interesting request: the one with parameters, logins, uploads, or weird behavior.
5. Send it to Repeater.
6. Mutate: change one input at a time and study the response.
7. Intruder only if you need it: many similar requests, like password guessing or fuzzing.
8. Decoder for weird encodings: base64, URL encoding, hashes, anything that does not read as plain text.

**Golden rule of this lab: understand the bug before you automate it.** Automation is for speed, not for thinking. If you cannot explain in one sentence why your payload works, go back to Repeater until you can.
