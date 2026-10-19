// Shared HTML helpers so every module looks consistent without a view engine.
// Every helper is a pure string function. Legacy signatures
// (esc, page, flagBox, hintBox, brief) are unchanged and keep working.

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// Optional fourth argument: { scoreChip } renders the topbar progress chip.
// Shell routes pass it; module routers ignore it and stay unchanged.
function page(title, body, activeNav, extra) {
  const chip = (extra && extra.scoreChip) || '';
  const nav = [
    ['/', 'Modules', 'home'],
    ['/scoreboard', 'Scoreboard', 'scoreboard'],
    ['/scenarios', 'Scenarios', 'scenarios'],
    ['/paths', 'Paths', 'paths'],
    ['/about', 'About', 'about'],
  ].map(([href, label, key]) =>
    `<a href="${href}"${activeNav === key ? ' aria-current="page"' : ''}>${label}</a>`
  ).join('');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · PenTrix VulnLab</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="icon" type="image/png" sizes="32x32" href="/favicon-32.png">
<link rel="icon" type="image/png" sizes="16x16" href="/favicon-16.png">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700&family=Nunito:wght@700;800;900&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/style.css">
<script src="/app.js" defer></script>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<div class="blobs" aria-hidden="true"><div class="blob blob-1"></div><div class="blob blob-2"></div><div class="blob blob-3"></div></div>
<header class="topbar">
  <a class="brand" href="/"><span class="orb" aria-hidden="true">🧪</span> PenTrix VulnLab</a>
  <nav aria-label="Primary">${nav}${chip}</nav>
</header>
<main class="wrap" id="main">${body}</main>
<footer class="foot">PenTrix VulnLab · intentionally vulnerable · run locally only</footer>
</body>
</html>`;
}

// Difficulty pill: colored dot plus a text label, never color alone.
const DIFF_DOTS = {
  beginner: 'dot-beginner',
  easy: 'dot-easy',
  medium: 'dot-medium',
  intermediate: 'dot-intermediate',
  hard: 'dot-hard',
  mixed: 'dot-mixed',
};
function difficultyPill(diff) {
  const d = String(diff ?? '').trim();
  const cls = DIFF_DOTS[d.toLowerCase()] || 'dot-unknown';
  return `<span class="clay-pill"><span class="dot ${cls}" aria-hidden="true"></span>${esc(d || 'Unknown')}</span>`;
}

// Labeled progress: recessed track plus adjacent text, never the bar alone.
function progressBar(done, total, label) {
  const d = Math.max(0, Number(done) || 0);
  const t = Math.max(0, Number(total) || 0);
  const pct = t ? Math.round((d / t) * 100) : 0;
  return `<div class="progress-meta"><div class="clay-progress" role="progressbar" aria-valuenow="${d}" aria-valuemin="0" aria-valuemax="${t}" aria-label="${esc(label || 'Progress')}"><div class="fill" style="width:${pct}%"></div></div><span>${d}/${t} · ${pct}%</span></div>`;
}

// Empty state card. `html` and `cta` are trusted HTML (same convention as brief/hintBox).
function emptyState(title, html, cta) {
  return `<div class="empty"><div class="orb" aria-hidden="true">∅</div><h2>${esc(title)}</h2><div>${html || ''}</div>${cta || ''}</div>`;
}

// Copy button for payload wells and flag wells. Works with the deferred
// enhancement script; without JS the payload text stays selectable.
function copyButton(label) {
  return `<button type="button" class="copy-btn" data-copy>${esc(label || 'Copy')}</button>`;
}

// Copyable code block: header strip with label plus copy button over a
// recessed mono well. `code` is escaped, never raw.
function payloadBlock(label, code) {
  return `<div class="payload"><div class="payload-head"><span>${esc(label || 'Payload')}</span>${copyButton('Copy')}</div><pre class="payload-body">${esc(code)}</pre></div>`;
}

// Mission briefing panel: violet eyebrow plus scannable content.
// `html` is trusted HTML (same convention as brief/hintBox).
function briefPanel(title, html, eyebrow) {
  return `<div class="brief brief-panel"><p class="eyebrow"><span class="orb" aria-hidden="true">✦</span>${esc(eyebrow || 'Mission brief')}</p><h2>${esc(title)}</h2><div>${html || ''}</div></div>`;
}

// Flag capture banner: announced via role="status", emerald orb plus the
// "Flag captured" heading carry the meaning (icon plus text, never icon
// alone). Next-step links are optional context the caller can pass.
function flagBanner(flag, opts) {
  const o = opts || {};
  const next = o.nextHref
    ? `<a class="clay-btn clay-btn-primary clay-btn-sm" href="${esc(o.nextHref)}">${esc(o.nextLabel || 'Next challenge')}</a>` : '';
  return `<div class="flag-banner" role="status"><div class="flag-top"><span class="flag-orb" aria-hidden="true">✓</span><div><h2>Flag captured</h2><p class="saved">Saved to your scoreboard</p></div></div><div class="flag-well"><code>${esc(flag)}</code>${copyButton('Copy flag')}</div><div class="next-steps">${next}<a class="clay-btn clay-btn-secondary clay-btn-sm" href="/scoreboard">Scoreboard</a><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/">All modules</a></div></div>`;
}

// Legacy signature, now renders the full capture banner so every module's
// capture moment upgrades without touching module routers.
function flagBox(flag) {
  return flagBanner(flag);
}

function hintBox(hint) {
  return `<details class="hint"><summary><span class="dot" aria-hidden="true"></span>Hint (click to reveal)<span class="chev" aria-hidden="true">▾</span></summary><p>${hint}</p></details>`;
}

function brief(title, text) {
  return `<div class="brief"><h2>${esc(title)}</h2><p>${text}</p></div>`;
}

// Styled error content rendered inside page(). `html` is trusted HTML.
function errorPage(status, title, html) {
  return `<div class="error-wrap"><div class="error-card"><div class="error-code" aria-hidden="true">${esc(String(status))}</div><h1>${esc(title)}</h1><div>${html || ''}</div><div class="next-steps"><a class="clay-btn clay-btn-primary" href="/">All modules</a><a class="clay-btn clay-btn-secondary" href="/scoreboard">Scoreboard</a></div></div></div>`;
}

module.exports = {
  esc, page, flagBox, hintBox, brief,
  difficultyPill, progressBar, emptyState, copyButton, payloadBlock,
  briefPanel, flagBanner, errorPage,
  appShell, hintLadder, fixPanel, toolsPill, trackBanner, scoreFor,
  claimBox,
};

// ---------------------------------------------------------------------------
// M7 curriculum helpers (added, existing signatures untouched).
// ---------------------------------------------------------------------------

// Neutral in-app chrome for challenge pages: a slim app header (brand mark +
// app name + inert nav labels) above the lab content, built only from existing
// CSS classes so it renders with the current stylesheet. The challenge reads
// as a small real application instead of a test harness. `bodyHtml` is trusted
// HTML; all form field names, routes, and award logic stay exactly as they were.
function appShell(appName, bodyHtml, opts) {
  const o = opts || {};
  const nav = (o.nav || ['Home', 'Catalog', 'Account']).map((n) =>
    `<span class="dim">${esc(n)}</span>`).join('<span class="dim"> · </span>');
  const crumb = o.crumb ? `<p class="dim">${esc(o.crumb)}</p>` : '';
  return `<div class="card app-shell">
    <div class="card-top"><span class="orb" aria-hidden="true">${esc(o.mark || '◈')}</span>
    <b>${esc(appName)}</b><span class="app-nav">${nav}</span></div>
    ${crumb}
    <div>${bodyHtml || ''}</div>
  </div>`;
}

// Progressive hint ladder. Renders v.hints as three tiered steps (nudge,
// technique, explicit). Falls back to the legacy single hintBox(v.hint).
// Hint text is escaped: ladders are plain text, never raw HTML.
function hintLadder(v) {
  const hints = (v && v.hints) || (v && v.hint ? [v.hint] : []);
  if (!hints.length) return '';
  if (hints.length === 1) return hintBox(esc(hints[0]));
  const labels = ['Nudge', 'Technique', 'Explicit'];
  const steps = hints.map((h, i) => `
    <details class="hint"><summary><span class="dot" aria-hidden="true"></span>Hint ${i + 1}: ${labels[i] || 'Step ' + (i + 1)} (click to reveal)<span class="chev" aria-hidden="true">▾</span></summary><p>${esc(h)}</p></details>`
  ).join('\n');
  return `<div class="hint-ladder" aria-label="Progressive hints">${steps}</div>`;
}

// Difficulty-weighted scoring: Easy=1, Medium=2, Hard=3. Used by the
// scoreboard (see docs/curriculum/LEARNING_PATHS.md for the app.js
// integration point; app.js itself is not touched by M7).
function scoreFor(difficulty) {
  const d = String(difficulty || '').toLowerCase();
  if (d === 'easy') return 1;
  if (d === 'hard') return 3;
  return 2; // Medium and anything unexpected
}

// ---------------------------------------------------------------------------
// Beacon claim UX (M7 Item 1): "How to claim this flag" box + live status widget.
// For beacon-style challenges (xss, csti, jsonp, postmsg), the flag is awarded
// when a beacon arrives with a valid page-bound token. Students who run
// alert(1) or a token-less beacon see nothing happen. This box explains the
// 3-step claim flow and provides a copyable payload pattern; the widget polls
// a claim-status endpoint and shows whether a valid beacon was received.
// ---------------------------------------------------------------------------

// Renders the "How to claim this flag" box. `opts`:
//   vulnId: the vuln id (e.g. 'reflected')
//   payload: the exact payload pattern HTML-escaped already, or plain text
//   statusUrl: the claim-status endpoint URL (e.g. '/xss/claim-status?v=reflected')
//   beaconInfo: optional extra line about the beacon (e.g. token location)
function claimBox(opts) {
  const o = opts || {};
  const vulnId = esc(o.vulnId || '');
  const payload = o.payload || '';
  const statusUrl = esc(o.statusUrl || '');
  const beaconInfo = o.beaconInfo ? `<p class="dim">${o.beaconInfo}</p>` : '';
  const widgetId = 'claim-status-' + String(o.vulnId || 'x').replace(/[^a-z0-9-]/gi, '');
  return `<div class="card claim-box">
    <div class="card-top"><b>How to claim this flag</b></div>
    <ol>
      <li>Load this page fresh. A new one-time token is rendered into it as
      <code>window.__px</code> on every load.</li>
      <li>Run a payload that phones home to the collector <b>with</b> the page
      token (<code>n='+window.__px</code>). A token-less beacon is rejected.</li>
      <li>The flag is awarded and the scoreboard marks it captured. The widget
      below polls for confirmation.</li>
    </ol>
    <p><b>Payload pattern for <code>${vulnId}</code>:</b></p>
    <div class="payload"><div class="payload-head"><span>Payload pattern</span>${copyButton('Copy payload')}</div><pre class="payload-body">${payload}</pre></div>
    ${beaconInfo}
    <p id="${widgetId}" class="status status-missing" role="status" data-status-url="${statusUrl}"><span class="dot" aria-hidden="true"></span><span class="claim-text">Checking claim status...</span></p>
    <details class="hint"><summary><span class="dot" aria-hidden="true"></span>Not getting the flag? Why beacons fail<span class="chev" aria-hidden="true">▾</span></summary>
      <div>
      <ul>
        <li><b>Token-less beacons are rejected (400).</b> The collector requires
        <code>n=window.__px</code>. A plain <code>alert(1)</code> proves the XSS to
        you, but the server cannot see your screen. The beacon with the page token
        is how you prove it to the server, and only then is the flag awarded.</li>
        <li><b>Tokens are single-use per page load.</b> Each page load renders a fresh
        <code>window.__px</code>. A token from an earlier load cannot be replayed.</li>
        <li><b>The beacon must carry data.</b> An empty <code>c=</code> parameter is
        rejected. Exfiltrate something (e.g. <code>document.cookie</code>).</li>
      </ul>
      </div>
    </details>
  </div>`;
}

// Per-vuln tool tags, rendered as small pills. v.tools is a comma-separated
// code list (B=browser, DT=devtools, C=curl, P=python, BZ=Burp/ZAP, N=node/jwt,
// W=wordlist/hashcat), e.g. "B, C".
const TOOL_NAMES = {
  B: 'Browser', DT: 'DevTools', C: 'curl', P: 'Python',
  'BZ': 'Burp/ZAP', N: 'Node/JWT', W: 'Wordlist',
};
function toolsPill(v) {
  const codes = String((v && v.tools) || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!codes.length) return '';
  const pills = codes.map((c) =>
    `<span class="clay-pill" title="${esc(TOOL_NAMES[c] || c)}">${esc(TOOL_NAMES[c] || c)}</span>`).join(' ');
  return `<p class="tools dim" aria-label="Tools needed"><b>Tools:</b> ${pills}</p>`;
}

// Learning-track banner for module index pages. Reads the TRACKS table below.
function trackBanner(mod) {
  const t = TRACKS[mod.id];
  if (!t) return '';
  const prereqs = (t.prerequisites && t.prerequisites.length)
    ? `<p><b>Prerequisites:</b> ${t.prerequisites.map((p) => esc(p)).join(', ')}</p>` : '';
  const tools = (t.tools && t.tools.length)
    ? `<p><b>Bring:</b> ${t.tools.map((x) => esc(x)).join(', ')}</p>` : '';
  return `<div class="brief brief-panel"><p class="eyebrow"><span class="orb" aria-hidden="true">✦</span>Learning track</p>
    <h2>${esc(t.track)}</h2>
    <p>${esc(t.blurb)}</p>
    ${prereqs}${tools}</div>`;
}

// Remediation panel: 2-4 sentences on the fix plus the OWASP Cheat Sheet link.
// Shown post-capture, after flagBox. Content lives in FIXES below; nothing is
// copied from the cheat sheets themselves.
function fixPanel(modId, vulnId) {
  const f = FIXES[modId + ':' + vulnId];
  if (!f) return '';
  return `<div class="brief fix-panel"><p class="eyebrow"><span class="orb" aria-hidden="true">✓</span>The fix</p>
    <p>${esc(f.text)}</p>
    <p><a href="${esc(f.url)}" target="_blank" rel="noopener">OWASP Cheat Sheet: ${esc(f.sheet)}</a></p></div>`;
}

// Learning tracks per module: honest difficulty replacement for "Mixed".
// Blurbs are one line; prerequisites name modules; tools name what to bring.
const TRACKS = {
  misconfig: { track: 'Foundations', blurb: 'Start here: the web leaks secrets in boring places. Learn to look.', prerequisites: [], tools: ['browser', 'curl'] },
  idor: { track: 'Foundations', blurb: 'The most common access-control bug: changing an id to see someone else\'s data.', prerequisites: ['misconfig'], tools: ['browser', 'curl'] },
  xss: { track: 'Foundations', blurb: 'Scripts in pages: how untrusted input becomes code in the victim\'s browser.', prerequisites: ['misconfig'], tools: ['browser', 'browser devtools'] },
  csrf: { track: 'Foundations', blurb: 'Forged requests: how an attacker\'s page acts as you.', prerequisites: ['xss'], tools: ['browser', 'curl'] },
  sqli: { track: 'Injection', blurb: 'The classic injection: break out of SQL strings and read the database.', prerequisites: ['Foundations track'], tools: ['browser', 'curl'] },
  cmdi: { track: 'Injection', blurb: 'Shell injection: turn input into commands.', prerequisites: ['sqli'], tools: ['browser', 'curl'] },
  ssti: { track: 'Injection', blurb: 'Template injection: when {{ }} runs on the server.', prerequisites: ['sqli', 'xss'], tools: ['browser', 'curl'] },
  xxe: { track: 'Injection', blurb: 'XML entities: make the parser read files for you.', prerequisites: ['sqli'], tools: ['browser', 'curl'] },
  lfi: { track: 'Injection', blurb: 'Path traversal: escape the intended directory.', prerequisites: ['sqli'], tools: ['browser', 'curl'] },
  upload: { track: 'Injection', blurb: 'Malicious files: beat the filters and get served.', prerequisites: ['xss'], tools: ['browser', 'curl'] },
  auth: { track: 'Auth and Sessions', blurb: 'Broken logins, resets, and OTPs.', prerequisites: ['Foundations track'], tools: ['browser', 'curl', 'python'] },
  session: { track: 'Auth and Sessions', blurb: 'Session flaws: fixation, prediction, and leaks.', prerequisites: ['auth'], tools: ['browser', 'browser devtools'] },
  jwt: { track: 'Auth and Sessions', blurb: 'Token attacks: none, weak secrets, and key confusion.', prerequisites: ['auth', 'crypto basics'], tools: ['node/jwt tooling', 'curl'] },
  oauth: { track: 'Auth and Sessions', blurb: 'OAuth flaws in a working in-lab identity provider.', prerequisites: ['auth', 'jwt'], tools: ['browser', 'curl'] },
  ssrf: { track: 'Advanced', blurb: 'Make the server fetch for you: bypasses and cloud metadata.', prerequisites: ['Injection track'], tools: ['curl', 'Burp/ZAP'] },
  crypto: { track: 'Advanced', blurb: 'Real cryptanalysis: ECB, CBC, length extension, and XOR.', prerequisites: ['Injection track'], tools: ['python', 'node'] },
  race: { track: 'Advanced', blurb: 'Race conditions: parallel requests beat check-then-act.', prerequisites: ['Auth and Sessions track'], tools: ['python', 'curl'] },
  proto: { track: 'Advanced', blurb: 'Prototype pollution: poison JavaScript objects.', prerequisites: ['xss', 'sqli'], tools: ['browser', 'curl'] },
  bizlogic: { track: 'Advanced', blurb: 'No CVE, just broken rules: prices, coupons, and workflows.', prerequisites: ['Foundations track'], tools: ['browser', 'Burp/ZAP'] },
  api: { track: 'Advanced', blurb: 'JSON APIs trust the client too much: extra fields, leaky responses, spoofable limits, and forgotten checks.', prerequisites: ['Auth and Sessions track', 'Injection track'], tools: ['curl', 'python'] },
  redirect: { track: 'Foundations', blurb: 'Open redirects: where the browser goes next.', prerequisites: ['misconfig'], tools: ['browser', 'curl'] },
  hostheader: { track: 'Auth and Sessions', blurb: 'Host header attacks: poison links and caches.', prerequisites: ['auth'], tools: ['curl'] },
  http: { track: 'Foundations', blurb: 'The protocol itself: logs, verbs, and caches.', prerequisites: ['misconfig'], tools: ['curl', 'browser'] },
  cors: { track: 'Auth and Sessions', blurb: 'Cross-origin policies: steal data across origins.', prerequisites: ['xss'], tools: ['browser', 'curl'] },
  postmsg: { track: 'Advanced', blurb: 'postMessage flaws: attacker and victim pages.', prerequisites: ['xss', 'cors'], tools: ['browser', 'browser devtools'] },
  csti: { track: 'Injection', blurb: 'Client-side templates: when {{ }} runs in the browser.', prerequisites: ['xss', 'ssti'], tools: ['browser'] },
  jsonp: { track: 'Advanced', blurb: 'JSONP: cross-origin data theft the old way.', prerequisites: ['xss', 'cors'], tools: ['browser', 'browser devtools'] },
  formula: { track: 'Foundations', blurb: 'CSV formulas: when spreadsheets run your input.', prerequisites: ['xss'], tools: ['browser'] },
  redos: { track: 'Advanced', blurb: 'Regex denial of service: catastrophic backtracking.', prerequisites: ['Injection track'], tools: ['browser', 'curl', 'python'] },
};

// Remediation teaching per vuln: the fix in 2-4 sentences plus the OWASP
// Cheat Sheet link. Keyed by "module:vuln". No cheat-sheet content is copied.
const FIXES = {
  "api:api-version-bypass": { text: "Apply authorization checks in shared middleware so every API version inherits them. When you copy an endpoint, copy its checks too; better, do not duplicate the code.", sheet: "REST Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html" },
  "api:exposure": { text: "Return only the fields the client needs (DTOs/projections), never full database rows. Audit every endpoint's response shape for secrets.", sheet: "REST Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html" },
  "api:mass-assignment": { text: "Use an explicit allowlist of settable fields when binding request data to models. Never copy every client-supplied key into a privileged object.", sheet: "REST Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html" },
  "api:rate-limit": { text: "Enforce server-side rate limits on authentication endpoints, with lockout or exponential backoff. Track by account and by IP, and make the limits actually block.", sheet: "REST Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html" },
  "api:ratelimit-xff": { text: "Derive rate-limit identity from the real connection IP (or authenticated user), never from X-Forwarded-For, which the client controls. Behind a proxy, use the proxy's verified header.", sheet: "REST Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html" },
  "auth:brute-force": { text: "Rate-limit login attempts and lock or slow down accounts after failures. Require strong passwords and consider multi-factor authentication so a guessed password alone is not enough.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "auth:change-pass-noverify": { text: "Require the current password (re-authentication) before a password change. A session cookie alone should not be enough to take over the credential.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "auth:otp-bruteforce": { text: "Rate-limit OTP attempts, expire codes after a few minutes, and invalidate a code after too many wrong guesses. A 4-digit code is only safe with strict throttling.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "auth:reset": { text: "Password-reset tokens must be random, single-use, and expire quickly. Never derive them from the username or any predictable value.", sheet: "Forgot Password", url: "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html" },
  "auth:reset-predictable": { text: "Generate reset tokens with a cryptographic random generator (e.g. 32 random bytes), store only a hash, and expire them. Deterministic tokens built from public data are forgeable.", sheet: "Forgot Password", url: "https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html" },
  "auth:security-question": { text: "Do not use security questions with publicly knowable answers. Prefer email-based reset links with random tokens, plus multi-factor authentication.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "auth:support-impersonate": { text: "Check authorization on every object access: a ticket, order, or profile must belong to the requester. Use indirect, random identifiers and verify ownership server-side.", sheet: "Authorization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" },
  "auth:user-enum": { text: "Return the same generic message for bad usernames and bad passwords ('Invalid username or password'). Do not let the error text reveal which accounts exist.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "bizlogic:biz-coupon-stack": { text: "Cap total discounts server-side and define how coupons combine (or forbid stacking). Compute the total yourself; do not sum client-supplied discounts blindly.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "bizlogic:biz-currency": { text: "Convert currencies server-side with a trusted rate table, and validate the currency against an allowlist. Do the money math yourself, in the smallest unit.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "bizlogic:biz-email-noreauth": { text: "Require re-authentication (current password or MFA) before changing the account email. The email is the recovery identity; changing it must be hard.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "bizlogic:biz-negative-qty": { text: "Validate business invariants server-side: quantities must be positive integers within sane bounds. Never trust arithmetic the client performed.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "bizlogic:biz-otp-client": { text: "Verify the OTP server-side on every attempt. Never trust a client-side flag like otp_ok; the client is the attacker.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "bizlogic:biz-price-tamper": { text: "Look up prices server-side from your own catalog; never accept a price from the client. The hidden field is attacker-controlled.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "bizlogic:biz-refund": { text: "Clamp refunds server-side to the order total (and to what was actually paid). Never take the amount from a client-supplied field.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "bizlogic:biz-workflow-skip": { text: "Enforce workflow order server-side with a state machine: the confirm step must verify that payment actually completed. Each step checks the previous one's outcome.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "cmdi:basic": { text: "Never pass user input to a shell. Use execFile/spawn with an argument array (no shell) so input cannot become commands. If you must use a shell, validate the input against a strict allowlist and reject everything else; blocklists of metacharacters are always bypassed.", sheet: "OS Command Injection Defense", url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" },
  "cmdi:bypass": { text: "Never pass user input to a shell. Use execFile/spawn with an argument array (no shell) so input cannot become commands. If you must use a shell, validate the input against a strict allowlist and reject everything else; blocklists of metacharacters are always bypassed.", sheet: "OS Command Injection Defense", url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" },
  "cmdi:cmdi-backtick": { text: "Never pass user input to a shell. Use execFile/spawn with an argument array (no shell) so input cannot become commands. If you must use a shell, validate the input against a strict allowlist and reject everything else; blocklists of metacharacters are always bypassed.", sheet: "OS Command Injection Defense", url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" },
  "cmdi:cmdi-braces": { text: "Never pass user input to a shell. Use execFile/spawn with an argument array (no shell) so input cannot become commands. If you must use a shell, validate the input against a strict allowlist and reject everything else; blocklists of metacharacters are always bypassed.", sheet: "OS Command Injection Defense", url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" },
  "cmdi:cmdi-ifs": { text: "Never pass user input to a shell. Use execFile/spawn with an argument array (no shell) so input cannot become commands. If you must use a shell, validate the input against a strict allowlist and reject everything else; blocklists of metacharacters are always bypassed.", sheet: "OS Command Injection Defense", url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" },
  "cmdi:cmdi-newline": { text: "Never pass user input to a shell. Use execFile/spawn with an argument array (no shell) so input cannot become commands. If you must use a shell, validate the input against a strict allowlist and reject everything else; blocklists of metacharacters are always bypassed.", sheet: "OS Command Injection Defense", url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" },
  "cmdi:cmdi-pipe": { text: "Never pass user input to a shell. Use execFile/spawn with an argument array (no shell) so input cannot become commands. If you must use a shell, validate the input against a strict allowlist and reject everything else; blocklists of metacharacters are always bypassed.", sheet: "OS Command Injection Defense", url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" },
  "cmdi:cmdi-tab": { text: "Never pass user input to a shell. Use execFile/spawn with an argument array (no shell) so input cannot become commands. If you must use a shell, validate the input against a strict allowlist and reject everything else; blocklists of metacharacters are always bypassed.", sheet: "OS Command Injection Defense", url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" },
  "cmdi:cmdi-wildcard": { text: "Never pass user input to a shell. Use execFile/spawn with an argument array (no shell) so input cannot become commands. If you must use a shell, validate the input against a strict allowlist and reject everything else; blocklists of metacharacters are always bypassed.", sheet: "OS Command Injection Defense", url: "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html" },
  "cors:cors-expose-headers": { text: "Expose only the headers cross-origin scripts genuinely need. A sensitive token in Access-Control-Expose-Headers is readable by any site.", sheet: "HTML5 Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html" },
  "cors:cors-null": { text: "Do not trust Origin: null with credentials. Null is sent by sandboxed iframes and redirects; it is not an identity.", sheet: "HTML5 Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html" },
  "cors:cors-reflect": { text: "Never reflect arbitrary origins with credentials. Maintain an explicit allowlist of trusted origins and echo only those, with Vary: Origin.", sheet: "HTML5 Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html" },
  "cors:cors-regex": { text: "Match origins exactly against an allowlist instead of with a loose regex. Anchor both ends, escape dots, and compare the parsed origin, not a substring.", sheet: "HTML5 Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html" },
  "cors:cors-subdomain": { text: "Validate subdomains against an explicit allowlist, not a suffix match. Suffix checks trust attacker subdomains of the trusted root.", sheet: "HTML5 Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html" },
  "cors:cors-wildcard-data": { text: "Do not use Access-Control-Allow-Origin: * on responses carrying sensitive data. Credentials require an explicit origin, never a wildcard.", sheet: "HTML5 Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html" },
  "crypto:crypto-b64-cookie": { text: "Base64 is encoding, not encryption. Protect cookie data with authenticated encryption (AES-GCM) and a server-side key, or keep the data server-side and store only a random session id.", sheet: "Cryptographic Storage", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html" },
  "crypto:crypto-cbc-bitflip": { text: "Use authenticated encryption (AES-GCM) so tampered ciphertexts are rejected. Unauthenticated CBC is malleable: attackers flip bits to change the plaintext.", sheet: "Cryptographic Storage", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html" },
  "crypto:crypto-ecb-oracle": { text: "Never use ECB mode: it leaks block equality. Use an authenticated mode like AES-GCM with a random IV, and do not build oracles that encrypt attacker-chosen plaintext.", sheet: "Cryptographic Storage", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html" },
  "crypto:crypto-hash-ext": { text: "Do not build MACs as hash(secret || message). Use HMAC with a proper key, which is not vulnerable to length extension.", sheet: "Cryptographic Storage", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html" },
  "crypto:crypto-key-in-js": { text: "Never ship encryption keys to the client. Keep keys server-side (in a vault/HSM); the browser should only ever see ciphertext or no secret at all.", sheet: "Cryptographic Storage", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html" },
  "crypto:crypto-md5-crack": { text: "Store passwords with a slow, salted hash (bcrypt, scrypt, or Argon2), never fast unsalted MD5/SHA. Each password gets its own random salt.", sheet: "Password Storage", url: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html" },
  "crypto:crypto-rand-pin": { text: "Use a cryptographic random generator (crypto.randomInt) for PINs and tokens. Math.random is predictable and must never be used for security values.", sheet: "Cryptographic Storage", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html" },
  "crypto:crypto-xor-crib": { text: "Never use repeating-key XOR (or any stream cipher) with a reused key. Use AES-GCM with a unique nonce per message.", sheet: "Cryptographic Storage", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html" },
  "csrf:clickjacking": { text: "Send X-Frame-Options: DENY (or SAMEORIGIN) or a frame-ancestors Content-Security-Policy so the page cannot be framed. Sensitive actions should also require re-authentication.", sheet: "Cross-Site Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "csrf:email": { text: "Protect state-changing requests with anti-CSRF tokens (unpredictable, tied to the session) and validate them server-side. Prefer SameSite=Lax/Strict cookies and require POST for state changes.", sheet: "Cross-Site Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "csrf:json-csrf": { text: "Do not accept text/plain or form-encoded bodies on JSON APIs: require Content-Type: application/json and validate a CSRF token or use SameSite cookies. Content-type confusion is a CSRF vector.", sheet: "Cross-Site Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "csrf:method-override-csrf": { text: "Do not honor method-override parameters (_method) on state-changing routes, or require the override to carry a valid CSRF token. The 'protected' method must actually be protected.", sheet: "Cross-Site Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "csrf:referer-bypass": { text: "Do not use the Referer header for authorization; it is attacker-controlled. Use anti-CSRF tokens tied to the session instead.", sheet: "Cross-Site Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "csti:attr": { text: "Encode template output for its context, and do not evaluate attribute values as templates. Data in attributes is still untrusted input.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "csti:basic": { text: "Do not evaluate user input as a template. If you use client-side templates, keep the template source developer-controlled and bind user data as values, never as template code.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "csti:constructor": { text: "Avoid template engines that expose powerful objects (like constructor) to template code. Use a sandboxed, logic-less engine if templates must be dynamic.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "csti:filter-bypass": { text: "Blocklists of delimiters do not fix template injection. The fix is architectural: user input must never become template source, regardless of delimiters.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "csti:stored": { text: "Encode stored values on output and never evaluate stored user content as a template. Stored template injection persists for every viewer.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "formula:formula-csv": { text: "Neutralize formulas in exports: prefix every cell starting with =, +, -, or @ with a single quote or a space. Do this at export time, for every field.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "formula:formula-dde": { text: "Same fix: neutralize formula prefixes on export. DDE payloads are just another formula spelling.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "formula:formula-hyperlink": { text: "Neutralize on export and warn users about external links. HYPERLINK exfiltration dies when the cell is not evaluated as a formula.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "formula:formula-pipe": { text: "Cover all spreadsheet apps: neutralize =, +, -, @, and | prefixes. Different apps trigger on different characters.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "hostheader:host-abs-url": { text: "Generate post-login destinations from a server-side allowlist or relative paths. Never put the request Host into a redirect Location.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "hostheader:host-cache-poison": { text: "Include the Host in the cache key, or better, do not reflect the Host into cached responses. Cache poisoning works when the cache key ignores the poisoned input.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "hostheader:host-reset-poison": { text: "Build absolute links from a configured base URL, never from the Host header. If you must use Host, validate it against an allowlist of your own domains.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "hostheader:host-ssrf": { text: "Do not build internal request URLs from the Host header. Use configured service addresses for health checks and internal calls.", sheet: "Server Side Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "hostheader:host-xforwarded": { text: "Do not trust X-Forwarded-Host (or vendor variants) unless it comes from your own verified proxy, and even then validate it against an allowlist. The client can send any value.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "http:cache-deception": { text: "Include everything that personalizes the response (user, role) in the cache key, or mark personalized responses private/no-store. A path-only cache key serves one user's data to another.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "http:crlf-log": { text: "Strip or encode CR and LF bytes before writing user input to logs, and HTML-encode log output in viewers. Log forging and log-viewer XSS both die when the bytes are neutralized.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "http:verb-tamper": { text: "Enforce the intended HTTP method on state-changing routes and reject the rest. A POST-only action must not run on GET.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "idor:admin": { text: "Enforce role checks on every admin route, not just the login page. Hide the link AND block the URL: authorization must be server-side.", sheet: "Authorization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" },
  "idor:function-browse": { text: "Apply authorization checks to every endpoint, including unlinked ones. Forced browsing works when a route assumes obscurity is protection.", sheet: "Authorization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" },
  "idor:idor-apikey-regen": { text: "Regeneration must act on the session's own account, and regenerating a key should require re-authentication. Log and alert on key changes.", sheet: "Authorization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" },
  "idor:idor-comment-delete": { text: "Verify the requester authored the comment (or is a moderator) before deleting. The id alone is not authorization.", sheet: "Authorization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" },
  "idor:idor-download": { text: "Check that the invoice belongs to the logged-in user before serving the file. Use random, unguessable download tokens if links must be shareable.", sheet: "Insecure Direct Object Reference Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html" },
  "idor:idor-email-change": { text: "Derive the target account from the session, never from a client-supplied user_id. Treat every request parameter as attacker-controlled.", sheet: "Authorization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" },
  "idor:profile": { text: "Verify ownership on every request: the requested user id must match the session's user (or the session must have an admin role). Never trust an id parameter alone.", sheet: "Insecure Direct Object Reference Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html" },
  "jsonp:array-hijack": { text: "Do not return sensitive data as a bare JavaScript array to cross-origin callers. Require authentication plus a CSRF token, or serve JSON with proper CORS instead of JSONP.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "jsonp:callback-xss": { text: "Validate the callback parameter against a strict allowlist (e.g. /^[a-zA-Z_$][a-zA-Z0-9_$]*$/). Better: stop using JSONP; use CORS with an explicit origin allowlist instead.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "jsonp:csrf-data": { text: "JSONP endpoints that return sensitive data need CSRF protection too: require a token or check the Origin/Referer. A <script> tag bypasses the same-origin policy by design.", sheet: "Cross-Site Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "jsonp:filter-bypass": { text: "Keyword blocklists do not sanitize callbacks. Use a strict character allowlist for the callback name, or drop JSONP entirely.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "jsonp:mimetype": { text: "Serve JSONP with Content-Type: application/javascript and X-Content-Type-Options: nosniff, and validate the callback. Serving it as text/html lets it parse as a document.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "jwt:alg-confusion": { text: "Keep RSA and HMAC keys strictly separate and enforce the expected algorithm per key. An RS256 public key must never be usable as an HS256 secret.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "jwt:aud-bypass": { text: "Validate the aud claim against the expected audience for this service. A token minted for one service must not work at another.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "jwt:jku": { text: "Do not trust the jku header: pin the JWKS URL server-side or distribute keys out of band. If you must support jku, allowlist the permitted domains and validate TLS.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "jwt:kid-default": { text: "Require an explicit kid and fail closed when it is missing or unknown. There should be no guessable fallback key.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "jwt:kid-sqli": { text: "Never interpolate the kid header into SQL; use parameterized lookups. Better: do not let clients choose keys at all; select the key server-side.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "jwt:no-expiry": { text: "Always validate exp (and iat/nbf) with a clock-skew leeway. Reject expired tokens; short lifetimes plus refresh tokens limit the damage of a leak.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "jwt:none-admin": { text: "Reject alg:none outright and allowlist the exact algorithms you support (e.g. only RS256). Never let the token's own header choose the verification method.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "jwt:weak-secret": { text: "Use a long cryptographically random HMAC secret (32+ bytes) stored in a vault, never a dictionary word. Rotate it and prefer RS256 with a private key over shared secrets.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "lfi:absolute": { text: "Map user input to an allowlist of permitted files instead of building paths from it. If you must build paths, resolve the canonical path and verify it stays inside the intended directory, and reject null bytes and absolute paths.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "lfi:config-read": { text: "Map user input to an allowlist of permitted files instead of building paths from it. If you must build paths, resolve the canonical path and verify it stays inside the intended directory, and reject null bytes and absolute paths.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "lfi:double-encode": { text: "Map user input to an allowlist of permitted files instead of building paths from it. If you must build paths, resolve the canonical path and verify it stays inside the intended directory, and reject null bytes and absolute paths.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "lfi:filter-bypass": { text: "Map user input to an allowlist of permitted files instead of building paths from it. If you must build paths, resolve the canonical path and verify it stays inside the intended directory, and reject null bytes and absolute paths.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "lfi:lang": { text: "Map user input to an allowlist of permitted files instead of building paths from it. If you must build paths, resolve the canonical path and verify it stays inside the intended directory, and reject null bytes and absolute paths.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "lfi:log-poison": { text: "Map user input to an allowlist of permitted files instead of building paths from it. If you must build paths, resolve the canonical path and verify it stays inside the intended directory, and reject null bytes and absolute paths.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "lfi:nested-deep": { text: "Map user input to an allowlist of permitted files instead of building paths from it. If you must build paths, resolve the canonical path and verify it stays inside the intended directory, and reject null bytes and absolute paths.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "lfi:proc-self": { text: "Map user input to an allowlist of permitted files instead of building paths from it. If you must build paths, resolve the canonical path and verify it stays inside the intended directory, and reject null bytes and absolute paths.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "lfi:traversal": { text: "Map user input to an allowlist of permitted files instead of building paths from it. If you must build paths, resolve the canonical path and verify it stays inside the intended directory, and reject null bytes and absolute paths.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "misconfig:backup": { text: "Keep backups, dumps, and archives outside the web root. If they must be reachable, protect them with authentication and do not use guessable names.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "misconfig:debug": { text: "Never show stack traces or config dumps to users. Log errors server-side with an ID, show users a generic message, and keep debug modes behind authentication and off in production.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "misconfig:env": { text: "Never serve .env files: keep them outside the web root and block dotfiles at the server. Secrets belong in a vault or environment, not in deployed files.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "misconfig:git": { text: "Never deploy the .git directory to production. Build artifacts from a clean export, and block hidden files/directories at the web server level.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "misconfig:listing": { text: "Disable directory listings on the web server. Every file in the web root should be there deliberately; audit the document root regularly.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "misconfig:manager": { text: "Change all vendor default credentials before deployment, and audit for them regularly. Default passwords are the first thing attackers try.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "misconfig:put": { text: "Disable unused HTTP methods (especially PUT/DELETE) or require authentication for them. An open PUT that writes into the web root is a file-upload vulnerability.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "misconfig:robots": { text: "Do not list sensitive paths in robots.txt; it is a public document. Protect the paths with authentication instead of advertising them.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "misconfig:swp": { text: "Keep editor temp files out of the web root (configure your editor or add them to .gitignore and deploy filters). A .swp file is source code with secrets.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "misconfig:trace": { text: "Disable the TRACE method on production web servers. It has no legitimate use for most apps and enables cross-site tracing attacks.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "oauth:code-leak": { text: "Never log authorization codes or tokens. Treat codes as secrets: single-use, short-lived, and bound to the client that requested them.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "oauth:code-replay": { text: "Make authorization codes single-use: invalidate the code when it is exchanged. Replayed codes must be rejected.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "oauth:implicit": { text: "Avoid the implicit flow; use the authorization code flow with PKCE. Tokens in URL fragments leak via history, logs, and referers.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "oauth:no-state": { text: "Always send and validate the state parameter (a random, session-bound value) to prevent login CSRF. The callback must verify it before exchanging the code.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "oauth:pkce-skip": { text: "Enforce PKCE: require the code_verifier and check it against the code_challenge on every exchange. A challenge that is never verified is theater.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "oauth:redirect-bypass": { text: "Validate redirect_uri with exact matching against the client's pre-registered URLs. Prefix or substring checks are bypassed with attacker domains that start the same way.", sheet: "Authorization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" },
  "oauth:scope-upgrade": { text: "Grant only the scopes the client is entitled to, and validate the requested scope against the user's actual permissions. Never echo back unrequested scopes.", sheet: "Authorization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" },
  "oauth:secret-in-js": { text: "Keep the client secret server-side; public clients (SPAs) must not have one. Use PKCE for public clients instead of a shared secret.", sheet: "Authentication", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
  "postmsg:csrf-action": { text: "Treat cross-window messages like requests: require an anti-CSRF token for privileged actions triggered by messages, and verify the sender's origin.", sheet: "Cross-Site Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "postmsg:data-xss": { text: "Treat event.data as untrusted input: validate its shape and never render it as HTML without sanitization. An origin check alone does not make the data safe.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "postmsg:no-check": { text: "Always verify event.origin against an exact allowlist before acting on a message. A handler with no origin check obeys any website.", sheet: "HTML5 Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html" },
  "postmsg:substring": { text: "Compare event.origin with exact string equality against the allowlist, not substring or suffix matches. Attacker domains contain the trusted string.", sheet: "HTML5 Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html" },
  "postmsg:wildcard": { text: "Never broadcast secrets with targetOrigin '*'. Specify the exact recipient origin so only that site receives the message.", sheet: "HTML5 Security", url: "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html" },
  "proto:proto-client": { text: "Apply the same key filtering client-side, and freeze shared objects where possible. Client-side pollution affects every script on the page.", sheet: "Deserialization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html" },
  "proto:proto-constructor": { text: "Blocking __proto__ alone is not enough; constructor.prototype reaches the same object. Block the full key path or avoid recursive merge of untrusted data.", sheet: "Deserialization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html" },
  "proto:proto-dos": { text: "Same fix as other pollution: do not merge untrusted keys into shared objects. Prototype pollution is a DoS vector when it breaks built-in methods.", sheet: "Deserialization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html" },
  "proto:proto-json": { text: "Validate JSON keys before merging: reject __proto__ and constructor paths. Safer: use schema validation and only copy known fields.", sheet: "Deserialization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html" },
  "proto:proto-query": { text: "Do not deep-merge untrusted input into objects. If you must merge, block __proto__, constructor, and prototype keys, or use a Map / Object.create(null).", sheet: "Deserialization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html" },
  "proto:proto-unicode-bypass": { text: "Filter on the decoded key, not the raw text: normalize (decode escapes) before checking. Better to allowlist known keys than to blacklist spellings.", sheet: "Deserialization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html" },
  "race:race-balance": { text: "Perform balance checks and debits in a single atomic transaction with row locking. Never check, await, then act on a stale read.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "race:race-coupon": { text: "Make the check-and-redeem atomic: use a database transaction with a uniqueness constraint or compare-and-swap so two concurrent requests cannot both succeed.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "race:race-ratelimit": { text: "Implement rate limits with atomic increments (e.g. Redis INCR with expiry), not read-then-write counters. The increment and the check must be one operation.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "race:race-referral": { text: "Same fix: atomic claim with a unique constraint on (user, promotion). Application-level 'already claimed' checks race.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "race:race-register": { text: "Put a UNIQUE constraint on the username column and handle the conflict. The database is the source of truth for uniqueness.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "race:race-stock": { text: "Decrement stock atomically (UPDATE ... WHERE stock > 0) and check the affected row count. Do not read stock, then write it back.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "race:race-upload-scan": { text: "Do not serve the file until the scan passes: hold uploads in quarantine and move them into place only after a clean verdict (atomic rename).", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "race:race-vote": { text: "Enforce uniqueness in the database (unique constraint), not just in application code. The constraint is the atomic gate.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "redirect:redirect-backslash": { text: "Parse the URL with a proper URL parser and compare the hostname, instead of string-matching the raw input. Backslashes, encodings, and userinfo all defeat naive prefix checks.", sheet: "Unvalidated Redirects and Forwards", url: "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html" },
  "redirect:redirect-data": { text: "Same fix: scheme allowlist. data: URLs in a redirect Location render attacker HTML in your origin's context.", sheet: "Unvalidated Redirects and Forwards", url: "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html" },
  "redirect:redirect-double-slash": { text: "Validate the redirect target against an allowlist of permitted destinations, or reject anything that is not a relative path on your own site. Parse the URL; do not do string prefix checks.", sheet: "Unvalidated Redirects and Forwards", url: "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html" },
  "redirect:redirect-javascript": { text: "Allowlist the permitted schemes (https only) as well as the host. A redirector that accepts javascript: or data: URLs is an XSS primitive.", sheet: "Unvalidated Redirects and Forwards", url: "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html" },
  "redirect:redirect-pollution": { text: "Decide which duplicate parameter wins and validate THAT value, or reject duplicate parameters outright. The validated value and the used value must be the same one.", sheet: "Unvalidated Redirects and Forwards", url: "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html" },
  "redos:redos-email": { text: "Rewrite the regex to avoid nested quantifiers, or use a well-tested validator instead of a hand-rolled pattern. Set a regex timeout as defense in depth.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "redos:redos-search": { text: "Never compile user input directly into a regex. Escape it (or reject regex metacharacters), and run matching with a timeout.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "redos:redos-url": { text: "Break the pattern into anchored, non-overlapping parts instead of nested groups. Test candidate regexes against evil inputs before deploying.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "redos:redos-username": { text: "Do not use patterns like (a+)+ with overlapping quantifiers. Simplify to a+ or use a possessive/atomic group if your engine supports it.", sheet: "Input Validation", url: "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html" },
  "session:fixation": { text: "Regenerate the session id on every privilege change (especially login). Never accept a session id the client chose before authentication.", sheet: "Session Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" },
  "session:log-leak": { text: "Never log session ids, tokens, or secrets. If you must log session events, log a truncated hash, and protect log files as sensitive data.", sheet: "Session Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" },
  "session:logout": { text: "Invalidate the session server-side on logout (delete it from the store), not just flip a client-side flag. Old cookies must stop working.", sheet: "Session Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" },
  "session:never-expires": { text: "Give sessions absolute and idle timeouts. A ten-year session is a ten-year window for a stolen cookie to work.", sheet: "Session Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" },
  "session:predictable": { text: "Generate session ids with a cryptographic random generator (128+ bits). Sequential or predictable ids let attackers guess active sessions.", sheet: "Session Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" },
  "session:url": { text: "Never put session ids in URLs. Keep them in HttpOnly, Secure, SameSite cookies so they do not leak via logs, history, or referers.", sheet: "Session Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" },
  "sqli:blind": { text: "Parameterized queries close the boolean oracle entirely. Also avoid leaking true/false signals: return generic errors and keep response timing uniform.", sheet: "SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
  "sqli:error": { text: "Use parameterized queries so malformed input cannot break the SQL syntax. Never show raw database errors to users; log them server-side and show a generic message.", sheet: "SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
  "sqli:groupby-having": { text: "Never put user input into GROUP BY expressions. Use an allowlist of permitted groupings, and parameterize everything else.", sheet: "SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
  "sqli:insert-inject": { text: "Use parameterized INSERT statements so values cannot break out of the VALUES list. Validate each field's type and length as well.", sheet: "SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
  "sqli:like-wildcard": { text: "Escape LIKE wildcards (%, _) in user input, or avoid LIKE on untrusted input entirely. And parameterize the query: wildcards are only half the problem, string interpolation is the other half.", sheet: "SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
  "sqli:limit-offset": { text: "Validate numeric parameters as numbers (parseInt and range-check) before they reach SQL. Better yet, use parameterized queries so the value can never change the query structure.", sheet: "SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
  "sqli:login-bypass": { text: "Never build SQL by gluing strings together. Use parameterized queries (prepared statements) so user input is always data, never code. As defense in depth, give the database account the fewest privileges it needs.", sheet: "SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
  "sqli:order-by": { text: "Never interpolate user input into ORDER BY. Map the sort parameter to an allowlist of column names (e.g. {'name': 'name', 'price': 'price'}) and reject anything else.", sheet: "SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
  "sqli:second-order": { text: "Treat stored data as untrusted input: parameterize the query that reads it, not just the one that wrote it. Second-order injection happens when 'safe' stored values are reused unsafely.", sheet: "SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
  "sqli:union": { text: "Use parameterized queries for every database call, including search fields. If you must build dynamic SQL, validate the input against a strict allowlist and never reflect raw database errors to the user.", sheet: "SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
  "sqli:union-filter-bypass": { text: "Blacklists do not fix SQL injection; attackers bypass them with case changes and comments. The fix is parameterized queries, which make the filter irrelevant.", sheet: "SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
  "ssrf:basic": { text: "Never fetch attacker-supplied URLs without validation. Allowlist the permitted hosts/schemes, resolve and check the IP (block private ranges), and disable redirects or re-validate after each hop.", sheet: "Server Side Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "ssrf:bypass": { text: "Validate the parsed IP address, not the raw string: normalize the URL first, then reject private/loopback ranges. String blocklists are bypassed with alternate IP spellings.", sheet: "Server Side Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "ssrf:ssrf-file": { text: "Restrict the fetcher to http(s) only, and validate the scheme after parsing. A scheme allowlist stops file://, gopher://, and other exotic handlers.", sheet: "Server Side Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "ssrf:ssrf-hex-ip": { text: "Normalize the host to a canonical IP (or hostname) before applying any blocklist. Hex, octal, and decimal spellings must all resolve to the same checked value.", sheet: "Server Side Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "ssrf:ssrf-metadata": { text: "Block the cloud metadata address (169.254.169.254) and require IMDSv2 (token-based) on your instances. Egress filtering should deny server-to-metadata requests.", sheet: "Server Side Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "ssrf:ssrf-octal-ip": { text: "Same fix as hex: canonicalize first, then check. Any validation done on the raw string can be evaded with an alternate encoding.", sheet: "Server Side Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "ssrf:ssrf-redirect": { text: "Re-validate the URL after every redirect, or disable following redirects entirely for user-supplied URLs. The initial check means nothing if the fetcher follows a 302 blindly.", sheet: "Server Side Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "ssrf:ssrf-userinfo": { text: "Parse the URL properly and validate the actual host that will be connected to, ignoring userinfo. Better: do not accept full URLs from users at all; accept an id and map it server-side.", sheet: "Server Side Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "ssrf:ssrf-zero-ip": { text: "Block 0.0.0.0 explicitly along with the other loopback/private ranges. Validate the resolved IP against a deny list of non-public ranges.", sheet: "Server Side Request Forgery Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
  "ssti:basic": { text: "Never render templates from untrusted input. Keep templates as developer-controlled files and pass user data as variables, not as template source. If user content must appear in templates, use a logic-less engine with auto-escaping and a minimal scope.", sheet: "Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html" },
  "ssti:rce": { text: "Never render templates from untrusted input. Keep templates as developer-controlled files and pass user data as variables, not as template source. If user content must appear in templates, use a logic-less engine with auto-escaping and a minimal scope.", sheet: "Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html" },
  "ssti:ssti-curly": { text: "Never render templates from untrusted input. Keep templates as developer-controlled files and pass user data as variables, not as template source. If user content must appear in templates, use a logic-less engine with auto-escaping and a minimal scope.", sheet: "Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html" },
  "ssti:ssti-dotblock": { text: "Never render templates from untrusted input. Keep templates as developer-controlled files and pass user data as variables, not as template source. If user content must appear in templates, use a logic-less engine with auto-escaping and a minimal scope.", sheet: "Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html" },
  "ssti:ssti-nobrackets": { text: "Never render templates from untrusted input. Keep templates as developer-controlled files and pass user data as variables, not as template source. If user content must appear in templates, use a logic-less engine with auto-escaping and a minimal scope.", sheet: "Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html" },
  "ssti:ssti-noquotes": { text: "Never render templates from untrusted input. Keep templates as developer-controlled files and pass user data as variables, not as template source. If user content must appear in templates, use a logic-less engine with auto-escaping and a minimal scope.", sheet: "Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html" },
  "ssti:ssti-nounderscore": { text: "Never render templates from untrusted input. Keep templates as developer-controlled files and pass user data as variables, not as template source. If user content must appear in templates, use a logic-less engine with auto-escaping and a minimal scope.", sheet: "Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html" },
  "ssti:ssti-rce": { text: "Never render templates from untrusted input. Keep templates as developer-controlled files and pass user data as variables, not as template source. If user content must appear in templates, use a logic-less engine with auto-escaping and a minimal scope.", sheet: "Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html" },
  "ssti:ssti-wordfilter": { text: "Never render templates from untrusted input. Keep templates as developer-controlled files and pass user data as variables, not as template source. If user content must appear in templates, use a logic-less engine with auto-escaping and a minimal scope.", sheet: "Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html" },
  "upload:stored-xss": { text: "Serve user uploads with Content-Disposition: attachment or from an isolated domain, never inline from your main origin. Validate content and consider re-encoding images to strip embedded scripts.", sheet: "File Upload", url: "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" },
  "upload:upload-case": { text: "Normalize case before comparing extensions, but do not rely on extension checks at all: they are a blacklist, and blacklists are bypassed. Content-based validation plus random stored names is the fix.", sheet: "File Upload", url: "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" },
  "upload:upload-ctype": { text: "Never trust the client-supplied Content-Type header. Inspect the file bytes server-side (magic numbers) to decide what it really is.", sheet: "File Upload", url: "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" },
  "upload:upload-double-ext": { text: "Validate the file by its actual content (magic bytes), not its name, and store it with a random server-chosen filename. Serve with a fixed safe Content-Type, never sniffed from the extension.", sheet: "File Upload", url: "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" },
  "upload:upload-overwrite": { text: "Scope every write to the session's own account and use unpredictable stored paths. Never derive a writable path directly from user input without an ownership check.", sheet: "File Upload", url: "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" },
  "upload:upload-polyglot": { text: "Do not sniff content to decide how to serve it: set an explicit safe Content-Type (and X-Content-Type-Options: nosniff). Re-encode images to destroy polyglots.", sheet: "File Upload", url: "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" },
  "upload:upload-strip-once": { text: "Apply sanitization repeatedly until the input stops changing, or better, avoid string-stripping filters: use an allowlist of safe names and randomize the stored filename.", sheet: "File Upload", url: "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" },
  "upload:upload-traversal": { text: "Resolve the final path and verify it stays inside the upload directory (containment check). Better: ignore the client filename entirely and generate a random name.", sheet: "File Upload", url: "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" },
  "xss:dom": { text: "Never pass untrusted data to innerHTML or document.write. Use textContent for text, and if you must build HTML, sanitize it with a well-maintained library like DOMPurify.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "xss:reflected": { text: "Encode all untrusted data for the HTML context before reflecting it (e.g. & becomes &amp;, < becomes &lt;). Better: use a framework that auto-escapes by default, and add a Content-Security-Policy as defense in depth.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "xss:stored": { text: "Encode stored user content on output, every time it is rendered. Store the raw input, encode on display: that way one fix covers every page that shows the data.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "xss:xss-attr-breakout": { text: "Encode for the attribute context (quotes included), not just the HTML body. Context-sensitive output encoding is the rule: the right encoder depends on where the data lands.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "xss:xss-backtick": { text: "Same rule as the JS-string lab: never build JavaScript code from untrusted strings, including inside template literals. Pass data as data, never as code.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "xss:xss-dom-clobber": { text: "Do not let attacker markup create named elements that shadow your JavaScript variables. Sanitize HTML input, and avoid reading security decisions from window properties that markup can influence.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "xss:xss-js-context": { text: "Never interpolate untrusted data into JavaScript code. Pass data via JSON in a safe container (e.g. a data attribute or a JSON script block) and let the script read it, instead of building code from strings.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "xss:xss-markdown": { text: "Validate link schemes in your markdown renderer: allow only http(s) and mailto, reject javascript: and data:. Render to HTML, then sanitize the result.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "xss:xss-svg-upload": { text: "Serve user-uploaded SVGs with Content-Disposition: attachment or from a separate sandboxed domain, never inline as image/svg+xml. Alternatively, sanitize the SVG server-side to strip scripts and event handlers.", sheet: "Cross Site Scripting Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
  "xxe:file": { text: "Disable DTDs and external entities in your XML parser (the exact flags depend on the library). Prefer a simpler format like JSON where possible, and if you must parse XML, use a hardened parser configuration.", sheet: "XML External Entity Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" },
  "xxe:ssrf": { text: "Disable DTDs and external entities in your XML parser (the exact flags depend on the library). Prefer a simpler format like JSON where possible, and if you must parse XML, use a hardened parser configuration.", sheet: "XML External Entity Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" },
  "xxe:xxe-billion-laughs": { text: "Disable DTDs and external entities in your XML parser (the exact flags depend on the library). Prefer a simpler format like JSON where possible, and if you must parse XML, use a hardened parser configuration.", sheet: "XML External Entity Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" },
  "xxe:xxe-external-dtd": { text: "Disable DTDs and external entities in your XML parser (the exact flags depend on the library). Prefer a simpler format like JSON where possible, and if you must parse XML, use a hardened parser configuration.", sheet: "XML External Entity Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" },
  "xxe:xxe-param-oob": { text: "Disable DTDs and external entities in your XML parser (the exact flags depend on the library). Prefer a simpler format like JSON where possible, and if you must parse XML, use a hardened parser configuration.", sheet: "XML External Entity Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" },
  "xxe:xxe-soap": { text: "Disable DTDs and external entities in your XML parser (the exact flags depend on the library). Prefer a simpler format like JSON where possible, and if you must parse XML, use a hardened parser configuration.", sheet: "XML External Entity Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" },
  "xxe:xxe-svg": { text: "Disable DTDs and external entities in your XML parser (the exact flags depend on the library). Prefer a simpler format like JSON where possible, and if you must parse XML, use a hardened parser configuration.", sheet: "XML External Entity Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" },
  "xxe:xxe-xinclude": { text: "Disable DTDs and external entities in your XML parser (the exact flags depend on the library). Prefer a simpler format like JSON where possible, and if you must parse XML, use a hardened parser configuration.", sheet: "XML External Entity Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html" },
};

// ---------------------------------------------------------------------------
// M11 break-then-fix UI (added, existing signatures untouched).
// ---------------------------------------------------------------------------

// Call to action shown on challenge pages. Reads lib/fixmode.js lazily so a
// missing or circular module degrades to the honest "not available yet" note.
function fixCta(moduleId, vulnId) {
  let has = false;
  try {
    const fixmode = require('./fixmode.js');
    if (fixmode && typeof fixmode.hasFixBlock === 'function') {
      has = !!fixmode.hasFixBlock(moduleId, vulnId);
    }
  } catch (e) { /* fixmode not written yet: treat as not available */ }
  if (has) {
    return `<div class="clay-card fix-cta">
      <div class="card-top"><span class="orb" aria-hidden="true">🛠</span></div>
      <h3>Fix this challenge</h3>
      <p class="tagline">You broke it. Now repair it. Edit the code, then the runner checks that the exploit is blocked and legitimate use still works.</p>
      <div class="card-foot"><a class="clay-btn clay-btn-primary" href="/fix/${esc(moduleId)}/${esc(vulnId)}">Try to fix this</a></div>
    </div>`;
  }
  return `<p class="dim fix-cta-soon">Fix mode is not available for this challenge yet.</p>`;
}

// Fix-mode editor page. `block` is the fix block record:
// { moduleId (or module), vulnId (or vuln), title, vulnerableCode (or code), fixHint }.
function fixEditorPage(block) {
  const b = block || {};
  const moduleId = b.moduleId || b.module || '';
  const vulnId = b.vulnId || b.vuln || '';
  const title = b.title || (vulnId ? String(vulnId) : 'Challenge');
  const code = b.vulnerableCode ?? b.code ?? '';
  const hint = b.fixHint ?? '';
  const hintHtml = hint
    ? `<div class="brief"><p class="eyebrow"><span class="orb" aria-hidden="true">✦</span>Fix hint</p><p>${esc(hint)}</p></div>`
    : '';
  const body = `<div class="clay-card fix-editor">
      <p class="eyebrow"><span class="orb" aria-hidden="true">🛠</span>Fix mode</p>
      <h1>${esc(title)}</h1>
      <p class="tagline">Read the vulnerable code, write your patch in the editor, then test it. The runner checks the exploit and a legitimate request.</p>
      <h2>The vulnerable code</h2>
      ${payloadBlock('Vulnerable code (read only)', code)}
      <h2>Your fix</h2>
      <form method="post" action="/fix/${esc(moduleId)}/${esc(vulnId)}/test" id="fix-form">
        <label class="fix-label" for="fix-code">Edit the code below, then press "Test my fix".</label>
        <textarea id="fix-code" name="code" class="fix-code" style="font-family:var(--font-mono)" spellcheck="false" rows="20">${esc(code)}</textarea>
        <div class="fix-actions"><button type="submit" class="clay-btn clay-btn-primary">Test my fix</button></div>
      </form>
      ${hintHtml}
      <div id="fix-result" aria-live="polite"></div>
    </div>`;
  return page('Fix mode · ' + title, body, '');
}

// Renders the fix runner result. `result` looks like
// { ok: true } on success, or { ok: false, error, exploitStillWorks, legitBroken }.
function fixResultHtml(result) {
  const r = result || {};
  if (r.ok) {
    return `<div class="flag-banner fix-success" role="status"><div class="flag-top"><span class="flag-orb" aria-hidden="true">✓</span><div><h2>Fix accepted</h2><p class="saved">The exploit is blocked and legitimate use still works. Badge earned.</p></div></div><div class="next-steps"><a class="clay-btn clay-btn-primary clay-btn-sm" href="/scoreboard">Scoreboard</a><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/">All modules</a></div></div>`;
  }
  let reason;
  if (r.error) {
    reason = esc(r.error);
  } else if (r.exploitStillWorks) {
    reason = 'The exploit still works against your fix. Read the hint, adjust your patch, and test again.';
  } else if (r.legitBroken) {
    reason = 'The exploit is blocked, but a legitimate use case broke. Keep the fix surgical: close the hole without changing normal behavior.';
  } else {
    reason = 'The fix did not pass the checks. Adjust your patch and test again.';
  }
  return `<div class="clay-card fix-fail"><div class="card-top"><span class="orb" aria-hidden="true">✗</span><b>Fix not passing yet</b></div><p>${reason}</p><p class="dim">Press "Test my fix" again after each change.</p></div>`;
}

// Small pill showing how many fix badges the user earned (scoreboard chip).
function fixBadgePill(count) {
  const n = Math.max(0, Number(count) || 0);
  return `<span class="clay-pill fix-badge"><span class="dot dot-beginner" aria-hidden="true"></span>🛠 ${n} fix${n === 1 ? '' : 'es'}</span>`;
}

Object.assign(module.exports, { fixCta, fixEditorPage, fixResultHtml, fixBadgePill });
