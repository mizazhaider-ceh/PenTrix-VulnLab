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
};
