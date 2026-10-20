'use strict';
// Stored XSS: guestbook entries are saved verbatim and rendered unencoded.
const express = require('express');
const { getDb } = require('../../../lib/db');
const { page, esc, emptyState, errorPage, claimBox, fixCta, flagBox, fixPanel } = require('../../../lib/page');
const { xssNonceTag, beacon, siteFrame, backLinks } = require('../shared');
const { award } = require('../../../lib/flags');
const vm = require('vm');
const crypto = require('crypto');

const router = express.Router();

router.get('/guestbook', (req, res) => {
  const db = getDb();
  // The shared comments table is seeded with one benign comment already.
  const rows = db.prepare('SELECT author, body, created_at FROM comments ORDER BY id DESC').all();
  // VULN: stored comment author and body are rendered raw, no output encoding.
  const items = rows.map((r) => `
    <article class="card">
      <p><b>${r.author}</b> <span class="muted">${esc(r.created_at)}</span></p>
      <p>${r.body}</p>
    </article>`).join('\n');
  res.send(page('Guestbook · Maple Street Cafe', `
    <h2>Maple Street Cafe</h2>
    ${xssNonceTag(req, 'stored')}
    ${siteFrame('Maple Street Cafe', ['Menu', 'Guestbook', 'Visit us'], `
      <p>Tell us how your visit went. Entries appear on this page for every visitor.</p>
      <form method="POST" action="/xss/guestbook">
        <div class="clay-field">
          <label for="author">Your name</label>
          <input class="clay-input" type="text" id="author" name="author" placeholder="Jordan" maxlength="80" required>
        </div>
        <div class="clay-field">
          <label for="body">Your message</label>
          <textarea class="clay-input" id="body" name="body" rows="4" placeholder="The flat white was excellent." maxlength="2000" required></textarea>
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Sign guestbook</button>
      </form>`)}
    <h3>Messages</h3>
    ${items || emptyState('No messages yet', '<p>Be the first to sign the guestbook.</p>')}
    ${claimBox({ vulnId: 'stored', payload: esc(`<script>${beacon('stored')}</script>`), statusUrl: '/xss/claim-status?v=stored', beaconInfo: 'window.__px is computed at runtime when the page loads; it never appears in the page source. This flag is victim-bound: the beacon only wins when it fires inside a victim session, so after planting your comment load <a href="/xss/victim-visit">/xss/victim-visit</a> and let the simulated victim trigger it.' })}
    ${fixCta('xss', 'stored')}
    ${backLinks('stored')}
  `));
});

router.post('/guestbook', (req, res) => {
  const author = String(req.body.author || '').slice(0, 80);
  const body = String(req.body.body || '').slice(0, 2000);
  if (!author.trim() || !body.trim()) {
    return res.status(400).send(page('Guestbook · Maple Street Cafe', errorPage(400, 'Name and message are required',
      '<p>Both fields must be filled in to sign the guestbook.</p><p><a href="/xss/guestbook">Back to the guestbook</a></p>')));
  }
  const db = getDb();
  // Prepared statement keeps this about XSS only; input is stored verbatim.
  db.prepare('INSERT INTO comments (author, body) VALUES (?, ?)').run(author, body);
  res.redirect('/xss/guestbook');
});

// GET /xss/victim-visit -> simulated victim. A fresh victim session loads
// the guestbook exactly as stored: every comment body's inline scripts run
// with window.__px set to a per-visit victim secret and the victim's own
// cookie in scope. The flag goes to YOUR session only when a beacon fired
// inside that victim execution carries the victim secret, proving the
// stored payload really executed in someone else's page load.
router.get('/victim-visit', (req, res) => {
  const secret = crypto.randomBytes(16).toString('hex');
  const db = getDb();
  const rows = db.prepare('SELECT body FROM comments ORDER BY id').all();
  const beacons = [];
  for (const r of rows) {
    const scripts = String(r.body).match(/<script\b[^>]*>([\s\S]*?)<\/script>/gi) || [];
    for (const tag of scripts) {
      const code = tag.replace(/^<script\b[^>]*>/i, '').replace(/<\/script\s*>$/i, '');
      // Hardened sandbox, same pattern as lib/fix-worker.js: the context
      // gets NO host values at all. Every helper the guest sees (window,
      // document, location, console, fetch, URLSearchParams) is built
      // inside the guest context from guest-realm intrinsics by the
      // bootstrap script below. URLSearchParams is a small guest-side
      // implementation (a bare vm context has no such global, and the
      // host class must never be handed in). Promise / String /
      // encodeURIComponent are the guest realm's own intrinsics. Guest
      // code can therefore never walk a host object to the host Function
      // constructor or the host process. fetch records its URL guest-side;
      // the host only ever reads back one plain JSON string of beacon
      // URLs, never a guest object.
      const context = vm.createContext(Object.create(null));
      const bootstrap = new vm.Script(`
        var window = { __px: ${JSON.stringify(secret)} };
        var document = { cookie: ${JSON.stringify('victimsession=victim-' + crypto.randomBytes(4).toString('hex'))} };
        var location = { search: "", href: "/xss/guestbook" };
        var console = { log: function () {}, warn: function () {}, error: function () {},
          info: function () {}, debug: function () {} };
        var __beacons = [];
        function fetch(u) { __beacons.push(String(u));
          return Promise.resolve({ json: function () { return Promise.resolve({}); } }); }
        function URLSearchParams(init) {
          this._pairs = [];
          if (init == null) return;
          if (typeof init === "string") {
            var s = init.charAt(0) === "?" ? init.slice(1) : init;
            if (!s) return;
            var parts = s.split("&");
            for (var i = 0; i < parts.length; i++) {
              if (!parts[i]) continue;
              var eq = parts[i].indexOf("=");
              var k = eq < 0 ? parts[i] : parts[i].slice(0, eq);
              var v = eq < 0 ? "" : parts[i].slice(eq + 1);
              this._pairs.push([decodeURIComponent(k.replace(/\\+/g, " ")),
                decodeURIComponent(v.replace(/\\+/g, " "))]);
            }
          } else if (Array.isArray(init)) {
            for (var j = 0; j < init.length; j++) this._pairs.push([String(init[j][0]), String(init[j][1])]);
          } else if (typeof init === "object") {
            for (var key in init) {
              if (Object.prototype.hasOwnProperty.call(init, key)) this._pairs.push([key, String(init[key])]);
            }
          }
        }
        URLSearchParams.prototype.get = function (name) {
          for (var i = 0; i < this._pairs.length; i++) if (this._pairs[i][0] === name) return this._pairs[i][1];
          return null;
        };
        URLSearchParams.prototype.getAll = function (name) {
          var out = [];
          for (var i = 0; i < this._pairs.length; i++) if (this._pairs[i][0] === name) out.push(this._pairs[i][1]);
          return out;
        };
        URLSearchParams.prototype.has = function (name) { return this.get(name) !== null; };
        URLSearchParams.prototype.append = function (name, value) { this._pairs.push([String(name), String(value)]); };
        URLSearchParams.prototype.set = function (name, value) {
          var done = false;
          for (var i = 0; i < this._pairs.length; i++) {
            if (this._pairs[i][0] === name) {
              if (!done) { this._pairs[i][1] = String(value); done = true; }
              else { this._pairs.splice(i, 1); i--; }
            }
          }
          if (!done) this._pairs.push([String(name), String(value)]);
        };
        URLSearchParams.prototype.delete = function (name) {
          this._pairs = this._pairs.filter(function (p) { return p[0] !== name; });
        };
        URLSearchParams.prototype.toString = function () {
          return this._pairs.map(function (p) {
            return encodeURIComponent(p[0]) + "=" + encodeURIComponent(p[1]);
          }).join("&");
        };
      `, { filename: 'victim-sandbox-bootstrap.js' });
      try {
        bootstrap.runInContext(context, { timeout: 1000 });
        try { vm.runInContext(code, context, { timeout: 1000 }); } catch (e) { /* a real victim browser swallows script errors too */ }
        const seen = vm.runInContext('JSON.stringify(__beacons)', context, { timeout: 1000 });
        if (typeof seen === 'string') {
          const list = JSON.parse(seen);
          if (Array.isArray(list)) {
            for (const u of list) if (typeof u === 'string') beacons.push(u.slice(0, 4000));
          }
        }
      } catch (e) { /* a real victim browser swallows script errors too */ }
    }
  }
  const won = beacons.some((u) => {
    try {
      const url = new URL(u, 'http://lab.invalid/');
      return url.pathname === '/xss/collect'
        && (url.searchParams.get('v') || '') === 'stored'
        && (url.searchParams.get('n') || '') === secret
        && (url.searchParams.get('c') || '').length > 0;
    } catch (e) { return false; }
  });
  let flags = '';
  if (won) {
    flags += flagBox(award(req, 'xss', 'stored'));
    flags += fixPanel('xss', 'stored');
  }
  res.send(page('Victim visit', `
    <h2>Simulated victim visit</h2>
    <p>A fresh victim just loaded the guestbook in their own session. ${beacons.length} beacon call(s) fired inside that page load.</p>
    ${flags || '<p class="dim">No beacon carrying this visit secret arrived, so no flag was awarded. Plant a guestbook comment whose script reads <code>window.__px</code> at runtime and fires <code>/xss/collect</code>, then come back here.</p>'}
    <p><a href="/xss/guestbook">Back to the guestbook</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'stored',
    name: 'Stored XSS',
    difficulty: 'Easy',
    hint: 'Comments are saved and shown to every visitor unescaped. Your payload persists and fires on every page view.',
    hints: [
      'Comments are saved and shown to every visitor. Where does your comment end up in the HTML?',
      'Send the sign-guestbook POST to Burp Repeater. The comment is stored verbatim and rendered raw, so your payload persists in the database and fires for every page view.',
      'Plant a beacon comment via Repeater that calls /xss/collect (parameters c, v=stored and n=window.__px), then load /xss/victim-visit: a simulated victim session loads the guestbook and your payload fires there with the victim token.',
    ],
    tools: 'BZ, B',
    how: 'In Burp Repeater, POST the exfiltration payload as a guestbook comment, then load /xss/victim-visit so a simulated victim loads the guestbook and the stored payload fires with the victim token.',
    link: '/xss/guestbook',
    start: 'Start Burp Proxy, browse to /xss/guestbook in your proxied browser, and read the Messages list. Then send the sign-guestbook POST to Repeater: the body field is stored verbatim and rendered raw for every visitor.',
  },
  router,
};
