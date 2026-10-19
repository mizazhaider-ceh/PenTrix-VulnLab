'use strict';
// DOM clobbering to admin: a script-only sanitizer lets form/input markup shadow window.settings.
const express = require('express');
const { page, esc, errorPage, flagBox, fixPanel } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { siteFrame, backLinks } = require('../shared');

const router = express.Router();

const DEFAULT_HTML = '<b>Nothing here yet.</b>';

// The custom HTML is kept per session, so one student's markup never unlocks
// the admin panel for another student.
function getClobberHtml(req) {
  return typeof req.session.xssClobber === 'string' ? req.session.xssClobber : DEFAULT_HTML;
}

function stripScripts(html) {
  return String(html).replace(/<script\b[^>]*>[\s\S]*?<\/script\s*>/gi, '');
}

// Mirrors what a browser would build from the sanitized markup: does it create
// a window.settings whose isAdmin property is truthy? Two real shapes work:
//   1. <form id="settings"> containing a control named (or id'd) isAdmin
//      (form.isAdmin returns that control), or a control tied to the form
//      through its form="settings" attribute.
//   2. Two <a id="settings"> elements, one with name="isAdmin"
//      (window.settings becomes an HTMLCollection, .isAdmin its named item).
// Comments, <textarea>/<title>/<style> text, wrong-case names and attribute
// look-alikes (data-id, title="id=settings") do not count.
const NAMEABLE = new Set(['input', 'img', 'select', 'textarea', 'button', 'object', 'embed', 'fieldset']);

function parseAttrs(src) {
  const attrs = {};
  const re = /([^\s"'<>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
  let m;
  while ((m = re.exec(src))) {
    const name = m[1].toLowerCase();
    if (!(name in attrs)) attrs[name] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return attrs;
}

function clobbersSettings(html) {
  const s = stripScripts(html)
    .replace(/<!--[\s\S]*?(?:-->|$)/g, '')
    .replace(/<(textarea|title|style|xmp|noembed|noframes|iframe)\b[^>]*>[\s\S]*?(?:<\/\1\s*>|$)/gi, '');
  const tagRe = /<(\/?)([a-zA-Z][^\s\/>]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/g;
  let m;
  let inForm = null; // null, 'settings' or 'other'
  let settingsForm = false;
  let tiedControl = false;
  let nestedControl = false;
  let anchorsWithId = 0;
  let anchorNamed = false;
  while ((m = tagRe.exec(s))) {
    const closing = m[1] === '/';
    const tag = m[2].toLowerCase();
    if (closing) {
      if (tag === 'form') inForm = null;
      continue;
    }
    const a = parseAttrs(m[3]);
    if (tag === 'form') {
      if (inForm === null) inForm = a.id === 'settings' ? 'settings' : 'other';
      if (a.id === 'settings') settingsForm = true;
    } else if (NAMEABLE.has(tag)) {
      const named = a.name === 'isAdmin' || a.id === 'isAdmin';
      if (named && inForm === 'settings') nestedControl = true;
      if (named && a.form === 'settings') tiedControl = true;
    } else if (tag === 'a' && a.id === 'settings') {
      anchorsWithId += 1;
      if (a.name === 'isAdmin') anchorNamed = true;
    }
  }
  return (settingsForm && (nestedControl || tiedControl)) || (anchorsWithId >= 2 && anchorNamed);
}

router.get('/clobber', (req, res) => {
  // VULN: the sanitizer only strips <script> tags; form/input markup is stored and rendered raw.
  const clean = stripScripts(getClobberHtml(req));
  const saved = typeof req.session.xssClobber === 'string' ? req.session.xssClobber : '';
  // VULN: the inline page script below trusts window.settings, which injected markup can clobber via id/name.
  res.send(page('Profile · Lumen Profiles', `
    <h2>Lumen Profiles</h2>
    ${siteFrame('Lumen Profiles', ['Profile', 'Messages', 'Staff'], `
      <p>Add custom HTML to your public profile. Scripts are stripped for your safety.</p>
      <form method="POST" action="/xss/clobber">
        <div class="clay-field">
          <label for="html">Custom HTML</label>
          <textarea class="clay-input" id="html" name="html" rows="6" placeholder="&lt;b&gt;Hello, I love hiking.&lt;/b&gt;" required>${esc(saved)}</textarea>
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Save profile HTML</button>
      </form>
      <h3>Your profile</h3>
      <div class="card" id="custom">${clean}</div>
      <div class="warn" id="adminpanel" hidden>
        <p class="warn-title"><span class="dot" aria-hidden="true"></span>Admin panel</p>
        <p>Staff tools are enabled for this session.</p>
        <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xss/clobber-admin">Open the admin panel</a></p>
      </div>
      <script>
        if (window.settings && window.settings.isAdmin) {
          document.getElementById('adminpanel').hidden = false;
        }
      </script>`)}
    <div class="note">
      <p>No beacon is needed here. The flag is awarded on the admin panel page when your saved profile HTML really takes over the page's settings check.</p>
    </div>
    ${backLinks('xss-dom-clobber')}
  `));
});

router.post('/clobber', (req, res) => {
  req.session.xssClobber = String(req.body.html || '').slice(0, 5000);
  res.redirect('/xss/clobber');
});

router.get('/clobber-admin', (req, res) => {
  // Award only when the stored markup would genuinely clobber window.settings.isAdmin.
  if (clobbersSettings(getClobberHtml(req))) {
    const flag = award(req, 'xss', 'xss-dom-clobber');
    return res.send(page('Admin panel · Lumen Profiles', `
      <h2>Admin panel unlocked</h2>
      <p>Your markup clobbered <code>window.settings</code>: the page script found a
      truthy <code>window.settings.isAdmin</code> and treated you as an admin.</p>
      ${flagBox(flag)}
      ${fixPanel('xss', 'xss-dom-clobber')}
      <p><a href="/xss">Back to the XSS module</a></p>
    `));
  }
  res.send(page('Admin panel · Lumen Profiles', errorPage(403, 'Access denied',
    '<p>The admin panel only unlocks when the page script sees a truthy <code>window.settings.isAdmin</code>. Your profile HTML does not do that yet.</p><p><a href="/xss/clobber">Back to your profile</a></p>')));
});

module.exports = {
  vuln: {
    id: 'xss-dom-clobber',
    name: 'DOM Clobbering to Admin',
    difficulty: 'Hard',
    hint: 'Scripts are stripped, but form and input tags survive. The page script trusts window.settings.isAdmin. Named elements in the DOM become window properties.',
    hints: [
      'The page has a script that reads window.settings.isAdmin. What else can create window properties?',
      'Named HTML elements (id= or name=) become properties of window. A form with id="settings" containing an input named isAdmin shadows the real settings object.',
      'Save profile HTML with a form whose id is settings and an input inside it whose name is isAdmin (case matters), then reload the profile and open the admin panel.',
    ],
    tools: 'B, DT',
    how: 'Inject <form id="settings"><input name="isAdmin" value="1"> so window.settings.isAdmin becomes truthy, then open the admin panel.',
    link: '/xss/clobber',
    start: 'curl -s http://localhost:3000/xss/clobber | grep -n -A4 "<script>"',
  },
  router,
};
