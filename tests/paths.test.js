'use strict';
// M13 career paths regression suite. Boots the real app as a child process
// against a throwaway database and checks the /paths index and detail pages:
// path names, step counts, progress readout, prerequisite badges and locks,
// the 404 case, and the no em dash rule. Run with: npm test
const test = require('node:test');
const assert = require('node:assert/strict');
const { FLAG_RE, bootLab, client } = require('./helpers');

const zeroToWeb = require('../paths/zero-to-web-pentester');
const apiHacker = require('../paths/api-hacker');
const authAssassin = require('../paths/authentication-assassin');

const PATHS = [zeroToWeb, apiHacker, authAssassin];
const INDEX_URL = '/paths';

// Minimal HTML entity decode so step notes can be matched against rendered text.
function decodeEntities(html) {
  return html
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ');
}

async function getPage(c, url) {
  const r = await c.get(url);
  assert.equal(r.status, 200, `GET ${url} did not return 200`);
  return r.text;
}

test('paths', async (t) => {
  const { srv } = await bootLab(t);
  const c = client(srv.base);

  await t.test('index: lists all three career paths', async () => {
    const text = await getPage(c, INDEX_URL);
    for (const p of PATHS) {
      assert.ok(text.includes(p.name), `index missing path name: ${p.name}`);
      assert.ok(text.includes(`${INDEX_URL}/${p.id}`), `index missing link to ${p.id}`);
    }
  });

  await t.test('zero-to-web-pentester: 10 steps, progress 0/10, no prereq banner', async () => {
    const text = await getPage(c, `${INDEX_URL}/${zeroToWeb.id}`);
    assert.ok(text.includes(zeroToWeb.name));
    assert.ok(text.includes('0/10'), 'progress readout 0/10 not found');
    const body = decodeEntities(text);
    const notesFound = zeroToWeb.steps.filter((s) => body.includes(s.note)).length;
    assert.equal(notesFound, 10, `expected all 10 step notes, found ${notesFound}`);
    assert.ok(!text.includes('Requires:'), 'prereq banner shown on a path with no prerequisites');
  });

  await t.test('api-hacker: prereq badge and locked note', async () => {
    const text = await getPage(c, `${INDEX_URL}/${apiHacker.id}`);
    assert.ok(text.includes(apiHacker.name));
    assert.ok(text.includes('Requires: Zero to Web Pentester'), 'prereq badge not found');
    assert.match(text, /lock/i, 'locked note not found');
  });

  await t.test('authentication-assassin: prereq badge', async () => {
    const text = await getPage(c, `${INDEX_URL}/${authAssassin.id}`);
    assert.ok(text.includes(authAssassin.name));
    assert.ok(text.includes('Requires: Zero to Web Pentester'), 'prereq badge not found');
  });

  await t.test('unknown path: 404', async () => {
    const r = await c.get(`${INDEX_URL}/nope`);
    assert.equal(r.status, 404, 'unknown path did not return 404');
  });

  await t.test('paths pages: no em dashes and no flag-shaped literals', async () => {
    for (const p of PATHS) {
      const text = await getPage(c, `${INDEX_URL}/${p.id}`);
      assert.doesNotMatch(text, /\u2014/, `em dash on ${p.id} page`);
      assert.doesNotMatch(text, FLAG_RE, `flag-shaped literal leaked on ${p.id} page`);
    }
    const index = await getPage(c, INDEX_URL);
    assert.doesNotMatch(index, /\u2014/, 'em dash on paths index');
    assert.doesNotMatch(index, FLAG_RE, 'flag-shaped literal leaked on paths index');
  });
});
