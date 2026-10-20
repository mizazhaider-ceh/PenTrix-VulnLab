'use strict';
// Runner hardening suite (backlog P1-7, P5-1, P5-4).
//
//   P1-7  Fix-mode student code runs in a worker thread with a memory cap
//         and a wall-clock timeout; hostile submissions cannot OOM or
//         freeze the lab. Async Express handlers are wrapped so a throw
//         after an `await` reaches the error middleware instead of
//         becoming an unhandledRejection, and process-level guards log
//         anything that still escapes without killing the lab.
//   P5-1  The boot gate serves a static 503 page (no stack trace) until
//         the app marks itself ready.
//   P5-4  Oversized request bodies get a clean 413, not a 500.

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');

const { bootLab, client } = require('./helpers');
const fixmode = require('../lib/fixmode');
const { ah, patchExpress } = require('../lib/async-handler');
const { createBootGate } = require('../lib/boot-gate');

const ROOT = path.join(__dirname, '..');
const MOD = 'sqli';
const VULN = 'login-bypass';

const LOOP_CODE = 'function vulnFn() { return 1; }\nwhile (true) {}';
const BOMB_CODE = [
  'var keep = [];',
  'while (keep.length < 100000) { keep.push(new Array(100000).fill("x")); }',
  'function vulnFn() { return true; }',
].join('\n');
// Atomics.wait blocks the worker thread in a way the vm script timeout
// cannot interrupt; only the parent-side wall-clock timer can stop it.
const SLEEP_CODE = [
  'var sab = new SharedArrayBuffer(4);',
  'Atomics.wait(new Int32Array(sab), 0, 0, 30000);',
  'function vulnFn() { return true; }',
].join('\n');

function runChild(script) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-e', script], { cwd: ROOT });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, out, err }));
  });
}

test('async handler wrapper (P1-7)', async (t) => {
  await t.test('ah forwards a rejection after an await to next(err)', async () => {
    const boom = new Error('thrown after await');
    const handler = ah(async () => {
      await new Promise((r) => setTimeout(r, 5));
      throw boom;
    });
    const got = await new Promise((resolve) => {
      handler({}, {}, (err) => resolve(err));
    });
    assert.equal(got, boom, 'next must receive the exact rejection');
  });

  await t.test('patched router: async handler throw after await -> 500 page, app keeps serving', async () => {
    patchExpress();
    const express = require('express');
    const app = express();
    const router = express.Router();
    // Same shape as the race-module handlers: bare async (req, res).
    router.get('/throws-after-await', async (req, res) => {
      await new Promise((r) => setTimeout(r, 5));
      throw new Error('race handler blew up after await');
    });
    router.get('/healthy', (req, res) => res.status(200).send('healthy'));
    app.use(router);
    // eslint-disable-next-line no-unused-vars
    app.use((err, req, res, next) => res.status(500).send('error page: ' + err.message));
    const srv = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    t.after(() => new Promise((resolve) => srv.close(resolve)));
    const base = 'http://127.0.0.1:' + srv.address().port;
    const bad = await fetch(base + '/throws-after-await');
    assert.equal(bad.status, 500, 'rejection must reach the error middleware as a 500');
    assert.match(await bad.text(), /race handler blew up after await/);
    const good = await fetch(base + '/healthy');
    assert.equal(good.status, 200, 'the app must keep serving after the throw');
    assert.equal(await good.text(), 'healthy');
  });
});

test('process guards (P1-7)', async (t) => {
  await t.test('unhandledRejection and uncaughtException are logged, process survives', async () => {
    const guardsPath = JSON.stringify(path.join(ROOT, 'lib', 'process-guards.js'));
    const script = [
      'require(' + guardsPath + ').installProcessGuards();',
      '(async () => { await new Promise((r) => setTimeout(r, 20)); throw new Error("rejection after await"); })();',
      'setTimeout(() => { throw new Error("uncaught in timer"); }, 60);',
      'setTimeout(() => { console.log("SURVIVED"); }, 400);',
    ].join('\n');
    const res = await runChild(script);
    assert.equal(res.code, 0, 'guarded process must exit cleanly, stderr was:\n' + res.err);
    assert.match(res.out, /SURVIVED/, 'process must still be alive after both incidents');
    assert.match(res.err, /\[guard\] unhandledRejection/, 'rejection must be logged by the guard');
    assert.match(res.err, /\[guard\] uncaughtException/, 'uncaught exception must be logged by the guard');
  });
});

test('boot gate (P5-1)', async (t) => {
  await t.test('before ready: static 503, Retry-After, no stack trace; after ready: passthrough', async () => {
    const express = require('express');
    const gate = createBootGate();
    const app = express();
    app.use(gate.middleware);
    app.get('/', (req, res) => res.status(200).send('home page'));
    const srv = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    t.after(() => new Promise((resolve) => srv.close(resolve)));
    const base = 'http://127.0.0.1:' + srv.address().port;

    const during = await fetch(base + '/');
    assert.equal(during.status, 503, 'boot window must answer 503');
    assert.equal(during.headers.get('retry-after'), '2');
    const body = await during.text();
    assert.match(body, /lab is starting/i);
    assert.doesNotMatch(body, /TypeError|ReferenceError|node_modules|at .*\.js:\d+/, 'no stack trace or internals in the boot page');

    gate.markReady();
    const after = await fetch(base + '/');
    assert.equal(after.status, 200, 'after markReady the gate must pass requests through');
    assert.equal(await after.text(), 'home page');
  });
});

test('fix-mode worker isolation (P1-7)', async (t) => {
  const block = fixmode.getFixBlock(MOD, VULN);
  assert.ok(block, 'reference fix block must exist');

  await t.test('infinite loop submission is killed by the timeout, runner stays usable', async () => {
    const started = Date.now();
    const res = await fixmode.testFix(MOD, VULN, LOOP_CODE);
    const elapsed = Date.now() - started;
    assert.equal(res.ok, false);
    assert.match(res.error, /took too long/i, 'loop must get the friendly timeout message, got: ' + res.error);
    assert.ok(elapsed < 15000, 'loop submission must return in bounded time, took ' + elapsed + 'ms');
    const after = await fixmode.testFix(MOD, VULN, block.fixedCode);
    assert.equal(after.ok, true, 'runner must still accept good code after the loop: ' + (after.error || ''));
  });

  await t.test('memory bomb submission is killed by the memory cap, runner stays usable', async () => {
    const started = Date.now();
    const res = await fixmode.testFix(MOD, VULN, BOMB_CODE);
    const elapsed = Date.now() - started;
    assert.equal(res.ok, false);
    assert.match(res.error, /too much memory/i, 'bomb must get the friendly memory message, got: ' + res.error);
    assert.ok(elapsed < 15000, 'bomb submission must return in bounded time, took ' + elapsed + 'ms');
    const after = await fixmode.testFix(MOD, VULN, block.fixedCode);
    assert.equal(after.ok, true, 'runner must still accept good code after the bomb: ' + (after.error || ''));
  });

  await t.test('worker that sleeps past the vm timeout is killed by the wall-clock timer', async () => {
    const started = Date.now();
    const res = await fixmode.testFix(MOD, VULN, SLEEP_CODE);
    const elapsed = Date.now() - started;
    assert.equal(res.ok, false);
    assert.match(res.error, /took too long/i, 'sleeping worker must get the timeout message, got: ' + res.error);
    assert.ok(elapsed < 15000, 'wall-clock timeout must bound the run, took ' + elapsed + 'ms');
    const after = await fixmode.testFix(MOD, VULN, block.fixedCode);
    assert.equal(after.ok, true, 'runner must still accept good code after the sleeper: ' + (after.error || ''));
  });
});

test('HTTP survival and oversized bodies (P1-7, P5-4)', async (t) => {
  const { srv } = await bootLab(t);
  const block = fixmode.getFixBlock(MOD, VULN);

  await t.test('fix-mode infinite loop over HTTP: friendly timeout, lab stays up', async () => {
    const c = client(srv.base);
    const started = Date.now();
    const res = await c.postJson('/fix/' + MOD + '/' + VULN + '/test', { code: LOOP_CODE });
    const elapsed = Date.now() - started;
    assert.equal(res.status, 200, 'submission must be answered, not hang or crash');
    assert.match(res.text, /took too long/i);
    assert.ok(elapsed < 20000, 'HTTP loop submission must return in bounded time, took ' + elapsed + 'ms');
    const home = await c.get('/');
    assert.equal(home.status, 200, 'lab must still serve after the loop submission');
  });

  await t.test('fix-mode memory bomb over HTTP: friendly error, lab stays up', async () => {
    const c = client(srv.base);
    const res = await c.postJson('/fix/' + MOD + '/' + VULN + '/test', { code: BOMB_CODE });
    assert.equal(res.status, 200);
    assert.match(res.text, /too much memory/i);
    const home = await c.get('/');
    assert.equal(home.status, 200, 'lab must still serve after the bomb submission');
    // ...and fix mode itself still works end to end afterwards.
    const good = await c.postJson('/fix/' + MOD + '/' + VULN + '/test', { code: block.fixedCode });
    assert.equal(good.status, 200);
    assert.match(good.text, /Fix accepted/, 'a real fix must still pass after the hostile submissions');
  });

  await t.test('oversized JSON body returns a clean 413 (P5-4)', async () => {
    const c = client(srv.base);
    const res = await c.postJson('/fix/' + MOD + '/' + VULN + '/test', { code: 'x'.repeat(300 * 1024) });
    assert.equal(res.status, 413, 'oversized body must be 413, got ' + res.status);
    assert.match(res.text, /too large/i);
    assert.doesNotMatch(res.text, /TypeError|node_modules|at .*\.js:\d+/, '413 page must not leak a stack trace');
    const home = await c.get('/');
    assert.equal(home.status, 200, 'lab must still serve after the oversized body');
  });

  await t.test('oversized form body returns a clean 413 (P5-4)', async () => {
    const c = client(srv.base);
    const res = await c.post('/fix/' + MOD + '/' + VULN + '/test', { code: 'x'.repeat(300 * 1024) });
    assert.equal(res.status, 413, 'oversized form body must be 413, got ' + res.status);
    assert.doesNotMatch(res.text, /TypeError|node_modules|at .*\.js:\d+/, '413 page must not leak a stack trace');
  });
});
