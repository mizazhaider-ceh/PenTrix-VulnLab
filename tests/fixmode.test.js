'use strict';
// M11 break-then-fix mode: fix-block discovery, validation and sandboxed
// student-code checks in lib/fixmode.js.
//
// The pilot set is 20 fix blocks (11 sqli + 9 xss), written by the fix-block
// workers. Tests iterate over listFixBlocks() dynamically. If fewer than 20
// blocks exist, the suite skips gracefully with a clear message instead of
// failing.
const test = require('node:test');
const assert = require('node:assert/strict');
const fixmode = require('../lib/fixmode');

const blocks = fixmode.listFixBlocks();
const EXPECTED_TOTAL = 20;
const READY = blocks.length >= EXPECTED_TOTAL;

if (!READY) {
  test('fix-mode pilot suite', (t) => {
    t.skip(
      'Only ' + blocks.length + '/' + EXPECTED_TOTAL +
      ' fix blocks exist right now (need 11 sqli + 9 xss). ' +
      'The fix-block workers are still writing them, so this suite skips ' +
      'until the full pilot set is present.'
    );
  });
} else {
  test('fix-mode pilot suite', async (t) => {
    await t.test('listFixBlocks returns the 20 pilot blocks, 11 sqli + 9 xss', () => {
      assert.equal(blocks.length, EXPECTED_TOTAL, 'pilot block count');
      const sqli = blocks.filter((b) => b.module === 'sqli');
      const xss = blocks.filter((b) => b.module === 'xss');
      assert.equal(sqli.length, 11, 'sqli pilot blocks');
      assert.equal(xss.length, 9, 'xss pilot blocks');
      for (const b of blocks) {
        assert.ok(typeof b.module === 'string' && b.module.length > 0, 'module set');
        assert.ok(typeof b.vulnId === 'string' && b.vulnId.length > 0, 'vulnId set');
        assert.ok(typeof b.title === 'string' && b.title.length > 0, 'title set');
      }
      const seen = new Set(blocks.map((b) => b.module + ':' + b.vulnId));
      assert.equal(seen.size, blocks.length, 'no duplicate blocks');
    });

    await t.test('hasFixBlock: true for a real pilot block, false for a missing one', () => {
      assert.equal(fixmode.hasFixBlock('sqli', 'login-bypass'), true);
      assert.equal(fixmode.hasFixBlock('ssrf', 'basic'), false);
      assert.equal(fixmode.hasFixBlock('nope', 'nope'), false);
      const block = fixmode.getFixBlock('sqli', 'login-bypass');
      assert.ok(block && typeof block === 'object', 'real block loads');
      assert.equal(fixmode.getFixBlock('ssrf', 'basic'), null, 'missing block is null');
    });

    await t.test('validateBlock passes for every pilot block', async () => {
      for (const b of blocks) {
        const block = fixmode.getFixBlock(b.module, b.vulnId);
        const res = await fixmode.validateBlock(block);
        assert.equal(res.valid, true, b.module + '/' + b.vulnId + ': ' + (res.error || ''));
        assert.equal(res.error, null);
      }
    });

    await t.test('validateBlock rejects a deliberately broken block', async () => {
      const good = fixmode.getFixBlock('sqli', 'login-bypass');
      const broken = Object.assign({}, good, { testExploit: '1 === 2' });
      const res = await fixmode.validateBlock(broken);
      assert.equal(res.valid, false, 'broken block must fail validation');
      assert.ok(typeof res.error === 'string' && res.error.length > 0, 'error message present');
      const empty = await fixmode.validateBlock(null);
      assert.equal(empty.valid, false);
      const missingField = Object.assign({}, good, { vulnerableCode: '' });
      assert.equal((await fixmode.validateBlock(missingField)).valid, false);
    });

    await t.test('testFix with the reference fixedCode accepts 3 sample blocks', async () => {
      const sample = blocks.slice(0, 3);
      assert.equal(sample.length, 3);
      for (const b of sample) {
        const block = fixmode.getFixBlock(b.module, b.vulnId);
        const res = await fixmode.testFix(b.module, b.vulnId, block.fixedCode);
        assert.equal(res.ok, true, b.module + '/' + b.vulnId + ': ' + (res.error || ''));
        assert.equal(res.exploitBlocked, true);
        assert.equal(res.legitWorks, true);
        assert.equal(res.error, null);
      }
    });

    await t.test('testFix with the vulnerable code rejects (exploit still works)', async () => {
      const b = blocks[0];
      const block = fixmode.getFixBlock(b.module, b.vulnId);
      const res = await fixmode.testFix(b.module, b.vulnId, block.vulnerableCode);
      assert.equal(res.ok, false);
      assert.equal(res.exploitBlocked, false, 'exploit must still be reported as working');
      assert.ok(typeof res.error === 'string' && res.error.length > 0, 'error message present');
    });

    await t.test('testFix with code that breaks legit use rejects with legitWorks false', async () => {
      const b = blocks[0];
      const throwing = 'function vulnFn() { throw new Error("broken on purpose"); }';
      const res = await fixmode.testFix(b.module, b.vulnId, throwing);
      assert.equal(res.ok, false);
      assert.equal(res.legitWorks, false, 'legit use must be reported as broken');
      assert.ok(typeof res.error === 'string' && res.error.length > 0, 'error message present');
    });

    await t.test('testFix with syntactically invalid JS fails cleanly, no crash', async () => {
      const b = blocks[0];
      const res = await fixmode.testFix(b.module, b.vulnId, 'function vulnFn( { this is not valid javascript');
      assert.equal(res.ok, false);
      assert.ok(typeof res.error === 'string' && res.error.length > 0, 'syntax error message present');
    });

    await t.test('testFix with an infinite loop fails fast (sandbox timeout), no hang', async () => {
      const b = blocks[0];
      const looping = 'function vulnFn() { return 1; }\nwhile (true) {}';
      const started = Date.now();
      const res = await fixmode.testFix(b.module, b.vulnId, looping);
      const elapsed = Date.now() - started;
      assert.equal(res.ok, false);
      assert.ok(typeof res.error === 'string' && res.error.length > 0, 'timeout error message present');
      assert.ok(elapsed < 15000, 'must return within a bounded time, took ' + elapsed + 'ms');
    });

    await t.test('testFix on a block that does not exist fails with a clear message', async () => {
      const res = await fixmode.testFix('ssrf', 'basic', 'function vulnFn() { return 1; }');
      assert.equal(res.ok, false);
      assert.ok(/No fix exercise found/.test(res.error), 'clear not-found message');
    });

    await t.test('testFix with empty student code asks for code', async () => {
      const b = blocks[0];
      const res = await fixmode.testFix(b.module, b.vulnId, '   ');
      assert.equal(res.ok, false);
      assert.ok(typeof res.error === 'string' && res.error.length > 0);
    });
  });
}
