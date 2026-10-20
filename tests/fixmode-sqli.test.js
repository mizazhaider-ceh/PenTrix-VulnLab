'use strict';
// tests/fixmode-sqli.test.js
// M11 break-then-fix: per-block checks for the sqli fix blocks.
// For each block found under modules/sqli/fixes/:
//   1. validateBlock(block) passes
//   2. testFix('sqli', vulnId, block.fixedCode) returns ok true
//   3. testFix('sqli', vulnId, block.vulnerableCode) returns ok false
// The test iterates dynamically over the blocks found on disk and reports
// missing expected blocks clearly (loud failure, not a silent skip).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { validateBlock, testFix, getFixBlock, resetFixCache } = require('../lib/fixmode');

// The full set of sqli fix blocks expected once all M11 workers finish.
const EXPECTED_VULN_IDS = [
  'login-bypass',
  'union',
  'blind',
  'error',
  'second-order',
  'insert-inject',
  'like-wildcard',
  'groupby-having',
  'order-by',
  'limit-offset',
  'union-filter-bypass',
];

// The shape every fix block must expose (per lib/fixmode.js contract).
const REQUIRED_STRING_FIELDS = [
  'module',
  'vulnId',
  'title',
  'language',
  'vulnerableCode',
  'fixedCode',
  'testExploit',
  'testLegit',
  'exploitDescription',
  'fixHint',
];

const fixesDir = path.join(__dirname, '..', 'modules', 'sqli', 'fixes');

function blocksOnDisk() {
  resetFixCache();
  let files = [];
  try {
    files = fs.readdirSync(fixesDir).filter(function (f) { return f.endsWith('.js'); }).sort();
  } catch (err) {
    return [];
  }
  return files.map(function (f) { return f.slice(0, -3); });
}

const foundIds = blocksOnDisk();

describe('sqli fix blocks (M11 break-then-fix)', function () {
  it('reports every expected block that is missing from disk', function () {
    const missing = EXPECTED_VULN_IDS.filter(function (id) { return !foundIds.includes(id); });
    assert.strictEqual(
      missing.length,
      0,
      'MISSING sqli fix blocks (not on disk yet): ' + missing.join(', ') +
      '. Found on disk: ' + (foundIds.join(', ') || '(none)') +
      '. Each missing block must be written at modules/sqli/fixes/<vulnId>.js.'
    );
  });

  for (const vulnId of foundIds) {
    describe('block: ' + vulnId, function () {
      let block = null;

      it('loads and exposes the required export shape', function () {
        block = getFixBlock('sqli', vulnId);
        assert.ok(block && typeof block === 'object', 'getFixBlock returned no block object');
        for (const field of REQUIRED_STRING_FIELDS) {
          assert.strictEqual(
            typeof block[field],
            'string',
            'block is missing or has a non-string field: ' + field
          );
          assert.ok(block[field].length > 0, 'block field is empty: ' + field);
        }
        assert.strictEqual(block.module, 'sqli', 'block.module must be "sqli"');
        assert.strictEqual(block.vulnId, vulnId, 'block.vulnId must match its filename');
      });

      it('1. validateBlock(block) passes', async function () {
        block = block || getFixBlock('sqli', vulnId);
        const res = await validateBlock(block);
        assert.strictEqual(res.valid, true, 'validateBlock failed: ' + res.error);
      });

      it('2. testFix with the fixed code returns ok true', async function () {
        block = block || getFixBlock('sqli', vulnId);
        const res = await testFix('sqli', vulnId, block.fixedCode);
        assert.strictEqual(res.ok, true,
          'fixed code rejected. exploitBlocked=' + res.exploitBlocked +
          ' legitWorks=' + res.legitWorks + ' error=' + res.error);
      });

      it('3. testFix with the vulnerable code returns ok false', async function () {
        block = block || getFixBlock('sqli', vulnId);
        const res = await testFix('sqli', vulnId, block.vulnerableCode);
        assert.strictEqual(res.ok, false,
          'vulnerable code was accepted as a fix. This block cannot teach the fix.');
        assert.strictEqual(res.exploitBlocked, false,
          'vulnerable code did not let the exploit succeed (exploitBlocked should be false)');
      });
    });
  }
});
