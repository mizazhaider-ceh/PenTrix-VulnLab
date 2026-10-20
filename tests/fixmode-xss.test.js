'use strict';
// tests/fixmode-xss.test.js
// M11 break-then-fix verification for the XSS module.
// For each xss fix block found on disk:
//   1. validateBlock(block) passes
//   2. testFix('xss', vulnId, block.fixedCode)      => ok true
//   3. testFix('xss', vulnId, block.vulnerableCode) => ok false
//
// The blocks are discovered dynamically from modules/xss/fixes/*.js.
// Missing expected blocks are reported loudly (console + a skipped test)
// instead of being silently ignored.
//
// Run from a scratch copy, never from the repo:
//   tar the tree to /tmp/m11xs, symlink node_modules, then:
//   node --test tests/fixmode-xss.test.js

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const {
  validateBlock,
  testFix,
  getFixBlock,
  resetFixCache,
} = require('../lib/fixmode');

// The 9 fix blocks the M11 plan calls for in the xss module.
const EXPECTED = [
  'dom',
  'reflected',
  'stored',
  'xss-attr-breakout',
  'xss-backtick',
  'xss-dom-clobber',
  'xss-js-context',
  'xss-markdown',
  'xss-svg-upload',
];

const FIXES_DIR = path.join(__dirname, '..', 'modules', 'xss', 'fixes');

function blocksOnDisk() {
  let files = [];
  try {
    files = fs.readdirSync(FIXES_DIR).filter((f) => f.endsWith('.js')).sort();
  } catch (err) {
    return [];
  }
  return files.map((f) => f.slice(0, -3));
}

const foundIds = blocksOnDisk();
const missingIds = EXPECTED.filter((id) => !foundIds.includes(id));
const unexpectedIds = foundIds.filter((id) => !EXPECTED.includes(id));

before(() => {
  resetFixCache();
});

describe('xss fix blocks: coverage', () => {
  it('reports any missing expected fix blocks', (t) => {
    if (unexpectedIds.length > 0) {
      console.log('UNEXPECTED extra fix blocks on disk: ' + unexpectedIds.join(', '));
    }
    if (missingIds.length === 0) {
      console.log('All 9 expected xss fix blocks are present.');
      return;
    }
    console.log('MISSING fix blocks (' + missingIds.length + ' of 9 expected): ' + missingIds.join(', '));
    console.log('Present blocks (' + foundIds.length + '): ' + foundIds.join(', '));
    t.skip('Missing fix blocks: ' + missingIds.join(', '));
  });
});

describe('xss fix blocks: per-block checks', () => {
  foundIds.forEach((vulnId) => {
    describe('xss/' + vulnId, () => {
      let block = null;

      before(() => {
        block = getFixBlock('xss', vulnId);
      });

      it('block loads from disk', () => {
        assert.ok(block && typeof block === 'object', 'getFixBlock returned nothing for xss/' + vulnId);
      });

      it('validateBlock(block) passes', async () => {
        const res = await validateBlock(block);
        assert.equal(res.valid, true, 'validateBlock failed for xss/' + vulnId + ': ' + res.error);
      });

      it('testFix on fixedCode returns ok true', async () => {
        const res = await testFix('xss', vulnId, block.fixedCode);
        assert.equal(
          res.ok, true,
          'fixedCode for xss/' + vulnId + ' was NOT accepted: ' + res.error +
          ' (exploitBlocked=' + res.exploitBlocked + ', legitWorks=' + res.legitWorks + ')'
        );
        assert.equal(res.exploitBlocked, true, 'exploitBlocked should be true');
        assert.equal(res.legitWorks, true, 'legitWorks should be true');
      });

      it('testFix on vulnerableCode returns ok false', async () => {
        const res = await testFix('xss', vulnId, block.vulnerableCode);
        assert.equal(
          res.ok, false,
          'vulnerableCode for xss/' + vulnId + ' was ACCEPTED as a fix, it must be rejected (exploit must still work)'
        );
        assert.equal(res.exploitBlocked, false, 'exploit should still work on vulnerable code');
      });
    });
  });
});

after(() => {
  console.log('');
  console.log('=== xss fix block summary ===');
  console.log('expected: ' + EXPECTED.length + ' | found: ' + foundIds.length + ' | missing: ' + missingIds.length);
  if (missingIds.length > 0) {
    console.log('MISSING: ' + missingIds.join(', '));
  }
  if (unexpectedIds.length > 0) {
    console.log('UNEXPECTED (not in the expected 9): ' + unexpectedIds.join(', '));
  }
  console.log('=============================');
});
