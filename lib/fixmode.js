// lib/fixmode.js
// Sandboxed runner core for M11 break-then-fix mode.
//
// A fix block (modules/<module>/fixes/<vulnId>.js) shows the vulnerable code
// for one challenge, lets the student edit it, and runs two checks against
// the student's code in a sandbox:
//   testExploit - a JS expression that is true when the EXPLOIT SUCCEEDS
//   testLegit   - a JS expression that is true when LEGITIMATE use WORKS
//
// A student fix is accepted only when the exploit is blocked (testExploit
// is false) and legitimate use still works (testLegit is true).

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('node:vm');

const FIXES_DIR = path.join(__dirname, '..', 'modules');
const RUN_TIMEOUT_MS = 2000;
const CODE_SIZE_LIMIT = 50 * 1024; // 50 KB
const ID_RE = /^[a-z0-9][a-z0-9_-]*$/i;

// ---- sandbox -----------------------------------------------------------

// Hardened sandbox: the context gets NO host values at all. A fresh V8
// context ships its OWN builtins (Object, Function, JSON, ...), so guest
// code only ever sees the context's own intrinsics and can never reach
// the host realm. Even the neutered console is built by a bootstrap
// script that runs INSIDE the guest context, so every function the guest
// can touch (including console.log.constructor) is a guest function.
// Passing host intrinsics in (e.g. `Object: Object`) let guest code run
// Object.constructor('return process')() and escape to the host process;
// that hole is closed. No require, no process, no real console, no file
// or network access.
const CONSOLE_METHODS = [
  'log', 'warn', 'error', 'info', 'debug', 'trace', 'dir', 'table',
  'time', 'timeEnd', 'assert', 'clear', 'count', 'countReset',
  'group', 'groupEnd', 'groupCollapsed', 'profile', 'profileEnd',
];

function makeSandbox() {
  const context = vm.createContext(Object.create(null));
  const bootstrap = new vm.Script(
    'var console = { ' +
      CONSOLE_METHODS.map(function (m) { return m + ': function () {}'; }).join(', ') +
      ' };',
    { filename: 'fix-sandbox-bootstrap.js' }
  );
  bootstrap.runInContext(context, { timeout: RUN_TIMEOUT_MS });
  return context;
}

function friendlyRunError(err) {
  if (!err) return 'Something went wrong while running the code.';
  const msg = String((err && err.message) || err);
  if (err.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT' || /timed out/i.test(msg)) {
    return 'Your code took too long to run (over 2 seconds). Check for an infinite loop and try again.';
  }
  if (err instanceof SyntaxError || /SyntaxError/.test(String(err.name))) {
    return 'There is a syntax error in the code: ' + msg;
  }
  if (/Maximum call stack size exceeded/.test(msg)) {
    return 'The code ran out of stack space (too much recursion). Simplify it and try again.';
  }
  return 'The code threw an error: ' + msg;
}

// Run `code` (which must define vulnFn), then evaluate `expression`.
// Returns { ran: true, value } or { ran: false, error } with a
// student-friendly error message.
function runCodeAndExpression(code, expression) {
  if (typeof code !== 'string' || typeof expression !== 'string') {
    return { ran: false, error: 'The code and the test must both be text.' };
  }
  if (Buffer.byteLength(code, 'utf8') > CODE_SIZE_LIMIT ||
      Buffer.byteLength(expression, 'utf8') > CODE_SIZE_LIMIT) {
    return { ran: false, error: 'The code is too large (over 50 KB). Keep the fix short.' };
  }
  let script;
  try {
    script = new vm.Script(code + '\n;(' + expression + ');', { filename: 'fix-check.js' });
  } catch (err) {
    return { ran: false, error: friendlyRunError(err) };
  }
  const context = makeSandbox();
  let value;
  try {
    value = script.runInContext(context, { timeout: RUN_TIMEOUT_MS });
  } catch (err) {
    return { ran: false, error: friendlyRunError(err) };
  }
  if (value !== null && (typeof value === 'object' || typeof value === 'function') &&
      typeof value.then === 'function') {
    return { ran: false, error: 'The test must give a plain answer, not a Promise. Keep it synchronous.' };
  }
  return { ran: true, value: value };
}

// Check that `code` defines a callable vulnFn in the sandbox.
function definesVulnFn(code) {
  const res = runCodeAndExpression(code, "typeof vulnFn === 'function'");
  if (!res.ran) return { ok: false, error: res.error };
  if (res.value !== true) {
    return { ok: false, error: 'Your code must define a function named vulnFn.' };
  }
  return { ok: true, error: null };
}

// ---- block loading -----------------------------------------------------

const listCache = { value: null };
const blockCache = new Map();

function fixesDirFor(module) {
  return path.join(FIXES_DIR, module, 'fixes');
}

function blockPathFor(module, vulnId) {
  return path.join(fixesDirFor(module), vulnId + '.js');
}

function safeId(id) {
  return typeof id === 'string' && ID_RE.test(id);
}

// Scan modules/*/fixes/*.js and return [{ module, vulnId, title }].
// The scan result is cached; call resetFixCache() to rescan.
function listFixBlocks() {
  if (listCache.value) return listCache.value.slice();
  const out = [];
  let moduleNames = [];
  try {
    moduleNames = fs.readdirSync(FIXES_DIR, { withFileTypes: true })
      .filter(function (d) { return d.isDirectory(); })
      .map(function (d) { return d.name; })
      .sort();
  } catch (err) {
    listCache.value = out;
    return out;
  }
  moduleNames.forEach(function (module) {
    const dir = fixesDirFor(module);
    let files = [];
    try {
      files = fs.readdirSync(dir).filter(function (f) { return f.endsWith('.js'); }).sort();
    } catch (err) {
      return; // no fixes dir for this module, skip
    }
    files.forEach(function (file) {
      const vulnId = file.slice(0, -3);
      if (!safeId(vulnId)) return;
      const block = getFixBlock(module, vulnId);
      if (block && typeof block.title === 'string') {
        out.push({ module: module, vulnId: vulnId, title: block.title });
      }
    });
  });
  listCache.value = out;
  return out.slice();
}

function hasFixBlock(module, vulnId) {
  return getFixBlock(module, vulnId) !== null;
}

// Return the fix block object, or null when it does not exist or
// cannot be loaded.
function getFixBlock(module, vulnId) {
  if (!safeId(module) || !safeId(vulnId)) return null;
  const key = module + ':' + vulnId;
  if (blockCache.has(key)) return blockCache.get(key);
  const file = blockPathFor(module, vulnId);
  let block = null;
  try {
    if (!fs.existsSync(file)) {
      blockCache.set(key, null);
      return null;
    }
    const loaded = require(file);
    if (loaded && typeof loaded === 'object') block = loaded;
  } catch (err) {
    block = null; // broken block file: treat as missing
  }
  blockCache.set(key, block);
  return block;
}

// Clear the cached scan and cached blocks (useful for tests).
function resetFixCache() {
  listCache.value = null;
  blockCache.clear();
}

// ---- validation and testing --------------------------------------------

// Sanity check for a fix block. The vulnerable code must really be
// vulnerable (testExploit true) and really usable (testLegit true).
// Returns { valid, error }.
function validateBlock(block) {
  if (!block || typeof block !== 'object') {
    return { valid: false, error: 'The fix exercise is empty or broken.' };
  }
  const need = ['vulnerableCode', 'fixedCode', 'testExploit', 'testLegit'];
  for (let i = 0; i < need.length; i++) {
    if (typeof block[need[i]] !== 'string' || block[need[i]].length === 0) {
      return { valid: false, error: 'The fix exercise is missing ' + need[i] + '.' };
    }
  }

  const fnCheck = definesVulnFn(block.vulnerableCode);
  if (!fnCheck.ok) {
    return { valid: false, error: 'The vulnerable code is broken: ' + fnCheck.error };
  }

  const exploitRun = runCodeAndExpression(block.vulnerableCode, block.testExploit);
  if (!exploitRun.ran) {
    return { valid: false, error: 'The exploit test could not run on the vulnerable code: ' + exploitRun.error };
  }
  if (exploitRun.value !== true) {
    return { valid: false, error: 'The vulnerable code does not show the exploit working. The exercise needs a real vulnerable example.' };
  }

  const legitRun = runCodeAndExpression(block.vulnerableCode, block.testLegit);
  if (!legitRun.ran) {
    return { valid: false, error: 'The legit test could not run on the vulnerable code: ' + legitRun.error };
  }
  if (legitRun.value !== true) {
    return { valid: false, error: 'The vulnerable code fails its own legit test. Normal use must work before it can be fixed.' };
  }

  return { valid: true, error: null };
}

// Test a student's fixed code against the block's two checks.
// Returns { ok, exploitBlocked, legitWorks, error }.
function testFix(module, vulnId, studentCode) {
  const fail = function (msg, extra) {
    return {
      ok: false,
      exploitBlocked: !!(extra && extra.exploitBlocked),
      legitWorks: !!(extra && extra.legitWorks),
      error: msg,
    };
  };

  if (typeof studentCode !== 'string' || studentCode.trim().length === 0) {
    return fail('Please paste your fixed code first.');
  }

  const block = getFixBlock(module, vulnId);
  if (!block) {
    return fail('No fix exercise found for ' + module + ' / ' + vulnId + '.');
  }

  const validation = validateBlock(block);
  if (!validation.valid) {
    return fail('This fix exercise is broken and cannot be checked: ' + validation.error);
  }

  const fnCheck = definesVulnFn(studentCode);
  if (!fnCheck.ok) {
    return fail(fnCheck.error);
  }

  const exploitRun = runCodeAndExpression(studentCode, block.testExploit);
  if (!exploitRun.ran) {
    return fail(exploitRun.error);
  }
  const exploitBlocked = exploitRun.value !== true;

  const legitRun = runCodeAndExpression(studentCode, block.testLegit);
  if (!legitRun.ran) {
    return fail(legitRun.error, { exploitBlocked: exploitBlocked, legitWorks: false });
  }
  const legitWorks = legitRun.value === true;

  if (!exploitBlocked) {
    return fail(
      'The exploit still works against your code. ' + (block.fixHint || 'Look at the hint and try again.'),
      { exploitBlocked: false, legitWorks: legitWorks }
    );
  }
  if (!legitWorks) {
    return fail(
      'The exploit is blocked, but normal use is broken too. Your fix must keep legitimate input working.',
      { exploitBlocked: true, legitWorks: false }
    );
  }

  return { ok: true, exploitBlocked: true, legitWorks: true, error: null };
}

module.exports = {
  listFixBlocks: listFixBlocks,
  hasFixBlock: hasFixBlock,
  getFixBlock: getFixBlock,
  validateBlock: validateBlock,
  testFix: testFix,
  resetFixCache: resetFixCache,
};
