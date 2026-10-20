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
//
// Runner hardening: student code NEVER runs on the lab's main thread.
// Every check runs in a short-lived worker thread (lib/fix-worker.js)
// with hard V8 resourceLimits (memory cap) plus a wall-clock timeout in
// this file, so an infinite loop or a giant allocation can only kill the
// throwaway worker, not the lab process, and a submission never blocks
// the event loop for other students. All runner entry points are async.

'use strict';

const fs = require('fs');
const path = require('path');
const { Worker } = require('node:worker_threads');

const FIXES_DIR = path.join(__dirname, '..', 'modules');
const WORKER_PATH = path.join(__dirname, 'fix-worker.js');
const RUN_TIMEOUT_MS = 2000; // vm-level cap on one script run, inside the worker
const WALL_CLOCK_TIMEOUT_MS = 6000; // parent-side cap: spawn + run + reply
const WORKER_OLD_GEN_MB = 96; // memory cap for student code (resourceLimits)
const WORKER_YOUNG_GEN_MB = 32;
const CODE_SIZE_LIMIT = 50 * 1024; // 50 KB
const ID_RE = /^[a-z0-9][a-z0-9_-]*$/i;

// ---- sandbox runner (worker-isolated) ----------------------------------

// The sandbox itself (fresh V8 context, guest-only intrinsics, neutered
// console built inside the guest context) lives in lib/fix-worker.js.
// Errors come back as plain { name, message, code } descriptors, so this
// formatter works on descriptors, not live error objects.
function friendlyRunError(err) {
  if (!err) return 'Something went wrong while running the code.';
  const msg = String((err && err.message) || err);
  if (err.code === 'ERR_WORKER_OUT_OF_MEMORY' || /out of memory/i.test(msg)) {
    return 'Your code used too much memory and was stopped. Work with less data and try again.';
  }
  if (err.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT' || err.code === 'PENTRIX_WALL_CLOCK_TIMEOUT' ||
      /timed out/i.test(msg)) {
    return 'Your code took too long to run (over 2 seconds). Check for an infinite loop and try again.';
  }
  if (/SyntaxError/.test(String(err.name)) || /SyntaxError/.test(msg)) {
    return 'There is a syntax error in the code: ' + msg;
  }
  if (/Maximum call stack size exceeded/.test(msg)) {
    return 'The code ran out of stack space (too much recursion). Simplify it and try again.';
  }
  return 'The code threw an error: ' + msg;
}

// Run one check in a fresh worker thread. Always resolves (never rejects)
// with { ran: true, value } or { ran: false, error } where error is a
// student-friendly message.
function runInWorker(code, expression) {
  return new Promise((resolve) => {
    let settled = false;
    let worker = null;
    let timer = null;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      if (worker) {
        // Fire and forget: the worker exits on its own once its script
        // finishes; terminate() only matters for a stuck worker, and its
        // rejection (worker already gone) is not an error for us.
        worker.terminate().catch(() => {});
      }
      resolve(result);
    };
    try {
      worker = new Worker(WORKER_PATH, {
        workerData: { code: code, expression: expression, runTimeoutMs: RUN_TIMEOUT_MS },
        resourceLimits: {
          maxOldGenerationSizeMb: WORKER_OLD_GEN_MB,
          maxYoungGenerationSizeMb: WORKER_YOUNG_GEN_MB,
        },
      });
    } catch (err) {
      finish({ ran: false, error: friendlyRunError(err) });
      return;
    }
    timer = setTimeout(() => {
      finish({
        ran: false,
        error: friendlyRunError({
          name: 'Error',
          message: 'The run exceeded its wall-clock time limit.',
          code: 'PENTRIX_WALL_CLOCK_TIMEOUT',
        }),
      });
    }, WALL_CLOCK_TIMEOUT_MS);
    worker.on('message', (msg) => {
      if (!msg || typeof msg !== 'object') {
        finish({ ran: false, error: 'Something went wrong while running the code.' });
        return;
      }
      if (msg.ran !== true) {
        if (msg.promise) {
          finish({ ran: false, error: 'The test must give a plain answer, not a Promise. Keep it synchronous.' });
          return;
        }
        finish({ ran: false, error: friendlyRunError(msg.error) });
        return;
      }
      // A non-cloneable result (function, symbol, ...) is never `true`,
      // which is all callers compare against, so undefined is exact.
      finish({ ran: true, value: msg.uncloneable ? undefined : msg.value });
    });
    worker.on('error', (err) => {
      finish({
        ran: false,
        error: friendlyRunError({
          name: String((err && err.name) || 'Error'),
          message: String((err && err.message) || err),
          code: err && err.code ? String(err.code) : '',
        }),
      });
    });
    worker.on('exit', (exitCode) => {
      // Normal path: the 'message' handler already settled. Reaching here
      // unsettled means the worker died silently (for example the thread
      // was aborted by the runtime) before it could report a result.
      finish({
        ran: false,
        error: 'The code runner stopped before it could finish (exit ' + exitCode + '). Simplify your code and try again.',
      });
    });
  });
}

// Run `code` (which must define vulnFn), then evaluate `expression`.
// Resolves to { ran: true, value } or { ran: false, error } with a
// student-friendly error message.
async function runCodeAndExpression(code, expression) {
  if (typeof code !== 'string' || typeof expression !== 'string') {
    return { ran: false, error: 'The code and the test must both be text.' };
  }
  if (Buffer.byteLength(code, 'utf8') > CODE_SIZE_LIMIT ||
      Buffer.byteLength(expression, 'utf8') > CODE_SIZE_LIMIT) {
    return { ran: false, error: 'The code is too large (over 50 KB). Keep the fix short.' };
  }
  return runInWorker(code, expression);
}

// Check that `code` defines a callable vulnFn in the sandbox.
async function definesVulnFn(code) {
  const res = await runCodeAndExpression(code, "typeof vulnFn === 'function'");
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
// Resolves to { valid, error }.
async function validateBlock(block) {
  if (!block || typeof block !== 'object') {
    return { valid: false, error: 'The fix exercise is empty or broken.' };
  }
  const need = ['vulnerableCode', 'fixedCode', 'testExploit', 'testLegit'];
  for (let i = 0; i < need.length; i++) {
    if (typeof block[need[i]] !== 'string' || block[need[i]].length === 0) {
      return { valid: false, error: 'The fix exercise is missing ' + need[i] + '.' };
    }
  }

  const fnCheck = await definesVulnFn(block.vulnerableCode);
  if (!fnCheck.ok) {
    return { valid: false, error: 'The vulnerable code is broken: ' + fnCheck.error };
  }

  const exploitRun = await runCodeAndExpression(block.vulnerableCode, block.testExploit);
  if (!exploitRun.ran) {
    return { valid: false, error: 'The exploit test could not run on the vulnerable code: ' + exploitRun.error };
  }
  if (exploitRun.value !== true) {
    return { valid: false, error: 'The vulnerable code does not show the exploit working. The exercise needs a real vulnerable example.' };
  }

  const legitRun = await runCodeAndExpression(block.vulnerableCode, block.testLegit);
  if (!legitRun.ran) {
    return { valid: false, error: 'The legit test could not run on the vulnerable code: ' + legitRun.error };
  }
  if (legitRun.value !== true) {
    return { valid: false, error: 'The vulnerable code fails its own legit test. Normal use must work before it can be fixed.' };
  }

  return { valid: true, error: null };
}

// Test a student's fixed code against the block's two checks.
// Resolves to { ok, exploitBlocked, legitWorks, error }.
async function testFix(module, vulnId, studentCode) {
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

  const validation = await validateBlock(block);
  if (!validation.valid) {
    return fail('This fix exercise is broken and cannot be checked: ' + validation.error);
  }

  const fnCheck = await definesVulnFn(studentCode);
  if (!fnCheck.ok) {
    return fail(fnCheck.error);
  }

  const exploitRun = await runCodeAndExpression(studentCode, block.testExploit);
  if (!exploitRun.ran) {
    return fail(exploitRun.error);
  }
  const exploitBlocked = exploitRun.value !== true;

  const legitRun = await runCodeAndExpression(studentCode, block.testLegit);
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
