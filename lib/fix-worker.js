// lib/fix-worker.js
// Worker-thread entry for the fix-mode sandbox (lib/fixmode.js).
//
// Student code never runs on the lab's main thread. Each check (one code
// string plus one test expression) runs here, inside a worker thread with
// hard resourceLimits, so a memory blow-up or a stuck loop can only kill
// this throwaway worker, never the lab process. The worker builds the same
// hardened vm sandbox the runner used before (fresh V8 context, guest-only
// intrinsics, neutered console built inside the guest context), runs the
// script once, and posts back a plain result object:
//
//   { ran: true, value }            expression evaluated; value is cloneable
//   { ran: true, uncloneable: true } expression evaluated to a function,
//                                   symbol or other non-cloneable value
//   { ran: false, promise: true }   expression returned a thenable
//   { ran: false, error: { name, message, code } }
//
// Errors travel as plain fields because a vm error object from the guest
// context cannot be posted to the parent thread reliably.

'use strict';

const { parentPort, workerData } = require('node:worker_threads');
const vm = require('node:vm');

const CONSOLE_METHODS = [
  'log', 'warn', 'error', 'info', 'debug', 'trace', 'dir', 'table',
  'time', 'timeEnd', 'assert', 'clear', 'count', 'countReset',
  'group', 'groupEnd', 'groupCollapsed', 'profile', 'profileEnd',
];

// Same sandbox shape as the pre-worker runner: the context gets NO host
// values at all, so guest code only ever sees its own context intrinsics
// and can never reach the host realm (see the note in lib/fixmode.js
// history: passing host intrinsics in let guest code escape).
function makeSandbox(runTimeoutMs) {
  const context = vm.createContext(Object.create(null));
  const bootstrap = new vm.Script(
    'var console = { ' +
      CONSOLE_METHODS.map(function (m) { return m + ': function () {}'; }).join(', ') +
      ' };',
    { filename: 'fix-sandbox-bootstrap.js' }
  );
  bootstrap.runInContext(context, { timeout: runTimeoutMs });
  return context;
}

function describeError(err) {
  return {
    name: String((err && err.name) || 'Error'),
    message: String((err && err.message) || err),
    code: err && err.code ? String(err.code) : '',
  };
}

function main() {
  const code = workerData && workerData.code;
  const expression = workerData && workerData.expression;
  const runTimeoutMs = (workerData && workerData.runTimeoutMs) || 2000;

  let script;
  try {
    script = new vm.Script(code + '\n;(' + expression + ');', { filename: 'fix-check.js' });
  } catch (err) {
    parentPort.postMessage({ ran: false, error: describeError(err) });
    return;
  }

  const context = makeSandbox(runTimeoutMs);
  let value;
  try {
    value = script.runInContext(context, { timeout: runTimeoutMs });
  } catch (err) {
    parentPort.postMessage({ ran: false, error: describeError(err) });
    return;
  }

  if (value !== null && (typeof value === 'object' || typeof value === 'function') &&
      typeof value.then === 'function') {
    parentPort.postMessage({ ran: false, promise: true });
    return;
  }

  try {
    parentPort.postMessage({ ran: true, value: value });
  } catch (cloneErr) {
    // Functions, symbols and similar values cannot cross the thread
    // boundary. Report that the run succeeded; callers only ever compare
    // the value against `true`, and a non-cloneable value is never true.
    parentPort.postMessage({ ran: true, uncloneable: true });
  }
}

main();
