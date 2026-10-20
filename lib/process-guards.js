// lib/process-guards.js
// Process-level last line of defence for a shared training lab.
//
// The async-handler wrapper (lib/async-handler.js) already forwards
// rejections from Express route handlers to the error middleware. These
// guards cover everything else: a rejection nobody awaited, a timer or
// event-emitter callback that throws, a promise library hook that fires
// late. On Node 24 an unhandled rejection kills the process by default;
// for one student's lab session that would take the lab down for every
// student on the instance.
//
// Deliberate tradeoff: a handler registered for uncaughtException means
// the process keeps running with possibly torn state, which strict
// correctness guidance forbids. This lab chooses availability over the
// crash: the guards log every incident with a full stack, the process
// stays up, and the broken handler's request gets a 500 page from the
// async-handler wrapper. Every incident is visible in the server log,
// so nothing fails silently.

'use strict';

let installed = false;

function installProcessGuards() {
  if (installed) return;
  installed = true;
  process.on('unhandledRejection', (reason) => {
    console.error(
      '[guard] unhandledRejection (lab kept alive):',
      reason && reason.stack ? reason.stack : reason
    );
  });
  process.on('uncaughtException', (err) => {
    console.error(
      '[guard] uncaughtException (lab kept alive):',
      err && err.stack ? err.stack : err
    );
  });
}

module.exports = { installProcessGuards: installProcessGuards };
