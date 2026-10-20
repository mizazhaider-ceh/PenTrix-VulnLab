// lib/async-handler.js
// Express 4 never catches rejections from async route handlers: a throw
// after an `await` becomes an unhandledRejection, and on Node 24 that kills
// the whole lab process. Two pieces fix this for every handler at once:
//
//   ah(fn)        - wraps one async (req, res, next) handler so a rejection
//                   is forwarded to next(err), which reaches the 500 page.
//   patchExpress()- wraps Router verb methods, Router.use and app verb
//                   methods so any async function handed to them is wrapped
//                   with ah() automatically. Idempotent; covers all current
//                   and future handlers (including the race-module async
//                   handlers), with zero edits to challenge files.
//
// Only true async functions are wrapped: plain functions, middleware that
// takes (req, res, next), sub-routers and arrays pass through untouched.

'use strict';

function isAsyncFn(fn) {
  return typeof fn === 'function' &&
    fn.constructor != null &&
    fn.constructor.name === 'AsyncFunction';
}

// Wrap one async handler: rejection goes to next(err), never to the void.
function ah(fn) {
  return function asyncHandlerWrapper(req, res, next) {
    Promise.resolve()
      .then(() => fn(req, res, next))
      .catch(next);
  };
}

// Wrap the handler-shaped arguments of one Express route-registration
// method (get/post/put/patch/delete/all/use). Async functions get wrapped
// with ah(); everything else is passed through unchanged.
function wrapMethod(original) {
  if (original.__pentrixAhPatched) return original;
  const wrapped = function (...args) {
    const out = args.map((a) => (isAsyncFn(a) ? ah(a) : a));
    return original.apply(this, out);
  };
  wrapped.__pentrixAhPatched = true;
  // Keep the original name for readable stack traces.
  try {
    Object.defineProperty(wrapped, 'name', { value: original.name || 'wrapped', configurable: true });
  } catch (err) { /* name is read-only on some engines; not important */ }
  return wrapped;
}

const ROUTER_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'all', 'use'];
const APP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'all', 'use'];

// Patch the express module once. Router instances look their verb methods
// up on the Router proto object, so patching applies to routers created
// before and after this call. Application verb methods are copied onto
// each app at creation time, so this must run before express() is called,
// which app.js guarantees by requiring this module first.
function patchExpress() {
  const express = require('express');
  for (const m of ROUTER_METHODS) {
    if (typeof express.Router[m] === 'function') {
      express.Router[m] = wrapMethod(express.Router[m]);
    }
  }
  const appProto = express.application;
  if (appProto) {
    for (const m of APP_METHODS) {
      if (typeof appProto[m] === 'function') {
        appProto[m] = wrapMethod(appProto[m]);
      }
    }
  }
}

module.exports = {
  ah: ah,
  isAsyncFn: isAsyncFn,
  patchExpress: patchExpress,
};
