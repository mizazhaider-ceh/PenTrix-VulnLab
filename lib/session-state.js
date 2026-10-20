'use strict';
// Per-session challenge state buckets (P1-1).
//
// Several labs used to keep their challenge state in process-global
// variables, so on a shared instance one student's actions leaked into every
// other student's lab: a redeemed coupon was redeemed for everyone, a poisoned
// cache served its flag to the next visitor, a reset wiped all students at
// once. This helper gives each express-session its own state object instead.
//
// The buckets live in process memory (keyed by session id), NOT in
// req.session: some state is not JSON-serializable (the race lab stores
// timer handles) and some must survive inside a single request burst without
// a store round trip per scheduled deletion.
//
// Lifecycle: a bucket is created on first use and dropped when it has been
// idle for the TTL (which matches the session store's own default), or when
// the lab's reset path calls reset(). A periodic sweep enforces the TTL so
// the map cannot grow without bound.
const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000; // matches SqliteStore default
const SWEEP_MS = 60 * 60 * 1000;

function createSessionState(factory, opts = {}) {
  const buckets = new Map(); // session id -> { state, touched }
  const ttlMs = opts.ttlMs || DEFAULT_TTL_MS;
  const onEvict = opts.onEvict || null;

  function evict(sid) {
    const b = buckets.get(sid);
    if (!b) return;
    buckets.delete(sid);
    if (onEvict) {
      try { onEvict(b.state); } catch (e) { /* eviction cleanup must never throw */ }
    }
  }

  const sweepTimer = setInterval(() => {
    const now = Date.now();
    for (const [sid, b] of buckets) {
      if (now - b.touched > ttlMs) evict(sid);
    }
  }, SWEEP_MS);
  sweepTimer.unref();

  function sidOf(req) {
    return req.sessionID || (req.session && req.session.id) || null;
  }

  // Return this session's state object, creating it on first use. Also marks
  // the session as touched so express-session persists it (and pins the
  // session id via Set-Cookie) even when the handler stores nothing else:
  // with saveUninitialized off, an untouched session gets a fresh id on every
  // request and per-session keying would fall apart.
  function get(req) {
    const sid = sidOf(req);
    if (!sid) throw new Error('session-state: request has no session id (is the session middleware mounted?)');
    if (req.session && !req.session.__labState) req.session.__labState = 1;
    let b = buckets.get(sid);
    if (!b) {
      b = { state: factory(), touched: Date.now() };
      buckets.set(sid, b);
    }
    b.touched = Date.now();
    return b.state;
  }

  // Read this session's state without creating it (null when absent).
  function peek(req) {
    const sid = sidOf(req);
    return peekSid(sid);
  }

  // Read another session's state by raw session id, without creating it and
  // without touching the requesting session. Used for capability-URL
  // lookups (the XXE collector's per-session DTD URL), where the fetching
  // party has no session cookie of its own.
  function peekSid(sid) {
    const b = sid ? buckets.get(sid) : null;
    return b ? b.state : null;
  }

  // Drop this session's state (running the evict cleanup) and hand back a
  // fresh one. Only the requesting session is affected.
  function reset(req) {
    const sid = sidOf(req);
    if (sid) evict(sid);
    return get(req);
  }

  return { get, peek, peekSid, reset, _size: () => buckets.size };
}

module.exports = { createSessionState };
