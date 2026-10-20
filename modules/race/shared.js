'use strict';
// Race module shared plumbing: the check-to-use sleep window, the per-session
// lab state, a reset helper, and the back-link snippet. State is scoped per
// express-session (P1-1): one student's parallel burst cannot touch another
// student's coupons, balances, votes, accounts, uploads, limits or stock,
// and one student's reset only resets their own lab. The solo learner sees
// exactly the same behavior as the old process-global state.
const { createSessionState } = require('../../lib/session-state');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Widen the check-to-use window so parallel requests reliably interleave even
// when process-spawn stagger separates them; a single click only waits ~0.2s.
const WINDOW = () => 150 + Math.floor(Math.random() * 101); // 150-250ms

function freshState() {
  return {
    coupon: { used: false, redeems: 0, credit: 0 },
    balance: 100,
    ledger: [],
    votes: {},                 // name -> number of votes recorded
    referral: { claimed: {}, claims: 0, points: 0 },
    accounts: [],              // { username, password }
    files: {},                 // name -> { content, timer }
    ratelimit: { count: 0, rejected: 0 },
    stock: { stock: 5, sold: 0 },
  };
}

// Evicting a state object must cancel any AV-scan timers it owns, or the
// timers would keep a dead state alive in memory. The same runs on resets.
function clearTimers(state) {
  if (!state || !state.files) return;
  for (const name of Object.keys(state.files)) {
    try { clearTimeout(state.files[name].timer); } catch (e) { /* already fired */ }
  }
}

const states = createSessionState(freshState, { onEvict: clearTimers });

// state(req): the requesting session's race lab state.
function state(req) {
  return states.get(req);
}

// Alias used by the ratelimit and stock challenge files.
function raceState(req) {
  return states.get(req);
}

function resetRace(req) {
  states.reset(req);
}

// Reset link snippet: a POST form, since /race/reset is a POST-only route
// (P1-2: the old unauthenticated GET was CSRF-able and wiped everyone).
const backLink = `<form method="POST" action="/race/reset" style="display:inline"><button type="submit" class="clay-btn clay-btn-secondary clay-btn-sm">Reset lab state</button></form>`;

module.exports = { sleep, WINDOW, state, raceState, resetRace, backLink };
