'use strict';
// Race module shared plumbing: the check-to-use sleep window, the shared lab
// state, a reset helper, and the back-link snippet. Every race challenge and
// the module index read this file, so one reset clears all lab state.
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
    ratelimit: { count: 0 },
    stock: { stock: 5, sold: 0 },
  };
}
let R = freshState();

function state() {
  return R;
}

// Alias used by the ratelimit and stock challenge files.
function raceState() {
  return R;
}

function resetRace() {
  for (const name of Object.keys(R.files)) clearTimeout(R.files[name].timer);
  R = freshState();
}

const backLink = `<p><a href="/race">Back to module</a> · <a href="/race/reset">Reset lab state</a></p>`;

module.exports = { sleep, WINDOW, state, raceState, resetRace, backLink };
