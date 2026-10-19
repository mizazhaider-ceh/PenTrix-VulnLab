'use strict';
// ReDoS module shared helpers: moved verbatim from the legacy router.js so
// the split challenge files (redos-url, redos-search) keep working. Do not
// change the vulnerability behavior here.
const { award } = require('../../lib/flags');
const { esc, flagBox, page } = require('../../lib/page');

const THRESHOLD_MS = 1000;

function tooLong(s, max) {
  return s.length > max;
}

function redosForm(action, field, label, maxLen, exampleNote) {
  const inputId = 'redos-' + String(action).replace(/[^a-z0-9-]/gi, '');
  return `
    <h2>${esc(label)}</h2>
    <form method="GET" action="/redos/${action}">
      <div class="clay-field">
        <label for="${inputId}">${esc(label)}</label>
        <input class="clay-input" type="text" id="${inputId}" name="${field}" placeholder="${esc(label)}" size="50" required />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Validate</button>
    </form>
    <p class="note">Max length: ${maxLen} characters. ${exampleNote}</p>
    <p><a href="/redos">Module index</a></p>`;
}

function redosResult(req, title, input, reSource, ok, ms, vulnId, back) {
  let extra = '';
  if (ms > THRESHOLD_MS) {
    const flag = award(req, 'redos', vulnId);
    extra = `<h3>Denial of service demonstrated</h3>
      <p>The check took <b>${ms} ms</b>. On a real server, every request like
      this one blocks the event loop for everyone.</p>${flagBox(flag)}`;
  }
  return page(title, `
    <h2>${esc(title)}</h2>
    <p>Input: <code>${esc(input)}</code></p>
    <p>Pattern: <code>${esc(reSource)}</code></p>
    <p>Match: <b>${ok ? 'yes' : 'no'}</b> &middot; Time: <b>${ms} ms</b>
    (threshold: ${THRESHOLD_MS} ms)</p>
    ${extra}
    <p><a href="${back}">Try another input</a> &middot; <a href="/redos">Module index</a></p>
  `);
}

module.exports = { THRESHOLD_MS, tooLong, redosForm, redosResult };
