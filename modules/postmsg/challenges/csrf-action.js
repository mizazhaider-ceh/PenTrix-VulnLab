'use strict';
// Privileged Action via Forged Message: the account settings page listens for
// postMessage commands and deletes the lab account for ANY message shaped like
// {action:'delete-account'}, with no origin check and no user confirmation.
// The victim page's own script fires the beacon once the deletion lands, so the
// flag is only awarded for a real forged-message deletion in this session.
//
// Award evidence (D19): the victim handler is the only caller that presents
// the page-bound token when it calls the delete endpoint, and it echoes the
// same token to the beacon, which consumes it. A bare HTTP client can POST
// the delete and call the beacon, but without executing the victim page's
// script it cannot present the token, so that shortcut earns nothing.
// Cross-site header evidence (the csrf module pattern) was rejected here:
// the forged message arrives frame to frame, and every HTTP request the
// genuine flow makes is sent by the victim page to its own origin, so a
// foreign Origin or Referer check would fail the real exploit while a
// non-browser client could forge those headers anyway.
const express = require('express');
const { page, esc, payloadBlock } = require('../../../lib/page');
const { pmNonceScript } = require('../shared');

const router = express.Router();
router.use(express.urlencoded({ extended: false }));

// ---------------------------------------------------------------------------
// Lab 5 victim page: account settings for the fictional PenMail webmail app.
// ---------------------------------------------------------------------------
router.get('/csrf-action', (req, res) => {
  const deleted = req.session.pm_deleted === true;
  res.send(page('PenMail account settings', `
    <h2>PenMail account settings</h2>
    <p class="dim">Typical time: 10-25 min</p>
    <div class="clay-card">
      <div class="card-top"><b>Your account</b>
        <span class="clay-pill"><span class="dot" style="background:${deleted ? '#d64545' : '#2fa36b'}"></span>${deleted ? 'DELETED' : 'Active'}</span>
      </div>
      <p class="dim">Signed in as <b>demo@penmail.lab</b>. Manage the settings for this mailbox below.</p>
    </div>
    <div class="clay-card">
      <div class="card-top"><b>Danger zone</b></div>
      <p class="dim">Deleting your account removes the mailbox and all its messages. This cannot be undone.</p>
      <form method="POST" action="/postmsg/csrf-action/delete">
        <button class="clay-btn clay-btn-primary" type="submit">Delete my account</button>
      </form>
      <p id="status" class="dim" role="status"></p>
    </div>
    <p class="dim">Lab attacker page: <a href="/postmsg/csrf-action/attacker">open it</a> and fire the payload.
    <a href="/postmsg/csrf-action/reset">Reset the lab account</a>.</p>
    <script>
      // Page-bound token: only a handler running in this loaded page can know it.
      ${pmNonceScript(req, 'csrf-action')}
      window.addEventListener('message', function (e) {
        var action = e.data && e.data.action;
        // VULN: a state-changing action is triggered by any cross-origin
        // message with no origin check and no user confirmation.
        if (action === 'delete-account') {
          fetch('/postmsg/csrf-action/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'n=' + encodeURIComponent(PM_NONCE)
          })
            .then(function (r) { return r.json(); })
            .then(function (j) {
              document.getElementById('status').textContent = j.status;
              fetch('/postmsg/beacon?v=csrf-action&d=' + encodeURIComponent('csrf-action:account-deleted') + '&n=' + encodeURIComponent(PM_NONCE));
            });
        }
      });
    </script>
    <p><a href="/postmsg">Back to the postMessage module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// State-changing endpoint. The victim's message handler calls it, and so does
// the legitimate delete button. No CSRF token on purpose: this is the lab.
// The deletion itself always happens. What the page-bound token changes is
// the flag evidence: a deletion only counts as message-driven when the
// request presents the token the loaded victim page's script computed. The
// token is validated here but not consumed; the beacon consumes it.
// ---------------------------------------------------------------------------
router.post('/csrf-action/delete', (req, res) => {
  req.session.pm_deleted = true;
  const n = String((req.body && req.body.n) || '');
  const m = req.session.pmNonce;
  const cur = m && Object.prototype.hasOwnProperty.call(m, 'csrf-action') ? m['csrf-action'] : null;
  if (cur && n && cur === n) req.session.pm_msg_deleted = true;
  res.json({ status: 'account deleted (lab only)' });
});

// ---------------------------------------------------------------------------
// Reset helper so the lab can be replayed.
// ---------------------------------------------------------------------------
router.get('/csrf-action/reset', (req, res) => {
  req.session.pm_deleted = false;
  req.session.pm_msg_deleted = false;
  res.redirect('/postmsg/csrf-action');
});

// ---------------------------------------------------------------------------
// Lab 5 attacker page: embeds the victim settings and sends it the forged
// delete-account message. No origin is checked by the victim.
// ---------------------------------------------------------------------------
router.get('/csrf-action/attacker', (req, res) => {
  res.send(page('Attacker: forged action', `
    <h2>Attacker page (lab 5)</h2>
    <div class="clay-card">
      <div class="card-top"><b>What this page does</b></div>
      <p class="dim">This page embeds the victim's PenMail account settings in the frame below
      and sends it a message the victim treats as a command. No origin is checked.</p>
    </div>
    <iframe id="v" src="/postmsg/csrf-action" width="100%" height="260" title="Victim account settings"></iframe>
    <p><button id="fire" class="clay-btn clay-btn-primary" type="button">Fire payload</button></p>
    <p id="log" class="dim" role="status"></p>
    ${payloadBlock('Message shape', "var frame = document.getElementById('v');\nframe.contentWindow.postMessage({ <property>: '<value you found in the victim handler>' }, '*');")}
    <div class="clay-card">
      <div class="card-top"><b>How to claim this flag</b></div>
      <ol>
        <li>Press <b>Fire payload</b> above. The forged message reaches the victim frame.</li>
        <li>The victim's own script deletes the lab account and calls the beacon, which awards the flag.</li>
        <li>The widget below polls the claim endpoint and flips when the server has captured the flag.</li>
      </ol>
      <p class="dim">A bare Repeater request to the beacon gets a 400, and so does a bare delete followed by a
      beacon call: the flag only lands when the victim page's script drives the deletion in your session and
      fires the beacon with its page-bound token. In Repeater you can replay the delete request from Proxy
      history to confirm the state change, but the award itself needs the live browser flow first.</p>
      <p id="claim-status-csrf-action" class="status status-missing" role="status" data-status-url="/postmsg/claim-status?v=csrf-action"><span class="dot" aria-hidden="true"></span><span class="claim-text">Checking claim status...</span></p>
    </div>
    <script>
      document.getElementById('fire').onclick = function () {
        document.getElementById('v').contentWindow.postMessage({ action: 'delete-account' }, '*');
        document.getElementById('log').textContent = 'Message sent. Reload the victim page to see the deleted account, and check your flag.';
      };
    </script>
    <p><a href="/postmsg">Back to the postMessage module</a></p>
  `));
});

module.exports = {
  vuln: {
    id: 'csrf-action',
    name: 'Privileged Action via Forged Message',
    difficulty: 'Medium',
    hint: 'The victim handler runs a state-changing action when it sees a matching message, and it never checks the origin. Inspect the handler in the victim page source to find which message property and value it reacts to.',
    hints: ["Proxy the victim settings page in Burp and read the message listener in the response to learn which message shape it acts on.", "The attacker page posts a forged message into the victim iframe; fire it with Proxy running and watch the resulting POST to the delete endpoint.", "Repeater can replay the delete POST to confirm the state change, but replaying requests earns nothing on its own: the beacon only awards when the victim page's own script drove the deletion and presented its page-bound token, so drive the real browser flow first and inspect the beacon in Proxy history."],
    tools: "BZ, B, DT",
    how: 'Forge the message into the victim iframe from the attacker page; the victim page\'s own script then deletes the account and fires the beacon that awards the flag.',
    link: '/postmsg#csrf-action',
    start: 'Set your browser to use Burp Proxy, then visit /postmsg/csrf-action/attacker and fire the payload while Proxy watches. In Proxy history, find the victim page\'s POST to /postmsg/csrf-action/delete and the beacon call that awards the flag.',
  },
  router,
};
