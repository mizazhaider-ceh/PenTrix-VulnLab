'use strict';
// XSS via naive markdown links: javascript: URLs survive the renderer.
const express = require('express');
const { page, esc, claimBox, fixCta } = require('../../../lib/page');
const { xssNonceTag, beacon, siteFrame, backLinks } = require('../shared');

const router = express.Router();

function naiveMarkdown(src) {
  let html = String(src);
  // VULN: link URLs pass through with no scheme validation, so javascript: URLs survive.
  // The URL part allows one level of balanced parentheses, like most real renderers.
  html = html.replace(/\[([^\]]+)\]\(((?:[^()\s]|\([^()\s]*\))+)\)/g, '<a href="$2">$1</a>');
  html = html.replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
  html = html.replace(/\n/g, '<br>');
  return html;
}

function notesPage(req, md, rendered) {
  const output = rendered === null
    ? '<p class="dim">Your rendered note appears here.</p>'
    : `<h3>Rendered note</h3>
      <div class="card">${rendered}</div>
      <h3>Source</h3>
      <pre><code>${esc(md)}</code></pre>`;
  return page('Notes preview · Inkwell Notes', `
    <h2>Inkwell Notes</h2>
    ${xssNonceTag(req, 'xss-markdown')}
    ${siteFrame('Inkwell Notes', ['Notebooks', 'Preview', 'Share'], `
      <p>Write a note in markdown. Links, <code>**bold**</code> text and line breaks are rendered.</p>
      <form method="POST" action="/xss/markdown">
        <div class="clay-field">
          <label for="md">Markdown</label>
          <textarea class="clay-input" id="md" name="md" rows="6" placeholder="Meeting notes: **agenda** and a [link](https://example.com)" required>${esc(md)}</textarea>
        </div>
        <button class="clay-btn clay-btn-primary" type="submit">Render</button>
      </form>
      ${output}`)}
    ${claimBox({ vulnId: 'xss-markdown', payload: esc(`[x](javascript:${beacon('xss-markdown')})`), statusUrl: '/xss/claim-status?v=xss-markdown', beaconInfo: 'Render the note first, then click the rendered link to fire the javascript: URL.' })}
    ${fixCta('xss', 'xss-markdown')}
    ${backLinks('xss-markdown')}
  `);
}

router.get('/markdown', (req, res) => {
  res.send(notesPage(req, '', null));
});

router.post('/markdown', (req, res) => {
  const md = String(req.body.md || '').slice(0, 5000);
  // VULN: naive markdown turns [text](javascript:...) into a live javascript: link.
  res.send(notesPage(req, md, naiveMarkdown(md)));
});

module.exports = {
  vuln: {
    id: 'xss-markdown',
    name: 'XSS via Naive Markdown Links',
    difficulty: 'Medium',
    est: 'about 10 to 25 minutes',
    hint: 'The renderer turns [text](url) into a link but never checks the URL scheme. Links are not limited to http(s).',
    hints: [
      'Intercept the Render POST in Burp Proxy and send it to Repeater. The renderer turns [text](url) into a link: what URL schemes can a link carry?',
      'The renderer never checks the URL scheme. A javascript: URL in the link target runs code when the rendered link is clicked.',
      'In Repeater, submit a markdown link whose target is a javascript: URL that calls /xss/collect (parameters c, v=xss-markdown and n=window.__px). Load the rendered note in your proxied browser and click the link.',
    ],
    tools: 'BZ, B',
    how: 'In Burp, replay the Render POST in Repeater so the link target becomes a javascript: URL, then click the rendered link in the proxied browser.',
    link: '/xss/markdown',
    start: 'Start Burp Proxy, browse to /xss/markdown in your proxied browser, and render a note normally. Send the captured POST to Repeater and watch how the md value lands inside <a href="..."> in the response, then open the rendered note and click the link to fire the beacon.',
  },
  router,
};
