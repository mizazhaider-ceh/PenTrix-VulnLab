'use strict';
// file:// scheme SSRF: GET /fetch-file fetches a user-supplied URL and
// honors the file:// scheme, turning the fetcher into a local file reader
// with the server's filesystem privileges. Reading a file whose content
// includes 'root:' awards the flag.
const express = require('express');
const fs = require('fs');
const { appShell, brief, esc, fixPanel, flagBox, hintLadder, page, payloadBlock } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { fetchBody, resultPage } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'ssrf-file',
  name: 'file:// scheme SSRF',
  difficulty: 'Medium',
  hint: 'This fetcher allows an extra URL scheme that reads from the local disk.',
  hints: ["The fetcher accepts URLs. Are http(s) the only schemes that fetch data?", "The file:// scheme turns the fetcher into a local file reader. Try file:///etc/passwd.", "Submit file:///etc/passwd as the URL. Look for 'root:' in the response."],
  tools: 'C',
  how: 'Fetch file:///etc/passwd via /ssrf/fetch-file.',
  link: '/ssrf#ssrf-file',
  start: 'curl -s "http://localhost:3000/ssrf/fetch-file?url=file:///etc/hostname"',
};

// Clay-styled fetcher form page. Shown when no ?url= is given; it reads like
// a small real app and never mentions the flaw.
function fetchPage(v, action, opts) {
  const o = opts || {};
  const body = `
    ${brief(o.kicker, o.briefHtml)}
    <form method="get" action="${esc(action)}" class="clay-card">
      <div class="clay-field">
        <label for="url">URL to fetch</label>
        <input class="clay-input" id="url" name="url" type="text" size="60" placeholder="${esc(o.placeholder || 'file:///etc/passwd')}" autocomplete="off" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>
    ${payloadBlock('Starting point', v.start)}
    ${hintLadder(v)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssrf">Back to the SSRF module</a></p>
  `;
  return page(v.name, appShell('FetchKit', body, { crumb: o.crumb || 'Local fetch', nav: ['Home', 'Dev tools', 'Docs'], mark: '⇄' }));
}

// GET /fetch-file -> fetches the ?url= server-side. Same behavior and flag
// condition as the module router; only the no-URL landing page is new.
router.get('/fetch-file', async (req, res) => {
  const url = String(req.query.url || '');
  const title = 'SSRF File Scheme';
  if (!url) {
    return res.send(fetchPage(vuln, '/ssrf/fetch-file', {
      kicker: 'Local fetch for developers',
      crumb: 'Local fetch',
      briefHtml: 'FetchKit Dev fetches http(s) URLs and, for local development, file:// URLs too, so you can preview local documentation through the same tool.',
      placeholder: 'file:///etc/passwd',
    }));
  }
  try {
    const parsed = new URL(url);
    let body;
    if (parsed.protocol === 'file:') {
      // VULN: the file:// scheme is allowed, turning the URL fetcher into a
      // local file reader with the server's filesystem privileges.
      body = fs.readFileSync(decodeURIComponent(parsed.pathname), 'utf8');
    } else {
      body = await fetchBody(url);
    }
    let html = `<h2>${esc(title)}</h2>`;
    html += `<p class="dim">Fetched: <code>${esc(url)}</code></p>`;
    html += `<h3>Response body</h3><pre class="resp">${esc(body)}</pre>`;
    if (body.includes('root:')) {
      html += flagBox(award(req, 'ssrf', 'ssrf-file'));
      html += fixPanel('ssrf', 'ssrf-file');
    } else {
      html += `<p class="dim">No local file content detected yet. Try <code>file:///etc/passwd</code>.</p>`;
    }
    html += `<p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssrf">&larr; Back to the SSRF module</a></p>`;
    res.send(page(title, html));
  } catch (e) {
    res.send(resultPage(title, req, url, '', e, 'ssrf', 'ssrf-file'));
  }
});

module.exports = { vuln, router };
