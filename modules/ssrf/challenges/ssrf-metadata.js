'use strict';
// Cloud metadata SSRF: GET /fetch-meta fetches a user-supplied URL, but
// requests to the cloud link-local metadata address are answered in-process
// with simulated instance credentials that contain the secret marker.
const express = require('express');
const { appShell, brief, esc, hintLadder, page, payloadBlock } = require('../../../lib/page');
const { fetchBody, metadataDoc, resultPage } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'ssrf-metadata',
  name: 'Cloud metadata SSRF',
  difficulty: 'Medium',
  hint: 'Cloud VMs expose instance credentials at a link-local address the fetcher does not block.',
  hints: ["Cloud VMs have a metadata service at a special IP. What is it, and what does it serve?", "169.254.169.254 is the link-local metadata address. It serves IAM credentials to the instance.", "Fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/."],
  tools: 'C',
  how: 'Fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/ via /ssrf/fetch-meta.',
  link: '/ssrf#ssrf-metadata',
  start: 'curl -s "http://localhost:3000/ssrf/fetch-meta?url=http://127.0.0.1:3000/ssrf/internal/status"',
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
        <input class="clay-input" id="url" name="url" type="text" size="60" placeholder="${esc(o.placeholder || 'http://example.com/')}" autocomplete="off" />
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Fetch</button>
    </form>
    ${payloadBlock('Starting point', v.start)}
    ${hintLadder(v)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssrf">Back to the SSRF module</a></p>
  `;
  return page(v.name, appShell('FetchKit', body, { crumb: o.crumb || 'URL debugger', nav: ['Home', 'Debugger', 'Docs'], mark: '⇄' }));
}

// GET /fetch-meta -> fetches the ?url= server-side. Same behavior and flag
// condition as the module router; only the no-URL landing page is new.
router.get('/fetch-meta', async (req, res) => {
  const url = String(req.query.url || '');
  const title = 'SSRF Cloud Metadata';
  if (!url) {
    return res.send(fetchPage(vuln, '/ssrf/fetch-meta', {
      kicker: 'URL fetch debugger',
      crumb: 'URL debugger',
      briefHtml: 'FetchKit Debug fetches any URL server side and shows the raw response body, so you can inspect what an endpoint returns before calling it from your own code.',
      placeholder: 'http://169.254.169.254/latest/meta-data/',
    }));
  }
  try {
    const parsed = new URL(url);
    // VULN: the fetcher happily requests the cloud link-local metadata
    // address; this lab simulates that metadata service in-process and it
    // returns instance credentials containing the secret marker.
    const body = parsed.hostname === '169.254.169.254' ? metadataDoc() : await fetchBody(url);
    res.send(resultPage(title, req, url, body, null, 'ssrf', 'ssrf-metadata'));
  } catch (e) {
    res.send(resultPage(title, req, url, '', e, 'ssrf', 'ssrf-metadata'));
  }
});

module.exports = { vuln, router };
