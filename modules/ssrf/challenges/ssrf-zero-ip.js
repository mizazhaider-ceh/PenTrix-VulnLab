'use strict';
// 0.0.0.0 bypass: GET /zero-ip fetches a user-supplied URL behind a naive
// substring blocklist. The lab rewrites 0.0.0.0 to loopback the way many
// HTTP stacks treat it ("this host"), so the string check never fires while
// the request still reaches the server itself.
const express = require('express');
const { appShell, brief, esc, hintLadder, page, payloadBlock } = require('../../../lib/page');
const { fetchBody, guardedFetch, rawHostBlock } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'ssrf-zero-ip',
  name: '0.0.0.0 bypass',
  difficulty: 'Easy',
  hint: 'The blocklist never mentions 0.0.0.0, and this fetcher treats it as "this host".',
  hints: ["With Burp Proxy on, submit the FetchKit form once with a harmless URL, then send the request to Repeater. Read the blocklist logic: which hosts does it check, and which does it never mention?", "In Repeater, tweak the url parameter's host. Many HTTP stacks treat 0.0.0.0 as 'this host', and the blocklist never lists it.", "In Repeater, point the url parameter at the internal secret endpoint with the all-zeros address as the host, then send it and read the response."],
  tools: 'BZ, C',
  how: 'In Repeater, fetch http://0.0.0.0:PORT/ssrf/internal/secret via /ssrf/zero-ip.',
  link: '/ssrf#ssrf-zero-ip',
  start: 'With Burp Proxy on, open FetchKit (/ssrf/zero-ip), submit a harmless URL in the form, then send the fetch request to Repeater and experiment with the url parameter.',
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
      <button class="clay-btn clay-btn-primary" type="submit">Fetch preview</button>
    </form>
    ${payloadBlock('Starting point', v.start)}
    ${hintLadder(v)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/ssrf">Back to the SSRF module</a></p>
  `;
  return page(v.name, appShell('FetchKit', body, { crumb: o.crumb || 'Link preview', nav: ['Home', 'Previews', 'Docs'], mark: '⇄' }));
}

// GET /zero-ip -> fetches the ?url= server-side. Same validation and flag
// condition as the module router; only the no-URL landing page is new.
router.get('/zero-ip', (req, res) => {
  const url = String(req.query.url || '');
  if (!url) {
    return res.send(fetchPage(vuln, '/ssrf/zero-ip', {
      kicker: 'Link preview service',
      crumb: 'Link preview',
      briefHtml: 'FetchKit builds link previews for chat apps: paste a URL and our server fetches it for you. Hosts on the internal blocklist are refused by policy.',
      placeholder: 'http://0.0.0.0:PORT/ssrf/internal/secret',
    }));
  }
  guardedFetch(req, res, {
    title: 'SSRF 0.0.0.0', vulnId: 'ssrf-zero-ip', check: rawHostBlock,
    fetch: async (url) => {
      const u = new URL(url);
      // 0.0.0.0 passes the string blocklist; many HTTP stacks treat it as
      // "this host", so the lab rewrites it to loopback the way those stacks do.
      if (u.hostname === '0.0.0.0') u.hostname = '127.0.0.1';
      return fetchBody(u.toString());
    },
  });
});

module.exports = { vuln, router };
