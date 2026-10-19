'use strict';
// XXE in SOAP Endpoint: a second XML endpoint expecting a SOAP envelope. It
// runs the same naive entity-expanding parser over whatever is sent before
// reading the Body.
const express = require('express');
const { page, esc, brief, flagBox, fixPanel, hintLadder, appShell } = require('../../../lib/page');
const { award } = require('../../../lib/flags');
const { expandEntities, SECRET_ABS } = require('../shared');

const router = express.Router();

const vuln = {
  id: 'xxe-soap',
  name: 'XXE in SOAP Endpoint',
  difficulty: 'Easy',
  hint: 'A second XML endpoint with the same naive parser, this time expecting a SOAP envelope. The DOCTYPE rides along the same way.',
  hints: ["SOAP messages are XML envelopes. Does this SOAP endpoint parse entities?", "Same XXE as the basic lab, wrapped in a SOAP envelope. The parser doesn't care about the wrapper.", "Send the file-read entity payload inside a SOAP <Envelope>."],
  tools: "C",
  how: 'Send a SOAP envelope whose DOCTYPE declares a file:// entity for secret.txt and references it inside <soap:Body>.',
  link: '/xxe#xxe-soap',
  start: 'curl -s http://localhost:3000/xxe/soap\ncurl -s -X POST --data-urlencode "xml=<soap:Envelope><soap:Body><GetStatus>hi</GetStatus></soap:Body></soap:Envelope>" http://localhost:3000/xxe/soap',
};

const chrome = (crumb) => ({
  nav: ['Status', 'Docs', 'API keys'],
  crumb,
  mark: '◉',
});

// ---- v8: SOAP endpoint ----
router.get('/soap', (req, res) => {
  const sample = `<?xml version="1.0"?>\n<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n  <soap:Body>\n    <GetStatus>hello</GetStatus>\n  </soap:Body>\n</soap:Envelope>`;
  res.send(page('SOAP XXE', appShell('FleetStatus API', `
    <h1>SOAP status service</h1>
    ${brief('SOAP status service', `
      <p>Send a SOAP envelope to query service status. The gateway parses the envelope with the
      standard XML importer, DOCTYPE included, then reads the <code>&lt;soap:Body&gt;</code>
      to build the response.</p>`)}
    <form class="clay-card" method="POST" action="/xxe/soap">
      <div class="card-top"><b>SOAP request</b></div>
      <div class="clay-field">
        <label for="xml">Envelope XML</label>
        <textarea id="xml" name="xml" rows="12" cols="80">${esc(sample)}</textarea>
      </div>
      <button class="clay-btn clay-btn-primary" type="submit">Call service</button>
    </form>
    ${hintLadder(vuln)}
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe">Back to XXE module</a></p>
  `, chrome('SOAP console'))));
});

router.post('/soap', async (req, res) => {
  const xml = String(req.body.xml || '').slice(0, 20000);
  // VULN: the SOAP parser expands external entities before reading the Body.
  const expanded = await expandEntities(xml);
  const bodyMatch = expanded.match(/<soap:Body[^>]*>([\s\S]*?)<\/soap:Body>/i);
  const shown = bodyMatch ? bodyMatch[1].trim() : expanded;
  let flags = '';
  if (expanded.includes('XXE-SECRET-4471')) {
    flags += flagBox(award(req, 'xxe', 'xxe-soap'));
    flags += fixPanel('xxe', 'xxe-soap');
  }
  res.send(page('SOAP XXE', appShell('FleetStatus API', `
    <h1>Service response</h1>
    ${flags}
    <h2>Body content</h2>
    <pre>${esc(shown.slice(0, 2000))}</pre>
    <p><a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe/soap">&larr; Call again</a>
    <a class="clay-btn clay-btn-secondary clay-btn-sm" href="/xxe">Back to XXE module</a></p>
  `, chrome('Service response'))));
});

module.exports = { vuln, router };
