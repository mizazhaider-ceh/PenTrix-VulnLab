// XXE Injection module — intentionally vulnerable XML importer.
const express = require('express');
const fs = require('fs');
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
  const re = /<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)">/g;
  const entities = {};
  let m;
  while ((m = re.exec(xml)) !== null) {
    entities[m[1]] = await resolveEntity(m[2]);
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
      <h3><a href="/xxe/import">${esc(v.name)}</a> <span class="pill">${esc(v.difficulty)}</span></h3>
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
  ],
  router,
};
