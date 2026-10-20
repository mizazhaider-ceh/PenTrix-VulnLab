'use strict';
// Drift guards for student-facing copy (backlog P3-1 and P3-5).
//
// 1. Port drift: the lab may run on any port, so student-facing copy must
//    never hardcode a lab address. Any `localhost:<port>` or
//    `127.0.0.1:<port>` in module code, README.md, SOLUTIONS.md, or the demo
//    cheat sheet fails, except two deliberate non-lab addresses:
//    8080 (Burp Suite's default proxy listener) and 13919 (the hostheader
//    module's loopback-only internal agent, a fixed attack target in code).
//    The upload module's runtime shim sentence that names the old address in
//    a .replace() call is also exempt (it rewrites stale text at render time).
// 2. README catalog drift: the catalog table in README.md is generated from
//    the modules' own name fields; this test fails if a row's module name,
//    challenge count, or challenge-name list no longer matches code.
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.join(__dirname, '..');
const ALLOWED_PORTS = new Set(['8080', '13919']);

function walk(dir, out) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else out.push(p);
  }
  return out;
}

test('student-facing copy has no hardcoded lab port', () => {
  const files = [
    ...walk(path.join(ROOT, 'modules'), []).filter((f) => f.endsWith('.js')),
    path.join(ROOT, 'README.md'),
    path.join(ROOT, 'SOLUTIONS.md'),
    path.join(ROOT, 'docs', 'demo-cheat-sheet.md'),
  ];
  const bad = [];
  const re = /(?:localhost|127\.0\.0\.1):(\d{2,5})/g;
  for (const f of files) {
    const text = fs.readFileSync(f, 'utf8');
    for (const line of text.split('\n')) {
      if (line.includes('curl.replace')) continue;
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(line)) !== null) {
        if (!ALLOWED_PORTS.has(m[1])) {
          bad.push(`${path.relative(ROOT, f)}: ${m[0]}`);
        }
      }
    }
  }
  assert.deepStrictEqual(bad, [],
    'Hardcoded lab addresses found (make the copy port-agnostic):\n' + bad.join('\n'));
});

test('README catalog matches the modules in code', () => {
  // Modules are required in a child process because several start timers or
  // listeners on require; the child prints the catalog and exits forcibly.
  const script = `
    const fs = require('fs');
    const ids = fs.readdirSync('modules').filter((d) => fs.existsSync('modules/' + d + '/index.js'));
    const out = [];
    for (const id of ids) {
      const m = require('./modules/' + id);
      out.push({ id, name: m.name, count: m.vulns.length, names: m.vulns.map((v) => v.name) });
    }
    process.stdout.write(JSON.stringify(out));
    process.exit(0);
  `;
  const raw = execFileSync(process.execPath, ['-e', script], { cwd: ROOT, encoding: 'utf8' });
  // Module require() can print boot log lines (e.g. first-boot minting) to
  // stdout alongside the catalog. The catalog is always the JSON array of
  // objects at the end of the output, so parse from the last '[{' onward.
  const catalog = JSON.parse(raw.slice(raw.lastIndexOf('[{')));
  const readme = fs.readFileSync(path.join(ROOT, 'README.md'), 'utf8');
  const rowRe = /^\| \*\*([a-z0-9-]+)\*\* – (.+?) \((\d+)\) \| (.+) \|$/gm;
  const rows = new Map();
  let m;
  while ((m = rowRe.exec(readme)) !== null) {
    rows.set(m[1], { name: m[2], count: Number(m[3]), highlights: m[4] });
  }
  const problems = [];
  for (const mod of catalog) {
    const row = rows.get(mod.id);
    if (!row) { problems.push(`README catalog is missing module ${mod.id}`); continue; }
    if (row.name !== mod.name) problems.push(`${mod.id}: README says "${row.name}", code says "${mod.name}"`);
    if (row.count !== mod.count) problems.push(`${mod.id}: README count ${row.count}, code count ${mod.count}`);
    const expected = mod.names.join(' · ');
    if (row.highlights !== expected) {
      problems.push(`${mod.id}: README highlights do not match the challenge names in code`);
    }
    rows.delete(mod.id);
  }
  for (const extra of rows.keys()) problems.push(`README catalog lists unknown module ${extra}`);
  assert.deepStrictEqual(problems, [], problems.join('\n'));
});
