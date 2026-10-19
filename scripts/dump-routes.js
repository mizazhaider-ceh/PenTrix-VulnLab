// Dumps the sorted route list of one module for before/after comparison.
// Usage: node scripts/dump-routes.js <module-id>
// Writers: run BEFORE splitting (save output), run AFTER splitting, diff.
// The lists must be identical (same routes, same behavior, only files moved).
'use strict';
process.env.DB_PATH = process.env.DB_PATH || '/tmp/dump-routes.db';
const fs = require('fs');
const path = require('path');

const modId = process.argv[2];
if (!modId) {
  console.error('usage: node scripts/dump-routes.js <module-id>');
  process.exit(2);
}
const dir = path.join(__dirname, '..', 'modules', modId);
const indexPath = path.join(dir, 'index.js');
const legacyPath = path.join(dir, 'router.js');
const modPath = fs.existsSync(indexPath) ? indexPath : legacyPath;
if (!fs.existsSync(modPath)) {
  console.error(`no index.js or router.js in ${dir}`);
  process.exit(2);
}
const mod = require(modPath);

function collect(router, out) {
  for (const layer of router.stack || []) {
    if (layer.route) {
      const methods = Object.keys(layer.route.methods || {})
        .filter((m) => layer.route.methods[m] && m !== '_all')
        .map((m) => m.toUpperCase())
        .sort()
        .join(',');
      out.push(`${methods} /${modId}${layer.route.path === '/' ? '' : layer.route.path}`);
    } else if (layer.handle && layer.handle.stack) {
      collect(layer.handle, out);
    }
  }
  return out;
}

const routes = [...new Set(collect(mod.router, []))].sort();
console.log(routes.join('\n'));
console.log(`# ${routes.length} routes, ${mod.vulns.length} vulns`);
