'use strict';
// XXE File Read: the shared XML importer expands external entities with no
// allowlist, so a SYSTEM "file://..." entity makes the server read a local
// file into the import result. This challenge shares the /import endpoint
// with the "SSRF via XXE" challenge (both map to the import page).
// The shared importer console lives in ../importer.js (one copy, no shadow).
// This challenge entry owns it: the importer awards this challenge's flag
// when a file:// entity reads the secret.
// VULN: the XML importer expands external entities with no allowlist, so a
// SYSTEM "file://..." entity makes the server read a local file into the
// import result.
const router = require('../importer');

const vuln = {
  id: 'file',
  name: 'XXE File Read',
  difficulty: 'Medium',
  est: 'about 10 minutes',
  hint: "Declare an external entity with a file:// URI pointing at the module's secret.txt (for example file://modules/xxe/secret.txt, a path relative to the app's working directory), then reference &name; inside <data>.",
  hints: [
    "The app parses your XML. Does it resolve external entities?",
    "Proxy the importer in Burp and send the POST to Repeater. A DOCTYPE can declare a general entity whose SYSTEM identifier is a local file URI, and the parser reads that file and substitutes the entity reference wherever it appears in the output.",
    "Your DOCTYPE must declare an external file-reading entity, then plant the entity reference where the import result renders. Key insight: the file path does not have to be absolute here, a path relative to the app's working directory works too, for example file://modules/xxe/secret.txt reads the module's secret.txt, and the success response shows you exactly where injected content echoes back. Absolute file:// paths also work, and the harder challenges in this module show an absolute path on their own pages when they need one. In Repeater, change only the xml form field, submit, and find that echo location first, then aim the reference there.",
  ],
  tools: 'BZ, B, C',
  how: 'External entities are read server-side. Make the parser read a file for you and echo what it found.',
  link: '/xxe#file',
  start: 'Open Burp, proxy your browser to it, and visit the XML importer at /xxe/import. Submit the form once with plain XML like <data>hello</data>, send that POST to Repeater, then replace only the xml form field with your DOCTYPE payload and submit again.',
};

module.exports = { vuln, router };
