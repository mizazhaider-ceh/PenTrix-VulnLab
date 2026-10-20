// lib/boot-gate.js
// P5-1: during boot (and during the restart window the students saw in the
// review wave) no request may ever see a stack trace. This middleware sits
// FIRST in the stack, before any body parsing or session handling, and
// answers every request with a static 503 page until app.js marks the lab
// ready in its listen() callback. The page is a fixed string: it carries no
// error detail, no stack, and nothing about internals.

'use strict';

const BOOT_PAGE = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PenTrix VulnLab: starting</title>
<style>
body { font-family: system-ui, -apple-system, sans-serif; background: #f4f1ea;
  color: #2b2b2b; display: flex; align-items: center; justify-content: center;
  min-height: 100vh; margin: 0; }
.card { background: #fffdf8; border: 1px solid #e3dccb; border-radius: 18px;
  padding: 2rem 2.5rem; max-width: 26rem; text-align: center;
  box-shadow: 0 6px 18px rgba(60, 50, 30, 0.08); }
h1 { font-size: 1.25rem; margin: 0 0 0.5rem; }
p { color: #6b6252; font-size: 0.95rem; }
</style>
</head>
<body>
<main class="card">
<h1>The lab is starting</h1>
<p>PenTrix VulnLab is still booting. Wait a moment, then refresh the page.</p>
</main>
</body>
</html>
`;

function createBootGate() {
  let ready = false;
  const middleware = (req, res, next) => {
    if (ready) return next();
    res.status(503);
    res.set('Retry-After', '2');
    res.type('html');
    res.send(BOOT_PAGE);
  };
  return {
    middleware: middleware,
    markReady: () => { ready = true; },
    isReady: () => ready,
    page: BOOT_PAGE,
  };
}

module.exports = { createBootGate: createBootGate, BOOT_PAGE: BOOT_PAGE };
