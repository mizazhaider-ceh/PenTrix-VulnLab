// Shared HTML helpers so every module looks consistent without a view engine.

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function page(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · PenTrix VulnLab</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header class="topbar">
  <a class="brand" href="/">🧪 PenTrix VulnLab</a>
  <nav><a href="/">Modules</a><a href="/scoreboard">Scoreboard</a><a href="/about">About</a></nav>
</header>
<main class="wrap">${body}</main>
<footer class="foot">PenTrix VulnLab · intentionally vulnerable · run locally only</footer>
</body>
</html>`;
}

function flagBox(flag) {
  return `<div class="flagbox">🚩 <b>Flag captured:</b> <code>${esc(flag)}</code> <span class="dim">· saved to your scoreboard</span></div>`;
}

function hintBox(hint) {
  return `<details class="hint"><summary>💡 Hint (click to reveal)</summary><p>${hint}</p></details>`;
}

function brief(title, text) {
  return `<div class="brief"><h2>${esc(title)}</h2><p>${text}</p></div>`;
}

module.exports = { esc, page, flagBox, hintBox, brief };
