// PenTrix VulnLab - Command Injection module (cmdi)
// Intentionally vulnerable training module. Local lab use only.
const express = require('express');
const { exec } = require('child_process');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award } = require('../../lib/flags');

const router = express.Router();

const VULNS = [
  {
    id: 'basic',
    name: 'Ping Gadget (no filtering)',
    difficulty: 'Medium',
    hint: 'The host value is pasted straight into a shell command. What happens when you add a second command after it?',
    how: 'Inject an extra shell command through the host field, e.g. ?host=127.0.0.1;id',
  },
  {
    id: 'bypass',
    name: 'Ping Gadget v2 (weak blacklist)',
    difficulty: 'Medium',
    hint: 'Only the ";" character is removed, and only once. Shells give you several other ways to chain commands.',
    how: 'Bypass the semicolon filter with && , || or a newline, e.g. ?host=127.0.0.1%26%26id',
  },
];

function pingForm(action, host) {
  return `<form method="get" action="${esc(action)}">
    <label>Host to ping: <input name="host" value="${esc(host)}" size="48" /></label>
    <button type="submit">Ping</button>
  </form>`;
}

// Shared ping runner. Calls done with (outputHtml).
function runPing(host, done) {
  // VULN: user input is concatenated into a shell command with no escaping.
  exec(`ping -c 1 ${host}`, { timeout: 8000 }, (err, stdout, stderr) => {
    const out = (stdout || '') + (stderr || '');
    let html = `<h3>Command output</h3><pre>${esc(out)}</pre>`;
    if (err && !out) {
      // ping binary may be missing on the host; show the raw error so the
      // injected command output is still visible to the learner.
      html = `<h3>Command output</h3><pre>${esc(String(err.message || err))}</pre>`;
    }
    done(html);
  });
}

// Decide whether the injection actually went through.
// v1: any shell metacharacter present means the extra command ran inside exec.
function awardCheckV1(host) {
  return /[;&|`]|\$\(/.test(host);
}

// v2: the naive filter only strips one ';', so &&, || or a real newline still chain.
function awardCheckV2(host) {
  return /&&|\|\||\n/.test(host);
}

// v1: no filtering at all
router.get('/ping', (req, res) => {
  const host = req.query.host !== undefined ? String(req.query.host) : '127.0.0.1';
  if (req.query.host === undefined) {
    return res.send(page('Ping Gadget', `
      <h1>Ping Gadget</h1>
      ${brief('Challenge', 'This network tool runs <code>ping</code> on a host you choose. Try to make it run <em>another</em> command too, like <code>id</code>.')}
      ${pingForm('/cmdi/ping', '127.0.0.1')}
      ${hintBox('What does the server do with your text? It drops it straight into a shell command. Characters like <code>;</code> end one command and start another.')}
    `));
  }
  runPing(host, (outputHtml) => {
    let extra = '';
    if (awardCheckV1(host)) {
      const flag = award(req, 'cmdi', 'basic');
      extra = flagBox(flag);
    }
    res.send(page('Ping Gadget', `
      <h1>Ping Gadget</h1>
      ${pingForm('/cmdi/ping', host)}
      ${outputHtml}
      ${extra}
      ${hintBox('Try <code>?host=127.0.0.1;id</code> - the semicolon ends the ping and starts a new command.')}
      <p><a href="/cmdi">Back to Command Injection</a></p>
    `));
  });
});

// v2: naive blacklist that strips ';' only, once
router.get('/ping2', (req, res) => {
  let host = req.query.host !== undefined ? String(req.query.host) : '127.0.0.1';
  if (req.query.host === undefined) {
    return res.send(page('Ping Gadget v2', `
      <h1>Ping Gadget v2 (filtered)</h1>
      ${brief('Challenge', 'The developers heard about command injection and "fixed" it by removing <code>;</code> from your input. Find a way around the filter.')}
      ${pingForm('/cmdi/ping2', '127.0.0.1')}
      ${hintBox('The filter only strips <code>;</code>, and only the first one. Shells let you chain commands with <code>&&</code>, <code>||</code>, or a newline. In a URL, <code>&</code> must be encoded as <code>%26</code>.')}
    `));
  }
  // VULN: weak blacklist that only removes a single ';' instead of proper escaping.
  const filtered = host.replace(';', '');
  runPing(filtered, (outputHtml) => {
    let extra = '';
    if (awardCheckV2(host)) {
      const flag = award(req, 'cmdi', 'bypass');
      extra = flagBox(flag);
    }
    res.send(page('Ping Gadget v2 (filtered)', `
      <h1>Ping Gadget v2 (filtered)</h1>
      ${pingForm('/cmdi/ping2', host)}
      <p class="dim">Filtered host value sent to the shell: <code>${esc(filtered)}</code></p>
      ${outputHtml}
      ${extra}
      ${hintBox('Try <code>?host=127.0.0.1%26%26id</code> (<code>&&</code> chained) or <code>?host=127.0.0.1%0aid</code> (newline).')}
      <p><a href="/cmdi">Back to Command Injection</a></p>
    `));
  });
});

// Module index page
router.get('/', (req, res) => {
  const rows = VULNS.map((v) => `
    <tr>
      <td><b>${esc(v.name)}</b><br><span class="dim">${esc(v.how)}</span></td>
      <td>${esc(v.difficulty)}</td>
      <td>${hintBox(esc(v.hint))}</td>
      <td><a href="/cmdi/${v.id === 'basic' ? 'ping' : 'ping2'}">Open challenge</a></td>
    </tr>`).join('');
  res.send(page('Command Injection', `
    <h1>Command Injection</h1>
    ${brief('Briefing', `
      A command-injection flaw happens when an application builds a shell command
      out of user input without sanitising it. Special shell characters
      (<code>;</code>, <code>&&</code>, <code>||</code>, <code>|</code>, backticks,
      <code>$()</code>, newlines) let you smuggle extra commands into the string.
      <br><br><b>Example payloads:</b>
      <br><code>?host=127.0.0.1;id</code> - run <code>ping</code>, then <code>id</code>
      <br><code>?host=127.0.0.1%26%26id</code> - same trick when <code>;</code> is filtered
    `)}
    <h2>Challenges</h2>
    <table>
      <tr><th>Challenge</th><th>Difficulty</th><th>Hint</th><th>Link</th></tr>
      ${rows}
    </table>
  `));
});

module.exports = {
  id: 'cmdi',
  name: 'Command Injection',
  tagline: 'Smuggle extra commands into a ping gadget.',
  description: 'Learn how unescaped user input becomes shell commands: first with no filtering at all, then against a naive blacklist you have to bypass.',
  difficulty: 'Intermediate',
  vulns: VULNS,
  router,
};
