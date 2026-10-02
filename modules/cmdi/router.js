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
    done(html, out);
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

// ------------------------------------------------- batch 05: filter-bypass series
// Each gadget below is a ping form with a slightly different naive filter.
// Challenge page slug per vuln id (used by the index page links).
const CMDI_PAGE_FOR = {
  basic: 'ping', bypass: 'ping2',
  'cmdi-ifs': 'ping3', 'cmdi-braces': 'ping4', 'cmdi-newline': 'ping5',
  'cmdi-backtick': 'ping6', 'cmdi-wildcard': 'ping7', 'cmdi-pipe': 'ping8',
  'cmdi-tab': 'ping9', 'cmdi-env': 'ping10',
};

VULNS.push(
  {
    id: 'cmdi-ifs',
    name: 'Ping Gadget v3 (spaces stripped)',
    difficulty: 'Medium',
    hint: 'Every space is deleted from your input, but the shell still needs word separators. Bash has a built-in variable that expands to whitespace.',
    how: 'Replace spaces with $IFS, e.g. ?host=127.0.0.1;cat$IFS/etc/passwd',
  },
  {
    id: 'cmdi-braces',
    name: 'Ping Gadget v4 ($IFS blocked too)',
    difficulty: 'Medium',
    hint: 'Spaces are stripped and the literal text $IFS is stripped as well. The braced form of a variable looks different to a naive string filter.',
    how: 'Use ${IFS} instead of $IFS, e.g. ?host=127.0.0.1;cat${IFS}/etc/passwd',
  },
  {
    id: 'cmdi-newline',
    name: 'Ping Gadget v5 (separators blocked)',
    difficulty: 'Medium',
    hint: 'The characters ; & and | are all stripped. But a shell treats more than those as command separators. In a URL, %0a becomes one of them.',
    how: 'Inject a newline (%0a) to start a second command, e.g. ?host=127.0.0.1%0acat /etc/passwd',
  },
  {
    id: 'cmdi-backtick',
    name: 'Ping Gadget v6 ($() blocked)',
    difficulty: 'Easy',
    hint: 'The filter removes $(, killing the modern command-substitution syntax. The shell has an older syntax that does the same job.',
    how: 'Use backticks for command substitution, e.g. ?host=127.0.0.1;echo `id`',
  },
  {
    id: 'cmdi-wildcard',
    name: 'Ping Gadget v7 (cat and / blocked)',
    difficulty: 'Hard',
    hint: 'The words "cat" and "/" are stripped as standalone tokens. The shell expands ? into any single character, including inside paths and command names.',
    how: 'Glob your way around both words, e.g. ?host=127.0.0.1;/???/bin/?at /???/p?sswd',
  },
  {
    id: 'cmdi-pipe',
    name: 'Ping Gadget v8 (; blocked)',
    difficulty: 'Easy',
    hint: 'Semicolons are stripped, but the shell has other ways to chain commands. One of them feeds the first command output into the second.',
    how: 'Chain with a pipe, e.g. ?host=127.0.0.1|id (encode & as %26 when you need it, but | needs no encoding)',
  },
  {
    id: 'cmdi-tab',
    name: 'Ping Gadget v9 (spaces blocked, again)',
    difficulty: 'Easy',
    hint: 'Spaces are stripped from your input. A literal tab character (%09 in a URL) is also whitespace to the shell.',
    how: 'Use a tab as the word separator, e.g. ?host=127.0.0.1;cat%09/etc/passwd',
  },
  {
    id: 'cmdi-env',
    name: 'Ping Gadget v10 (metachars blocked, unquoted)',
    difficulty: 'Medium',
    hint: 'The blacklist strips ; | & $ and backticks, and the value is dropped into the command line with no quotes. One classic separator is missing from the list.',
    how: 'Inject a newline (%0a) to run a second command, e.g. ?host=127.0.0.1%0aid',
  },
);

// Generic filtered ping gadget. opts: { route, vulnId, title, briefHtml, hintHtml,
// filter(host)->filtered, awardCheck(host, filtered, stdout)->bool }
function filteredGadget(opts) {
  router.get('/' + opts.route, (req, res) => {
    const host = req.query.host !== undefined ? String(req.query.host) : '127.0.0.1';
    if (req.query.host === undefined) {
      return res.send(page(opts.title, `
        <h1>${esc(opts.title)}</h1>
        ${brief('Challenge', opts.briefHtml)}
        ${pingForm('/cmdi/' + opts.route, '127.0.0.1')}
        ${hintBox(opts.hintHtml)}
      `));
    }
    const filtered = opts.filter(host);
    runPing(filtered, (outputHtml, out) => {
      let extra = '';
      if (opts.awardCheck(host, filtered, out || '')) {
        const flag = award(req, 'cmdi', opts.vulnId);
        extra = flagBox(flag);
      }
      res.send(page(opts.title, `
        <h1>${esc(opts.title)}</h1>
        ${pingForm('/cmdi/' + opts.route, host)}
        <p class="dim">Filtered host value sent to the shell: <code>${esc(filtered)}</code></p>
        ${outputHtml}
        ${extra}
        ${hintBox(opts.hintHtml)}
        <p><a href="/cmdi">Back to Command Injection</a></p>
      `));
    });
  });
}

filteredGadget({
  route: 'ping3', vulnId: 'cmdi-ifs', title: 'Ping Gadget v3',
  briefHtml: 'The developers now strip <b>every space</b> from your input before building the shell command. Find another way to separate your words.',
  hintHtml: 'Try <code>?host=127.0.0.1;cat$IFS/etc/passwd</code> - <code>$IFS</code> expands to whitespace inside the shell.',
  // VULN: spaces are stripped, but $IFS still expands to a word separator in the shell.
  filter: (host) => host.replace(/ /g, ''),
  awardCheck: (host, filtered, out) => /\$(\{)?IFS\}?/.test(host) && out.includes('root:'),
});

filteredGadget({
  route: 'ping4', vulnId: 'cmdi-braces', title: 'Ping Gadget v4',
  briefHtml: 'Spaces are stripped, and now the literal text <code>$IFS</code> is stripped too. The filter is just string matching, not shell parsing.',
  hintHtml: 'Try <code>?host=127.0.0.1;cat${IFS}/etc/passwd</code> - the braced form <code>${IFS}</code> does not match the <code>$IFS</code> string filter.',
  // VULN: the filter removes the exact string $IFS, but ${IFS} expands the same variable.
  filter: (host) => host.replace(/ /g, '').replace(/\$IFS/g, ''),
  awardCheck: (host, filtered, out) => /\$\{IFS\}/.test(host) && out.includes('root:'),
});

filteredGadget({
  route: 'ping5', vulnId: 'cmdi-newline', title: 'Ping Gadget v5',
  briefHtml: 'The filter now strips <code>;</code>, <code>&amp;</code> and <code>|</code>. Every classic command separator is gone... or is it?',
  hintHtml: 'Try <code>?host=127.0.0.1%0acat /etc/passwd</code> - <code>%0a</code> decodes to a newline, and the shell runs each line as its own command.',
  // VULN: ; & | are stripped, but a newline still separates commands in the shell.
  filter: (host) => host.replace(/[;&|]/g, ''),
  awardCheck: (host, filtered, out) => host.includes('\n') && out.includes('root:'),
});

filteredGadget({
  route: 'ping6', vulnId: 'cmdi-backtick', title: 'Ping Gadget v6',
  briefHtml: 'The filter removes <code>$(</code>, blocking the modern <code>$(...)</code> command-substitution syntax. Older shells had another way.',
  hintHtml: 'Try <code>?host=127.0.0.1;echo `id`</code> - backticks are the legacy command-substitution syntax and the filter never mentions them.',
  // VULN: $( is stripped, but legacy backtick command substitution still runs.
  filter: (host) => host.replace(/\$\(/g, ''),
  awardCheck: (host, filtered, out) => host.includes('`') && out.includes('uid='),
});

filteredGadget({
  route: 'ping7', vulnId: 'cmdi-wildcard', title: 'Ping Gadget v7',
  briefHtml: 'The filter strips the word <code>cat</code> and any standalone <code>/</code> token. You need to read <code>/etc/passwd</code> without typing either.',
  hintHtml: 'Try <code>?host=127.0.0.1;/???/bin/?at /???/p?sswd</code> - the shell expands each <code>?</code> into one character, rebuilding <code>/bin/cat /etc/passwd</code> at run time.',
  // VULN: word-boundary blacklist for cat and / is defeated by ? glob wildcards.
  filter: (host) => host.replace(/\bcat\b/gi, '').replace(/(^|\s)\/(?=\s|$)/g, '$1'),
  awardCheck: (host, filtered, out) => host.includes('?') && out.includes('root:'),
});

filteredGadget({
  route: 'ping8', vulnId: 'cmdi-pipe', title: 'Ping Gadget v8',
  briefHtml: 'Semicolons are stripped from your input. The shell offers other command separators that this filter forgot.',
  hintHtml: 'Try <code>?host=127.0.0.1|id</code> - the pipe chains ping into id without any semicolon.',
  // VULN: only ; is stripped; | still chains commands.
  filter: (host) => host.replace(/;/g, ''),
  awardCheck: (host, filtered, out) => host.includes('|') && out.includes('uid='),
});

filteredGadget({
  route: 'ping9', vulnId: 'cmdi-tab', title: 'Ping Gadget v9',
  briefHtml: 'Spaces are stripped from your input again. But space is not the only whitespace the shell understands.',
  hintHtml: 'Try <code>?host=127.0.0.1;cat%09/etc/passwd</code> - <code>%09</code> decodes to a literal tab, which separates words just like a space.',
  // VULN: spaces are stripped, but a literal tab still acts as a shell word separator.
  filter: (host) => host.replace(/ /g, ''),
  awardCheck: (host, filtered, out) => host.includes('\t') && out.includes('root:'),
});

filteredGadget({
  route: 'ping10', vulnId: 'cmdi-env', title: 'Ping Gadget v10',
  briefHtml: 'The blacklist strips <code>;</code> <code>|</code> <code>&amp;</code> <code>$</code> and backticks, and your value is dropped into the command line <b>with no quotes</b>. One separator is missing from the list.',
  hintHtml: 'Try <code>?host=127.0.0.1%0aid</code> - <code>%0a</code> decodes to a newline, and an unquoted newline starts a brand-new command.',
  // VULN: the blacklist misses newline, and the unquoted value lets it start a second command.
  filter: (host) => host.replace(/[;|&$`]/g, ''),
  awardCheck: (host, filtered, out) => host.includes('\n') && out.includes('uid='),
});

// Module index page
router.get('/', (req, res) => {
  const rows = VULNS.map((v) => `
    <tr>
      <td><b>${esc(v.name)}</b><br><span class="dim">${esc(v.how)}</span></td>
      <td>${esc(v.difficulty)}</td>
      <td>${hintBox(esc(v.hint))}</td>
      <td><a href="/cmdi/${CMDI_PAGE_FOR[v.id]}">Open challenge</a></td>
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
