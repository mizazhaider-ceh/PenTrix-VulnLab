const express = require('express');
const { page, esc, flagBox, hintBox, brief } = require('../../lib/page');
const { award, flagFor } = require('../../lib/flags');

const router = express.Router();

const VULNS = [
  {
    id: 'basic',
    name: 'Basic Template Injection',
    difficulty: 'Medium',
    hint: 'The greeting is built with a naive template engine: anything you put inside {{ }} gets evaluated. Start by proving it with simple arithmetic, for example name={{7*7}}.',
    how: 'Submit name={{7*7}} so the evaluated expression (49) appears in the greeting.',
    link: '/ssti/greet',
  },
  {
    id: 'rce',
    name: 'Flag Extraction via Scope Leak',
    difficulty: 'Medium',
    hint: 'Once you know {{ }} is evaluated, ask yourself: what server-side variables are in scope when the expression runs? Probe for a variable that holds the flag, e.g. name={{secretFlag}}.',
    how: 'Submit name={{secretFlag}} to evaluate the in-scope variable holding the flag.',
    link: '/ssti/greet',
  },
  {
    id: 'ssti-echo2',
    name: 'Template Injection on a Second Endpoint',
    difficulty: 'Easy',
    hint: 'A second endpoint runs the same naive engine. Prove evaluation with arithmetic first: ?msg={{7*7}}.',
    how: 'Submit msg={{7*7}} so the evaluated expression (49) appears in the invitation card.',
    link: '/ssti/card',
  },
  {
    id: 'ssti-wordfilter',
    name: 'Word Blacklist Bypass',
    difficulty: 'Medium',
    hint: 'The words flag, secret and config are deleted from your input. Build the blocked word at run time instead of typing it.',
    how: 'Use nested eval with string concatenation, e.g. input={{eval("vaultSec"+"ret")}}, to read the filtered variable name.',
    link: '/ssti/wordfilter',
  },
  {
    id: 'ssti-nounderscore',
    name: 'Underscore Blacklist Bypass',
    difficulty: 'Medium',
    hint: 'Underscores are deleted from your input. JavaScript can build any character from its code: String.fromCharCode(95) is _.',
    how: 'Evaluate the variable name assembled at run time, e.g. input={{eval("db"+String.fromCharCode(95)+"pass")}}.',
    link: '/ssti/nounderscore',
  },
  {
    id: 'ssti-nobrackets',
    name: 'Bracket Blacklist Bypass',
    difficulty: 'Medium',
    hint: 'Brackets are deleted and the object key has a dash, so neither indexing nor dot access works directly. Dump the whole object instead.',
    how: 'Serialize the object to text, e.g. input={{JSON.stringify(cfg)}}, to reveal the flag without indexing.',
    link: '/ssti/nobrackets',
  },
  {
    id: 'ssti-dotblock',
    name: 'Dot Blacklist Bypass',
    difficulty: 'Medium',
    hint: 'Dots are deleted from your input. JavaScript has a second property-access syntax that uses no dots.',
    how: 'Use bracket notation, e.g. input={{db["key"]}}, to read the property without a dot.',
    link: '/ssti/dotblock',
  },
  {
    id: 'ssti-curly',
    name: 'Curly-Brace Strip Bypass',
    difficulty: 'Medium',
    hint: 'The filter removes the first {{ and the first }} only, once each. Feed it more braces than it can strip.',
    how: 'Double the braces, e.g. input={{{{7*7}}}}, so one stripped pair leaves a working {{7*7}} behind.',
    link: '/ssti/curly',
  },
  {
    id: 'ssti-noquotes',
    name: 'Quote Blacklist Bypass',
    difficulty: 'Hard',
    hint: 'Quotes are deleted and the variable name is blocked as a word. Spell the name with character codes and evaluate the result.',
    how: 'Use eval with String.fromCharCode, e.g. input={{eval(String.fromCharCode(118,97,117,108,116,75,101,121))}}, to reference vaultKey without quotes.',
    link: '/ssti/noquotes',
  },
  {
    id: 'ssti-rce',
    name: 'SSTI to Remote Code Execution',
    difficulty: 'Hard',
    hint: 'There is no sandbox: expressions run in Node.js with require() in scope. Reach child_process and run a system command.',
    how: 'Execute expr={{require("child_process").execSync("id").toString()}} and read the uid= output.',
    link: '/ssti/exec',
  },
];

router.get('/', (req, res) => {
  const rows = VULNS.map((v) => `
    <tr>
      <td><a href="${v.link}"><strong>${esc(v.name)}</strong></a></td>
      <td>${esc(v.difficulty)}</td>
      <td>${hintBox(v.hint)}</td>
    </tr>`).join('');

  res.send(page('Server-Side Template Injection', `
    ${brief('Server-Side Template Injection',
      `<p>This greeting card renders your name through a <strong>homemade template engine</strong>: ` +
      `it takes the string <code>Hello &lt;your name&gt;!</code> and evaluates anything inside <code>{{ }}</code> as code.</p>` +
      `<p><strong>Escalation path:</strong> first prove evaluation works with <code>{{7*7}}</code> ` +
      `(you should see <strong>49</strong> in the greeting), then look for variables in scope and try <code>{{secretFlag}}</code>.</p>`)}
    <h2>Challenges</h2>
    <table class="vuln-table">
      <thead><tr><th>Challenge</th><th>Difficulty</th><th>Hint</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  `));
});

router.get('/greet', (req, res) => {
  const name = req.query.name || 'guest';
  const secretFlag = flagFor('ssti', 'rce'); // server-side variable, in scope below

  let result = '';
  let awardHtml = '';

  if (req.query.name) {
    const tpl = `Hello ${name}!`;
    // VULN: naive template engine eval()s anything inside {{ }} with the function's scope (name, secretFlag) visible
    const rendered = tpl.replace(/\{\{(.*?)\}\}/g, (_, e) => { try { return eval(e); } catch { return ''; } });

    // VULN: the evaluated result is injected into the page raw so students can see the output plainly
    result = `<div class="ssti-result">${rendered}</div>`;

    if (/\{\{.*\}\}/.test(name) && rendered.includes('49')) {
      awardHtml += flagBox(award(req, 'ssti', 'basic'));
    }
    if (rendered.includes(secretFlag)) {
      awardHtml += flagBox(award(req, 'ssti', 'rce'));
    }
  }

  res.send(page('SSTI Greeting', `
    ${brief('Greeting card',
      `<p>Enter your name and the server greets you. The greeting is rendered by a naive template engine ` +
      `that evaluates <code>{{ expressions }}</code>. Try <code>{{7*7}}</code> first, then hunt for what is in scope.</p>`)}
    <form method="get" action="/ssti/greet">
      <label for="name">Name:</label>
      <input id="name" name="name" type="text" value="${esc(req.query.name || '')}" size="40" />
      <button type="submit">Greet me</button>
    </form>
    ${result}
    ${awardHtml}
    <p>Quick links: <a href="/ssti/greet?name={{7*7}}">test {{7*7}}</a></p>
  `));
});

// ------------------------------------------------- batch 05: filter-bypass series
// Same homemade engine as /ssti/greet (eval inside {{ }}), but each gadget adds a
// naive input blacklist. The scope object is exposed to evaluated expressions via
// with(scope), mirroring how the basic lab leaks its closure variables.
// VULN: with(scope) puts server-side secret variables in the eval scope chain.
function sstiRender(tpl, scope) {
  // VULN: naive template engine eval()s anything inside {{ }} with attacker input in the template
  return tpl.replace(/\{\{(.*?)\}\}/g, (_, e) => {
    try {
      with (scope) { return eval(e); }
    } catch (err) { return ''; }
  });
}

// Generic filtered SSTI gadget. opts: { route, vulnId, title, param, briefHtml, hintHtml,
// template(input)->string, filter(s)->string, scope()->object, awardCheck(raw, input, rendered)->bool }
function sstiGadget(opts) {
  router.get('/' + opts.route, (req, res) => {
    const hasInput = req.query[opts.param] !== undefined;
    const raw = hasInput ? String(req.query[opts.param]) : '';
    let result = '';
    let awardHtml = '';
    if (hasInput) {
      const input = opts.filter(raw);
      const tpl = opts.template(input);
      // VULN: the evaluated result is injected into the page raw so learners see the output plainly
      const rendered = sstiRender(tpl, opts.scope());
      result = `<div class="ssti-result">${rendered}</div>`;
      if (opts.awardCheck(raw, input, rendered)) {
        awardHtml = flagBox(award(req, 'ssti', opts.vulnId));
      }
    }
    res.send(page(opts.title, `
      ${brief(opts.title, opts.briefHtml)}
      <form method="get" action="/ssti/${opts.route}">
        <label>${esc(opts.param)}: <input name="${esc(opts.param)}" type="text" value="${esc(raw)}" size="48" /></label>
        <button type="submit">Render</button>
      </form>
      ${result}
      ${awardHtml}
      ${hintBox(opts.hintHtml)}
      <p><a href="/ssti">Back to SSTI module</a></p>
    `));
  });
}

sstiGadget({
  route: 'card', vulnId: 'ssti-echo2', title: 'Invitation Card', param: 'msg',
  briefHtml: `<p>A second greeting endpoint with the same naive template engine: anything inside
    <code>{{ }}</code> is evaluated server-side. Start with arithmetic.</p>`,
  hintHtml: 'Try <code>?msg={{7*7}}</code> - if the card shows 49, the expression was evaluated on the server.',
  template: (i) => `You're invited: ${i}`,
  filter: (s) => s,
  scope: () => ({}),
  awardCheck: (raw, input, rendered) => /\{\{.*\}\}/.test(raw) && rendered.includes('49'),
});

sstiGadget({
  route: 'wordfilter', vulnId: 'ssti-wordfilter', title: 'Filtered Note', param: 'input',
  briefHtml: `<p>The engine still evaluates <code>{{ }}</code>, but a filter now deletes the words
    <code>flag</code>, <code>secret</code> and <code>config</code> from your input. A server-side
    variable holds the flag - its name contains one of those words.</p>`,
  hintHtml: 'The filter is plain string matching. Build the blocked word at run time instead of typing it: <code>{{eval("vaultSec"+"ret")}}</code>.',
  template: (i) => `Note: ${i}`,
  // VULN: word blacklist is defeated by splitting the blocked word across a string concatenation.
  filter: (s) => s.replace(/flag|secret|config/gi, ''),
  scope: () => ({ vaultSecret: flagFor('ssti', 'ssti-wordfilter') }),
  awardCheck: (raw, input, rendered) => rendered.includes(flagFor('ssti', 'ssti-wordfilter')),
});

sstiGadget({
  route: 'nounderscore', vulnId: 'ssti-nounderscore', title: 'No Underscores', param: 'input',
  briefHtml: `<p>The engine still evaluates <code>{{ }}</code>, but every underscore is deleted from
    your input. The flag lives in a variable whose name contains an underscore.</p>`,
  hintHtml: 'You cannot type the underscore, but JavaScript can build any character: <code>String.fromCharCode(95)</code> is <code>_</code>. Combine it with <code>eval</code>.',
  template: (i) => `Note: ${i}`,
  // VULN: underscore blacklist is defeated by building the character from its char code.
  filter: (s) => s.replace(/_/g, ''),
  scope: () => ({ db_pass: flagFor('ssti', 'ssti-nounderscore') }),
  awardCheck: (raw, input, rendered) => rendered.includes(flagFor('ssti', 'ssti-nounderscore')),
});

sstiGadget({
  route: 'nobrackets', vulnId: 'ssti-nobrackets', title: 'No Brackets', param: 'input',
  briefHtml: `<p>The engine still evaluates <code>{{ }}</code>, but <code>[</code> and <code>]</code>
    are deleted from your input. The flag is stored as an object property whose key contains a dash,
    so dot notation cannot reach it either.</p>`,
  hintHtml: 'You cannot index the object, but you can dump the whole thing: what function turns any object into text?',
  template: (i) => `Config: ${i}`,
  // VULN: bracket blacklist is defeated by serializing the object instead of indexing it.
  filter: (s) => s.replace(/[\[\]]/g, ''),
  scope: () => ({ cfg: { 'db-pass': flagFor('ssti', 'ssti-nobrackets') } }),
  awardCheck: (raw, input, rendered) => rendered.includes(flagFor('ssti', 'ssti-nobrackets')),
});

sstiGadget({
  route: 'dotblock', vulnId: 'ssti-dotblock', title: 'No Dots', param: 'input',
  briefHtml: `<p>The engine still evaluates <code>{{ }}</code>, but every dot is deleted from your
    input. The flag is a property of an object - dot access is the first thing you would try.</p>`,
  hintHtml: 'Dots are gone, but JavaScript has a second syntax for property access that uses no dots at all.',
  template: (i) => `Record: ${i}`,
  // VULN: dot blacklist is defeated by bracket-notation property access.
  filter: (s) => s.replace(/\./g, ''),
  scope: () => ({ db: { key: flagFor('ssti', 'ssti-dotblock') } }),
  awardCheck: (raw, input, rendered) => rendered.includes(flagFor('ssti', 'ssti-dotblock')),
});

sstiGadget({
  route: 'curly', vulnId: 'ssti-curly', title: 'Curly Stripper', param: 'input',
  briefHtml: `<p>The engine still evaluates <code>{{ }}</code>, but a filter removes the first
    <code>{{</code> and the first <code>}}</code> from your input - once each, like the naive
    semicolon filter in the command-injection module.</p>`,
  hintHtml: 'The filter strips one pair of braces. What happens if you send two pairs?',
  template: (i) => `Echo: ${i}`,
  // VULN: single-strip filter is defeated by doubling the stripped sequence.
  filter: (s) => s.replace('{{', '').replace('}}', ''),
  scope: () => ({}),
  awardCheck: (raw, input, rendered) => /\{\{/.test(raw) && rendered.includes('49'),
});

sstiGadget({
  route: 'noquotes', vulnId: 'ssti-noquotes', title: 'No Quotes', param: 'input',
  briefHtml: `<p>The engine still evaluates <code>{{ }}</code>, but single and double quotes are deleted
    from your input, and the flag variable name itself is blocked as a word. No string literals, no
    direct reference.</p>`,
  hintHtml: 'Build the variable name without typing it and without quotes: spell it with character codes, then evaluate the result.',
  template: (i) => `Vault: ${i}`,
  // VULN: quote blacklist is defeated by spelling strings with String.fromCharCode and eval.
  filter: (s) => s.replace(/['"]/g, '').replace(/vaultKey/g, ''),
  scope: () => ({ vaultKey: flagFor('ssti', 'ssti-noquotes') }),
  awardCheck: (raw, input, rendered) => rendered.includes(flagFor('ssti', 'ssti-noquotes')),
});

sstiGadget({
  route: 'exec', vulnId: 'ssti-rce', title: 'Template to Shell', param: 'expr',
  briefHtml: `<p>The engine evaluates <code>{{ }}</code> with a full Node.js runtime behind it - there
    is no sandbox. Expressions can reach <code>require</code> and from there the operating system.
    Prove it by running a system command and showing its output.</p>`,
  hintHtml: 'You are one <code>require("child_process")</code> away from the shell. What does <code>execSync("id")</code> return?',
  template: (i) => `Result: ${i}`,
  filter: (s) => s,
  scope: () => ({}),
  // VULN: template expressions run in Node with require() in scope: SSTI becomes remote code execution.
  awardCheck: (raw, input, rendered) => rendered.includes('uid='),
});

module.exports = {
  id: 'ssti',
  name: 'Server-Side Template Injection',
  tagline: 'A greeting card that eval()s your name. Prove it with {{7*7}}, then steal the flag.',
  description: 'The /ssti/greet endpoint renders your name through a naive homemade template engine that evaluates anything inside {{ }} as server-side code. Prove expression evaluation with arithmetic, then escalate to read a secret variable from the template scope.',
  difficulty: 'Intermediate',
  vulns: VULNS,
  router,
};
