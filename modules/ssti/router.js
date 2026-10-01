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

module.exports = {
  id: 'ssti',
  name: 'Server-Side Template Injection',
  tagline: 'A greeting card that eval()s your name. Prove it with {{7*7}}, then steal the flag.',
  description: 'The /ssti/greet endpoint renders your name through a naive homemade template engine that evaluates anything inside {{ }} as server-side code. Prove expression evaluation with arithmetic, then escalate to read a secret variable from the template scope.',
  difficulty: 'Intermediate',
  vulns: VULNS,
  router,
};
