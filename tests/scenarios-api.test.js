'use strict';
// "API Heist" scenario: a chained kill-chain across four challenges.
//   stage 1: api/exposure           (excessive data exposure)
//   stage 2: api/mass-assignment    (privilege escalation via mass assignment)
//   stage 3: jwt/none-admin         (alg=none JWT forgery)
//   stage 4: api/api-version-bypass (broken access control in v2)
// Stage 1 starts unlocked with an "Enter the challenge" link; each later
// stage unlocks only after the real exploit for the previous stage's
// challenge lands for this student's session. Finishing all four stages
// awards the scenario flag, stored under ('scenario', 'api-heist').
//
// Contract this suite pins (for the infra lead wiring scenarios/api-heist.js):
//   GET /scenarios            -> 200, names the "API Heist" scenario and links
//                                to /scenarios/api-heist.
//   GET /scenarios/api-heist  -> 200; unlocked stages render an <a> whose
//                                visible text is exactly "Enter the challenge";
//                                locked stages render NO such link.
//   Completion renders the scenario flag in the form PENTRIX{<32 hex>},
//   equal to flagFromDb(dataDir, 'scenario', 'api-heist').
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, FLAG_RE } = require('./helpers');

function b64u(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

// All <a> hrefs whose visible text is exactly "Enter the challenge",
// in document order (stages render in order).
function enterChallengeLinks(text) {
  const links = [];
  const re = /<a\b[^>]*href=(["'])(.*?)\1[^>]*>\s*Enter the challenge\s*<\/a>/gi;
  let m;
  while ((m = re.exec(text)) !== null) links.push(m[2]);
  return links;
}

function noEmDash(text, where) {
  assert.ok(!text.includes('\u2014'), `em dash on ${where}`);
}

// --- The real exploits, mirroring tests/api.test.js and tests/jwt.test.js ---

async function exploitExposure(c, dataDir) {
  const r = await c.get('/api/users');
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('x-pentrix-flag'), flagFromDb(dataDir, 'api', 'exposure'));
}

async function exploitMassAssignment(c, dataDir) {
  await c.get('/api/login/alice');
  const r = await c.patchJson('/api/me', { role: 'admin' });
  assert.equal(r.status, 200);
  assert.equal(r.body.flag, flagFromDb(dataDir, 'api', 'mass-assignment'));
}

async function exploitJwtNoneAdmin(c, dataDir) {
  const token = b64u({ alg: 'none', typ: 'JWT' }) + '.' + b64u({ user: 'guest', role: 'admin' }) + '.';
  const r = await c.post('/jwt/none', { token });
  assert.equal(r.status, 200);
  assert.ok(r.text.includes(flagFromDb(dataDir, 'jwt', 'none-admin')));
}

async function exploitApiVersionBypass(c, dataDir) {
  await c.get('/api/login/alice');
  const r = await c.get('/api/v2/users/3');
  assert.equal(r.status, 200);
  assert.equal(r.body.flag, flagFromDb(dataDir, 'api', 'api-version-bypass'));
}

async function scenarioPage(c) {
  const { status, text } = await c.get('/scenarios/api-heist');
  assert.equal(status, 200);
  return text;
}

test('scenario: API Heist', async (t) => {
  const { srv, dataDir } = await bootLab(t);

  await t.test('index lists the API Heist scenario', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/scenarios');
    assert.equal(status, 200);
    assert.ok(text.includes('API Heist'), 'scenario name listed');
    assert.ok(text.includes('/scenarios/api-heist'), 'link to the scenario page');
    assert.equal((text.match(FLAG_RE) || []).length, 0, 'no flag on the index');
    noEmDash(text, 'GET /scenarios');
    assert.ok(!/<table>/.test(text), 'unstyled table');
  });

  await t.test('fresh page: stage 1 open, stages 2-4 locked', async () => {
    const c = client(srv.base);
    const text = await scenarioPage(c);
    const links = enterChallengeLinks(text);
    assert.equal(links.length, 1, 'only stage 1 shows an "Enter the challenge" link');
    const entry = await c.get(links[0]);
    assert.equal(entry.status, 200, 'stage 1 link resolves');
    assert.equal((text.match(FLAG_RE) || []).length, 0, 'no scenario flag before completion');
    noEmDash(text, 'fresh GET /scenarios/api-heist');
  });

  await t.test('exposure exploit unlocks stage 2, stage 3 stays locked', async () => {
    const c = client(srv.base);
    await exploitExposure(c, dataDir);
    const text = await scenarioPage(c);
    const links = enterChallengeLinks(text);
    assert.equal(links.length, 2, 'stages 1-2 open, stage 3 still locked');
    for (const href of links) {
      assert.equal((await c.get(href)).status, 200, `link resolves: ${href}`);
    }
    assert.equal((text.match(FLAG_RE) || []).length, 0, 'no scenario flag yet');
    noEmDash(text, 'stage 2 unlocked page');
  });

  await t.test('mass-assignment exploit unlocks stage 3, stage 4 stays locked', async () => {
    const c = client(srv.base);
    await exploitExposure(c, dataDir);
    await exploitMassAssignment(c, dataDir);
    const text = await scenarioPage(c);
    const links = enterChallengeLinks(text);
    assert.equal(links.length, 3, 'stages 1-3 open, stage 4 still locked');
    for (const href of links) {
      assert.equal((await c.get(href)).status, 200, `link resolves: ${href}`);
    }
    noEmDash(text, 'stage 3 unlocked page');
  });

  await t.test('jwt none-admin exploit unlocks stage 4', async () => {
    const c = client(srv.base);
    await exploitExposure(c, dataDir);
    await exploitMassAssignment(c, dataDir);
    await exploitJwtNoneAdmin(c, dataDir);
    const text = await scenarioPage(c);
    const links = enterChallengeLinks(text);
    assert.equal(links.length, 4, 'all four stages open');
    for (const href of links) {
      assert.equal((await c.get(href)).status, 200, `link resolves: ${href}`);
    }
    assert.equal((text.match(FLAG_RE) || []).length, 0, 'scenario flag needs stage 4 too');
    noEmDash(text, 'stage 4 unlocked page');
  });

  await t.test('api-version-bypass completes the heist and awards the scenario flag', async () => {
    const c = client(srv.base);
    await exploitExposure(c, dataDir);
    await exploitMassAssignment(c, dataDir);
    await exploitJwtNoneAdmin(c, dataDir);
    await exploitApiVersionBypass(c, dataDir);
    const text = await scenarioPage(c);
    const shown = text.match(FLAG_RE) || [];
    assert.ok(shown.length >= 1, 'captured scenario flag banner shown');
    assert.ok(
      shown.includes(flagFromDb(dataDir, 'scenario', 'api-heist')),
      'banner flag equals the scenario flag in the database'
    );
    noEmDash(text, 'completed scenario page');
  });

  await t.test('fresh client never sees locked stage links', async () => {
    const first = client(srv.base);
    const freshLinks = enterChallengeLinks(await scenarioPage(first));
    assert.equal(freshLinks.length, 1, 'fresh client sees only the stage 1 link');
    await exploitExposure(first, dataDir);
    const unlockedLinks = enterChallengeLinks(await scenarioPage(first));
    assert.equal(unlockedLinks.length, 2);
    assert.ok(
      !freshLinks.includes(unlockedLinks[1]),
      'stage 2 link was absent while locked, never leaked early'
    );
    const second = client(srv.base);
    assert.equal(
      enterChallengeLinks(await scenarioPage(second)).length,
      1,
      'unlocks are per student session, not global'
    );
  });

  await t.test('no em dashes anywhere on the scenario pages', async () => {
    const c = client(srv.base);
    noEmDash((await c.get('/scenarios')).text, 'GET /scenarios');
    noEmDash(await scenarioPage(c), 'GET /scenarios/api-heist');
    await exploitExposure(c, dataDir);
    await exploitMassAssignment(c, dataDir);
    await exploitJwtNoneAdmin(c, dataDir);
    await exploitApiVersionBypass(c, dataDir);
    noEmDash(await scenarioPage(c), 'completed GET /scenarios/api-heist');
  });
});
