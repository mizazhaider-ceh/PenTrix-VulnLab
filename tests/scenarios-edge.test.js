'use strict';
// M12 unlock edge cases for the kill-chain scenarios framework.
// These pin the behaviors the framework must keep while scenario authors
// and other teams change defs and modules:
//
//   1. Completing stages out of order by direct navigation (stage 3's
//      challenge first) must not break the scenario page and must not
//      double-award the scenario flag.
//   2. Progress is per session: a fresh browser mid-scenario sees stage 1
//      only.
//   3. GET /scenarios/nope returns the styled 404, no crash.
//   4. Revisiting the scenario page after all stages are done and the flag
//      is already awarded shows the flag banner again, does not error, and
//      does not re-award.
//   5. Locked stages expose no briefing text and no link in the HTML.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { client, bootLab, flagFromDb, FLAG_RE } = require('./helpers');

function b64u(obj) {
  return Buffer.from(JSON.stringify(obj)).toString('base64url');
}

// All <a> hrefs whose visible text is exactly "Enter the challenge".
function enterChallengeLinks(text) {
  const links = [];
  const re = /<a\b[^>]*href=(["'])(.*?)\1[^>]*>\s*Enter the challenge\s*<\/a>/gi;
  let m;
  while ((m = re.exec(text)) !== null) links.push(m[2]);
  return links;
}

// Distinctive briefing phrases, one per API Heist stage (titles are public
// even when locked; briefings must not leak).
const BRIEFING = {
  1: 'The API browser viewer lies by design',
  2: 'turn a nobody into a somebody',
  3: 'declare it trustworthy',
  4: 'forgot the authorization check entirely',
};

function noEmDash(text, where) {
  assert.ok(!text.includes('\u2014'), `em dash on ${where}`);
}

// How many flag rows exist for one (module_id, vuln_id) pair in the
// deployment database: the scenario flag must be seeded exactly once and
// never duplicated by the award path.
function flagRowCount(dataDir, modId, vulnId) {
  const Database = require('better-sqlite3');
  const db = new Database(path.join(dataDir, 'vulnlab.db'), { readonly: true });
  const row = db
    .prepare('SELECT COUNT(*) AS n FROM flags WHERE module_id = ? AND vuln_id = ?')
    .get(modId, vulnId);
  db.close();
  return row.n;
}

// --- The real exploits, mirroring tests/scenarios-api.test.js ---

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

test('M12 unlock edge cases', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const scenarioFlag = flagFromDb(dataDir, 'scenario', 'api-heist');

  await t.test('out-of-order completion: stage 3 first does not break the page or double-award', async () => {
    const c = client(srv.base);
    // Jump straight to stage 3's challenge URL, skipping stages 1-2.
    await exploitJwtNoneAdmin(c, dataDir);
    let text = await scenarioPage(c);
    let links = enterChallengeLinks(text);
    // Stage 1 is always open; stage 4 unlocks because its previous stage
    // (stage 3) is captured; stages 2-3 stay locked.
    assert.equal(links.length, 2, 'stage 1 open plus stage 4 unlocked by stage 3, nothing else');
    for (const href of links) {
      assert.equal((await c.get(href)).status, 200, `link resolves: ${href}`);
    }
    assert.ok(text.includes(BRIEFING[1]), 'stage 1 briefing visible');
    assert.ok(!text.includes(BRIEFING[2]), 'stage 2 briefing stays hidden while locked');
    assert.ok(!text.includes(BRIEFING[3]), 'captured-but-gated stage 3 briefing stays hidden until stage 2 is done');
    assert.equal((text.match(FLAG_RE) || []).length, 0, 'no scenario flag yet');
    noEmDash(text, 'out-of-order scenario page');

    // Finish the rest in a scrambled order: stage 4, then 1, then 2.
    await exploitApiVersionBypass(c, dataDir);
    await exploitExposure(c, dataDir);
    await exploitMassAssignment(c, dataDir);
    text = await scenarioPage(c);
    const shown = text.match(FLAG_RE) || [];
    assert.ok(shown.includes(scenarioFlag), 'scenario flag awarded on completion');
    assert.equal(shown.length, 1, 'the banner shows the scenario flag exactly once');
    assert.equal(flagRowCount(dataDir, 'scenario', 'api-heist'), 1, 'exactly one flag row in the flags table');

    // Revisit: banner again, no error, no re-award.
    text = await scenarioPage(c);
    const reshown = text.match(FLAG_RE) || [];
    assert.ok(reshown.includes(scenarioFlag), 'revisit still shows the scenario flag banner');
    assert.equal(reshown.length, 1, 'banner still rendered exactly once');
    assert.equal(flagRowCount(dataDir, 'scenario', 'api-heist'), 1, 'revisit did not duplicate the flag row');
    noEmDash(text, 'completed scenario page revisit');
  });

  await t.test('fresh session mid-scenario sees stage 1 only', async () => {
    const first = client(srv.base);
    await exploitExposure(first, dataDir);
    await exploitMassAssignment(first, dataDir);
    await exploitJwtNoneAdmin(first, dataDir);
    assert.equal(enterChallengeLinks(await scenarioPage(first)).length, 4, 'first student unlocked all four stages (stage 4 opens once stage 3 is captured)');

    const second = client(srv.base);
    const text = await scenarioPage(second);
    assert.equal(enterChallengeLinks(text).length, 1, 'new browser sees stage 1 only');
    assert.equal((text.match(FLAG_RE) || []).length, 0, 'new browser sees no flags');
    assert.ok(text.includes(BRIEFING[1]), 'stage 1 briefing visible to the new browser');
    assert.ok(!text.includes(BRIEFING[2]), 'locked stage 2 briefing not leaked to the new browser');
    assert.ok(!text.includes(BRIEFING[3]), 'locked stage 3 briefing not leaked to the new browser');
    assert.ok(!text.includes(BRIEFING[4]), 'locked stage 4 briefing not leaked to the new browser');
  });

  await t.test('unknown scenario id returns the styled 404 without crashing', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/scenarios/nope');
    assert.equal(status, 404, 'unknown scenario id is a 404');
    assert.ok(text.includes('No such scenario'), 'styled error page explains the miss');
    assert.ok(text.includes('/scenarios'), 'error page links back to the scenarios index');
    assert.equal((text.match(FLAG_RE) || []).length, 0, 'no flag on the 404 page');
    noEmDash(text, 'GET /scenarios/nope');
  });

  await t.test('completed scenario revisit shows the banner, no error, no re-award', async () => {
    const c = client(srv.base);
    await exploitExposure(c, dataDir);
    await exploitMassAssignment(c, dataDir);
    await exploitJwtNoneAdmin(c, dataDir);
    await exploitApiVersionBypass(c, dataDir);
    // First visit awards the scenario flag.
    let text = await scenarioPage(c);
    assert.ok((text.match(FLAG_RE) || []).includes(scenarioFlag), 'first visit awards and shows the flag');
    // Second and third visits: banner again, same flag, still one row.
    for (let i = 0; i < 2; i++) {
      text = await scenarioPage(c);
      const shown = text.match(FLAG_RE) || [];
      assert.ok(shown.includes(scenarioFlag), `revisit ${i + 1} shows the scenario flag banner`);
      assert.equal(shown.length, 1, `revisit ${i + 1} renders the banner exactly once`);
      assert.equal(flagRowCount(dataDir, 'scenario', 'api-heist'), 1, 'flag row never duplicated');
      noEmDash(text, `completed scenario revisit ${i + 1}`);
    }
  });

  await t.test('locked stages expose no briefing text and no link in the HTML', async () => {
    const c = client(srv.base);
    const text = await scenarioPage(c);
    // Stage cards render in order; the only "Enter the challenge" link
    // belongs to stage 1.
    assert.equal(enterChallengeLinks(text).length, 1, 'only stage 1 exposes a challenge link');
    // Titles are public; briefings of locked stages must not appear.
    assert.ok(text.includes(BRIEFING[1]), 'unlocked stage 1 briefing is shown');
    for (const n of [2, 3, 4]) {
      assert.ok(!text.includes(BRIEFING[n]), `locked stage ${n} briefing absent from the HTML`);
    }
    // Locked stage cards contain no anchor at all (belt and braces: split
    // the stage cards out and check each locked one has no href).
    const cards = text.split('<article class="clay-card');
    assert.ok(cards.length > 1, 'stage cards rendered');
    for (const card of cards.slice(1)) {
      if (card.includes('stage-locked')) {
        assert.ok(!/href=/.test(card.split('</article>')[0]), 'locked stage card contains no link');
      }
    }
    noEmDash(text, 'locked stages view-source check');
  });
});
