'use strict';
// M12 kill-chain scenarios: chained, story-driven labs that span modules.
// Each scenario is a def file (see api-heist.js for the real format). Defs
// are loaded defensively: a missing or broken def only warns, it never
// breaks the boot. Scenario authors own their def files; this index owns
// the framework (index page, stage gating, completion award).
const express = require('express');
const { page, esc, briefPanel, difficultyPill, progressBar, flagBanner, errorPage } = require('../lib/page');
const { captured, award, flagFor } = require('../lib/flags');

function loadDef(p) {
  try { return require(p); }
  catch (e) { console.warn('[warn] scenario def missing: ' + p); return null; }
}

// Real defs are written by the scenario authors into these exact files;
// the fallbacks keep the framework working until they land.
const scenarios = ['./shop-takeover', './api-heist', './ghost-in-the-cms'].map(loadDef).filter(Boolean);

// Challenge registry, injected by app.js after the modules mount.
// Used to resolve the "Enter the challenge" link (vuln.link), falling
// back to the module index when the challenge is unknown.
let registry = [];
function setScenariosRegistry(reg) { registry = reg; }

function findScenario(id) {
  return scenarios.find((s) => s && s.id === String(id)) || null;
}

function challengeLink(moduleId, vulnId) {
  const m = (registry || []).find((mm) => mm && mm.id === moduleId);
  const v = m && Array.isArray(m.vulns) && m.vulns.find((vv) => vv && vv.id === vulnId);
  return (v && v.link) || ('/' + moduleId);
}

// Stage i is unlocked when it is the first stage, or the previous stage's
// flag is already captured by this student.
function stageUnlocked(req, sc, i) {
  if (i === 0) return true;
  const prev = sc.stages[i - 1];
  return captured(req, prev.moduleId, prev.vulnId);
}

function stagesDone(req, sc) {
  return sc.stages.filter((st) => captured(req, st.moduleId, st.vulnId)).length;
}

// Same score chip markup as app.js so the topbar stays consistent.
function scoreChipHtml(req) {
  let got = 0, total = 0;
  for (const m of registry || []) {
    const vulns = Array.isArray(m.vulns) ? m.vulns : [];
    total += vulns.length;
    got += vulns.filter((v) => captured(req, m.id, v.id)).length;
  }
  return `<span class="score-chip" title="Flags captured"><span aria-hidden="true">🚩</span> ${got}/${total}</span>`;
}

const router = express.Router();

// GET /scenarios -> the scenarios index page.
router.get('/', (req, res) => {
  const cards = scenarios.map((sc, i) => {
    const done = stagesDone(req, sc);
    const total = sc.stages.length;
    const num = String(i + 1).padStart(2, '0');
    const doneAll = captured(req, 'scenario', sc.id);
    return `<a class="clay-card reveal" href="/scenarios/${esc(sc.id)}">
      <div class="card-top"><span class="orb" aria-hidden="true">${num}</span>${difficultyPill(sc.difficulty)}</div>
      <h3>${esc(sc.name)}</h3>
      <p class="tagline">${esc(sc.tagline)}</p>
      <div class="card-foot">
        ${doneAll ? '<span class="status status-captured"><span class="dot" aria-hidden="true"></span>Completed</span>' : ''}
        ${progressBar(done, total, sc.name + ' progress')}
      </div>
    </a>`;
  }).join('');

  res.send(page('Kill-chain scenarios', `
    <h1>Kill-chain scenarios</h1>
    <p class="lead">Real attacks are chains, not single bugs. Each scenario
    strings several challenges across modules into one story. Stages unlock
    one at a time: capture the previous stage's flag to open the next.
    Finish every stage to earn the scenario flag.</p>
    <section class="grid" aria-label="Scenarios">${cards}</section>`,
    'scenarios', { scoreChip: scoreChipHtml(req) }));
});

// GET /scenarios/:id -> one scenario: story, gated stage list, completion award.
router.get('/:id', (req, res) => {
  const sc = findScenario(req.params.id);
  if (!sc) {
    res.status(404).send(page('Not found',
      errorPage(404, 'No such scenario',
        '<p>That scenario does not exist. Check the scenarios index for the ones that shipped.</p>'),
      'scenarios', { scoreChip: scoreChipHtml(req) }));
    return;
  }

  const done = stagesDone(req, sc);
  const total = sc.stages.length;
  const allDone = total > 0 && done === total;

  // Completion: award the scenario flag once, the moment the last stage's
  // flag is in. The banner renders at the top of the page.
  let completionHtml = '';
  if (allDone && !captured(req, 'scenario', sc.id)) {
    const flag = award(req, 'scenario', sc.id);
    completionHtml = flagBanner(flag);
  } else if (allDone) {
    // Revisit after the award: show the flag banner again (read from the
    // seeded flags row, never re-awarded) so the student can re-copy it.
    completionHtml = flagBanner(flagFor('scenario', sc.id));
  }

  const stagesHtml = sc.stages.map((st, i) => {
    const num = String(i + 1).padStart(2, '0');
    const hit = captured(req, st.moduleId, st.vulnId);
    if (!stageUnlocked(req, sc, i)) {
      return `<article class="clay-card dim stage-locked" id="stage-${i + 1}" aria-label="Stage ${num}: locked">
        <div class="card-top"><span class="orb" aria-hidden="true">🔒</span></div>
        <h3>${esc(st.title)}</h3>
        <p class="tagline">Complete the previous stage to unlock</p>
      </article>`;
    }
    return `<article class="clay-card reveal" id="stage-${i + 1}" aria-label="Stage ${num}: ${esc(st.title)}">
      <div class="card-top"><span class="orb" aria-hidden="true">${num}</span>
        ${hit ? '<span class="status status-captured"><span class="dot" aria-hidden="true"></span>Captured</span>' : ''}
      </div>
      <h3>${esc(st.title)}</h3>
      <div class="tagline">${st.briefing || ''}</div>
      <div class="card-foot"><a class="clay-btn clay-btn-primary clay-btn-sm" href="${esc(challengeLink(st.moduleId, st.vulnId))}">Enter the challenge</a></div>
    </article>`;
  }).join('');

  res.send(page(sc.name, `
    <p class="eyebrow"><a href="/scenarios">Scenarios</a> · ${difficultyPill(sc.difficulty)}</p>
    <h1>${esc(sc.name)}</h1>
    <p class="lead">${esc(sc.tagline)}</p>
    <p class="how-earned note"><strong>How the scenario flag is earned.</strong> Stages unlock one at a time: capture a stage's flag and the next stage opens. Capture every stage's flag and the scenario flag is awarded here, at the top of this page.</p>
    ${completionHtml}
    ${briefPanel('The story', sc.story || '', 'Kill chain')}
    <h2>Stages</h2>
    <div class="progress-meta" style="margin-bottom:1rem">${progressBar(done, total, sc.name + ' progress')}</div>
    <section class="grid" aria-label="Stages">${stagesHtml}</section>`,
    'scenarios', { scoreChip: scoreChipHtml(req) }));
});

module.exports = { router, scenarios, setScenariosRegistry };
