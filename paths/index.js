'use strict';
// M13 career paths: guided challenge sequences with progress tracking and
// verifiable PNG certificates. Defs live in sibling files (real content is
// owned by the path authors); this index owns the framework: loading,
// progress, prerequisites, verification codes, and the four routes.
// The certpng.js renderer is owned by the cert worker and loaded lazily
// with a try/catch so a missing renderer can never break the boot.
const express = require('express');
const crypto = require('crypto');
const { page, esc, briefPanel, difficultyPill, progressBar, errorPage } = require('../lib/page');
const { captured } = require('../lib/flags');
const { installId } = require('../lib/db');

function loadDef(p) {
  try { return require(p); }
  catch (e) { console.warn('[warn] path def missing: ' + p); return null; }
}

// Real defs are written by the path authors into these exact files; the
// defensive loader keeps the framework working if one is missing.
const paths = ['./zero-to-web-pentester', './api-hacker', './authentication-assassin']
  .map(loadDef)
  .filter(Boolean);

// Challenge registry, injected by app.js after the modules mount.
// Used to resolve step titles and the "Enter" challenge links (vuln.link),
// falling back to the module index when the registry is unset.
let registry = [];
function setPathsRegistry(reg) { registry = Array.isArray(reg) ? reg : []; }

function findPath(id) {
  return paths.find((p) => p && p.id === String(id)) || null;
}

function findVuln(moduleId, vulnId) {
  const m = (registry || []).find((mm) => mm && mm.id === moduleId);
  if (!m) return null;
  const v = (Array.isArray(m.vulns) ? m.vulns : []).find((vv) => vv && vv.id === vulnId);
  return { mod: m, vuln: v };
}

function stepTitle(s) {
  const found = findVuln(s.moduleId, s.vulnId);
  if (found && found.vuln && found.vuln.name) {
    return found.mod.name + ': ' + found.vuln.name;
  }
  return s.moduleId + ': ' + s.vulnId;
}

function stepLink(s) {
  const found = findVuln(s.moduleId, s.vulnId);
  return (found && found.vuln && found.vuln.link) || ('/' + s.moduleId);
}

function pathSteps(p) {
  return Array.isArray(p.steps) ? p.steps : [];
}

function pathProgress(req, p) {
  const steps = pathSteps(p);
  const done = steps.filter((s) => captured(req, s.moduleId, s.vulnId)).length;
  return { done, total: steps.length };
}

function pathComplete(req, p) {
  const { done, total } = pathProgress(req, p);
  return total > 0 && done === total;
}

function prereqsMet(req, p) {
  const prereqs = Array.isArray(p.prerequisites) ? p.prerequisites : [];
  return prereqs.every((id) => {
    const pre = findPath(id);
    return pre ? pathComplete(req, pre) : false;
  });
}

// Certificate verification code: PTX-<8 hex>, bound to this install and,
// when one is given, to the student's name. Derived from the
// per-deployment install_id, so a certificate minted on another machine
// cannot verify here. Case-insensitive by convention.
//
// Identity binding is OPT-IN. Without a name the derivation is the legacy
// one (installId + ':' + pathId), so every certificate ever generated for
// solo learners keeps verifying unchanged. With a name it becomes
// installId + ':' + pathId + ':' + name, so two classmates on the same
// install no longer receive identical codes. The verify page is explicit:
// a code is identity-bound only when a name was entered at generation.
function normalizeStudentName(name) {
  return String(name == null ? '' : name).trim().replace(/\s+/g, ' ').toLowerCase().slice(0, 48);
}
function verifyCodeFor(pathId, studentName) {
  const name = normalizeStudentName(studentName);
  const input = name
    ? installId() + ':' + String(pathId) + ':' + name
    : installId() + ':' + String(pathId);
  return 'PTX-' + crypto.createHash('sha256')
    .update(input)
    .digest('hex')
    .slice(0, 8)
    .toUpperCase();
}

// Short public fingerprint of this install, printed on certificates.
function installFingerprint() {
  return crypto.createHash('sha256')
    .update(installId())
    .digest('hex')
    .slice(0, 12);
}

// Same score chip markup as app.js so the topbar stays consistent when the
// paths router mounts. Guards an unset registry (counts stay zero).
function scoreChipHtml(req) {
  let got = 0, total = 0;
  for (const m of registry || []) {
    const vulns = Array.isArray(m.vulns) ? m.vulns : [];
    total += vulns.length;
    got += vulns.filter((v) => captured(req, m.id, v.id)).length;
  }
  return `<span class="score-chip" title="Flags captured"><span aria-hidden="true">🚩</span> ${got}/${total}</span>`;
}

function statusPill(hit, capturedLabel, missingLabel) {
  return hit
    ? `<span class="status status-captured"><span class="dot" aria-hidden="true"></span>${esc(capturedLabel || 'Captured')}</span>`
    : `<span class="status status-missing"><span class="dot" aria-hidden="true"></span>${esc(missingLabel || 'Not captured')}</span>`;
}

function notFoundHtml(id) {
  return page('Not found',
    errorPage(404, 'No such path',
      '<p>That career path does not exist. See the paths index for the available career paths.</p>'),
    'paths', { scoreChip: '' });
}

const router = express.Router();

// GET /paths -> the paths index page.
router.get('/', (req, res) => {
  const cards = paths.map((p, i) => {
    const { done, total } = pathProgress(req, p);
    const num = String(i + 1).padStart(2, '0');
    const complete = pathComplete(req, p);
    const met = prereqsMet(req, p);
    const prereqs = Array.isArray(p.prerequisites) ? p.prerequisites : [];
    const prereqBadges = prereqs.map((id) => {
      const pre = findPath(id);
      const preName = pre ? pre.name : id;
      return `<span class="clay-pill">Requires: ${esc(preName)}</span>`;
    }).join(' ');
    const lockNote = (!met && prereqs.length)
      ? `<p class="dim" style="display:flex;gap:.6rem;align-items:flex-start"><span class="orb" aria-hidden="true">🔒</span><span><b>Locked: finish ${prereqs.map((id) => {
        const pre = findPath(id);
        return esc(pre ? pre.name : id);
      }).join(', ')} first.</b> This is guidance, not a hard block: you can still browse the steps now.</span></p>`
      : '';
    return `<a class="clay-card reveal" href="/paths/${esc(p.id)}">
      <div class="card-top"><span class="orb" aria-hidden="true">${num}</span>${difficultyPill(p.difficulty)}</div>
      <h3>${esc(p.name)}</h3>
      <p class="tagline">${esc(p.tagline || '')}</p>
      ${prereqBadges ? `<p>${prereqBadges}</p>` : ''}
      ${lockNote}
      <div class="card-foot">
        ${complete ? statusPill(true, 'Path completed') : ''}
        ${progressBar(done, total, p.name + ' progress')}
      </div>
    </a>`;
  }).join('');

  const body = paths.length
    ? `<section class="grid" aria-label="Career paths">${cards}</section>`
    : `<div class="empty"><h2>No paths yet</h2><p>Career paths are still being prepared. Check back soon.</p></div>`;

  res.send(page('Career paths', `
    <h1>Career paths</h1>
    <p class="lead">Guided sequences of challenges that take you from one
    skill level to the next. Work the steps in order, capture every flag,
    and earn a verifiable certificate bound to this install, and to your
    name if you enter one when you generate it. A path may
    suggest finishing another path first: that is guidance, not a lock.</p>
    ${body}`,
    'paths', { scoreChip: scoreChipHtml(req) }));
});

// GET /paths/:id/certificate -> PNG certificate (complete paths only).
// Registered BEFORE the generic /:id route so "certificate" is not
// swallowed as a path id.
router.get('/:id/certificate', async (req, res) => {
  const p = findPath(req.params.id);
  if (!p) {
    res.status(404).send(notFoundHtml(req.params.id));
    return;
  }
  if (!pathComplete(req, p)) {
    res.status(403).send(page('Certificate locked',
      errorPage(403, 'Certificate not unlocked yet',
        `<p>Capture all ${pathSteps(p).length} flags on the <a href="/paths/${esc(p.id)}">${esc(p.name)}</a> path first. Your certificate unlocks when every step shows captured: a downloadable PNG with a verification code anyone can check on this install.</p>`),
      'paths', { scoreChip: scoreChipHtml(req) }));
    return;
  }
  let renderCertificate;
  try {
    ({ renderCertificate } = require('../lib/certpng'));
  } catch (e) {
    res.status(500).send(page('Certificate unavailable',
      errorPage(500, 'Certificate renderer missing',
        '<p>The certificate renderer is not installed on this deployment yet. The path itself is unaffected; only the PNG download is unavailable.</p>'),
      'paths', { scoreChip: scoreChipHtml(req) }));
    return;
  }
  // Student identity (P1-5): the name is entered on the path page's
  // certificate form (?name=) and remembered on the session. It is what
  // the certificate prints, and it is mixed into the verification code so
  // the code identifies this student. No name anywhere -> the legacy
  // per-install code and the generic printed name, exactly as before.
  const entered = typeof req.query.name === 'string' ? req.query.name.trim().slice(0, 48) : '';
  if (entered && req.session) {
    try { req.session.studentName = entered; } catch (e) { /* display-only fallback below */ }
  }
  const accountName = (req.session && req.session.user && req.session.user.username) || '';
  const boundName = entered || (req.session && req.session.studentName) || accountName || '';
  try {
    const buf = await Promise.resolve(renderCertificate({
      pathName: p.name,
      studentName: boundName || 'PenTrix Student',
      dateStr: new Date().toISOString().slice(0, 10),
      installFingerprint: installFingerprint(),
      verifyCode: verifyCodeFor(p.id, boundName),
      pathId: p.id,
    }));
    res.type('png').send(buf);
  } catch (e) {
    res.status(500).send(page('Certificate error',
      errorPage(500, 'Could not render the certificate',
        '<p>The certificate renderer failed on this request. Try again; if it keeps failing, report it.</p>'),
      'paths', { scoreChip: scoreChipHtml(req) }));
  }
});

// GET /paths/:id/verify -> check a certificate verification code against
// this install. Codes are derived from this install's secret identity, so
// a code minted on another machine will not validate here.
router.get('/:id/verify', (req, res) => {
  const p = findPath(req.params.id);
  if (!p) {
    res.status(404).send(notFoundHtml(req.params.id));
    return;
  }
  const submitted = typeof req.query.code === 'string' ? req.query.code.trim() : '';
  const submittedName = typeof req.query.name === 'string' ? req.query.name : '';
  let resultHtml = '';
  if (submitted) {
    const expected = verifyCodeFor(p.id, submittedName);
    const valid = submitted.toUpperCase() === expected.toUpperCase();
    const who = normalizeStudentName(submittedName)
      ? ` for the student name on the form (<b>${esc(normalizeStudentName(submittedName))}</b>)`
      : ' (no student name: this is the per-install code, not bound to a person)';
    resultHtml = valid
      ? `<div class="card" role="status"><div class="card-top">${statusPill(true, 'Valid')}</div>
        <p>This code is a genuine certificate for <b>${esc(p.name)}</b> issued by <b>this install</b> (fingerprint <code>${esc(installFingerprint())}</code>)${who}.</p></div>`
      : `<div class="card" role="alert"><div class="card-top">${statusPill(false, null, 'Invalid')}</div>
        <p><b>Invalid code.</b> <code>${esc(submitted)}</code> is <b>not</b> a valid certificate code for <b>${esc(p.name)}</b> on this install${who}. Check the code for typos, and note that certificates minted on a different machine will never validate here. If the certificate was generated with a name, enter the exact same name.</p></div>`;
  }
  res.send(page('Verify certificate', `
    <p class="eyebrow"><a href="/paths/${esc(p.id)}">${esc(p.name)}</a></p>
    <h1>Verify a certificate</h1>
    <p class="lead">Enter the verification code printed on a ${esc(p.name)}
    certificate. The code is derived from this install's secret identity, so
    it only validates on the machine that issued it. A certificate generated
    with a student name also binds the code to that name: enter the same
    name below. A certificate generated without one is <b>not identity
    bound</b> and verifies with the name left empty.</p>
    <form method="get" action="/paths/${esc(p.id)}/verify" class="clay-card" style="max-width:28rem">
      <div class="card-top"><span class="orb" aria-hidden="true">✓</span></div>
      <label for="verify-code"><b>Verification code</b></label>
      <input class="clay-input" id="verify-code" name="code" type="text" autocomplete="off" spellcheck="false"
        placeholder="PTX-XXXXXXXX" value="${esc(submitted)}">
      <label for="verify-name"><b>Student name</b> <span class="dim">(only if one was entered when the certificate was generated)</span></label>
      <input class="clay-input" id="verify-name" name="name" type="text" autocomplete="off" spellcheck="false"
        placeholder="Name on the certificate" value="${esc(submittedName)}">
      <div class="card-foot"><button class="clay-btn clay-btn-primary" type="submit">Verify</button></div>
    </form>
    ${resultHtml}`,
    'paths', { scoreChip: scoreChipHtml(req) }));
});

// GET /paths/:id -> one path: description, prerequisites, ordered steps.
router.get('/:id', (req, res) => {
  const p = findPath(req.params.id);
  if (!p) {
    res.status(404).send(notFoundHtml(req.params.id));
    return;
  }
  const steps = pathSteps(p);
  const { done, total } = pathProgress(req, p);
  const complete = pathComplete(req, p);
  const met = prereqsMet(req, p);
  const prereqs = Array.isArray(p.prerequisites) ? p.prerequisites : [];
  const prereqBadges = prereqs.map((id) => {
    const pre = findPath(id);
    return `<span class="clay-pill">Requires: ${esc(pre ? pre.name : id)}</span>`;
  }).join(' ');

  const prereqHtml = !prereqs.length ? '' : briefPanel('Prerequisites',
    `<p>${prereqBadges}</p>` +
    ((!met)
      ? prereqs.map((id) => {
        const pre = findPath(id);
        const preName = pre ? pre.name : id;
        return `<p class="dim" style="display:flex;gap:.6rem;align-items:flex-start"><span class="orb" aria-hidden="true">🔒</span><span><b>Locked: finish <a href="/paths/${esc(id)}">${esc(preName)}</a> first.</b> This is guidance, not a hard block: you can still enter the challenges below, but the path is designed to be taken after its prerequisites.</span></p>`;
      }).join('')
      : `<p class="dim">All prerequisites are complete. This path is fully unlocked for you.</p>`),
    'Prerequisites');

  const stepsHtml = steps.map((s, i) => {
    const num = String(i + 1).padStart(2, '0');
    const hit = captured(req, s.moduleId, s.vulnId);
    return `<article class="clay-card reveal path-step" aria-label="Step ${num}: ${esc(stepTitle(s))}">
      <div class="card-top"><span class="orb" aria-hidden="true">${num}</span>${statusPill(hit)}</div>
      <h3>${esc(stepTitle(s))}</h3>
      <div class="tagline">${s.note ? esc(s.note) : ''}</div>
      <p class="dim"><code>${esc(stepLink(s))}</code></p>
      <div class="card-foot"><a class="clay-btn clay-btn-primary clay-btn-sm" href="${esc(stepLink(s))}">Enter the challenge</a></div>
    </article>`;
  }).join('');

  const savedName = (req.session && req.session.studentName) || '';
  const certHtml = complete
    ? `<form method="get" action="/paths/${esc(p.id)}/certificate" class="clay-card" style="max-width:28rem">
       <div class="card-top"><span class="orb" aria-hidden="true">🎓</span></div>
       <label for="cert-name"><b>Your name or handle</b></label>
       <input class="clay-input" id="cert-name" name="name" type="text" maxlength="48" autocomplete="off" spellcheck="false"
         placeholder="e.g. Ada Lovelace" value="${esc(savedName)}">
       <p class="dim">Your certificate is a PNG with this name printed on it and a verification code derived from it, so your code differs from every classmate's on this install. Leave the name empty to use the plain per-install code instead: that code is <b>not identity bound</b> and is the same for every student here.</p>
       <div class="card-foot"><button class="clay-btn clay-btn-primary" type="submit">Get my certificate</button>
       <a class="clay-btn clay-btn-secondary" href="/paths/${esc(p.id)}/verify">Verify a certificate</a></div>
       </form>`
    : `<p class="dim">Capture all ${total} flags to earn your certificate: a PNG you can download, with a verification code printed on it. Anyone can check that code on the <a href="/paths/${esc(p.id)}/verify">verify page</a> of this install. Add your name when you generate it and the code is bound to you; without a name it is only bound to this install.</p>`;

  res.send(page(p.name, `
    <p class="eyebrow"><a href="/paths">Career paths</a> · ${difficultyPill(p.difficulty)}</p>
    <h1>${esc(p.name)}</h1>
    <p class="lead">${esc(p.tagline || '')}</p>
    ${prereqHtml}
    ${briefPanel('The path', p.description || '', 'What you will learn')}
    <div class="progress-meta" style="margin-bottom:1rem">${progressBar(done, total, p.name + ' progress')}</div>
    <h2>Steps</h2>
    <section class="grid" aria-label="Path steps">${stepsHtml}</section>
    <h2>Certificate</h2>
    ${certHtml}`,
    'paths', { scoreChip: scoreChipHtml(req) }));
});

module.exports = {
  router, paths, setPathsRegistry,
  pathProgress, pathComplete, prereqsMet,
  verifyCodeFor, installFingerprint, normalizeStudentName,
};
