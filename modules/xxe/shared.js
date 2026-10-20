'use strict';
// XXE module shared helpers: the deliberately naive entity-expansion
// machinery, copied verbatim from modules/xxe/router.js by the finisher so
// every challenge file can require it from '../shared'.
// State shared with the module index page's OOB collector routes: oobLog is
// the single pingback log array (same identity everywhere it is used).

const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');

const SECRET_ABS = path.join(__dirname, 'secret.txt');
const oobLog = []; // { time, d, ip }

// Fetch a URL with a 5s timeout, used to resolve http:// external entities.
// The optional trace ({ fetches: [] }) records every URL fetched, so an
// award handler can prove the pingback really happened during this request's
// entity expansion instead of trusting a shared log anyone can ping.
function fetchUrl(url, trace) {
  // Per-request dedupe: one expansion pass can declare the same entity in
  // two places (for example an external DTD is expanded once on its own and
  // again once spliced into the document), so the same URL used to be
  // fetched twice for a single honest solve and the pingback counter read
  // 2. Within one traced request, a repeated fetch of the exact same URL
  // returns the first result instead of firing a second request, and it is
  // recorded in trace.fetches only once.
  if (trace && trace.fetchCache && Object.prototype.hasOwnProperty.call(trace.fetchCache, url)) {
    return Promise.resolve(trace.fetchCache[url]);
  }
  return new Promise((resolve) => {
    if (trace && trace.fetches) trace.fetches.push(url);
    const client = url.startsWith('https://') ? https : http;
    let done = false;
    const finish = (value) => {
      if (!done) {
        done = true;
        if (trace) {
          if (!trace.fetchCache) trace.fetchCache = {};
          trace.fetchCache[url] = value;
        }
        resolve(value);
      }
    };
    // Per-session collection (P1-1): when the award handlers pass the
    // student's cookie + this app's own base URL in the trace, fetches back
    // into this app (the collector routes) run inside the student's session,
    // so /xxe/collector/dtd serves that student's hosted DTD. External URLs
    // never receive the cookie.
    const headers = {};
    if (trace && trace.cookie && trace.selfBase && url.startsWith(trace.selfBase)) {
      headers.cookie = trace.cookie;
    }
    let req;
    try {
      req = client.get(url, { timeout: 5000, headers }, (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => finish(body));
      });
    } catch (e) {
      return finish(`[entity error: ${e.message}]`);
    }
    req.on('timeout', () => { req.destroy(); finish('[entity error: request timed out after 5s]'); });
    req.on('error', (e) => finish(`[entity error: ${e.message}]`));
  });
}

// Resolve one SYSTEM entity URI to its content.
// The optional trace ({ reads: [] }) records every file:// read with its
// content, so an award handler can prove the secret really was read from
// disk during this request (typing the marker text into the input box, or
// hosting a DTD with the literal marker in it, reads no file).
async function resolveEntity(uri, trace) {
  if (uri.startsWith('file://')) {
    // VULN: arbitrary local file read , SYSTEM file:// entities are honored with no allowlist.
    const filePath = uri.slice('file://'.length);
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      if (trace && trace.reads) trace.reads.push({ uri, content });
      return content;
    } catch (e) {
      return `[entity error: could not read file "${filePath}": ${e.message}]`;
    }
  }
  if (uri.startsWith('http://') || uri.startsWith('https://')) {
    // VULN: SSRF via external entity , any http(s) URL is fetched server-side.
    return await fetchUrl(uri, trace);
  }
  return `[entity error: unsupported scheme in "${uri}"]`;
}

// Deliberately naive regex-based entity expander (single pass, no recursion guard needed).
async function expandEntities(xml, trace) {
  // Accept double- or single-quoted SYSTEM URIs (single quotes let parameter-entity
  // payloads nest one entity declaration inside another).
  const re = /<!ENTITY\s+(\w+)\s+SYSTEM\s+(?:"([^"]+)"|'([^']+)')>/g;
  const entities = {};
  let m;
  while ((m = re.exec(xml)) !== null) {
    entities[m[1]] = await resolveEntity(m[2] !== undefined ? m[2] : m[3], trace);
  }
  let expanded = xml;
  for (const name of Object.keys(entities)) {
    // VULN: entity values are substituted blindly, including attacker-controlled file/URL content.
    expanded = expanded.split('&' + name + ';').join(entities[name]);
  }
  return expanded;
}

// Recursive internal-entity expander with NO recursion guard: nested entities
// blow up exponentially (billion laughs). Output is capped so the lab box survives.
// VULN: unbounded recursive entity expansion enables an XML DoS.
function expandRecursive(xml) {
  const defs = {};
  const re = /<!ENTITY\s+(\w+)\s+"([^"]*)">/g;
  let m;
  while ((m = re.exec(xml)) !== null) defs[m[1]] = m[2];
  let out = xml;
  for (let i = 0; i < 30; i++) {
    // Stop before the next 10x jump blows past ~80 MB: worst case stays bounded in seconds.
    if (out.length > 8000000) break;
    const next = out.replace(/&(\w+);/g, (mm, name) => (name in defs ? defs[name] : mm));
    if (next === out) break;
    out = next;
  }
  return out;
}

// External-DTD expander: fetches a remote DTD via a parameter entity, expands
// parameter entities declared inside it, then resolves general entities.
// VULN: external DTDs are fetched and their parameter entities honored with no allowlist.
async function expandExternalDtd(xml, trace) {
  let doc = xml;
  // The outer SYSTEM identifier and the parameter entities declared inside
  // the fetched DTD all accept double- or single-quoted URIs, like the
  // general-entity expander already does, so a single-quoted SYSTEM no
  // longer fails silently.
  const reExt = /<!ENTITY\s+%\s+(\w+)\s+SYSTEM\s+(?:"([^"]+)"|'([^']+)')>/g;
  let m;
  while ((m = reExt.exec(xml)) !== null) {
    const uri = m[2] !== undefined ? m[2] : m[3];
    const dtdText = await resolveEntity(uri, trace);
    const pe = {};
    const rePe = /<!ENTITY\s+%\s+(\w+)\s+SYSTEM\s+(?:"([^"]+)"|'([^']+)')>/g;
    let m2;
    while ((m2 = rePe.exec(dtdText)) !== null) pe[m2[1]] = await resolveEntity(m2[2] !== undefined ? m2[2] : m2[3], trace);
    let dtdExpanded = dtdText;
    let guard = 0, prev;
    do {
      prev = dtdExpanded;
      dtdExpanded = dtdExpanded.replace(/%(\w+);/g, (mm, n) => (n in pe ? pe[n] : mm));
      guard++;
    } while (dtdExpanded !== prev && guard < 10);
    // Resolving here fires http:// entities declared in the DTD (the OOB pingback).
    dtdExpanded = await expandEntities(dtdExpanded, trace);
    doc = doc.split('%' + m[1] + ';').join(dtdExpanded);
  }
  return expandEntities(doc, trace);
}

// Inline parameter-entity expander: %file; reads a file, %oob; can smuggle a brand
// new <!ENTITY> declaration into the doctype, which is then resolved (OOB).
// VULN: parameter entities are expanded inside the doctype, so an attacker can
// declare new external entities at parse time and exfiltrate out-of-band.
async function expandParamEntities(xml, trace) {
  const extPe = {};
  let m;
  // External parameter entities accept double- or single-quoted SYSTEM
  // URIs here too, for the same reason as in expandExternalDtd.
  const reExt = /<!ENTITY\s+%\s+(\w+)\s+SYSTEM\s+(?:"([^"]+)"|'([^']+)')>/g;
  while ((m = reExt.exec(xml)) !== null) extPe[m[1]] = await resolveEntity(m[2] !== undefined ? m[2] : m[3], trace);
  const intPe = {};
  const reInt = /<!ENTITY\s+%\s+(\w+)\s+"([^"]*)">/g;
  while ((m = reInt.exec(xml)) !== null) intPe[m[1]] = m[2];
  const allPe = {};
  for (const k of Object.keys(intPe)) {
    allPe[k] = intPe[k].replace(/%(\w+);/g, (mm, n) => (n in extPe ? extPe[n] : mm));
  }
  let doc = xml, prev, guard = 0;
  do {
    prev = doc;
    doc = doc.replace(/%(\w+);/g, (mm, n) => {
      if (n in allPe) return allPe[n];
      if (n in extPe) return extPe[n];
      return mm;
    });
    guard++;
  } while (doc !== prev && guard < 10);
  // Entities declared via %oob; are now plain <!ENTITY> declarations: resolve them.
  return expandEntities(doc, trace);
}

// XInclude expander: xi:include hrefs are resolved server-side like entities.
// VULN: xi:include file:// and http:// hrefs are honored with no allowlist.
async function expandXInclude(xml, trace) {
  const re = /<xi:include\b[^>]*?\bhref="([^"]+)"[^>]*?\/>/gi;
  const jobs = [];
  let m;
  while ((m = re.exec(xml)) !== null) jobs.push({ tag: m[0], href: m[1] });
  let out = xml;
  for (const j of jobs) {
    const content = await resolveEntity(j.href, trace);
    out = out.split(j.tag).join(content);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Award evidence: proof that a real entity resolution happened, not that the
// marker string was merely typed into the input box.
//
// markerProven (inline challenges): the marker appears in the expanded output,
// it does NOT appear in the raw submitted input, and the submission declares
// an entity (or an xi:include) that could have produced it.
// ---------------------------------------------------------------------------
function hasEntityDeclaration(xml) {
  return /<!ENTITY/i.test(xml) || /<xi:include/i.test(xml);
}

function markerProven(xml, out, marker) {
  return out.includes(marker) && !xml.includes(marker) && hasEntityDeclaration(xml);
}

// oobProven (out-of-band challenges): during this request's expansion the
// server really read a file whose content carries the marker, and really
// fired a pingback to the collector whose d value carries the marker.
// A direct ping of the collector log, or a hosted DTD with the literal
// marker text in it, reads no such file and fires no such request.
function oobProven(xml, trace, marker) {
  if (!trace || xml.includes(marker) || !/<!ENTITY/i.test(xml)) return false;
  const reads = trace.reads || [];
  const readHit = reads.some((r) => String(r.content).includes(marker));
  if (!readHit) return false;
  const fetches = trace.fetches || [];
  return fetches.some((u) => {
    try {
      const url = new URL(u);
      return url.pathname.endsWith('/collector/log') && (url.searchParams.get('d') || '').includes(marker);
    } catch (e) {
      return u.includes('/collector/log') && u.includes(marker);
    }
  });
}

// ---------------------------------------------------------------------------
// Pingback ownership: the shared collector log used to show every student's
// exfiltrated marker text to every other student. Each award handler now
// claims the pingbacks its own request caused; the collector page only shows
// a student the entries their own session caused.
// ---------------------------------------------------------------------------
const pingbackOwners = new Map(); // d value -> Set of session ids

function claimPingbacks(sessionId, trace) {
  if (!sessionId || !trace || !trace.fetches) return;
  for (const u of trace.fetches) {
    let d = null;
    try {
      const url = new URL(u);
      if (url.pathname.endsWith('/collector/log')) d = url.searchParams.get('d') || '';
    } catch (e) { /* not a URL */ }
    if (d === null || d === undefined) continue;
    if (!pingbackOwners.has(d)) pingbackOwners.set(d, new Set());
    pingbackOwners.get(d).add(sessionId);
  }
}

function pingbackOwnedBy(d, sessionId) {
  const owners = pingbackOwners.get(d);
  return !!owners && owners.has(sessionId);
}

// Count distinct pingbacks fired by one request, not raw fetch attempts:
// one honest solve that resolves the same collector URL must read as 1,
// even if an expander passes over that URL more than once.
function countUniquePingbacks(trace) {
  if (!trace || !trace.fetches) return 0;
  return new Set(trace.fetches.filter((u) => u.includes('/collector/log'))).size;
}

module.exports = {
  SECRET_ABS,
  oobLog,
  fetchUrl,
  resolveEntity,
  expandEntities,
  expandRecursive,
  expandExternalDtd,
  expandParamEntities,
  expandXInclude,
  markerProven,
  oobProven,
  claimPingbacks,
  pingbackOwnedBy,
  countUniquePingbacks,
};
