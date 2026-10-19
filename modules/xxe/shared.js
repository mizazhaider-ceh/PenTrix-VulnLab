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
function fetchUrl(url) {
  return new Promise((resolve) => {
    const client = url.startsWith('https://') ? https : http;
    let done = false;
    const finish = (value) => { if (!done) { done = true; resolve(value); } };
    let req;
    try {
      req = client.get(url, { timeout: 5000 }, (res) => {
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
async function resolveEntity(uri) {
  if (uri.startsWith('file://')) {
    // VULN: arbitrary local file read , SYSTEM file:// entities are honored with no allowlist.
    const filePath = uri.slice('file://'.length);
    try {
      return fs.readFileSync(filePath, 'utf8');
    } catch (e) {
      return `[entity error: could not read file "${filePath}": ${e.message}]`;
    }
  }
  if (uri.startsWith('http://') || uri.startsWith('https://')) {
    // VULN: SSRF via external entity , any http(s) URL is fetched server-side.
    return await fetchUrl(uri);
  }
  return `[entity error: unsupported scheme in "${uri}"]`;
}

// Deliberately naive regex-based entity expander (single pass, no recursion guard needed).
async function expandEntities(xml) {
  // Accept double- or single-quoted SYSTEM URIs (single quotes let parameter-entity
  // payloads nest one entity declaration inside another).
  const re = /<!ENTITY\s+(\w+)\s+SYSTEM\s+(?:"([^"]+)"|'([^']+)')>/g;
  const entities = {};
  let m;
  while ((m = re.exec(xml)) !== null) {
    entities[m[1]] = await resolveEntity(m[2] !== undefined ? m[2] : m[3]);
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
async function expandExternalDtd(xml) {
  let doc = xml;
  const reExt = /<!ENTITY\s+%\s+(\w+)\s+SYSTEM\s+"([^"]+)">/g;
  let m;
  while ((m = reExt.exec(xml)) !== null) {
    const dtdText = await resolveEntity(m[2]);
    const pe = {};
    const rePe = /<!ENTITY\s+%\s+(\w+)\s+SYSTEM\s+"([^"]+)">/g;
    let m2;
    while ((m2 = rePe.exec(dtdText)) !== null) pe[m2[1]] = await resolveEntity(m2[2]);
    let dtdExpanded = dtdText;
    let guard = 0, prev;
    do {
      prev = dtdExpanded;
      dtdExpanded = dtdExpanded.replace(/%(\w+);/g, (mm, n) => (n in pe ? pe[n] : mm));
      guard++;
    } while (dtdExpanded !== prev && guard < 10);
    // Resolving here fires http:// entities declared in the DTD (the OOB pingback).
    dtdExpanded = await expandEntities(dtdExpanded);
    doc = doc.split('%' + m[1] + ';').join(dtdExpanded);
  }
  return expandEntities(doc);
}

// Inline parameter-entity expander: %file; reads a file, %oob; can smuggle a brand
// new <!ENTITY> declaration into the doctype, which is then resolved (OOB).
// VULN: parameter entities are expanded inside the doctype, so an attacker can
// declare new external entities at parse time and exfiltrate out-of-band.
async function expandParamEntities(xml) {
  const extPe = {};
  let m;
  const reExt = /<!ENTITY\s+%\s+(\w+)\s+SYSTEM\s+"([^"]+)">/g;
  while ((m = reExt.exec(xml)) !== null) extPe[m[1]] = await resolveEntity(m[2]);
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
  return expandEntities(doc);
}

// XInclude expander: xi:include hrefs are resolved server-side like entities.
// VULN: xi:include file:// and http:// hrefs are honored with no allowlist.
async function expandXInclude(xml) {
  const re = /<xi:include\b[^>]*?\bhref="([^"]+)"[^>]*?\/>/gi;
  const jobs = [];
  let m;
  while ((m = re.exec(xml)) !== null) jobs.push({ tag: m[0], href: m[1] });
  let out = xml;
  for (const j of jobs) {
    const content = await resolveEntity(j.href);
    out = out.split(j.tag).join(content);
  }
  return out;
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
};
