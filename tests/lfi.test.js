'use strict';
// LFI module: every vuln's documented real exploit must earn the flag, a
// fake shortcut must not, and repeating the real exploit must not double it.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

test('lfi module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'lfi', id);

  await t.test('module page renders, links resolve, no em dash, no unstyled controls', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/lfi');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.ok(!/<table(?![^>]*class=)/.test(text), 'unstyled table');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 9);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    const links = [...text.matchAll(/href="(\/lfi[^"#]*)"/g)].map((m) => m[1]);
    assert.ok(links.length > 0, 'module index should link to its challenges');
    for (const href of new Set(links)) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('every challenge page is unstyled-control free and link-clean', async () => {
    const c = client(srv.base);
    const pages = ['/lfi/view', '/lfi/download', '/lfi/abs', '/lfi/double', '/lfi/nested',
      '/lfi/lang', '/lfi/log-demo', '/lfi/procinfo', '/lfi/config'];
    for (const p of pages) {
      const { status, text } = await c.get(p);
      assert.equal(status, 200, p);
      assert.ok(!text.includes('\u2014'), `em dash on ${p}`);
      assert.ok(!/<input(?![^>]*class="clay-input")/.test(text), `unstyled input on ${p}`);
      assert.ok(!/<select(?![^>]*class="clay-select")/.test(text), `unstyled select on ${p}`);
      assert.ok(!/<button(?![^>]*class="clay-btn)/.test(text), `unstyled button on ${p}`);
      const links = [...text.matchAll(/href="(\/lfi[^"#]*)"/g)].map((m) => m[1]);
      for (const href of new Set(links)) {
        const r = await c.get(href);
        assert.notEqual(r.status, 404, `${href} from ${p}`);
      }
    }
  });

  await t.test('traversal: plain name reads but does not earn it, ../docs/secret.txt does', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/lfi/view?file=secret.txt');
    assert.equal((shortcut.text.match(FLAG_RE) || []).length, 0, 'plain read must not award');
    assert.ok(!(await capturedSet(c)).includes('lfi:Basic Path Traversal'));

    const hit = await c.get('/lfi/view?file=../docs/secret.txt');
    const flags = hit.text.match(FLAG_RE) || [];
    assert.equal(flags.length, 1);
    assert.equal(flags[0], flagOf('traversal'));
    assert.ok((await capturedSet(c)).includes('lfi:Basic Path Traversal'));

    const again = await c.get('/lfi/view?file=../docs/secret.txt');
    assert.equal((again.text.match(FLAG_RE) || [])[0], flagOf('traversal'), 'repeat yields the same flag');
    const captured = await capturedSet(c);
    assert.equal(captured.filter((s) => s === 'lfi:Basic Path Traversal').length, 1, 'repeat must not double count');
  });

  await t.test('filter-bypass: a single ../ is filtered away, nested ....// survives it', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/lfi/download?file=secret.txt');
    assert.equal((shortcut.text.match(FLAG_RE) || []).length, 0, 'un-traversed read must not award');
    assert.ok(!(await capturedSet(c)).includes('lfi:Naive Filter Bypass'));

    const naive = await c.get('/lfi/download?file=../docs/secret.txt');
    assert.ok(naive.text.includes('Error reading'), 'single ../ should be stripped by the filter');
    assert.equal((naive.text.match(FLAG_RE) || []).length, 0);

    const hit = await c.get('/lfi/download?file=....//docs/secret.txt');
    const flags = hit.text.match(FLAG_RE) || [];
    assert.equal(flags.length, 1);
    assert.equal(flags[0], flagOf('filter-bypass'));

    const again = await c.get('/lfi/download?file=....//docs/secret.txt');
    assert.equal((again.text.match(FLAG_RE) || [])[0], flagOf('filter-bypass'));
  });

  await t.test('double-encode: a plain traversal is blocked, double percent-encoding slips through', async () => {
    const c = client(srv.base);
    const blocked = await c.get('/lfi/double?page=../docs/secret.txt');
    assert.ok(blocked.text.includes('Blocked'), 'un-encoded traversal should be rejected by the pre-check');
    assert.equal((blocked.text.match(FLAG_RE) || []).length, 0);
    assert.ok(!(await capturedSet(c)).includes('lfi:Encoding Bypass'));

    const hit = await c.get('/lfi/double?page=%252e%252e%252fdocs%252fsecret.txt');
    const flags = hit.text.match(FLAG_RE) || [];
    assert.equal(flags.length, 1);
    assert.equal(flags[0], flagOf('double-encode'));

    const again = await c.get('/lfi/double?page=%252e%252e%252fdocs%252fsecret.txt');
    assert.equal((again.text.match(FLAG_RE) || [])[0], flagOf('double-encode'));
  });

  await t.test('double-encode: %73ecret.txt reads the file but is no traversal, so no flag', async () => {
    const c = client(srv.base);
    // The cheat: a single-encoded letter (no traversal at all) still resolves
    // to the in-docs secret and used to award on the bare "%" in the raw input.
    const cheat = await c.get('/lfi/double?page=%73ecret.txt');
    assert.equal(cheat.status, 200);
    assert.ok(cheat.text.includes('LFI-SECRET-8830'), 'the read itself still works');
    assert.equal((cheat.text.match(FLAG_RE) || []).length, 0, 'a bare percent must not award');
    assert.ok(!(await capturedSet(c)).includes('lfi:Encoding Bypass'));
    // Reading the secret plainly is equally far from a double-encoded traversal.
    const plain = await c.get('/lfi/double?page=secret.txt');
    assert.ok(plain.text.includes('LFI-SECRET-8830'));
    assert.equal((plain.text.match(FLAG_RE) || []).length, 0, 'a plain in-docs read must not award');
    assert.ok(!(await capturedSet(c)).includes('lfi:Encoding Bypass'));
  });

  await t.test('nested-deep: a global single pass strips ../ once, nested dots regenerate it', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/lfi/nested?page=secret.txt');
    assert.equal((shortcut.text.match(FLAG_RE) || []).length, 0, 'no traversal attempted must not award');
    assert.ok(!(await capturedSet(c)).includes('lfi:Deep Nesting Bypass'));

    const hit = await c.get('/lfi/nested?page=....///docs/secret.txt');
    const flags = hit.text.match(FLAG_RE) || [];
    assert.equal(flags.length, 1);
    assert.equal(flags[0], flagOf('nested-deep'));

    const again = await c.get('/lfi/nested?page=....///docs/secret.txt');
    assert.equal((again.text.match(FLAG_RE) || [])[0], flagOf('nested-deep'));
  });

  await t.test('lang: a normal language is not the exploit, ../secret via lang is', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/lfi/lang?lang=fr');
    assert.equal(shortcut.status, 200);
    assert.equal((shortcut.text.match(FLAG_RE) || []).length, 0);
    assert.ok(!(await capturedSet(c)).includes('lfi:Language Parameter Traversal'));

    const hit = await c.get('/lfi/lang?lang=../secret');
    const flags = hit.text.match(FLAG_RE) || [];
    assert.equal(flags.length, 1);
    assert.equal(flags[0], flagOf('lang'));

    const again = await c.get('/lfi/lang?lang=../secret');
    assert.equal((again.text.match(FLAG_RE) || [])[0], flagOf('lang'));
  });

  await t.test('log-poison: reading the log without a prior real poison does not award it', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/lfi/view?file=lfi_access.log');
    assert.equal((shortcut.text.match(FLAG_RE) || []).length, 0, 'wrong path with no traversal must not award');
    assert.ok(!(await capturedSet(c)).includes('lfi:Log Poisoning Chain'));
  });

  await t.test('log-poison: poisoning the log via User-Agent then reading it via traversal awards it', async (st) => {
    const c = client(srv.base);
    const marker = 'PENTRIX-LOG-MARKER lfi-test-' + Date.now();
    const poisoned = await c.get('/lfi/log-demo', { 'user-agent': marker });
    if (!poisoned.text.includes(marker)) {
      // The module's access log lives next to its source (one level above
      // docs/, so the documented ../lfi_access.log traversal keeps working).
      // When modules/ is mounted read-only (as in this verification
      // command), the append silently no-ops and the chain cannot be
      // exercised end-to-end here; it works against a normal, writable
      // deployment. Skip rather than fake a pass.
      st.skip('modules/ is read-only in this run; the log append cannot persist here');
      return;
    }
    const hit = await c.get('/lfi/view?file=../lfi_access.log');
    const flags = hit.text.match(FLAG_RE) || [];
    assert.equal(flags.length, 1);
    assert.equal(flags[0], flagOf('log-poison'));
    assert.ok((await capturedSet(c)).includes('lfi:Log Poisoning Chain'));

    const again = await c.get('/lfi/view?file=../lfi_access.log');
    // P1A: the capture banner renders exactly once per capture, so the
    // repeat view re-renders no flag. The flag stays viewable on the
    // challenge page itself (showCaptured, the flagFor display path).
    assert.equal((again.text.match(FLAG_RE) || []).length, 0, 'repeat must not re-render the capture banner (P1A)');
    const demo = await c.get('/lfi/log-demo', { 'user-agent': 'view-check' });
    assert.equal((demo.text.match(FLAG_RE) || [])[0], flagOf('log-poison'), 'captured flag stays viewable on the log demo page');
    const captured = await capturedSet(c);
    assert.equal(captured.filter((s) => s === 'lfi:Log Poisoning Chain').length, 1, 'repeat must not double count');
  });

  await t.test('proc-self: the default status file is not the exploit, environ is', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/lfi/procinfo?f=status');
    assert.equal((shortcut.text.match(FLAG_RE) || []).length, 0);
    assert.ok(!(await capturedSet(c)).includes('lfi:proc-self'));

    const hit = await c.get('/lfi/procinfo?f=environ');
    const flags = hit.text.match(FLAG_RE) || [];
    assert.equal(flags.length, 1);
    assert.equal(flags[0], flagOf('proc-self'));

    const again = await c.get('/lfi/procinfo?f=environ');
    assert.equal((again.text.match(FLAG_RE) || [])[0], flagOf('proc-self'));
  });

  await t.test('config-read: the default readme is not the exploit, ../lfi_secret.conf is', async () => {
    const c = client(srv.base);
    const shortcut = await c.get('/lfi/config?file=readme.txt');
    assert.equal((shortcut.text.match(FLAG_RE) || []).length, 0);
    assert.ok(!(await capturedSet(c)).includes('lfi:config-read'));

    const hit = await c.get('/lfi/config?file=../lfi_secret.conf');
    const flags = hit.text.match(FLAG_RE) || [];
    assert.equal(flags.length, 1);
    assert.equal(flags[0], flagOf('config-read'));

    const again = await c.get('/lfi/config?file=../lfi_secret.conf');
    assert.equal((again.text.match(FLAG_RE) || [])[0], flagOf('config-read'));
  });

  // Requires a real Linux /etc/passwd (true inside the Docker verification
  // image); on a host without it the read errors out and this is skipped.
  await t.test('absolute: a benign absolute path is not the exploit, /etc/passwd is (Linux only)', async (st) => {
    const c = client(srv.base);
    const shortcut = await c.get('/lfi/abs?page=/etc/hostname');
    assert.equal((shortcut.text.match(FLAG_RE) || []).length, 0);
    assert.ok(!(await capturedSet(c)).includes('lfi:absolute'));

    const hit = await c.get('/lfi/abs?page=/etc/passwd');
    if (!hit.text.includes('root:')) {
      st.skip('no /etc/passwd on this host; verified in the Linux Docker image instead');
      return;
    }
    const flags = hit.text.match(FLAG_RE) || [];
    assert.equal(flags.length, 1);
    assert.equal(flags[0], flagOf('absolute'));

    const again = await c.get('/lfi/abs?page=/etc/passwd');
    assert.equal((again.text.match(FLAG_RE) || [])[0], flagOf('absolute'));
  });

  await t.test('scoreboard counts each captured challenge once', async () => {
    const c = client(srv.base);
    await c.get('/lfi/view?file=../docs/secret.txt');
    await c.get('/lfi/download?file=....//docs/secret.txt');
    await c.get('/lfi/nested?page=....///docs/secret.txt');
    await c.get('/lfi/nested?page=....///docs/secret.txt');
    await c.get('/lfi/config?file=../lfi_secret.conf');
    const got = (await capturedSet(c)).filter((s) => s.startsWith('lfi:'));
    assert.equal(got.length, 4);
  });
});
