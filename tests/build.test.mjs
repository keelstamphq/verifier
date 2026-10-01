// Copyright 2026 PowerQuant ApS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The built page: self-contained, network-blocking CSP whose hashes match, reproducible, and its
// exact inline script verifies the committed fixtures with the same results as the CLI.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import { buildPage } from '../scripts/build.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const fixture = (name) => readFileSync(join(root, 'tests/fixtures', name), 'utf8');
const sha256b64 = (s) => createHash('sha256').update(s, 'utf8').digest('base64');

let dirs;
let html;
let script;

before(async () => {
  dirs = [mkdtempSync(join(tmpdir(), 'ks-build-a-')), mkdtempSync(join(tmpdir(), 'ks-build-b-'))];
  const a = await buildPage(dirs[0]);
  html = readFileSync(a.path, 'utf8');
  script = /<script>([\s\S]*?)<\/script>/.exec(html)[1];
});

after(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
});

test('the build is reproducible', async () => {
  const b = await buildPage(dirs[1]);
  assert.equal(readFileSync(b.path, 'utf8'), html);
});

test('CSP blocks all network access and pins the inline script and style by hash', () => {
  const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)?.[1];
  assert.ok(csp, 'CSP meta element present');
  const directives = new Map(csp.split(';').map((d) => d.trim().split(/\s+/)).map(([k, ...v]) => [k, v.join(' ')]));
  assert.equal(directives.get('default-src'), "'none'");
  assert.equal(directives.get('connect-src'), "'none'");
  assert.equal(directives.get('script-src'), `'sha256-${sha256b64(script)}'`);
  const style = /<style>([\s\S]*?)<\/style>/.exec(html)[1];
  assert.equal(directives.get('style-src'), `'sha256-${sha256b64(style)}'`);
  assert.ok(!/unsafe-inline|unsafe-eval|\*/.test(csp));
});

test('the page is one file: no external resources of any kind', () => {
  assert.equal((html.match(/<script\b/g) ?? []).length, 1);
  assert.ok(!/<(link|img|iframe|object|embed|base|form)\b/i.test(html));
  assert.ok(!/\s(src|href|action|srcset)\s*=/i.test(html));
  for (const api of ['fetch(', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'sendBeacon', 'import(', 'importScripts']) {
    assert.ok(!script.includes(api), `bundle must not use ${api}`);
  }
});

test('the page states it is pre-release', () => {
  assert.match(html, /Pre-release:<\/strong> the format may change before Keelstamp is in operation/);
});

test('the inline script verifies the fixtures like the CLI does', () => {
  const sandbox = { TextEncoder, TextDecoder };
  vm.createContext(sandbox);
  vm.runInContext(script, sandbox);
  const { verify } = sandbox.KeelstampVerifier;
  const keys = fixture('keelstamp-keys.json');
  const run = (r, c, k = keys) => verify(fixture(r), k, c && fixture(c));
  // Array.from: arrays created in the vm context have another realm's prototype.
  const codes = (res) => Array.from(res.reasons, (x) => x.code);

  assert.equal(run('valid.json').ok, true);
  assert.equal(run('valid.json', 'checkpoint.json').ok, true);
  assert.deepEqual(codes(run('invalid-altered-payload.json')), ['SIGNATURE_INVALID']);
  assert.deepEqual(codes(run('valid.json', null, fixture('keys-wrong-key.json'))), ['KEY_MISMATCH']);
  assert.deepEqual(codes(run('invalid-unknown-kid.json')), ['KID_UNKNOWN']);
  assert.deepEqual(codes(run('invalid-inclusion-path.json', 'checkpoint.json')), ['INCLUSION_PROOF_INVALID']);
  assert.deepEqual(codes(run('valid.json', 'checkpoint-tampered.json')), ['CHECKPOINT_SIGNATURE_INVALID']);
  assert.deepEqual(codes(run('invalid-unknown-profile.json')), ['PROFILE_UNKNOWN']);
});
