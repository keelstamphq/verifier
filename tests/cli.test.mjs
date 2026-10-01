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

// The CLI against the committed fixtures (tests/fixtures/expected.json), its usage errors, and the
// rule that keys only ever come from --keys.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import * as ts from './test-signer.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = (...args) => spawnSync(process.execPath, ['bin/verify.mjs', ...args], { cwd: root, encoding: 'utf8' });
const expected = JSON.parse(readFileSync(join(root, 'tests/fixtures/expected.json'), 'utf8'));
const TRUSTED_KEYS = 'tests/keys/keelstamp-keys.json';

for (const c of expected.cases.filter((x) => x.exit !== 2)) {
  test(`fixture: ${c.name} → exit ${c.exit}${c.reasons.length ? ` (${c.reasons.join(', ')})` : ''}`, () => {
    const human = cli(...c.args);
    assert.equal(human.status, c.exit, human.stdout + human.stderr);
    assert.ok(human.stdout.startsWith(c.exit === 0 ? 'VERIFIED' : 'NOT VERIFIED'));
    for (const code of c.reasons) assert.ok(human.stdout.includes(`${code}: `), `stdout names ${code}`);

    const json = cli(...c.args, '--json');
    assert.equal(json.status, c.exit);
    const result = JSON.parse(json.stdout);
    assert.equal(result.ok, c.exit === 0);
    assert.deepEqual(result.reasons.map((r) => r.code), c.reasons);
  });
}

for (const c of expected.cases.filter((x) => x.exit === 2)) {
  test(`fixture: ${c.name} → exit 2, nothing verified`, () => {
    const r = cli(...c.args);
    assert.equal(r.status, 2, r.stdout + r.stderr);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /--keys <keys\.json> is required/);
  });
}

test('the fixtures cover the acceptance matrix', () => {
  const reasons = new Set(expected.cases.flatMap((c) => c.reasons ?? []));
  for (const code of ['SIGNATURE_INVALID', 'KEY_MISMATCH', 'KID_UNKNOWN', 'INCLUSION_PROOF_INVALID', 'CHECKPOINT_SIGNATURE_INVALID', 'PROFILE_UNKNOWN']) {
    assert.ok(reasons.has(code), code);
  }
});

test('no keys file is ever kept next to the receipts in the fixtures', () => {
  for (const name of readdirSync(join(root, 'tests/fixtures'))) {
    const doc = JSON.parse(readFileSync(join(root, 'tests/fixtures', name), 'utf8'));
    assert.notEqual(doc.format, 'keelstamp-keys-v1', `tests/fixtures/${name} is a keys file`);
  }
});

test('the output names the keys file used and its SHA-256', () => {
  const r = cli('tests/fixtures/valid.json', '--keys', TRUSTED_KEYS);
  assert.equal(r.status, 0);
  const sha = createHash('sha256').update(readFileSync(join(root, TRUSTED_KEYS))).digest('hex');
  assert.match(r.stdout, new RegExp(`keys file {2}tests/keys/keelstamp-keys\\.json\\n +sha256 ${sha} `));
  assert.match(r.stdout, /\(e\) inclusion in the log \(RFC 9942\/9162\) +pass \(log receipt; no --checkpoint given\)/);
  const j = JSON.parse(cli('tests/fixtures/valid.json', '--keys', TRUSTED_KEYS, '--json').stdout);
  assert.equal(j.files.keys_sha256, sha);
  assert.equal(j.details.keys.sha256, sha);
});

test('review forgery: a forged receipt with its own keys file next to it never verifies', () => {
  // The attack the internal review reproduced: someone signs a receipt with their own key, using
  // the real issuer string, and puts a keys file with that key next to it under the name the CLI
  // used to read by default. That combination verified with exit 0 before --keys was required.
  const attacker = ts.buildWorld();
  const dir = mkdtempSync(join(tmpdir(), 'ks-forgery-'));
  try {
    writeFileSync(join(dir, 'keelstamp-keys.json'), JSON.stringify(attacker.keys));
    writeFileSync(join(dir, 'receipt.json'), JSON.stringify(attacker.receiptDoc));
    const forged = join(dir, 'receipt.json');

    // 1. Without --keys nothing is verified and nothing next to the receipt is read.
    for (const extra of [[], ['--json'], ['--checkpoint', 'tests/fixtures/checkpoint.json']]) {
      const r = cli(forged, ...extra);
      assert.equal(r.status, 2, r.stdout + r.stderr);
      assert.equal(r.stdout, '');
      assert.match(r.stderr, /--keys <keys\.json> is required/);
    }
    // 2. With the published keys the forgery is rejected: neither its signer nor its log key is known.
    const r = cli(forged, '--keys', TRUSTED_KEYS, '--json');
    assert.equal(r.status, 1);
    assert.deepEqual(JSON.parse(r.stdout).reasons.map((x) => x.code), ['KID_UNKNOWN', 'LOG_RECEIPT_KID_UNKNOWN']);
    // 3. Keys smuggled into the receipt file are rejected, not used.
    writeFileSync(forged, JSON.stringify({ ...attacker.receiptDoc, keys: attacker.keys }));
    const smuggled = cli(forged, '--keys', TRUSTED_KEYS, '--json');
    assert.equal(smuggled.status, 1);
    assert.deepEqual(JSON.parse(smuggled.stdout).reasons.map((x) => x.code), ['RECEIPT_MALFORMED']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('usage and file errors exit 2 with a readable message', () => {
  for (const [args, pattern] of [
    [[], /missing <receipt\.json>/],
    [['--bogus', 'tests/fixtures/valid.json'], /unknown option --bogus/],
    [['tests/fixtures/valid.json', '--keys'], /--keys needs a file name/],
    [['tests/fixtures/valid.json', '--keys', TRUSTED_KEYS, '--keys', TRUSTED_KEYS], /--keys given twice/],
    [['tests/fixtures/does-not-exist.json', '--keys', TRUSTED_KEYS], /cannot read receipt file/],
    [['tests/fixtures/valid.json', '--keys', 'tests/fixtures/none.json'], /cannot read keys file/],
    [['tests/fixtures/valid.json', '--keys', TRUSTED_KEYS, '--checkpoint', 'tests/fixtures/none.json'], /cannot read checkpoint file/],
    [['tests/fixtures/valid.json', '--checkpoint', 'tests/fixtures/checkpoint.json'], /--keys <keys\.json> is required/],
  ]) {
    const r = cli(...args);
    assert.equal(r.status, 2, `${args.join(' ')}: ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, pattern);
  }
});

test('--help exits 0', () => {
  const r = cli('--help');
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^Usage: node bin\/verify\.mjs/);
});

test('text from a receipt cannot inject terminal controls or bidi overrides into the output', () => {
  const w = ts.buildWorld();
  const evil = '\u001b[2J\u001b]0;title\u0007\u202e\u2066\u009b\u061c\u00ad\u{E0041}';
  const dir = mkdtempSync(join(tmpdir(), 'ks-cli-'));
  try {
    writeFileSync(join(dir, 'keelstamp-keys.json'), JSON.stringify(w.keys));
    const cases = {
      // iss is shown on the "signed" line and in the ISSUER_MISMATCH reason
      'issuer.json': w.signReceipt({ iss: `x${evil}` }),
      // receipt_id fails the profile syntax, so payload fields are not displayed at all
      'receipt-id.json': w.signReceipt({ payload: { ...w.payload, receipt_id: `id${evil}` } }),
      // an unknown member name appears in the PAYLOAD_SCHEMA_INVALID reason
      'member.json': w.signReceipt({ payload: { ...w.payload, [`m${evil}`]: 1 } }),
    };
    for (const [name, statement] of Object.entries(cases)) {
      writeFileSync(join(dir, name), JSON.stringify(ts.receiptFileDoc(statement.bytes)));
      const r = spawnSync(process.execPath, [join(root, 'bin/verify.mjs'), join(dir, name), '--keys', join(dir, 'keelstamp-keys.json')], { encoding: 'utf8' });
      assert.equal(r.status, 1, name);
      assert.ok(!/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/.test(r.stdout), `${name}: raw control character in output`);
      // where the value is displayed at all, it is displayed escaped
      if (name !== 'receipt-id.json') assert.ok(r.stdout.includes('\\u001b'), `${name}: escaped form shown`);
      assert.ok(!/[\u007f-\u009f\p{Cf}\p{Zl}\p{Zp}]/u.test(r.stdout), `${name}: raw format character in output`);
      // --json: same data, escaped, still valid JSON
      const j = spawnSync(process.execPath, [join(root, 'bin/verify.mjs'), join(dir, name), '--keys', join(dir, 'keelstamp-keys.json'), '--json'], { encoding: 'utf8' });
      assert.equal(j.status, 1);
      assert.ok(!/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\p{Cf}\p{Zl}\p{Zp}]/u.test(j.stdout), `${name}: raw character in --json output`);
      const parsed = JSON.parse(j.stdout);
      if (name === 'issuer.json') assert.equal(parsed.details.receipt.iss, `x${evil}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
