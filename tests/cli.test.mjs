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

// The CLI against the committed fixtures (tests/fixtures/expected.json) and its usage errors.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import * as ts from './test-signer.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const cli = (...args) => spawnSync(process.execPath, ['bin/verify.mjs', ...args], { cwd: root, encoding: 'utf8' });
const expected = JSON.parse(readFileSync(join(root, 'tests/fixtures/expected.json'), 'utf8'));

for (const c of expected.cases) {
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

test('the fixtures cover the acceptance matrix', () => {
  const reasons = new Set(expected.cases.flatMap((c) => c.reasons));
  for (const code of ['SIGNATURE_INVALID', 'KEY_MISMATCH', 'KID_UNKNOWN', 'INCLUSION_PROOF_INVALID', 'CHECKPOINT_SIGNATURE_INVALID', 'PROFILE_UNKNOWN']) {
    assert.ok(reasons.has(code), code);
  }
});

test('the default keys file is the one next to the receipt, and the output says so', () => {
  const r = cli('tests/fixtures/valid.json');
  assert.equal(r.status, 0);
  assert.match(r.stdout, /keys file {2}tests\/fixtures\/keelstamp-keys\.json \(default: next to the receipt/);
  assert.match(r.stdout, /\(e\) inclusion in signed checkpoint +skipped \(no --checkpoint given\)/);
});

test('usage and file errors exit 2 with a readable message', () => {
  for (const [args, pattern] of [
    [[], /missing <receipt\.json>/],
    [['--bogus', 'tests/fixtures/valid.json'], /unknown option --bogus/],
    [['tests/fixtures/valid.json', '--keys'], /--keys needs a file name/],
    [['tests/fixtures/does-not-exist.json'], /cannot read receipt file/],
    [['tests/fixtures/valid.json', '--keys', 'tests/fixtures/none.json'], /cannot read keys file/],
    [['tests/fixtures/valid.json', '--checkpoint', 'tests/fixtures/none.json'], /cannot read checkpoint file/],
    [['LICENSE'], /cannot read keys \(no --keys given; default\) file/],
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
  const evil = '\u001b[2J\u001b]0;title\u0007\u202e\u2066';
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
      const r = spawnSync(process.execPath, [join(root, 'bin/verify.mjs'), join(dir, name)], { encoding: 'utf8' });
      assert.equal(r.status, 1, name);
      assert.ok(!/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/.test(r.stdout), `${name}: raw control character in output`);
      // where the value is displayed at all, it is displayed escaped
      if (name !== 'receipt-id.json') assert.ok(r.stdout.includes('\\u001b'), `${name}: escaped form shown`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
