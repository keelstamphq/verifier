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

// The web page's input handling (no DOM needed: app.mjs only wires the page when a document
// exists): keys only from the keys field, the keys file shown, and checkpoints handled like the CLI.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { verify } from '../src/index.mjs';
import { checkpointArg, keysRows, selectKeys } from '../web/app.mjs';
import * as ts from './test-signer.mjs';

const testsDir = dirname(fileURLToPath(import.meta.url));
const fixture = (name) => readFileSync(join(testsDir, 'fixtures', name), 'utf8');
const keysText = readFileSync(join(testsDir, 'keys', 'keelstamp-keys.json'), 'utf8');
const sha256 = (data) => createHash('sha256').update(data).digest('hex');
const row = (shown, key) => shown.rows.find(([k]) => k === key)?.[1];

test('an empty checkpoint field skips the comparison; whitespace or a BOM fails like a malformed checkpoint file', () => {
  const run = (cp) => verify(fixture('valid.json'), keysText, checkpointArg(cp));
  assert.equal(checkpointArg(''), undefined);
  assert.equal(run('').ok, true);
  for (const cp of [' ', '\n', '\ufeff']) {
    const r = run(cp);
    assert.equal(r.ok, false);
    assert.deepEqual(r.reasons.map((x) => x.code), ['CHECKPOINT_MALFORMED']);
  }
});

test('keys come only from the keys field; an empty field verifies nothing', () => {
  assert.deepEqual(selectKeys('', null), { input: undefined, source: 'none' });
  const r = verify(fixture('valid.json'), selectKeys('', null).input);
  assert.equal(r.ok, false);
  assert.deepEqual(r.reasons.map((x) => x.code), ['KEYS_MALFORMED']);
  assert.equal(keysRows(selectKeys('', null)).ok, false);
});

test('a loaded keys file is shown by name and by the SHA-256 of its own bytes; edits are shown as such', () => {
  const bytes = new TextEncoder().encode(keysText);
  const loaded = { name: 'keelstamp-keys.json', bytes, text: keysText };
  const fromFile = selectKeys(keysText, loaded);
  assert.equal(fromFile.input, bytes);
  const shown = keysRows(fromFile);
  assert.equal(shown.ok, true);
  assert.equal(row(shown, 'Source'), 'file "keelstamp-keys.json"');
  assert.equal(row(shown, 'SHA-256'), sha256(keysText));
  assert.equal(row(shown, 'Issuer'), ts.TEST_ISSUER);
  assert.equal(shown.rows.filter(([k]) => k.startsWith('Key (')).length, 3);

  const edited = keysRows(selectKeys(`${keysText} `, loaded));
  assert.equal(row(edited, 'Source'), 'text edited after loading file "keelstamp-keys.json"');
  assert.equal(row(edited, 'SHA-256'), sha256(`${keysText} `));
  assert.equal(row(keysRows(selectKeys(keysText, null)), 'Source'), 'pasted text');
});

test('a keys file that does not parse is shown with its SHA-256 and the problem', () => {
  const shown = keysRows(selectKeys('{"format":"keelstamp-keys-v0"}', null));
  assert.equal(shown.ok, false);
  assert.equal(row(shown, 'SHA-256'), sha256('{"format":"keelstamp-keys-v0"}'));
  assert.match(row(shown, 'Problem'), /not a valid keys file/);
});

test('review forgery in the page: the attacker\'s receipt fails against the published keys', () => {
  const attacker = ts.buildWorld();
  const r = verify(JSON.stringify(attacker.receiptDoc), selectKeys(keysText, null).input);
  assert.equal(r.ok, false);
  assert.deepEqual(r.reasons.map((x) => x.code), ['KID_UNKNOWN', 'LOG_RECEIPT_KID_UNKNOWN']);
});
