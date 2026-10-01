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

// The web page's input handling agrees with the CLI (no DOM needed: app.mjs only wires the page
// when a document exists).

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { verify } from '../src/index.mjs';
import { checkpointArg } from '../web/app.mjs';

const fixture = (name) => readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'fixtures', name), 'utf8');

test('an empty checkpoint field skips (e); whitespace or a BOM fails like a malformed checkpoint file', () => {
  const run = (cp) => verify(fixture('valid.json'), fixture('keelstamp-keys.json'), checkpointArg(cp));
  assert.equal(checkpointArg(''), undefined);
  assert.equal(run('').ok, true);
  for (const cp of [' ', '\n', '\ufeff']) {
    const r = run(cp);
    assert.equal(r.ok, false);
    assert.deepEqual(r.reasons.map((x) => x.code), ['CHECKPOINT_MALFORMED']);
  }
});
