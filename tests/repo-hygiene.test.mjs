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

// Repository rules, checked mechanically: license headers, no network code, no private keys in
// fixtures, every dependency justified in SPEC.md, and no marketing claims in published text.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => readFileSync(join(root, p), 'utf8');

function files(dir, pattern) {
  const out = [];
  for (const entry of readdirSync(join(root, dir), { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...files(p, pattern));
    else if (pattern.test(entry.name)) out.push(p);
  }
  return out;
}

const SOURCE = ['src', 'bin', 'web', 'scripts', 'tests'].flatMap((d) => files(d, /\.(mjs|js|html)$/));

test('every source file carries the Apache-2.0 header', () => {
  const header = read('scripts/license-header.txt').trim();
  const htmlHeader = header.split('\n').map((l) => l.replace(/^\/\/ ?/, '')).join('\n');
  for (const f of SOURCE) {
    const text = read(f).replace(/^#!.*\n/, '');
    const normalized = f.endsWith('.html') ? text.split('\n').map((l) => l.replace(/^ {2}/, '')).join('\n') : text;
    assert.ok(normalized.includes(f.endsWith('.html') ? htmlHeader : header), `${f} lacks the license header`);
  }
});

test('sources contain no invisible, bidi or control characters (write them as \\u escapes)', () => {
  for (const f of [...SOURCE, 'README.md', 'SPEC.md', 'package.json', '.github/workflows/ci.yml']) {
    const m = /[\p{Cf}\p{Zl}\p{Zp}\uFFFD]|(?![\n\r\t])\p{Cc}/u.exec(read(f));
    assert.equal(m, null, `${f} contains U+${m && m[0].codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`);
  }
});

test('runtime code has no network access', () => {
  const runtime = SOURCE.filter((f) => /^(src|bin|web)\//.test(relative(root, join(root, f))));
  const banned = [/\bfetch\s*\(/, /XMLHttpRequest/, /WebSocket/, /EventSource/, /sendBeacon/, /\bimport\s*\(/,
    /['"]node:(http|https|http2|net|tls|dgram|dns)['"]/, /require\(\s*['"](http|https|net|tls|dgram|dns)['"]/];
  for (const f of runtime) {
    const text = read(f);
    for (const re of banned) assert.ok(!re.test(text), `${f} matches ${re}`);
  }
});

test('fixtures contain public keys only', () => {
  for (const f of files('tests/fixtures', /\.json$/)) {
    const text = read(f);
    assert.ok(!/PRIVATE KEY/.test(text), `${f} contains a PEM private key`);
    JSON.parse(text, (key, value) => {
      assert.notEqual(key, 'd', `${f} contains a JWK private key member "d"`);
      return value;
    });
  }
});

test('every dependency is named and justified in SPEC.md', () => {
  const pkg = JSON.parse(read('package.json'));
  const spec = read('SPEC.md');
  const start = spec.search(/^## (\d+\. )?Dependencies$/m);
  assert.ok(start >= 0, 'SPEC.md has a Dependencies section');
  const section = spec.slice(start, spec.indexOf('\n## ', start + 1));
  for (const name of [...Object.keys(pkg.dependencies), ...Object.keys(pkg.devDependencies)]) {
    assert.ok(section.includes(`\`${name}\``), `${name} is not justified in SPEC.md`);
    assert.match(pkg.dependencies?.[name] ?? pkg.devDependencies[name], /^\d+\.\d+\.\d+$/, `${name} must be pinned exactly`);
  }
});

test('published text makes no marketing claims', () => {
  const banned = [/\bcertif(ied|ication)\b/i, /\bcomplian(t|ce)\b/i, /\bSOC\s*2\b/i, /\bfirst\b/i, /\bgovernance\b/i];
  for (const f of ['README.md', 'SPEC.md', 'web/index.html', 'web/app.mjs', 'bin/verify.mjs', 'src/reasons.mjs']) {
    // Comments are not published text (the Apache-2.0 header itself says "in compliance with").
    const text = read(f).replace(/^\s*\/\/.*$/gm, '').replace(/<!--[\s\S]*?-->/g, '');
    for (const re of banned) assert.ok(!re.test(text), `${f} matches ${re}`);
  }
});

test('README.md opens with the pre-release notice', () => {
  const firstLines = read('README.md').split('\n').slice(0, 4).join('\n');
  assert.match(firstLines, /Pre-release: format kan ændre sig, før Keelstamp er i drift|Pre-release: the format may change before Keelstamp is in operation/);
});
