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

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalize, parseCanonicalJson } from '../src/jcs.mjs';

const enc = (s) => new TextEncoder().encode(s);

test('RFC 8785 §3.2.2 example: numbers, string escaping, literals', () => {
  const input = `{
    "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
    "string": "\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\"\\/",
    "literals": [null, true, false]
  }`;
  const expected = '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}';
  assert.equal(canonicalize(JSON.parse(input)), expected);
  assert.equal(parseCanonicalJson(enc(expected)).ok, true);
});

test('RFC 8785 §3.2.3 example: members sorted by UTF-16 code units', () => {
  const input = '{"\\u20ac":"Euro Sign","\\r":"Carriage Return","\\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\\ud83d\\ude00":"Emoji: Grinning Face","\\u0080":"Control","\\u00f6":"Latin Small Letter O With Diaeresis"}';
  const order = ['\r', '1', '\u0080', 'ö', '€', '😀', 'דּ'];
  const value = JSON.parse(input);
  // Compare text, not re-parsed keys: JS objects list integer-like keys ("1") first.
  const expected = `{${order.map((k) => `${JSON.stringify(k)}:${JSON.stringify(value[k])}`).join(',')}}`;
  assert.equal(canonicalize(value), expected);
});

test('canonical input is accepted and returns the value', () => {
  const r = parseCanonicalJson(enc('{"a":[1,"x",{"b":null}],"z":true}'));
  assert.deepEqual(r, { ok: true, value: { a: [1, 'x', { b: null }], z: true } });
});

for (const [name, text] of [
  ['whitespace', '{"a": 1}'],
  ['trailing newline', '{"a":1}\n'],
  ['unsorted members', '{"b":1,"a":2}'],
  ['duplicate members', '{"a":1,"a":1}'],
  ['non-canonical number 1.0', '{"a":1.0}'],
  ['non-canonical number 1e3', '{"a":1e3}'],
  ['negative zero', '{"a":-0}'],
  ['integer beyond 2^53', '{"a":9007199254740993}'],
  ['unnecessary escape', '{"a":"\\u0041"}'],
  ['lone surrogate', '{"a":"\\ud800"}'],
  ['not JSON', '{"a":'],
]) {
  test(`rejects ${name}`, () => {
    assert.equal(parseCanonicalJson(enc(text)).ok, false);
  });
}

test('rejects a UTF-8 BOM and invalid UTF-8', () => {
  assert.equal(parseCanonicalJson(Uint8Array.of(0xef, 0xbb, 0xbf, ...enc('{}'))).ok, false);
  assert.equal(parseCanonicalJson(Uint8Array.of(0x22, 0xff, 0x22)).ok, false);
});
