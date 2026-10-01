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

// Published test vectors and byte-level checks for the building blocks.

import * as ed from '@noble/ed25519';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  HDR_RECEIPTS, HDR_VDP, HDR_VDS, VDP_INCLUSION, VDS_RFC9162_SHA256, decodeCoseSign1, logEntry, sigStructure,
} from '../src/cose.mjs';
import { ed25519Verify } from '../src/crypto.mjs';
import { base64urlDecode, base64urlEncode, hexDecode, hexEncode, parseUtcSeconds } from '../src/encoding.mjs';
import { jsonSafe, printable } from '../src/display.mjs';
import { jwkThumbprintB64 } from '../src/keys.mjs';
import * as ts from './test-signer.mjs';

// RFC 8032 §7.1, TEST 1 (empty message)
const RFC8032_PUBLIC = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
const RFC8032_SIG = 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';

test('Ed25519: RFC 8032 test 1 verifies; a flipped bit does not', () => {
  const pub = hexDecode(RFC8032_PUBLIC);
  const sig = hexDecode(RFC8032_SIG);
  assert.equal(ed25519Verify(sig, new Uint8Array(0), pub), true);
  const bad = sig.slice();
  bad[0] ^= 1;
  assert.equal(ed25519Verify(bad, new Uint8Array(0), pub), false);
  assert.equal(ed25519Verify(sig, Uint8Array.of(0), pub), false);
});

test('Ed25519 is verified strictly: a small-order key signature that ZIP-215 accepts is rejected', () => {
  // A = identity point, R = identity point, S = 0 satisfies the cofactored equation for any message.
  const identity = Uint8Array.from({ length: 32 }, (_, i) => (i === 0 ? 1 : 0));
  const sig = Uint8Array.from([...identity, ...new Uint8Array(32)]);
  const msg = new TextEncoder().encode('any message');
  assert.equal(ed.verify(sig, msg, identity, { zip215: true }), true, 'vector must be ZIP-215-valid to be meaningful');
  assert.equal(ed25519Verify(sig, msg, identity), false);
});

test('JWK Thumbprint: RFC 8037 Appendix A.3 value for the RFC 8032 test key', () => {
  const x = base64urlEncode(hexDecode(RFC8032_PUBLIC));
  assert.equal(x, '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo');
  assert.equal(jwkThumbprintB64(x), 'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k');
});

test('Sig_structure bytes are exactly ["Signature1", protected, h\'\', payload] (RFC 9052 §4.4)', () => {
  const protectedBytes = Uint8Array.of(0xa1, 0x01, 0x32); // {1: -19}
  const payload = new TextEncoder().encode('{}');
  const expected = Uint8Array.from([
    0x84, // array(4)
    0x6a, ...new TextEncoder().encode('Signature1'), // text(10)
    0x43, ...protectedBytes, // bytes(3)
    0x40, // bytes(0): external_aad
    0x42, ...payload, // bytes(2)
  ]);
  assert.equal(hexEncode(sigStructure(protectedBytes, payload)), hexEncode(expected));
  // and the test signer's independent encoder agrees
  assert.equal(hexEncode(ts.cbor(['Signature1', protectedBytes, new Uint8Array(0), payload])), hexEncode(expected));
});

test('COSE_Sign1 from the test signer decodes to its parts, with the log receipt in header 394', () => {
  const w = ts.buildWorld({ treeSize: 1, leafIndex: 0 });
  const d = decodeCoseSign1(w.receipt.bytes);
  assert.equal(hexEncode(d.protectedBytes), hexEncode(w.receipt.protectedBytes));
  assert.equal(hexEncode(d.payload), hexEncode(w.receipt.payloadBytes));
  assert.equal(hexEncode(d.signature), hexEncode(w.receipt.signature));
  assert.equal(d.protectedHeader.get(1), -19);
  assert.deepEqual([...d.unprotectedHeader.keys()], [HDR_RECEIPTS]);
  const [receiptBytes] = d.unprotectedHeader.get(HDR_RECEIPTS);
  assert.equal(hexEncode(receiptBytes), hexEncode(w.logReceipt.bytes));
  const r = decodeCoseSign1(receiptBytes, { detached: true });
  assert.equal(r.payload, null);
  assert.equal(r.protectedHeader.get(HDR_VDS), VDS_RFC9162_SHA256);
  assert.deepEqual([...r.unprotectedHeader.get(HDR_VDP).keys()], [VDP_INCLUSION]);
  assert.throws(() => decodeCoseSign1(receiptBytes), /detached payload is not supported/);
  assert.throws(() => decodeCoseSign1(w.receipt.bytes, { detached: true }), /payload must be detached/);
});

test('log entry: the statement as signed (empty unprotected header), byte for byte as the test signer builds it', () => {
  const w = ts.buildWorld();
  const d = decodeCoseSign1(w.receipt.bytes);
  const entry = logEntry(d.protectedBytes, d.payload, d.signature);
  assert.equal(hexEncode(entry), hexEncode(ts.logEntry(w.statement)));
  assert.equal(hexEncode(entry), hexEncode(w.statement.bytes));
  assert.equal(hexEncode(entry), hexEncode(w.leaves[w.leafIndex]));
  // d2 84 = tag 18, array(4); the unprotected header is the empty map a0
  assert.equal(hexEncode(entry.subarray(0, 2)), 'd284');
  assert.ok(hexEncode(entry).includes(`${hexEncode(d.protectedBytes)}a0`));
});

test('base64url: strict and canonical', () => {
  for (const n of [0, 1, 2, 3, 4, 31, 32, 33]) {
    const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 0xff);
    const text = base64urlEncode(bytes);
    assert.equal(text, Buffer.from(bytes).toString('base64url'));
    assert.deepEqual(base64urlDecode(text), bytes);
  }
  assert.equal(base64urlDecode('AA=='), null); // padding
  assert.equal(base64urlDecode('AB'), null); // non-zero unused bits
  assert.equal(base64urlDecode('A'), null); // impossible length
  assert.equal(base64urlDecode('a+b/'), null); // standard alphabet
  assert.equal(base64urlDecode(' AA'), null);
});

test('hex: lowercase only', () => {
  assert.deepEqual(hexDecode('00ff'), Uint8Array.of(0, 255));
  assert.equal(hexDecode('00FF'), null);
  assert.equal(hexDecode('0'), null);
});

test('RFC 3339 UTC parsing rejects offsets, fractions and impossible dates', () => {
  const t = parseUtcSeconds(new Date(0).toISOString().replace('.000Z', 'Z'));
  assert.equal(t, 0);
  const base = new Date(0).toISOString().slice(0, 4); // year only, to build test strings
  assert.equal(parseUtcSeconds(`${base}-02-30T00:00:00Z`), null);
  assert.equal(parseUtcSeconds(`${base}-01-01T24:00:00Z`), null);
  assert.equal(parseUtcSeconds(`${base}-01-01T00:00:00.5Z`), null);
  assert.equal(parseUtcSeconds(`${base}-01-01T00:00:00+00:00`), null);
});

test('printable escapes controls, line separators and bidi/zero-width characters only', () => {
  assert.equal(printable('a\u001b[31mb'), 'a\\u001b[31mb');
  assert.equal(printable('x\u202ey\u2066z\u200b\u2028'), 'x\\u202ey\\u2066z\\u200b\\u2028');
  assert.equal(printable('Ærø ö € 😀 sha256:ab'), 'Ærø ö € 😀 sha256:ab');
});

test('printable and jsonSafe cover Cc, Cf, Zl and Zp, including astral tag characters', () => {
  const evil = '\u009b\u061c\u00ad\u180e\ufff9\u{E0041}\u200d';
  assert.equal(printable(evil), '\\u009b\\u061c\\u00ad\\u180e\\ufff9\\u{e0041}\\u200d');
  const json = jsonSafe(JSON.stringify({ k: `a${evil}\u2028\n` }, null, 2));
  assert.ok(!/[\u007f-\u009f\p{Cf}\p{Zl}\p{Zp}]/u.test(json));
  assert.deepEqual(JSON.parse(json), { k: `a${evil}\u2028\n` });
});
