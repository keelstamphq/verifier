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

// Crafted Ed25519 vectors for the strictness the specification promises (SPEC.md sections 3 and 4).
// Each vector is built from an honest key with plain group arithmetic, and each test first shows
// that the vector is meaningful (another verifier, or the same equation without the strict rule,
// would accept it) before showing that this verifier rejects it.

import * as ed from '@noble/ed25519';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';
import { describe, test } from 'node:test';
import { verify } from '../src/index.mjs';
import * as ts from './test-signer.mjs';

const { Point } = ed;
const L = Point.CURVE().n;
const sha512 = (...parts) => {
  const h = createHash('sha512');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};
const le = (bytes) => BigInt(`0x${Buffer.from(bytes).reverse().toString('hex') || '0'}`);
const le32 = (n) => Uint8Array.from(Buffer.from(n.toString(16).padStart(64, '0'), 'hex').reverse());
const utf8 = (s) => new TextEncoder().encode(s);

/** The secret scalar and nonce prefix of a test-signer key (RFC 8032 §5.1.5). */
function secretOf(key) {
  const seed = Buffer.from(key.privateKey.export({ format: 'jwk' }).d, 'base64url');
  const h = sha512(seed);
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  return { scalar: le(h.subarray(0, 32)), prefix: h.subarray(32) };
}

/** RFC 8032 signing with an explicit public key encoding, so the key may be a crafted point. */
function rawSign({ scalar, prefix }, publicKeyBytes, message) {
  const r = le(sha512(prefix, message)) % L;
  const R = Point.BASE.multiply(r).toBytes();
  const k = le(sha512(R, publicKeyBytes, message)) % L;
  return { signature: Uint8Array.from([...R, ...le32((r + k * scalar) % L)]), k };
}

/** A point of order 8 (RFC 8032 §5.1.3 encoding). */
const T8 = Point.fromHex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a');

/** OpenSSL (via node:crypto) uses the cofactorless equation; @noble in strict mode the cofactored one. */
function opensslAccepts(signature, message, publicKeyBytes) {
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: ts.b64url(publicKeyBytes) }, format: 'jwk' });
  return nodeVerify(null, message, key, signature);
}

/** A receipt in world `w`, signed by `secret` but naming the (possibly crafted) key `x`. */
function receiptNaming(w, x, secret, attempt = 0) {
  const kidBytes = new Uint8Array(createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: ts.b64url(x) })).digest());
  const payload = { ...w.payload, receipt_id: `${w.payload.receipt_id.slice(0, 16)}${String(attempt).padStart(4, '0')}` };
  const protectedBytes = ts.cbor(ts.protectedHeader({ kidBytes, iss: w.issuer, sub: payload.receipt_id, iat: w.iat }));
  const payloadBytes = utf8(ts.jcs(payload));
  const toBeSigned = ts.cbor(['Signature1', protectedBytes, new Uint8Array(0), payloadBytes]);
  const { signature, k } = rawSign(secret, x, toBeSigned);
  const key = { ...w.receiptKey, x: ts.b64url(x), kid: ts.b64url(kidBytes) };
  return {
    toBeSigned, signature, k, key,
    doc: ts.receiptFileDoc(ts.encodeSign1({ protectedBytes, payloadBytes, signature })),
    keys: ts.keysDoc(w.issuer, [key, w.logKey]),
  };
}

describe('Ed25519 keys outside the prime-order subgroup', () => {
  const w = ts.buildWorld();
  const secret = secretOf(w.receiptKey);
  const honest = Point.fromBytes(Buffer.from(w.receiptKey.x, 'base64url'));

  test('a mixed-order key (honest key + order-8 point) is rejected when the keys file is read → KEYS_MALFORMED', () => {
    const mixed = honest.add(T8);
    assert.equal(T8.isSmallOrder(), true);
    assert.equal(mixed.isSmallOrder(), false, 'not caught by the small-order rule alone');
    const x = mixed.toBytes();
    // Meaningful: an honest signature under the mixed key passes the cofactored equation, while
    // OpenSSL rejects it whenever k is not a multiple of 8. Pick such a receipt.
    let v;
    for (let attempt = 0; attempt < 64; attempt++) {
      v = receiptNaming(w, x, secret, attempt);
      if (v.k % 8n !== 0n) break;
    }
    assert.notEqual(v.k % 8n, 0n);
    assert.equal(ed.verify(v.signature, v.toBeSigned, x, { zip215: false }), true, 'strict cofactored verification accepts it');
    assert.equal(opensslAccepts(v.signature, v.toBeSigned, x), false, 'a cofactorless verifier rejects it');

    const r = verify(v.doc, v.keys);
    assert.equal(r.ok, false);
    assert.deepEqual(r.reasons.map((x2) => x2.code), ['KEYS_MALFORMED']);
    assert.match(r.reasons[0].message, /keys\[0\]: x is not in the prime-order subgroup/);
  });

  test('the same receipt signed under the honest key verifies, and OpenSSL agrees', () => {
    const v = receiptNaming(w, honest.toBytes(), secret);
    assert.equal(opensslAccepts(v.signature, v.toBeSigned, honest.toBytes()), true);
    const r = verify(v.doc, v.keys);
    assert.deepEqual(r.reasons, []);
    assert.equal(r.ok, true);
  });
});
