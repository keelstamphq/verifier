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
const expectOnly = (result, code) => {
  assert.equal(result.ok, false, 'expected the receipt to be rejected');
  assert.deepEqual(result.reasons.map((r) => r.code), [code]);
};

/** The secret scalar and nonce prefix of a test-signer key (RFC 8032 §5.1.5). */
function secretOf(key) {
  const seed = Buffer.from(key.privateKey.export({ format: 'jwk' }).d, 'base64url');
  const h = sha512(seed);
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  return { scalar: le(h.subarray(0, 32)), prefix: h.subarray(32) };
}

/**
 * RFC 8032 signing with an explicit public key encoding, so the key may be a crafted point.
 * `nonce` ({ r, R }) replaces the deterministic nonce and its encoding, so R may be crafted too.
 */
function rawSign({ scalar, prefix }, publicKeyBytes, message, nonce) {
  const r = nonce ? nonce.r : le(sha512(prefix, message)) % L;
  const R = nonce ? nonce.R : Point.BASE.multiply(r).toBytes();
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

const P = Point.CURVE().p;
/** The 32-byte encoding of y (sign bit 0); for y >= p this is a non-canonical encoding of y - p. */
const encodeY = (y) => le32(y);

describe('Ed25519 signatures that strict verification must reject', () => {
  const w = ts.buildWorld();
  const secret = secretOf(w.receiptKey);
  const x = Buffer.from(w.receiptKey.x, 'base64url');
  const sig1 = (over) => ts.receiptFileDoc(ts.encodeSign1({ ...w.statement, ...over }));
  const toBeSigned = ts.cbor(['Signature1', w.statement.protectedBytes, new Uint8Array(0), w.statement.payloadBytes]);

  test('malleated signature: S replaced by S + L (same value mod L) → SIGNATURE_INVALID', () => {
    const S = le(w.statement.signature.subarray(32));
    assert.ok(S < L && S + L < 2n ** 256n, 'S + L still fits in 32 bytes');
    assert.equal((S + L) % L, S, 'S + L satisfies the same verification equation');
    const malleated = Uint8Array.from([...w.statement.signature.subarray(0, 32), ...le32(S + L)]);
    assert.equal(ed.verify(w.statement.signature, toBeSigned, x, { zip215: false }), true, 'the original verifies');
    expectOnly(verify(sig1({ signature: malleated }), w.keys), 'SIGNATURE_INVALID');
  });

  test('malleated log receipt signature (S + L) → INCLUSION_PROOF_INVALID', () => {
    const sig = w.logReceipt.signature;
    const S = le(sig.subarray(32));
    const malleated = Uint8Array.from([...sig.subarray(0, 32), ...le32(S + L)]);
    expectOnly(verify(w.receiptDocWith(ts.encodeSign1({ ...w.logReceipt, signature: malleated })), w.keys), 'INCLUSION_PROOF_INVALID');
  });

  test('non-canonical R (y >= p) in an otherwise valid signature → SIGNATURE_INVALID', () => {
    // R = the identity point (y = 1) written as y = 1 + p, with r = 0. ZIP-215 decoding accepts
    // the encoding and the signature then satisfies the equation; strict RFC 8032 decoding does not.
    const R = encodeY(1n + P);
    const { signature } = rawSign(secret, x, toBeSigned, { r: 0n, R });
    assert.equal(ed.verify(signature, toBeSigned, x, { zip215: true }), true, 'valid apart from the encoding');
    assert.equal(ed.verify(signature, toBeSigned, x, { zip215: false }), false);
    expectOnly(verify(sig1({ signature }), w.keys), 'SIGNATURE_INVALID');
  });
});

describe('Ed25519 public keys that the keys file must reject', () => {
  const w = ts.buildWorld();
  const withKey = (xBytes) => {
    const keys = JSON.parse(JSON.stringify(w.keys));
    keys.keys[0].x = ts.b64url(xBytes);
    keys.keys[0].kid = ts.b64url(createHash('sha256').update(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x: keys.keys[0].x })).digest());
    return keys;
  };

  test('non-canonical encoding (y >= p) of a valid point of large order → KEYS_MALFORMED', () => {
    // Look for a y below 19 that is a point of large order; y + p is then a second encoding of it.
    let y = 0n;
    let point = null;
    for (; y < 19n && point === null; y++) {
      try {
        const p = Point.fromBytes(encodeY(y));
        if (!p.isSmallOrder()) point = p;
      } catch {
        // not a point
      }
    }
    assert.ok(point, 'a valid y below 19 exists');
    y -= 1n;
    const nonCanonical = encodeY(y + P);
    assert.ok(Point.fromBytes(nonCanonical, true).equals(point), 'lax decoding reads the same point');
    const r = verify(w.receiptDoc, withKey(nonCanonical));
    expectOnly(r, 'KEYS_MALFORMED');
    assert.match(r.reasons[0].message, /keys\[0\]: x is not a valid Ed25519 public key/);
  });

  test('a point of order 8 → KEYS_MALFORMED', () => {
    const r = verify(w.receiptDoc, withKey(T8.toBytes()));
    expectOnly(r, 'KEYS_MALFORMED');
    assert.match(r.reasons[0].message, /keys\[0\]: x is a small-order point/);
  });
});

describe('known limitation: cofactored verification (SPEC section 11)', () => {
  const w = ts.buildWorld();
  const secret = secretOf(w.receiptKey);
  const x = Buffer.from(w.receiptKey.x, 'base64url');
  const toBeSigned = ts.cbor(['Signature1', w.statement.protectedBytes, new Uint8Array(0), w.statement.payloadBytes]);

  test('a key holder can craft R with a torsion component: accepted here, rejected by a cofactorless verifier', () => {
    const r = 1234567n;
    const R = Point.BASE.multiply(r).add(T8).toBytes();
    const { signature } = rawSign(secret, x, toBeSigned, { r, R });
    assert.equal(opensslAccepts(signature, toBeSigned, x), false);
    const result = verify(ts.receiptFileDoc(ts.encodeSign1({ ...w.statement, signature })), w.keys);
    assert.deepEqual(result.reasons, []);
    assert.equal(result.ok, true, 'documented in SPEC section 11; a change here must update the SPEC');
  });

  test('honest signatures are judged the same by both', () => {
    assert.equal(opensslAccepts(w.statement.signature, toBeSigned, x), true);
    assert.equal(verify(ts.receiptFileDoc(w.statement.bytes), w.keys).ok, true);
  });
});
