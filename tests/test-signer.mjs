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

// Test signer: produces keelstamp-aac-v1 receipts, checkpoints and keys files as SPEC.md
// describes them, for tests and fixtures only.
//
// It deliberately shares no code with src/: CBOR is encoded by the small encoder below, Ed25519
// and SHA-256 come from node:crypto (the verifier uses @noble), and the Merkle tree is built with
// the recursive definitions of RFC 9162 §2.1.1 / §2.1.3.1 (the verifier uses the iterative
// algorithm of §2.1.3.2). Keys are generated fresh on every call and private keys never leave
// memory; nothing here is a real Keelstamp key.

import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';

export const TEST_ISSUER = 'issuer.test.keelstamp.invalid';
export const TEST_LOG_ID = 'log.test.keelstamp.invalid/v1';
export const DAY = 86400;

const sha256 = (...parts) => {
  const h = createHash('sha256');
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
};
export const hex = (bytes) => Buffer.from(bytes).toString('hex');
export const b64url = (bytes) => Buffer.from(bytes).toString('base64url');
const utf8 = (s) => new TextEncoder().encode(s);

// ---------------------------------------------------------------- CBOR (RFC 8949), encode only

export class Tag {
  constructor(tag, value) {
    this.tag = tag;
    this.value = value;
  }
}

/** Bytes inserted verbatim, to build malformed CBOR in negative tests. */
export class Raw {
  constructor(bytes) {
    this.bytes = Uint8Array.from(bytes);
  }
}

function head(major, n) {
  const m = major << 5;
  if (n < 24) return [m | n];
  if (n < 0x100) return [m | 24, n];
  if (n < 0x10000) return [m | 25, n >> 8, n & 0xff];
  if (n < 0x100000000) return [m | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
  const big = BigInt(n);
  return [m | 27, ...Array.from({ length: 8 }, (_, i) => Number((big >> BigInt(56 - 8 * i)) & 0xffn))];
}

function cborArr(v) {
  if (v instanceof Raw) return [...v.bytes];
  if (v === null) return [0xf6];
  if (typeof v === 'boolean') return [v ? 0xf5 : 0xf4];
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) throw new Error('test signer encodes integers only');
    return v >= 0 ? head(0, v) : head(1, -1 - v);
  }
  if (v instanceof Uint8Array) return [...head(2, v.length), ...v];
  if (typeof v === 'string') {
    const b = utf8(v);
    return [...head(3, b.length), ...b];
  }
  if (Array.isArray(v)) return [...head(4, v.length), ...v.flatMap(cborArr)];
  if (v instanceof Map) {
    // Core deterministic encoding (RFC 8949 §4.2.1): keys sorted by their encoded bytes.
    const entries = [...v].map(([k, val]) => [cborArr(k), cborArr(val)]);
    entries.sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
    return [...head(5, entries.length), ...entries.flatMap(([k, val]) => [...k, ...val])];
  }
  if (v instanceof Tag) return [...head(6, v.tag), ...cborArr(v.value)];
  throw new Error(`test signer cannot encode ${typeof v}`);
}

export const cbor = (v) => Uint8Array.from(cborArr(v));

// ---------------------------------------------------------------- JSON (RFC 8785 subset)

/** RFC 8785 for the value shapes used here (ASCII strings, safe integers, objects, arrays). */
export function jcs(v) {
  if (Array.isArray(v)) return `[${v.map(jcs).join(',')}]`;
  if (v !== null && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

// ---------------------------------------------------------------- keys

/** A fresh Ed25519 key. validFrom/validUntil are seconds since the epoch (validUntil may be null). */
export function newKey({ purpose = 'receipt', validFrom, validUntil = null }) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const x = publicKey.export({ format: 'jwk' }).x;
  // RFC 7638 JWK Thumbprint, computed independently of src/keys.mjs.
  const kidBytes = sha256(utf8(JSON.stringify({ crv: 'Ed25519', kty: 'OKP', x })));
  return { privateKey, x, kidBytes, kid: b64url(kidBytes), purpose, validFrom, validUntil };
}

const isoSeconds = (s) => new Date(s * 1000).toISOString().replace('.000Z', 'Z');

export function jwk(key, overrides = {}) {
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: key.x,
    kid: key.kid,
    purpose: key.purpose,
    valid_from: isoSeconds(key.validFrom),
    valid_until: key.validUntil === null ? null : isoSeconds(key.validUntil),
    ...overrides,
  };
}

export function keysDoc(issuer, keys) {
  return { format: 'keelstamp-keys-v1', issuer, keys: keys.map((k) => jwk(k)) };
}

// ---------------------------------------------------------------- COSE_Sign1

export function protectedHeader({ alg = -19, kidBytes, iss, sub, iat, contentType = 'application/json' }) {
  const claims = new Map([[1, iss], [2, sub], [6, iat]]);
  return new Map([[1, alg], [3, contentType], [4, kidBytes], [15, claims]]);
}

export function encodeSign1({ protectedBytes, unprotected = new Map(), payloadBytes, signature, tag = 18 }) {
  const body = [protectedBytes, unprotected, payloadBytes, signature];
  return cbor(tag === null ? body : new Tag(tag, body));
}

/**
 * Signs a statement. `payload` may be an object (serialized with jcs), a string or bytes.
 * `header` replaces the protected header map; `signWith` signs with another key than the one the
 * header names (for negative tests).
 */
export function signStatement({ key, signWith = key, payload, iss, sub, iat, alg, header, unprotected, tag }) {
  const payloadBytes = payload instanceof Uint8Array ? payload : utf8(typeof payload === 'string' ? payload : jcs(payload));
  const protectedBytes = header instanceof Uint8Array ? header : cbor(header ?? protectedHeader({ alg, kidBytes: key.kidBytes, iss, sub, iat }));
  const toBeSigned = cbor(['Signature1', protectedBytes, new Uint8Array(0), payloadBytes]);
  const signature = new Uint8Array(sign(null, toBeSigned, signWith.privateKey));
  const parts = { protectedBytes, unprotected, payloadBytes, signature, tag };
  return { ...parts, bytes: encodeSign1(parts) };
}

// ---------------------------------------------------------------- Merkle tree (RFC 9162 §2.1)

const largestPowerOfTwoBelow = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};

/** MTH(D[n]) */
export function merkleRoot(leaves) {
  if (leaves.length === 0) return sha256(new Uint8Array(0));
  if (leaves.length === 1) return sha256(Uint8Array.of(0), leaves[0]);
  const k = largestPowerOfTwoBelow(leaves.length);
  return sha256(Uint8Array.of(1), merkleRoot(leaves.slice(0, k)), merkleRoot(leaves.slice(k)));
}

/** PATH(m, D[n]) */
export function inclusionPath(m, leaves) {
  if (leaves.length <= 1) return [];
  const k = largestPowerOfTwoBelow(leaves.length);
  return m < k
    ? [...inclusionPath(m, leaves.slice(0, k)), merkleRoot(leaves.slice(k))]
    : [...inclusionPath(m - k, leaves.slice(k)), merkleRoot(leaves.slice(0, k))];
}

// ---------------------------------------------------------------- files

export const receiptFileDoc = (bytes, proof) => ({ format: 'keelstamp-receipt-file-v1', receipt: b64url(bytes), ...(proof ? { inclusion_proof: proof } : {}) });
export const checkpointFileDoc = (bytes) => ({ format: 'keelstamp-checkpoint-file-v1', checkpoint: b64url(bytes) });

export const commitment = () => `sha256:${hex(randomBytes(32))}`;

export function aacPayload(overrides = {}) {
  return {
    profile: 'keelstamp-aac-v1',
    receipt_id: b64url(randomBytes(16)),
    partner: commitment(),
    tenant: commitment(),
    event: 'action.approved',
    digests: { request: commitment(), response: commitment() },
    ...overrides,
  };
}

export function checkpointPayload(leaves, logId = TEST_LOG_ID) {
  return { profile: 'keelstamp-checkpoint-v1', log_id: logId, tree_size: leaves.length, root_hash: hex(merkleRoot(leaves)) };
}

/**
 * A complete, valid world: keys file (receipt key, checkpoint key, a rotated-out receipt key),
 * one receipt included at `leafIndex` of a log of `treeSize` entries, and a checkpoint of that log.
 * All times are relative to the moment of generation; nothing depends on the verifier's clock.
 */
export function buildWorld({ treeSize = 7, leafIndex = 5, now = Math.floor(Date.now() / 1000) } = {}) {
  const issuer = TEST_ISSUER;
  const receiptKey = newKey({ purpose: 'receipt', validFrom: now - 30 * DAY });
  const checkpointKey = newKey({ purpose: 'checkpoint', validFrom: now - 30 * DAY });
  const retiredKey = newKey({ purpose: 'receipt', validFrom: now - 60 * DAY, validUntil: now - 30 * DAY });
  const keys = keysDoc(issuer, [receiptKey, checkpointKey, retiredKey]);

  const payload = aacPayload();
  const iat = now - DAY;
  const receipt = signStatement({ key: receiptKey, payload, iss: issuer, sub: payload.receipt_id, iat });

  const leaves = Array.from({ length: treeSize }, () => new Uint8Array(randomBytes(64)));
  leaves[leafIndex] = receipt.bytes;
  const proof = {
    log_id: TEST_LOG_ID,
    tree_size: treeSize,
    leaf_index: leafIndex,
    inclusion_path: inclusionPath(leafIndex, leaves).map(hex),
  };
  const cpPayload = checkpointPayload(leaves);
  const checkpoint = signStatement({ key: checkpointKey, payload: cpPayload, iss: issuer, sub: TEST_LOG_ID, iat: now });

  return {
    now, issuer, iat, payload, leaves, proof, cpPayload,
    receiptKey, checkpointKey, retiredKey, keys,
    receipt, checkpoint,
    receiptDoc: receiptFileDoc(receipt.bytes, proof),
    checkpointDoc: checkpointFileDoc(checkpoint.bytes),
    /** Re-sign a receipt in this world with changes (payload, header fields, keys). */
    signReceipt(opts = {}) {
      const p = opts.payload ?? payload;
      return signStatement({ key: receiptKey, iss: issuer, sub: p.receipt_id ?? payload.receipt_id, iat, ...opts, payload: p });
    },
    /** Sign a checkpoint in this world with changes. */
    signCheckpoint(opts = {}) {
      return signStatement({ key: checkpointKey, payload: cpPayload, iss: issuer, sub: TEST_LOG_ID, iat: now, ...opts });
    },
  };
}
