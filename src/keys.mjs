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

// The public keys file (/.well-known/keelstamp-keys.json, format keelstamp-keys-v1).
// Every entry is an Ed25519 JWK (RFC 7517 / RFC 8037) whose "kid" is its own JWK Thumbprint
// (RFC 7638, SHA-256), plus a purpose and a validity window.

import { sha256 } from '@noble/hashes/sha2.js';
import { Point } from './crypto.mjs';
import { base64urlDecode, base64urlEncode, parseUtcSeconds, utf8Encode } from './encoding.mjs';

export const KEYS_FORMAT = 'keelstamp-keys-v1';
export const KEY_PURPOSES = Object.freeze(['receipt', 'checkpoint']);

const FILE_MEMBERS = new Set(['format', 'issuer', 'keys']);
const KEY_MEMBERS = new Set(['kty', 'crv', 'x', 'kid', 'purpose', 'valid_from', 'valid_until']);

export class KeysError extends Error {}

/** RFC 7638 JWK Thumbprint of an Ed25519 OKP key: SHA-256 over {"crv","kty","x"} in lexicographic order, no whitespace. */
export function jwkThumbprint(x) {
  return sha256(utf8Encode(`{"crv":"Ed25519","kty":"OKP","x":"${x}"}`));
}

export const jwkThumbprintB64 = (x) => base64urlEncode(jwkThumbprint(x));

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function unknownMember(obj, allowed) {
  return Object.keys(obj).find((k) => !allowed.has(k));
}

/**
 * Parses and validates a keys file (object). Throws KeysError with a readable message.
 * Validation is structural: an entry whose kid does not match its key is kept and reported by
 * the verifier as KEY_MISMATCH when a statement refers to it, so the reason points at the key
 * actually used.
 */
export function parseKeysFile(doc) {
  if (!isPlainObject(doc)) throw new KeysError('keys file must be a JSON object');
  const extra = unknownMember(doc, FILE_MEMBERS);
  if (extra !== undefined) throw new KeysError(`unknown member "${extra}"`);
  if (doc.format !== KEYS_FORMAT) throw new KeysError(`format must be "${KEYS_FORMAT}"`);
  if (typeof doc.issuer !== 'string' || doc.issuer.length === 0) throw new KeysError('issuer must be a non-empty string');
  if (!Array.isArray(doc.keys)) throw new KeysError('keys must be an array');

  const byKid = new Map();
  doc.keys.forEach((k, i) => {
    const where = `keys[${i}]`;
    if (!isPlainObject(k)) throw new KeysError(`${where} must be an object`);
    const extraKey = unknownMember(k, KEY_MEMBERS);
    if (extraKey !== undefined) throw new KeysError(`${where}: unknown member "${extraKey}"`);
    if (k.kty !== 'OKP' || k.crv !== 'Ed25519') throw new KeysError(`${where}: only kty "OKP" with crv "Ed25519" is supported`);
    const publicKey = base64urlDecode(k.x);
    if (publicKey === null || publicKey.length !== 32) throw new KeysError(`${where}: x must be 32 bytes, base64url without padding`);
    let point;
    try {
      point = Point.fromBytes(publicKey, false);
    } catch {
      throw new KeysError(`${where}: x is not a valid Ed25519 public key`);
    }
    if (point.isSmallOrder()) throw new KeysError(`${where}: x is a small-order point`);
    const kidBytes = base64urlDecode(k.kid);
    if (kidBytes === null || kidBytes.length !== 32) throw new KeysError(`${where}: kid must be a base64url SHA-256 JWK Thumbprint`);
    if (!KEY_PURPOSES.includes(k.purpose)) throw new KeysError(`${where}: purpose must be one of ${KEY_PURPOSES.join(', ')}`);
    const validFrom = parseUtcSeconds(k.valid_from);
    if (validFrom === null) throw new KeysError(`${where}: valid_from must be an RFC 3339 UTC time (YYYY-MM-DDThh:mm:ssZ)`);
    // valid_until is required; only an explicit null means open-ended (a missing member must not).
    if (!Object.hasOwn(k, 'valid_until')) throw new KeysError(`${where}: valid_until is missing (use null for an open-ended key)`);
    let validUntil = null;
    if (k.valid_until !== null) {
      validUntil = parseUtcSeconds(k.valid_until);
      if (validUntil === null) throw new KeysError(`${where}: valid_until must be null or an RFC 3339 UTC time`);
      if (validUntil <= validFrom) throw new KeysError(`${where}: valid_until must be after valid_from`);
    }
    if (byKid.has(k.kid)) throw new KeysError(`${where}: duplicate kid ${k.kid}`);
    byKid.set(k.kid, {
      kid: k.kid,
      kidBytes,
      publicKey,
      purpose: k.purpose,
      validFrom,
      validUntil,
      thumbprintMatches: jwkThumbprintB64(k.x) === k.kid,
    });
  });
  return { issuer: doc.issuer, keys: [...byKid.values()], byKid };
}
