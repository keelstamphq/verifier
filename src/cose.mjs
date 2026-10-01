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

// COSE_Sign1 (RFC 9052 §4.2) decoding and the Sig_structure to be signed (RFC 9052 §4.4).

import { decode, encode, Tagged } from 'cborg';

export const COSE_SIGN1_TAG = 18;

// Header parameter labels (IANA "COSE Header Parameters").
export const HDR_ALG = 1;
export const HDR_CRIT = 2;
export const HDR_CONTENT_TYPE = 3;
export const HDR_KID = 4;
export const HDR_CWT_CLAIMS = 15; // RFC 9597

// CWT claim keys (RFC 8392 §4).
export const CWT_ISS = 1;
export const CWT_SUB = 2;
export const CWT_IAT = 6;

// Strict decoding: minimal-length integers and lengths, no indefinite lengths, no duplicate map
// keys, no undefined/NaN/Infinity, no integers outside the safe range, only tag 18 understood,
// no trailing bytes (cborg's decode() rejects them). Maps decode to Map so integer labels survive.
const STRICT = Object.freeze({
  useMaps: true,
  rejectDuplicateMapKeys: true,
  strict: true,
  allowIndefinite: false,
  allowUndefined: false,
  allowInfinity: false,
  allowNaN: false,
  allowBigInt: false,
});

export class CoseError extends Error {}

export function decodeStrict(bytes, tags = {}) {
  return decode(bytes, { ...STRICT, tags });
}

/**
 * Decodes a COSE_Sign1_Tagged structure:
 *   18([ protected: bstr .cbor header_map, unprotected: header_map, payload: bstr, signature: bstr ])
 * Detached payloads (nil) are not part of keelstamp profiles and are rejected here.
 */
export function decodeCoseSign1(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new CoseError('empty input');
  let top;
  try {
    top = decodeStrict(bytes, { [COSE_SIGN1_TAG]: Tagged.decoder(COSE_SIGN1_TAG) });
  } catch (e) {
    throw new CoseError(`not strict CBOR: ${e.message}`);
  }
  if (!(top instanceof Tagged) || top.tag !== COSE_SIGN1_TAG) {
    throw new CoseError('not a COSE_Sign1_Tagged structure (CBOR tag 18 required)');
  }
  const arr = top.value;
  if (!Array.isArray(arr) || arr.length !== 4) throw new CoseError('COSE_Sign1 must be an array of 4 elements');
  const [protectedBytes, unprotectedHeader, payload, signature] = arr;
  if (!(protectedBytes instanceof Uint8Array)) throw new CoseError('protected header must be a byte string');
  if (!(unprotectedHeader instanceof Map)) throw new CoseError('unprotected header must be a map');
  if (payload === null) throw new CoseError('detached payload is not supported by this profile');
  if (!(payload instanceof Uint8Array)) throw new CoseError('payload must be a byte string');
  if (!(signature instanceof Uint8Array)) throw new CoseError('signature must be a byte string');

  let protectedHeader;
  if (protectedBytes.length === 0) {
    protectedHeader = new Map(); // RFC 9052 §3: a zero-length bstr encodes an empty protected header
  } else {
    try {
      protectedHeader = decodeStrict(protectedBytes);
    } catch (e) {
      throw new CoseError(`protected header is not strict CBOR: ${e.message}`);
    }
    if (!(protectedHeader instanceof Map)) throw new CoseError('protected header must encode a map');
  }
  return { protectedBytes, protectedHeader, unprotectedHeader, payload, signature };
}

/** Sig_structure = ["Signature1", body_protected, external_aad, payload] (RFC 9052 §4.4). */
export function sigStructure(protectedBytes, payload, externalAad = new Uint8Array(0)) {
  return encode(['Signature1', protectedBytes, externalAad, payload]);
}
