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

// verify(receipt, keys, checkpoint?) → { ok, reasons[], checks, details }
//
//   (a) signature  COSE_Sign1 with Ed25519 over the RFC 9052 Sig_structure
//   (b) payload    the payload bytes are canonical JSON (RFC 8785)
//   (c) profile    the payload profile is known and the payload matches it
//   (d) key        the key id is in the keys file, belongs to the key, and was valid at iat
//   (e) inclusion  RFC 9162 inclusion proof against a signed checkpoint (only when one is given)
//
// Fail-closed: ok is true only when every required check passed and no reason was recorded;
// unexpected exceptions become INTERNAL_ERROR, never a pass. No network access, no clock: the
// result depends only on the three inputs.

import {
  CWT_IAT, CWT_ISS, CWT_SUB, HDR_ALG, HDR_CONTENT_TYPE, HDR_CWT_CLAIMS, HDR_KID,
  decodeCoseSign1, sigStructure,
} from './cose.mjs';
import { ed25519Verify } from './crypto.mjs';
import {
  base64urlDecode, base64urlEncode, bytesEqual, formatUtcSeconds, hexDecode, hexEncode, utf8DecodeStrict,
} from './encoding.mjs';
import { parseCanonicalJson, parseJsonNoDuplicates } from './jcs.mjs';
import { parseKeysFile } from './keys.mjs';
import { leafHash, rootFromInclusionProof } from './merkle.mjs';
import { findProfile, knownProfiles } from './profiles.mjs';
import { checkpointReason, reason } from './reasons.mjs';

export const RECEIPT_FILE_FORMAT = 'keelstamp-receipt-file-v1';
export const CHECKPOINT_FILE_FORMAT = 'keelstamp-checkpoint-file-v1';
export const ALG_ED25519 = -19; // IANA COSE Algorithms: Ed25519 (fully specified)
export const CONTENT_TYPE_JSON = 'application/json';

const PROTECTED_LABELS = new Set([HDR_ALG, HDR_CONTENT_TYPE, HDR_KID, HDR_CWT_CLAIMS]);
const CWT_KEYS = new Set([CWT_ISS, CWT_SUB, CWT_IAT]);
const LOG_ID = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;
const HASH_HEX = /^[0-9a-f]{64}$/;

const PASS = 'pass';
const FAIL = 'fail';
const SKIPPED = 'skipped';

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * Accepts a parsed JSON value, a JSON string or UTF-8 bytes. Returns { doc } or { error }.
 * Text input with duplicate member names is rejected: JSON.parse keeps the last one, another
 * parser may keep the other, and the two would read different documents.
 */
function readJson(input) {
  try {
    if (input instanceof Uint8Array) return { doc: parseJsonNoDuplicates(utf8DecodeStrict(input)) };
    if (typeof input === 'string') return { doc: parseJsonNoDuplicates(input) };
    return { doc: input };
  } catch (e) {
    return { error: `not valid JSON (${e.message})` };
  }
}

function unknownMember(obj, allowed) {
  return Object.keys(obj).find((k) => !allowed.includes(k));
}

function parseReceiptFile(doc) {
  if (!isPlainObject(doc)) return { error: 'must be a JSON object' };
  const extra = unknownMember(doc, ['format', 'receipt', 'inclusion_proof']);
  if (extra !== undefined) return { error: `unknown member "${extra}"` };
  if (doc.format !== RECEIPT_FILE_FORMAT) return { error: `format must be "${RECEIPT_FILE_FORMAT}"` };
  const bytes = base64urlDecode(doc.receipt);
  if (bytes === null || bytes.length === 0) return { error: 'receipt must be the COSE_Sign1 bytes, base64url without padding' };
  return { bytes, proof: doc.inclusion_proof };
}

/** Shape of the inclusion proof (RFC 9162 inclusion_proof_v2 fields, JSON form). Returns { proof } or { error }. */
function parseInclusionProof(p) {
  if (!isPlainObject(p)) return { error: 'must be an object' };
  const members = ['log_id', 'tree_size', 'leaf_index', 'inclusion_path'];
  const extra = unknownMember(p, members);
  if (extra !== undefined) return { error: `unknown member "${extra}"` };
  const missing = members.find((k) => !(k in p));
  if (missing !== undefined) return { error: `missing member "${missing}"` };
  if (typeof p.log_id !== 'string' || !LOG_ID.test(p.log_id)) return { error: 'log_id has an invalid form' };
  if (!Number.isSafeInteger(p.tree_size) || p.tree_size < 1) return { error: 'tree_size must be a positive safe integer' };
  if (!Number.isSafeInteger(p.leaf_index) || p.leaf_index < 0) return { error: 'leaf_index must be a non-negative safe integer' };
  if (p.leaf_index >= p.tree_size) return { error: 'leaf_index must be smaller than tree_size' };
  if (!Array.isArray(p.inclusion_path) || !p.inclusion_path.every((h) => typeof h === 'string' && HASH_HEX.test(h))) {
    return { error: 'inclusion_path must be an array of 64-character lowercase hex hashes' };
  }
  return { proof: { ...p, path: p.inclusion_path.map(hexDecode) } };
}

function parseCheckpointFile(doc) {
  if (!isPlainObject(doc)) return { error: 'must be a JSON object' };
  const extra = unknownMember(doc, ['format', 'checkpoint']);
  if (extra !== undefined) return { error: `unknown member "${extra}"` };
  if (doc.format !== CHECKPOINT_FILE_FORMAT) return { error: `format must be "${CHECKPOINT_FILE_FORMAT}"` };
  const bytes = base64urlDecode(doc.checkpoint);
  if (bytes === null || bytes.length === 0) return { error: 'checkpoint must be the COSE_Sign1 bytes, base64url without padding' };
  return { bytes };
}

const isText = (v) => typeof v === 'string' && v.length > 0;

/** Protected-header rules shared by all keelstamp profiles. */
function readHeader(cose) {
  const errors = [];
  const h = cose.protectedHeader;
  if (cose.unprotectedHeader.size !== 0) errors.push('unprotected header must be empty');
  for (const label of h.keys()) {
    if (!PROTECTED_LABELS.has(label)) errors.push(`unexpected protected header parameter ${JSON.stringify(label)}`);
  }
  const alg = h.get(HDR_ALG);
  if (alg === undefined) errors.push('alg (1) is missing');
  if (h.get(HDR_CONTENT_TYPE) !== CONTENT_TYPE_JSON) errors.push(`content type (3) must be "${CONTENT_TYPE_JSON}"`);
  const kid = h.get(HDR_KID);
  const kidOk = kid instanceof Uint8Array && kid.length === 32;
  if (!kidOk) errors.push('kid (4) must be a 32-byte byte string (the key\'s JWK Thumbprint)');
  const claims = h.get(HDR_CWT_CLAIMS);
  let iss;
  let sub;
  let iat;
  if (!(claims instanceof Map)) {
    errors.push('CWT Claims (15) must be a map');
  } else {
    for (const key of claims.keys()) {
      if (!CWT_KEYS.has(key)) errors.push(`unexpected CWT claim ${JSON.stringify(key)}`);
    }
    iss = claims.get(CWT_ISS);
    sub = claims.get(CWT_SUB);
    iat = claims.get(CWT_IAT);
    if (!isText(iss)) errors.push('CWT iss (1) must be a non-empty text string');
    if (!isText(sub)) errors.push('CWT sub (2) must be a non-empty text string');
    if (!Number.isSafeInteger(iat) || iat < 0) errors.push('CWT iat (6) must be a non-negative integer (seconds)');
  }
  return { errors, alg, kidBytes: kidOk ? kid : undefined, iss, sub, iat };
}

/**
 * Checks (a)-(d) for one signed statement of the given kind ("receipt" or "checkpoint").
 * Returns { reasons, checks, info } where info holds the decoded fields for display.
 */
function checkStatement(bytes, keys, kind) {
  const reasons = [];
  const checks = { signature: SKIPPED, payload_jcs: SKIPPED, profile: SKIPPED, key: SKIPPED };
  const info = {};
  const fail = (check, code, detail) => {
    reasons.push(reason(code, detail));
    checks[check] = FAIL;
  };

  let cose;
  try {
    cose = decodeCoseSign1(bytes);
  } catch (e) {
    fail('signature', 'COSE_MALFORMED', e.message);
    return { reasons, checks, info };
  }

  const hdr = readHeader(cose);
  const headerOk = hdr.errors.length === 0 && hdr.alg === ALG_ED25519;
  if (hdr.errors.length) fail('signature', 'COSE_HEADER_INVALID', hdr.errors.join('; '));
  if (hdr.alg !== undefined && hdr.alg !== ALG_ED25519) fail('signature', 'ALG_UNSUPPORTED', `alg is ${JSON.stringify(hdr.alg)}`);
  if (headerOk) Object.assign(info, { kid: base64urlEncode(hdr.kidBytes), iss: hdr.iss, sub: hdr.sub, iat: hdr.iat, signed_at: formatUtcSeconds(hdr.iat) });

  // (b) canonical JSON payload
  const parsed = parseCanonicalJson(cose.payload);
  if (!parsed.ok) {
    fail('payload_jcs', 'PAYLOAD_NOT_JCS', parsed.detail);
  } else {
    checks.payload_jcs = PASS;
    info.payload = parsed.value;
    // (c) profile
    const name = isPlainObject(parsed.value) ? parsed.value.profile : undefined;
    const profile = findProfile(name, kind);
    if (!profile) {
      const known = knownProfiles(kind).join(', ');
      fail('profile', 'PROFILE_UNKNOWN', name === undefined ? `payload has no "profile" member (known: ${known})` : `${JSON.stringify(name)} (known: ${known})`);
    } else {
      info.profile = profile.name;
      const errors = profile.validate(parsed.value);
      if (errors.length) {
        fail('profile', 'PAYLOAD_SCHEMA_INVALID', errors.join('; '));
      } else if (headerOk && hdr.sub !== parsed.value[profile.subjectMember]) {
        fail('profile', 'SUBJECT_MISMATCH', `sub is ${JSON.stringify(hdr.sub)}, payload ${profile.subjectMember} is ${JSON.stringify(parsed.value[profile.subjectMember])}`);
      } else {
        checks.profile = PASS;
      }
    }
  }

  if (!headerOk) return { reasons, checks, info };

  // (d) key
  const kid = base64urlEncode(hdr.kidBytes);
  const entry = keys.byKid.get(kid);
  if (!entry) {
    fail('key', 'KID_UNKNOWN', kid);
    return { reasons, checks, info };
  }
  if (!entry.thumbprintMatches) {
    fail('key', 'KEY_MISMATCH', kid);
    return { reasons, checks, info };
  }
  const keyReasons = reasons.length;
  if (entry.purpose !== kind) fail('key', 'KEY_PURPOSE_MISMATCH', `key ${kid} is for ${entry.purpose} statements, this is a ${kind}`);
  if (hdr.iss !== keys.issuer) fail('key', 'ISSUER_MISMATCH', `iss is ${JSON.stringify(hdr.iss)}, keys file issuer is ${JSON.stringify(keys.issuer)}`);
  if (hdr.iat < entry.validFrom || (entry.validUntil !== null && hdr.iat >= entry.validUntil)) {
    const window = `${formatUtcSeconds(entry.validFrom)} .. ${entry.validUntil === null ? 'open' : formatUtcSeconds(entry.validUntil)}`;
    fail('key', 'KEY_NOT_VALID_AT_TIME', `signed at ${formatUtcSeconds(hdr.iat)}, key valid ${window}`);
  }
  if (reasons.length === keyReasons) checks.key = PASS;

  // (a) signature
  const toBeSigned = sigStructure(cose.protectedBytes, cose.payload);
  if (ed25519Verify(cose.signature, toBeSigned, entry.publicKey)) {
    checks.signature = PASS;
  } else {
    const actual = keys.keys.find((k) => k !== entry && k.thumbprintMatches && ed25519Verify(cose.signature, toBeSigned, k.publicKey));
    if (actual) fail('signature', 'WRONG_KEY', `signed by ${actual.kid}, key id names ${kid}`);
    else fail('signature', 'SIGNATURE_INVALID', `key ${kid}`);
  }
  return { reasons, checks, info };
}

function checkInclusion(receiptBytes, receiptInfo, proofInput, checkpointInput, keys, details) {
  const reasons = [];
  const read = readJson(checkpointInput);
  const cpFile = read.error ? read : parseCheckpointFile(read.doc);
  if (cpFile.error) return [reason('CHECKPOINT_MALFORMED', cpFile.error)];

  const cp = checkStatement(cpFile.bytes, keys, 'checkpoint');
  details.checkpoint = { ...cp.info, checks: cp.checks };
  reasons.push(...cp.reasons.map(checkpointReason));

  if (proofInput === undefined) {
    reasons.push(reason('INCLUSION_PROOF_MISSING'));
    return reasons;
  }
  const parsed = parseInclusionProof(proofInput);
  // A malformed proof is already reported by the caller.
  if (parsed.error || cp.reasons.length) return reasons;

  const { proof } = parsed;
  const cpPayload = cp.info.payload;
  if (proof.log_id !== cpPayload.log_id) {
    reasons.push(reason('CHECKPOINT_LOG_MISMATCH', `proof log_id ${JSON.stringify(proof.log_id)}, checkpoint log_id ${JSON.stringify(cpPayload.log_id)}`));
  } else if (proof.tree_size !== cpPayload.tree_size) {
    reasons.push(reason('CHECKPOINT_TREE_SIZE_MISMATCH', `proof tree_size ${proof.tree_size}, checkpoint tree_size ${cpPayload.tree_size}`));
  } else {
    const root = rootFromInclusionProof(proof.leaf_index, proof.tree_size, leafHash(receiptBytes), proof.path);
    const expected = hexDecode(cpPayload.root_hash);
    if (root === null) {
      reasons.push(reason('INCLUSION_PROOF_INVALID', `a path of ${proof.path.length} hashes cannot prove leaf ${proof.leaf_index} in a tree of size ${proof.tree_size}`));
    } else if (!bytesEqual(root, expected)) {
      reasons.push(reason('INCLUSION_PROOF_INVALID', `computed root ${hexEncode(root)}, checkpoint root ${cpPayload.root_hash}`));
    }
  }
  if (receiptInfo.iat !== undefined && receiptInfo.iat > cp.info.iat) {
    reasons.push(reason('RECEIPT_AFTER_CHECKPOINT', `receipt signed at ${formatUtcSeconds(receiptInfo.iat)}, checkpoint signed at ${formatUtcSeconds(cp.info.iat)}`));
  }
  return reasons;
}

function verifyUnsafe(receiptInput, keysInput, checkpointInput) {
  const reasons = [];
  const checks = { signature: SKIPPED, payload_jcs: SKIPPED, profile: SKIPPED, key: SKIPPED, inclusion: SKIPPED };
  const details = {};
  const result = () => {
    const required = ['signature', 'payload_jcs', 'profile', 'key'].every((c) => checks[c] === PASS);
    const inclusionOk = checks.inclusion === PASS || checks.inclusion === SKIPPED;
    if (reasons.length === 0 && !(required && inclusionOk)) reasons.push(reason('INTERNAL_ERROR', 'a required check did not run'));
    return { ok: reasons.length === 0, reasons, checks, details };
  };

  const receiptRead = readJson(receiptInput);
  const receiptFile = receiptRead.error ? receiptRead : parseReceiptFile(receiptRead.doc);
  if (receiptFile.error) {
    reasons.push(reason('RECEIPT_MALFORMED', receiptFile.error));
    return result();
  }
  const keysRead = readJson(keysInput);
  let keys;
  try {
    if (keysRead.error) throw new Error(keysRead.error);
    keys = parseKeysFile(keysRead.doc);
  } catch (e) {
    reasons.push(reason('KEYS_MALFORMED', e.message));
    return result();
  }
  details.keys_issuer = keys.issuer;

  const st = checkStatement(receiptFile.bytes, keys, 'receipt');
  reasons.push(...st.reasons);
  Object.assign(checks, st.checks);
  details.receipt = st.info;

  let inclusionReasons = [];
  if (receiptFile.proof !== undefined) {
    const parsed = parseInclusionProof(receiptFile.proof);
    if (parsed.error) inclusionReasons.push(reason('INCLUSION_PROOF_MALFORMED', parsed.error));
    else details.inclusion = { log_id: parsed.proof.log_id, tree_size: parsed.proof.tree_size, leaf_index: parsed.proof.leaf_index };
  }
  const haveCheckpoint = checkpointInput !== undefined && checkpointInput !== null;
  if (haveCheckpoint) {
    inclusionReasons = inclusionReasons.concat(checkInclusion(receiptFile.bytes, st.info, receiptFile.proof, checkpointInput, keys, details));
  }
  if (inclusionReasons.length) checks.inclusion = FAIL;
  else if (haveCheckpoint) checks.inclusion = PASS;
  reasons.push(...inclusionReasons);
  return result();
}

/**
 * Verifies a keelstamp receipt file against a keys file and, optionally, a checkpoint file.
 * Each input may be a parsed JSON value, a JSON string or UTF-8 bytes. Never throws.
 */
export function verify(receipt, keys, checkpoint) {
  try {
    return verifyUnsafe(receipt, keys, checkpoint);
  } catch (e) {
    let detail;
    try {
      detail = String(e?.message ?? e);
    } catch {
      detail = 'unprintable exception';
    }
    return {
      ok: false,
      reasons: [reason('INTERNAL_ERROR', detail)],
      checks: { signature: SKIPPED, payload_jcs: SKIPPED, profile: SKIPPED, key: SKIPPED, inclusion: SKIPPED },
      details: {},
    };
  }
}
