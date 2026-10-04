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
//   (e) inclusion  the log receipt (COSE Receipt, RFC 9942, header 394) verifies over the RFC 9162
//                  root computed from the receipt and its inclusion proof; when a checkpoint is
//                  given, that root is also the one the checkpoint signs for the same tree size
//
// Keys come only from the `keys` argument. Nothing in or next to the receipt is used as a key.
// Fail-closed: ok is true only when every required check passed and no reason was recorded;
// unexpected exceptions become INTERNAL_ERROR, never a pass. No network access, no clock: the
// result depends only on the three inputs.

import {
  CWT_IAT, CWT_ISS, CWT_SUB, HDR_ALG, HDR_CONTENT_TYPE, HDR_CWT_CLAIMS, HDR_KID, HDR_RECEIPTS, HDR_VDP,
  HDR_VDS, VDP_CONSISTENCY, VDP_INCLUSION, VDS_RFC9162_SHA256,
  decodeCoseSign1, decodeStrict, logEntry, sigStructure,
} from './cose.mjs';
import { ed25519Verify } from './crypto.mjs';
import {
  base64urlDecode, base64urlEncode, bytesEqual, formatUtcSeconds, hexDecode, hexEncode, utf8DecodeStrict,
} from './encoding.mjs';
import { parseCanonicalJson, parseJsonNoDuplicates } from './jcs.mjs';
import { describeKeys, keysFileSha256, parseKeysFile } from './keys.mjs';
import { leafHash, rootFromInclusionProof } from './merkle.mjs';
import { findProfile, knownProfiles } from './profiles.mjs';
import { show } from './display.mjs';
import { checkpointReason, logReceiptReason, reason } from './reasons.mjs';

export const RECEIPT_FILE_FORMAT = 'keelstamp-receipt-file-v1';
export const CHECKPOINT_FILE_FORMAT = 'keelstamp-checkpoint-file-v1';
export const ALG_ED25519 = -19; // RFC 9864: Ed25519 (fully specified)
export const CONTENT_TYPE_JSON = 'application/json';

// Header rules per kind of COSE_Sign1. Anything not listed is rejected, so no key material (COSE_Key,
// certificates, JWKs) can ride along in a header and be mistaken for a trusted key.
const RULES = {
  receipt: {
    protected: [HDR_ALG, HDR_CONTENT_TYPE, HDR_KID, HDR_CWT_CLAIMS],
    unprotected: [HDR_RECEIPTS],
    contentType: CONTENT_TYPE_JSON,
    purpose: 'statement',
  },
  checkpoint: {
    protected: [HDR_ALG, HDR_CONTENT_TYPE, HDR_KID, HDR_CWT_CLAIMS],
    unprotected: [],
    contentType: CONTENT_TYPE_JSON,
    purpose: 'log',
  },
  logReceipt: {
    protected: [HDR_ALG, HDR_KID, HDR_CWT_CLAIMS, HDR_VDS],
    unprotected: [HDR_VDP],
    contentType: undefined,
    purpose: 'log',
  },
};
const CWT_KEYS = new Set([CWT_ISS, CWT_SUB, CWT_IAT]);
const LOG_ID = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;

const PASS = 'pass';
const FAIL = 'fail';
const SKIPPED = 'skipped';

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isText = (v) => typeof v === 'string' && v.length > 0;

/**
 * A signed structure counts as verified only on positive evidence: every one of its checks passed
 * and no reason was recorded. The absence of reasons alone is not enough, since a check that never
 * ran leaves no reason behind.
 */
export function allChecksPassed({ reasons, checks }) {
  const values = Object.values(checks);
  return reasons.length === 0 && values.length > 0 && values.every((c) => c === PASS);
}

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
  const extra = unknownMember(doc, ['format', 'receipt']);
  if (extra !== undefined) return { error: `unknown member "${extra}" (a receipt file holds only format and receipt; keys never come with it)` };
  if (doc.format !== RECEIPT_FILE_FORMAT) return { error: `format must be "${RECEIPT_FILE_FORMAT}"` };
  const bytes = base64urlDecode(doc.receipt);
  if (bytes === null || bytes.length === 0) return { error: 'receipt must be the COSE_Sign1 bytes, base64url without padding' };
  return { bytes };
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

const labelList = (labels) => (labels.length ? labels.join(', ') : 'none');

/** Header rules shared by all keelstamp COSE_Sign1 structures, parameterized by kind. */
function readHeader(cose, rules) {
  const errors = [];
  const h = cose.protectedHeader;
  for (const label of cose.unprotectedHeader.keys()) {
    if (!rules.unprotected.includes(label)) {
      errors.push(`unexpected unprotected header parameter ${show(label)} (allowed: ${labelList(rules.unprotected)})`);
    }
  }
  for (const label of h.keys()) {
    if (!rules.protected.includes(label)) errors.push(`unexpected protected header parameter ${show(label)}`);
  }
  const alg = h.get(HDR_ALG);
  if (alg === undefined) errors.push('alg (1) is missing');
  if (rules.contentType !== undefined && h.get(HDR_CONTENT_TYPE) !== rules.contentType) {
    errors.push(`content type (3) must be "${rules.contentType}"`);
  }
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
      if (!CWT_KEYS.has(key)) errors.push(`unexpected CWT claim ${show(key)}`);
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

/** Reports header problems; returns true when the header is usable for key and signature checks. */
function checkHeader(hdr, fail) {
  if (hdr.errors.length) fail('signature', 'COSE_HEADER_INVALID', hdr.errors.join('; '));
  if (hdr.alg !== undefined && hdr.alg !== ALG_ED25519) fail('signature', 'ALG_UNSUPPORTED', `alg is ${show(hdr.alg)}`);
  return hdr.errors.length === 0 && hdr.alg === ALG_ED25519;
}

/**
 * (d) and (a) for one COSE_Sign1: the key named by kid, its purpose, issuer and validity at iat,
 * then the Ed25519 signature over `toBeSigned`. `toBeSigned` null means the content to verify
 * could not be computed; the caller has reported that.
 */
function checkKeyAndSignature({ hdr, keys, purpose, what, toBeSigned, signature, fail, pass, signatureFailCode }) {
  const kid = base64urlEncode(hdr.kidBytes);
  const entry = keys.byKid.get(kid);
  if (!entry) {
    fail('key', 'KID_UNKNOWN', kid);
    return;
  }
  if (!entry.thumbprintMatches) {
    fail('key', 'KEY_MISMATCH', kid);
    return;
  }
  let keyOk = true;
  const keyFail = (code, detail) => {
    keyOk = false;
    fail('key', code, detail);
  };
  if (entry.purpose !== purpose) keyFail('KEY_PURPOSE_MISMATCH', `key ${kid} is a ${entry.purpose} key; ${what} must be signed with a ${purpose} key`);
  if (hdr.iss !== keys.issuer) keyFail('ISSUER_MISMATCH', `iss is ${show(hdr.iss)}, keys file issuer is ${show(keys.issuer)}`);
  if (hdr.iat < entry.validFrom || (entry.validUntil !== null && hdr.iat >= entry.validUntil)) {
    const window = `${formatUtcSeconds(entry.validFrom)} .. ${entry.validUntil === null ? 'open' : formatUtcSeconds(entry.validUntil)}`;
    keyFail('KEY_NOT_VALID_AT_TIME', `signed at ${formatUtcSeconds(hdr.iat)}, key valid ${window}`);
  }
  if (keyOk) pass('key');
  if (toBeSigned === null) return;

  if (ed25519Verify(signature, toBeSigned, entry.publicKey)) {
    pass('signature');
  } else {
    const actual = keys.keys.find((k) => k !== entry && k.thumbprintMatches && ed25519Verify(signature, toBeSigned, k.publicKey));
    if (actual) fail('signature', 'WRONG_KEY', `signed by ${actual.kid}, key id names ${kid}`);
    else fail('signature', signatureFailCode, `key ${kid}`);
  }
}

/**
 * Checks (a)-(d) for a signed statement of the given kind ("receipt" or "checkpoint").
 * Returns { reasons, checks, info, cose } where info holds the decoded fields for display.
 */
function checkStatement(bytes, keys, kind) {
  const rules = RULES[kind];
  const reasons = [];
  const checks = { signature: SKIPPED, payload_jcs: SKIPPED, profile: SKIPPED, key: SKIPPED };
  const info = {};
  const fail = (check, code, detail) => {
    reasons.push(reason(code, detail));
    checks[check] = FAIL;
  };
  const pass = (check) => {
    if (checks[check] === SKIPPED) checks[check] = PASS;
  };

  let cose;
  try {
    cose = decodeCoseSign1(bytes);
  } catch (e) {
    fail('signature', 'COSE_MALFORMED', e.message);
    return { reasons, checks, info, cose: null };
  }

  const hdr = readHeader(cose, rules);
  const headerOk = checkHeader(hdr, fail);
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
      fail('profile', 'PROFILE_UNKNOWN', name === undefined ? `payload has no "profile" member (known: ${known})` : `${show(name)} (known: ${known})`);
    } else {
      info.profile = profile.name;
      const errors = profile.validate(parsed.value);
      if (errors.length) {
        fail('profile', 'PAYLOAD_SCHEMA_INVALID', errors.join('; '));
      } else if (headerOk && hdr.sub !== parsed.value[profile.subjectMember]) {
        fail('profile', 'SUBJECT_MISMATCH', `sub is ${show(hdr.sub)}, payload ${profile.subjectMember} is ${show(parsed.value[profile.subjectMember])}`);
      } else {
        checks.profile = PASS;
      }
    }
  }

  if (headerOk) {
    checkKeyAndSignature({
      hdr, keys, purpose: rules.purpose, what: `a ${kind}`, toBeSigned: sigStructure(cose.protectedBytes, cose.payload),
      signature: cose.signature, fail, pass, signatureFailCode: 'SIGNATURE_INVALID',
    });
  }
  return { reasons, checks, info, cose };
}

/** RFC 9942 vdp for RFC9162_SHA256: { -1: [ bstr .cbor [tree-size, leaf-index, inclusion-path: [ + bstr ]] ] }. */
function parseInclusionProof(vdp) {
  if (!(vdp instanceof Map)) return { error: 'vdp (396) must be a map of proofs' };
  for (const type of vdp.keys()) {
    if (type === VDP_CONSISTENCY) return { error: 'consistency proofs (vdp -2) are not supported in this version' };
    if (type !== VDP_INCLUSION) return { error: `unknown proof type ${show(type)} in vdp (396)` };
  }
  const list = vdp.get(VDP_INCLUSION);
  if (!Array.isArray(list) || list.length !== 1 || !(list[0] instanceof Uint8Array)) {
    return { error: 'vdp (396) must hold exactly one inclusion proof (-1), as a byte string' };
  }
  let proof;
  try {
    proof = decodeStrict(list[0]);
  } catch (e) {
    return { error: `inclusion proof is not strict CBOR: ${e.message}` };
  }
  if (!Array.isArray(proof) || proof.length !== 3) return { error: 'inclusion proof must be [tree-size, leaf-index, inclusion-path]' };
  const [treeSize, leafIndex, path] = proof;
  if (!Number.isSafeInteger(treeSize) || treeSize < 1) return { error: 'tree-size must be a positive integer' };
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0) return { error: 'leaf-index must be a non-negative integer' };
  if (leafIndex >= treeSize) return { error: 'leaf-index must be smaller than tree-size' };
  if (!Array.isArray(path) || !path.every((h) => h instanceof Uint8Array && h.length === 32)) {
    return { error: 'inclusion-path must be an array of 32-byte hashes' };
  }
  // RFC 9942 defines inclusion-path as [ + bstr ]: at least one hash. A tree of size 1 therefore
  // has no conformant inclusion proof, and an empty path is malformed whatever the tree size.
  if (path.length === 0) return { error: 'inclusion-path must hold at least one hash (RFC 9942: [ + bstr ])' };
  return { treeSize, leafIndex, path };
}

/**
 * (e) for the log receipt: a COSE Receipt (RFC 9942) with vds RFC9162_SHA256 whose detached payload
 * is the Merkle root computed from `entry` (the statement as signed) and the inclusion proof.
 * Returns { reasons, info, ok } with info = { log_id, tree_size, leaf_index, root_hash, ... }.
 */
function checkLogReceipt(bytes, entry, keys) {
  const reasons = [];
  const info = {};
  const checks = { key: SKIPPED, signature: SKIPPED };
  const fail = (check, code, detail) => {
    reasons.push(logReceiptReason(reason(code, detail)));
    if (check in checks) checks[check] = FAIL;
  };
  const pass = (check) => {
    if (checks[check] === SKIPPED) checks[check] = PASS;
  };

  let cose;
  try {
    cose = decodeCoseSign1(bytes, { detached: true });
  } catch (e) {
    fail('', 'COSE_MALFORMED', e.message);
    return { reasons, info, ok: false };
  }
  const hdr = readHeader(cose, RULES.logReceipt);
  const vds = cose.protectedHeader.get(HDR_VDS);
  if (vds !== VDS_RFC9162_SHA256) hdr.errors.push(`vds (395) must be ${VDS_RFC9162_SHA256} (RFC9162_SHA256), not ${show(vds)}`);
  if (isText(hdr.sub) && !LOG_ID.test(hdr.sub)) hdr.errors.push('CWT sub (2) must be a log id matching [A-Za-z0-9][A-Za-z0-9._/-]{0,127}');
  const headerOk = checkHeader(hdr, fail);

  const proof = parseInclusionProof(cose.unprotectedHeader.get(HDR_VDP));
  if (proof.error) fail('', 'INCLUSION_PROOF_MALFORMED', proof.error);
  if (!headerOk || proof.error) return { reasons, info, ok: false };

  Object.assign(info, {
    log_id: hdr.sub, tree_size: proof.treeSize, leaf_index: proof.leafIndex,
    kid: base64urlEncode(hdr.kidBytes), iat: hdr.iat, signed_at: formatUtcSeconds(hdr.iat),
  });
  const root = rootFromInclusionProof(proof.leafIndex, proof.treeSize, leafHash(entry), proof.path);
  if (root === null) {
    fail('', 'INCLUSION_PROOF_INVALID', `a path of ${proof.path.length} hashes cannot prove leaf ${proof.leafIndex} in a tree of size ${proof.treeSize}`);
  } else {
    info.root_hash = hexEncode(root);
  }
  checkKeyAndSignature({
    hdr, keys, purpose: RULES.logReceipt.purpose, what: 'a log receipt',
    toBeSigned: root === null ? null : sigStructure(cose.protectedBytes, root),
    signature: cose.signature, fail, pass, signatureFailCode: 'INCLUSION_PROOF_INVALID',
  });
  return { reasons, info, ok: allChecksPassed({ reasons, checks }) };
}

/** The receipts header (394) of a signed statement: exactly one COSE Receipt, as a byte string. */
function readReceiptsHeader(cose) {
  const receipts = cose.unprotectedHeader.get(HDR_RECEIPTS);
  if (receipts === undefined) return { none: true };
  if (!Array.isArray(receipts) || receipts.length !== 1 || !(receipts[0] instanceof Uint8Array)) {
    return { error: 'receipts (394) must be an array holding exactly one COSE Receipt as a byte string' };
  }
  return { bytes: receipts[0] };
}

function checkInclusion(st, keys, checkpointInput, details) {
  const reasons = [];
  let log = null;
  let receiptsHeader = { none: true };
  if (st.cose) {
    receiptsHeader = readReceiptsHeader(st.cose);
    if (receiptsHeader.error) {
      reasons.push(reason('INCLUSION_PROOF_MALFORMED', receiptsHeader.error));
    } else if (!receiptsHeader.none) {
      log = checkLogReceipt(receiptsHeader.bytes, logEntry(st.cose.protectedBytes, st.cose.payload, st.cose.signature), keys);
      reasons.push(...log.reasons);
      details.inclusion = { ...log.info, checkpoint: 'not given' };
      if (log.ok && st.info.iat !== undefined && st.info.iat > log.info.iat) {
        reasons.push(reason('RECEIPT_AFTER_LOG_RECEIPT', `receipt signed at ${formatUtcSeconds(st.info.iat)}, log receipt signed at ${formatUtcSeconds(log.info.iat)}`));
      }
    }
  }

  const haveCheckpoint = checkpointInput !== undefined && checkpointInput !== null;
  if (haveCheckpoint) {
    if (st.cose && receiptsHeader.none) reasons.push(reason('INCLUSION_PROOF_MISSING'));
    const read = readJson(checkpointInput);
    const cpFile = read.error ? read : parseCheckpointFile(read.doc);
    if (cpFile.error) {
      reasons.push(reason('CHECKPOINT_MALFORMED', cpFile.error));
    } else {
      const cp = checkStatement(cpFile.bytes, keys, 'checkpoint');
      details.checkpoint = { ...cp.info, checks: cp.checks };
      reasons.push(...cp.reasons.map(checkpointReason));
      // Compare only authenticated values: a verified log receipt against a verified checkpoint.
      const cpOk = allChecksPassed(cp);
      if (log && log.ok && cpOk) {
        const head = cp.info.payload;
        if (log.info.log_id !== head.log_id) {
          reasons.push(reason('CHECKPOINT_LOG_MISMATCH', `log receipt is for ${show(log.info.log_id)}, checkpoint for ${show(head.log_id)}`));
        } else if (log.info.tree_size !== head.tree_size) {
          reasons.push(reason('CHECKPOINT_TREE_SIZE_MISMATCH', `log receipt tree size ${log.info.tree_size}, checkpoint tree size ${head.tree_size}`));
        } else if (!bytesEqual(hexDecode(log.info.root_hash), hexDecode(head.root_hash))) {
          reasons.push(reason('CHECKPOINT_ROOT_MISMATCH', `tree size ${head.tree_size}: log receipt root ${log.info.root_hash}, checkpoint root ${head.root_hash}`));
        } else {
          details.inclusion.checkpoint = 'matched';
        }
      }
      if (cpOk && st.info.iat !== undefined && st.info.iat > cp.info.iat) {
        reasons.push(reason('RECEIPT_AFTER_CHECKPOINT', `receipt signed at ${formatUtcSeconds(st.info.iat)}, checkpoint signed at ${formatUtcSeconds(cp.info.iat)}`));
      }
    }
  }

  if (haveCheckpoint && details.inclusion && details.inclusion.checkpoint !== 'matched') details.inclusion.checkpoint = 'not matched';

  // (e) passes only on a verified log receipt (and, when given, a matching checkpoint). A given
  // checkpoint that could not be compared, e.g. because the receipt itself did not decode, fails it.
  let status = SKIPPED;
  if (reasons.length) status = FAIL;
  else if (log) status = PASS;
  else if (haveCheckpoint) status = FAIL;
  return { reasons, status };
}

function noKeysGiven(input) {
  return input === undefined || input === null || (typeof input === 'string' && input.trim() === '') || (input instanceof Uint8Array && input.length === 0);
}

function verifyUnsafe(receiptInput, keysInput, checkpointInput, details) {
  const reasons = [];
  const checks = { signature: SKIPPED, payload_jcs: SKIPPED, profile: SKIPPED, key: SKIPPED, inclusion: SKIPPED };
  const result = () => {
    const required = ['signature', 'payload_jcs', 'profile', 'key'].every((c) => checks[c] === PASS);
    const inclusionOk = checks.inclusion === PASS || checks.inclusion === SKIPPED;
    if (reasons.length === 0 && !(required && inclusionOk)) reasons.push(reason('INTERNAL_ERROR', 'a required check did not run'));
    return { ok: reasons.length === 0, reasons, checks, details };
  };

  // Both files are read before either error returns, so the keys used are reported either way.
  const receiptRead = readJson(receiptInput);
  const receiptFile = receiptRead.error ? receiptRead : parseReceiptFile(receiptRead.doc);
  if (receiptFile.error) reasons.push(reason('RECEIPT_MALFORMED', receiptFile.error));
  let keys;
  try {
    if (noKeysGiven(keysInput)) throw new Error('no keys file given');
    const keysRead = readJson(keysInput);
    if (keysRead.error) throw new Error(keysRead.error);
    keys = parseKeysFile(keysRead.doc);
    details.keys = { ...describeKeys(keys), sha256: keysFileSha256(keysInput) };
  } catch (e) {
    reasons.push(reason('KEYS_MALFORMED', e.message));
  }
  if (reasons.length) return result();

  const st = checkStatement(receiptFile.bytes, keys, 'receipt');
  reasons.push(...st.reasons);
  Object.assign(checks, st.checks);
  details.receipt = st.info;

  const inclusion = checkInclusion(st, keys, checkpointInput, details);
  reasons.push(...inclusion.reasons);
  checks.inclusion = inclusion.status;
  return result();
}

/**
 * Verifies a keelstamp receipt file against a keys file and, optionally, a checkpoint file.
 * Each input may be a parsed JSON value, a JSON string or UTF-8 bytes. The keys argument is the
 * only source of keys. Never throws.
 */
export function verify(receipt, keys, checkpoint) {
  const details = {};
  try {
    return verifyUnsafe(receipt, keys, checkpoint, details);
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
      details,
    };
  }
}

/**
 * Describes a keys file for display before or after verification: its SHA-256 (of the exact bytes,
 * or of the text as UTF-8), and its issuer and keys when it parses. Never throws.
 */
export function inspectKeysFile(input) {
  let sha256;
  try {
    if (noKeysGiven(input)) return { given: false };
    sha256 = keysFileSha256(input);
    const read = readJson(input);
    if (read.error) return { given: true, sha256, error: read.error };
    return { given: true, sha256, ...describeKeys(parseKeysFile(read.doc)) };
  } catch (e) {
    let error;
    try {
      error = String(e?.message ?? e);
    } catch {
      error = 'unreadable keys file';
    }
    return { given: true, sha256, error };
  }
}
