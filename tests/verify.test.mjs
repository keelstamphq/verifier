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

// POS and NEG tests for verify(), on vectors produced by the test signer with fresh keys.
// Every NEG test asserts the exact list of reason codes, so each failure has its own reason.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, test } from 'node:test';
import { LOG_RECEIPT_CODES, REASONS, inspectKeysFile, leafPosition, verify } from '../src/index.mjs';
import * as internals from '../src/verify.mjs';
import * as ts from './test-signer.mjs';

const seen = new Set();
const codes = (r) => {
  for (const x of r.reasons) seen.add(x.code);
  return r.reasons.map((x) => x.code);
};

function expectCodes(result, list) {
  assert.equal(result.ok, false, 'expected the receipt to be rejected');
  assert.deepEqual(codes(result), list);
  for (const r of result.reasons) assert.ok(r.message.length > 0);
}

const expectOnly = (result, code) => expectCodes(result, [code]);

function expectOk(result) {
  assert.deepEqual(codes(result), []);
  assert.equal(result.ok, true);
}

const utf8 = (s) => new TextEncoder().encode(s);
const clone = (v) => JSON.parse(JSON.stringify(v));
const flipHex = (h) => (h[0] === '0' ? '1' : '0') + h.slice(1);
const flipByte = (bytes, i = 0) => {
  const copy = Uint8Array.from(bytes);
  copy[i] ^= 1;
  return copy;
};

const w = ts.buildWorld();
const receiptOnly = (statement) => ts.receiptFileDoc(statement.bytes);
const statementWith = (unprotected) => ts.receiptFileDoc(ts.encodeSign1({ ...w.statement, unprotected }));
const pathOf = () => ts.inclusionPath(w.leafIndex, w.leaves);
const proofOf = () => [w.leaves.length, w.leafIndex, pathOf()];
const vdpOf = (...proofs) => new Map([[-1, proofs.map((p) => ts.cbor(p))]]);
const withLog = (opts) => w.receiptDocWith(w.signLogReceipt(opts));
const ALL_PASS = { signature: 'pass', payload_jcs: 'pass', profile: 'pass', key: 'pass', inclusion: 'pass' };

describe('POS', () => {
  test('valid receipt without checkpoint: (a)-(d) pass and its log receipt verifies', () => {
    const r = verify(w.receiptDoc, w.keys);
    expectOk(r);
    assert.deepEqual(r.checks, ALL_PASS);
    assert.equal(r.details.receipt.profile, 'keelstamp-aac-v1');
    assert.equal(r.details.receipt.kid, w.receiptKey.kid);
    assert.deepEqual(r.details.receipt.payload, w.payload);
    const inc = r.details.inclusion;
    assert.deepEqual([inc.log_id, inc.tree_size, inc.leaf_index, inc.root_hash, inc.kid, inc.checkpoint],
      [ts.TEST_LOG_ID, w.leaves.length, w.leafIndex, w.cpPayload.root_hash, w.logKey.kid, 'not given']);
  });

  test('valid receipt with checkpoint: all five checks pass and the roots match', () => {
    const r = verify(w.receiptDoc, w.keys, w.checkpointDoc);
    expectOk(r);
    assert.deepEqual(r.checks, ALL_PASS);
    assert.equal(r.details.inclusion.checkpoint, 'matched');
    assert.equal(r.details.checkpoint.payload.tree_size, w.leaves.length);
  });

  test('receipt without a log receipt and without checkpoint: (a)-(d) pass, inclusion skipped', () => {
    const r = verify(receiptOnly(w.statement), w.keys);
    expectOk(r);
    assert.equal(r.checks.inclusion, 'skipped');
  });

  test('the keys used are reported: issuer, keys and the SHA-256 of the keys file exactly as given', () => {
    const text = JSON.stringify(w.keys, null, 2);
    for (const input of [text, utf8(text)]) {
      const r = verify(w.receiptDoc, input);
      expectOk(r);
      assert.equal(r.details.keys.issuer, w.issuer);
      assert.deepEqual(r.details.keys.keys.map((k) => [k.kid, k.purpose]), [[w.receiptKey.kid, 'statement'], [w.logKey.kid, 'log'], [w.retiredKey.kid, 'statement']]);
      assert.equal(r.details.keys.sha256, createHash('sha256').update(text).digest('hex'));
    }
  });

  test('inputs may be JSON text or UTF-8 bytes', () => {
    expectOk(verify(JSON.stringify(w.receiptDoc), JSON.stringify(w.keys), JSON.stringify(w.checkpointDoc)));
    expectOk(verify(utf8(JSON.stringify(w.receiptDoc)), utf8(JSON.stringify(w.keys)), utf8(JSON.stringify(w.checkpointDoc))));
  });

  test('every leaf position in logs of size 2..17, with log receipt and checkpoint', () => {
    for (let n = 2; n <= 17; n++) {
      for (let m = 0; m < n; m++) {
        const v = ts.buildWorld({ treeSize: n, leafIndex: m });
        const r = verify(v.receiptDoc, v.keys, v.checkpointDoc);
        assert.equal(r.ok, true, `leaf ${m} of ${n}: ${JSON.stringify(r.reasons)}`);
      }
    }
  });

  test('a receipt signed inside a rotated-out key\'s window still verifies later', () => {
    const iat = w.retiredKey.validFrom + ts.DAY;
    const s = w.signReceipt({ key: w.retiredKey, iat });
    expectOk(verify(receiptOnly(s), w.keys));
  });

  test('iat equal to valid_from is inside the window (half-open interval)', () => {
    const s = w.signReceipt({ iat: w.receiptKey.validFrom });
    expectOk(verify(receiptOnly(s), w.keys));
  });
});

describe('NEG (acceptance matrix)', () => {
  test('altered payload → SIGNATURE_INVALID', () => {
    const p = { ...w.payload, digests: { ...w.payload.digests, request: ts.commitment() } };
    const forged = ts.encodeSign1({ ...w.statement, payloadBytes: utf8(ts.jcs(p)) });
    expectOnly(verify(ts.receiptFileDoc(forged), w.keys), 'SIGNATURE_INVALID');
  });

  test('altered payload with its log receipt kept: the log receipt no longer covers it either', () => {
    const p = { ...w.payload, event: 'action.rejected' };
    const forged = ts.encodeSign1({ ...w.receipt, payloadBytes: utf8(ts.jcs(p)) });
    expectCodes(verify(ts.receiptFileDoc(forged), w.keys, w.checkpointDoc), ['SIGNATURE_INVALID', 'INCLUSION_PROOF_INVALID']);
  });

  test('wrong key: the keys file lists another public key under the receipt\'s kid → KEY_MISMATCH', () => {
    const keys = clone(w.keys);
    keys.keys[0].x = ts.newKey({ validFrom: w.now }).x;
    expectOnly(verify(w.receiptDoc, keys), 'KEY_MISMATCH');
  });

  test('wrong key: signed with another key from the keys file than the kid names → WRONG_KEY', () => {
    const s = w.signReceipt({ signWith: w.retiredKey });
    expectOnly(verify(receiptOnly(s), w.keys), 'WRONG_KEY');
  });

  test('wrong key: signed with an unlisted key under a listed kid → SIGNATURE_INVALID', () => {
    const s = w.signReceipt({ signWith: ts.newKey({ validFrom: w.now }) });
    expectOnly(verify(receiptOnly(s), w.keys), 'SIGNATURE_INVALID');
  });

  test('unknown key id → KID_UNKNOWN', () => {
    const s = w.signReceipt({ key: ts.newKey({ validFrom: w.now - 30 * ts.DAY }) });
    expectOnly(verify(receiptOnly(s), w.keys), 'KID_UNKNOWN');
  });

  test('wrong inclusion path in the log receipt → INCLUSION_PROOF_INVALID (with and without checkpoint)', () => {
    const path = pathOf();
    path[1] = flipByte(path[1]);
    const doc = withLog({ proof: [w.leaves.length, w.leafIndex, path] });
    expectOnly(verify(doc, w.keys), 'INCLUSION_PROOF_INVALID');
    expectOnly(verify(doc, w.keys, w.checkpointDoc), 'INCLUSION_PROOF_INVALID');
  });

  test('wrong checkpoint: root hash changed after signing → CHECKPOINT_SIGNATURE_INVALID', () => {
    const forged = ts.encodeSign1({ ...w.checkpoint, payloadBytes: utf8(ts.jcs({ ...w.cpPayload, root_hash: flipHex(w.cpPayload.root_hash) })) });
    expectOnly(verify(w.receiptDoc, w.keys, ts.checkpointFileDoc(forged)), 'CHECKPOINT_SIGNATURE_INVALID');
  });

  test('wrong checkpoint: signed checkpoint of another log → CHECKPOINT_LOG_MISMATCH', () => {
    const logId = 'other.test.keelstamp.invalid/v1';
    const cp = w.signCheckpoint({ payload: { ...w.cpPayload, log_id: logId }, sub: logId });
    expectOnly(verify(w.receiptDoc, w.keys, ts.checkpointFileDoc(cp.bytes)), 'CHECKPOINT_LOG_MISMATCH');
  });

  test('wrong checkpoint: signed checkpoint of another tree size → CHECKPOINT_TREE_SIZE_MISMATCH', () => {
    const leaves = [...w.leaves, utf8('next entry')];
    const cp = w.signCheckpoint({ payload: ts.checkpointPayload(leaves) });
    expectOnly(verify(w.receiptDoc, w.keys, ts.checkpointFileDoc(cp.bytes)), 'CHECKPOINT_TREE_SIZE_MISMATCH');
  });

  test('wrong checkpoint: the log signed a different root for the same tree size → CHECKPOINT_ROOT_MISMATCH', () => {
    const leaves = w.leaves.map((l, i) => (i === 0 ? utf8('different entry') : l));
    const cp = w.signCheckpoint({ payload: ts.checkpointPayload(leaves) });
    expectOnly(verify(w.receiptDoc, w.keys, ts.checkpointFileDoc(cp.bytes)), 'CHECKPOINT_ROOT_MISMATCH');
  });

  test('unknown profile version → PROFILE_UNKNOWN', () => {
    const s = w.signReceipt({ payload: { ...w.payload, profile: 'keelstamp-aac-v2' } });
    expectOnly(verify(receiptOnly(s), w.keys), 'PROFILE_UNKNOWN');
  });
});

describe('NEG: keys never come from the receipt', () => {
  test('no keys file → KEYS_MALFORMED, even for an otherwise valid receipt', () => {
    for (const keys of [undefined, null, '', '  \n', new Uint8Array(0)]) {
      const r = verify(w.receiptDoc, keys);
      expectOnly(r, 'KEYS_MALFORMED');
      assert.match(r.reasons[0].message, /\(no keys file given\)$/);
    }
  });

  test('a keys file embedded in the receipt file is rejected, never used → RECEIPT_MALFORMED', () => {
    expectOnly(verify({ ...w.receiptDoc, keys: w.keys }, w.keys), 'RECEIPT_MALFORMED');
    expectCodes(verify({ ...w.receiptDoc, keys: w.keys }, undefined), ['RECEIPT_MALFORMED', 'KEYS_MALFORMED']);
  });

  test('a COSE_Key in the statement\'s unprotected header → COSE_HEADER_INVALID', () => {
    const coseKey = new Map([[1, 1], [-1, 6], [-2, Buffer.from(w.receiptKey.x, 'base64url')]]);
    const doc = ts.receiptFileDoc(ts.withReceipts(w.statement, [w.logReceipt], [['cose_key', coseKey]]).bytes);
    expectOnly(verify(doc, w.keys), 'COSE_HEADER_INVALID');
  });

  test('a certificate chain (x5chain, 33) in the statement\'s protected header → COSE_HEADER_INVALID', () => {
    const h = ts.protectedHeader({ kidBytes: w.receiptKey.kidBytes, iss: w.issuer, sub: w.payload.receipt_id, iat: w.iat });
    h.set(33, utf8('certificate'));
    expectOnly(verify(receiptOnly(w.signReceipt({ header: h })), w.keys), 'COSE_HEADER_INVALID');
  });

  test('key material in the log receipt\'s unprotected header → LOG_RECEIPT_COSE_HEADER_INVALID', () => {
    const unprotected = new Map([[ts.HDR_VDP, vdpOf(proofOf())], [33, utf8('certificate')]]);
    expectOnly(verify(withLog({ unprotected }), w.keys), 'LOG_RECEIPT_COSE_HEADER_INVALID');
  });
});

describe('NEG: COSE structure and header', () => {
  const sign1 = (over) => ts.receiptFileDoc(ts.encodeSign1({ ...w.statement, ...over }));
  const header = (over = {}) => ts.protectedHeader({ kidBytes: w.receiptKey.kidBytes, iss: w.issuer, sub: w.payload.receipt_id, iat: w.iat, ...over });

  test('untagged COSE_Sign1 → COSE_MALFORMED', () => expectOnly(verify(sign1({ tag: null }), w.keys), 'COSE_MALFORMED'));
  test('COSE_Sign tag 98 instead of 18 → COSE_MALFORMED', () => expectOnly(verify(sign1({ tag: 98 }), w.keys), 'COSE_MALFORMED'));
  test('detached payload → COSE_MALFORMED', () => expectOnly(verify(sign1({ payloadBytes: null }), w.keys), 'COSE_MALFORMED'));
  test('trailing byte after the structure → COSE_MALFORMED', () => {
    const bytes = Uint8Array.from([...w.receipt.bytes, 0]);
    expectOnly(verify(ts.receiptFileDoc(bytes), w.keys), 'COSE_MALFORMED');
  });
  test('random bytes → COSE_MALFORMED', () => expectOnly(verify(ts.receiptFileDoc(utf8('not cbor at all')), w.keys), 'COSE_MALFORMED'));
  test('non-minimal integer in the protected header → COSE_MALFORMED', () => {
    // {1: -19} with -19 written in two bytes (0x38 0x12) instead of one (0x32)
    const s = w.signReceipt({ header: Uint8Array.of(0xa1, 0x01, 0x38, 0x12) });
    expectOnly(verify(receiptOnly(s), w.keys), 'COSE_MALFORMED');
  });
  test('duplicate label in the protected header → COSE_MALFORMED', () => {
    const s = w.signReceipt({ header: Uint8Array.of(0xa2, 0x01, 0x32, 0x01, 0x32) });
    expectOnly(verify(receiptOnly(s), w.keys), 'COSE_MALFORMED');
  });
  test('unprotected header with a label other than 394 (a kid) → COSE_HEADER_INVALID', () => {
    expectOnly(verify(sign1({ unprotected: new Map([[4, w.receiptKey.kidBytes]]) }), w.keys), 'COSE_HEADER_INVALID');
  });
  test('crit header parameter → COSE_HEADER_INVALID', () => {
    const h = header();
    h.set(2, [99]);
    expectOnly(verify(receiptOnly(w.signReceipt({ header: h })), w.keys), 'COSE_HEADER_INVALID');
  });
  test('missing kid → COSE_HEADER_INVALID', () => {
    const h = header();
    h.delete(4);
    expectOnly(verify(receiptOnly(w.signReceipt({ header: h })), w.keys), 'COSE_HEADER_INVALID');
  });
  test('content type other than application/json → COSE_HEADER_INVALID', () => {
    expectOnly(verify(receiptOnly(w.signReceipt({ header: header({ contentType: 'text/plain' }) })), w.keys), 'COSE_HEADER_INVALID');
  });
  test('missing, negative or textual iat → COSE_HEADER_INVALID', () => {
    for (const iat of [undefined, -1, 'yesterday']) {
      const h = header();
      if (iat === undefined) h.get(15).delete(6);
      else h.get(15).set(6, iat);
      expectOnly(verify(receiptOnly(w.signReceipt({ header: h })), w.keys), 'COSE_HEADER_INVALID');
    }
  });
  test('extra CWT claim → COSE_HEADER_INVALID', () => {
    const h = header();
    h.get(15).set(4, w.iat + ts.DAY); // exp
    expectOnly(verify(receiptOnly(w.signReceipt({ header: h })), w.keys), 'COSE_HEADER_INVALID');
  });
  test('float instead of integer: alg value -19.0, label 1.0 or iat → COSE_MALFORMED', () => {
    const half = (bytes) => new ts.Raw(bytes);
    const iatDouble = Buffer.alloc(9);
    iatDouble[0] = 0xfb;
    iatDouble.writeDoubleBE(w.iat, 1);
    const claims = new Map([[1, w.issuer], [2, w.payload.receipt_id], [6, w.iat]]);
    const variants = [
      new Map([[1, half([0xf9, 0xcc, 0xc0])], [3, 'application/json'], [4, w.receiptKey.kidBytes], [15, claims]]),
      new Map([[half([0xf9, 0x3c, 0x00]), -19], [3, 'application/json'], [4, w.receiptKey.kidBytes], [15, claims]]),
      new Map([[1, -19], [3, 'application/json'], [4, w.receiptKey.kidBytes], [15, new Map([[1, w.issuer], [2, w.payload.receipt_id], [6, new ts.Raw(iatDouble)]])]]),
    ];
    for (const h of variants) expectOnly(verify(receiptOnly(w.signReceipt({ header: h })), w.keys), 'COSE_MALFORMED');
  });
  test('header text that does not decode byte-exactly (BOM prefix, invalid UTF-8) → COSE_MALFORMED', () => {
    expectOnly(verify(receiptOnly(w.signReceipt({ iss: `\ufeff${w.issuer}` })), w.keys), 'COSE_MALFORMED');
    const h = header();
    h.get(15).set(1, new ts.Raw([0x62, 0xff, 0xfe]));
    expectOnly(verify(receiptOnly(w.signReceipt({ header: h })), w.keys), 'COSE_MALFORMED');
  });
  test('alg EdDSA (-8) → ALG_UNSUPPORTED', () => expectOnly(verify(receiptOnly(w.signReceipt({ alg: -8 })), w.keys), 'ALG_UNSUPPORTED'));
  test('alg ES256 (-7) → ALG_UNSUPPORTED', () => expectOnly(verify(receiptOnly(w.signReceipt({ alg: -7 })), w.keys), 'ALG_UNSUPPORTED'));
  test('truncated signature → SIGNATURE_INVALID', () => {
    expectOnly(verify(sign1({ signature: w.statement.signature.subarray(0, 63) }), w.keys), 'SIGNATURE_INVALID');
  });
});

describe('NEG: payload', () => {
  test('signed payload with whitespace → PAYLOAD_NOT_JCS', () => {
    const s = w.signReceipt({ payload: JSON.stringify(w.payload, null, 1) });
    expectOnly(verify(receiptOnly(s), w.keys), 'PAYLOAD_NOT_JCS');
  });
  test('signed payload with unsorted members → PAYLOAD_NOT_JCS', () => {
    const { profile, ...rest } = w.payload;
    const s = w.signReceipt({ payload: JSON.stringify({ ...rest, profile }) });
    expectOnly(verify(receiptOnly(s), w.keys), 'PAYLOAD_NOT_JCS');
  });
  test('signed payload that is not JSON → PAYLOAD_NOT_JCS', () => {
    expectOnly(verify(receiptOnly(w.signReceipt({ payload: 'approved' })), w.keys), 'PAYLOAD_NOT_JCS');
  });
  test('payload without a profile member → PROFILE_UNKNOWN', () => {
    const { profile, ...rest } = w.payload;
    expectOnly(verify(receiptOnly(w.signReceipt({ payload: rest })), w.keys), 'PROFILE_UNKNOWN');
  });
  test('a checkpoint profile inside a receipt → PROFILE_UNKNOWN', () => {
    expectOnly(verify(receiptOnly(w.signReceipt({ payload: { ...w.cpPayload, receipt_id: w.payload.receipt_id } })), w.keys), 'PROFILE_UNKNOWN');
  });
  test('extra plaintext member → PAYLOAD_SCHEMA_INVALID', () => {
    expectOnly(verify(receiptOnly(w.signReceipt({ payload: { ...w.payload, note: 'call Jane at 12' } })), w.keys), 'PAYLOAD_SCHEMA_INVALID');
  });
  test('plaintext instead of a commitment → PAYLOAD_SCHEMA_INVALID', () => {
    expectOnly(verify(receiptOnly(w.signReceipt({ payload: { ...w.payload, tenant: 'Example ApS' } })), w.keys), 'PAYLOAD_SCHEMA_INVALID');
  });
  test('empty digests → PAYLOAD_SCHEMA_INVALID', () => {
    expectOnly(verify(receiptOnly(w.signReceipt({ payload: { ...w.payload, digests: {} } })), w.keys), 'PAYLOAD_SCHEMA_INVALID');
  });
  test('CWT sub differs from receipt_id → SUBJECT_MISMATCH', () => {
    expectOnly(verify(receiptOnly(w.signReceipt({ sub: 'another-receipt-id-0001' })), w.keys), 'SUBJECT_MISMATCH');
  });
});

describe('NEG: key validity', () => {
  test('signed before valid_from → KEY_NOT_VALID_AT_TIME', () => {
    const s = w.signReceipt({ iat: w.receiptKey.validFrom - 1 });
    expectOnly(verify(receiptOnly(s), w.keys), 'KEY_NOT_VALID_AT_TIME');
  });
  test('signed at valid_until with a rotated-out key → KEY_NOT_VALID_AT_TIME', () => {
    const s = w.signReceipt({ key: w.retiredKey, iat: w.retiredKey.validUntil });
    expectOnly(verify(receiptOnly(s), w.keys), 'KEY_NOT_VALID_AT_TIME');
  });
  test('iat beyond the Date range is still judged, not an internal error → KEY_NOT_VALID_AT_TIME', () => {
    const s = w.signReceipt({ key: w.retiredKey, iat: 9e12 });
    expectOnly(verify(receiptOnly(s), w.keys), 'KEY_NOT_VALID_AT_TIME');
  });
  test('receipt signed with the log key → KEY_PURPOSE_MISMATCH', () => {
    expectOnly(verify(receiptOnly(w.signReceipt({ key: w.logKey })), w.keys), 'KEY_PURPOSE_MISMATCH');
  });
  test('iss differs from the keys file issuer → ISSUER_MISMATCH', () => {
    expectOnly(verify(receiptOnly(w.signReceipt({ iss: 'someone-else.invalid' })), w.keys), 'ISSUER_MISMATCH');
  });
  for (const [name, mutate] of [
    ['wrong format', (k) => { k.format = 'keelstamp-keys-v0'; }],
    ['unknown member', (k) => { k.extra = true; }],
    ['missing issuer', (k) => { delete k.issuer; }],
    ['duplicate kid', (k) => { k.keys.push(k.keys[0]); }],
    ['x of 31 bytes', (k) => { k.keys[0].x = k.keys[0].x.slice(0, 42); }],
    ['x padded', (k) => { k.keys[0].x += '='; }],
    ['x is a small-order point', (k) => { k.keys[0].x = ts.b64url(new Uint8Array(32)); }],
    ['kty RSA', (k) => { k.keys[0].kty = 'RSA'; }],
    ['unknown purpose', (k) => { k.keys[0].purpose = 'anything'; }],
    ['old purpose name "receipt"', (k) => { k.keys[0].purpose = 'receipt'; }],
    ['valid_from not RFC 3339 UTC', (k) => { k.keys[0].valid_from = k.keys[0].valid_from.replace('Z', '+00:00'); }],
    ['valid_from on a day that does not exist', (k) => { k.keys[0].valid_from = k.keys[0].valid_from.replace(/^(\d{4})-\d\d-\d\d/, '$1-02-31'); }],
    ['valid_until before valid_from', (k) => { k.keys[0].valid_until = k.keys[2].valid_from; }],
    ['private key member present', (k) => { k.keys[0].d = 'AAAA'; }],
    ['valid_until member missing (must not read as open-ended)', (k) => { delete k.keys[2].valid_until; }],
  ]) {
    test(`keys file: ${name} → KEYS_MALFORMED`, () => {
      const keys = clone(w.keys);
      mutate(keys);
      expectOnly(verify(w.receiptDoc, keys), 'KEYS_MALFORMED');
    });
  }
  test('keys file that is not JSON → KEYS_MALFORMED', () => expectOnly(verify(w.receiptDoc, '{"keys":'), 'KEYS_MALFORMED'));
});

describe('NEG: log receipt (COSE Receipt, RFC 9942)', () => {
  test('signed by an unknown log key → LOG_RECEIPT_KID_UNKNOWN', () => {
    expectOnly(verify(withLog({ key: ts.newKey({ purpose: 'log', validFrom: w.now - 30 * ts.DAY }) }), w.keys), 'LOG_RECEIPT_KID_UNKNOWN');
  });
  test('the keys file lists another public key under the log key\'s kid → LOG_RECEIPT_KEY_MISMATCH', () => {
    const keys = clone(w.keys);
    keys.keys[1].x = ts.newKey({ validFrom: w.now }).x;
    expectOnly(verify(w.receiptDoc, keys), 'LOG_RECEIPT_KEY_MISMATCH');
  });
  test('signed with the statement key → LOG_RECEIPT_KEY_PURPOSE_MISMATCH', () => {
    expectOnly(verify(withLog({ key: w.receiptKey }), w.keys), 'LOG_RECEIPT_KEY_PURPOSE_MISMATCH');
  });
  test('signed by another listed key than its kid names → LOG_RECEIPT_WRONG_KEY', () => {
    expectOnly(verify(withLog({ signWith: w.receiptKey }), w.keys), 'LOG_RECEIPT_WRONG_KEY');
  });
  test('iss differs from the keys file issuer → LOG_RECEIPT_ISSUER_MISMATCH', () => {
    expectOnly(verify(withLog({ iss: 'someone-else.invalid' }), w.keys), 'LOG_RECEIPT_ISSUER_MISMATCH');
  });
  test('log key not valid at the log receipt\'s iat → LOG_RECEIPT_KEY_NOT_VALID_AT_TIME', () => {
    expectOnly(verify(withLog({ iat: w.logKey.validFrom - 1 }), w.keys), 'LOG_RECEIPT_KEY_NOT_VALID_AT_TIME');
  });
  test('alg EdDSA (-8) → LOG_RECEIPT_ALG_UNSUPPORTED', () => {
    expectOnly(verify(withLog({ alg: -8 }), w.keys), 'LOG_RECEIPT_ALG_UNSUPPORTED');
  });
  for (const [name, opts] of [
    ['vds 2 instead of 1 (RFC9162_SHA256)', { vds: 2 }],
    ['sub that is not a log id', { sub: 'not a log id' }],
    ['content type in the protected header', { header: new Map([[1, -19], [3, 'application/json'], [4, w.logKey.kidBytes], [15, new Map([[1, w.issuer], [2, ts.TEST_LOG_ID], [6, w.logReceiptIat]])], [ts.HDR_VDS, 1]]) }],
    ['vds missing', { header: new Map([[1, -19], [4, w.logKey.kidBytes], [15, new Map([[1, w.issuer], [2, ts.TEST_LOG_ID], [6, w.logReceiptIat]])]]) }],
  ]) {
    test(`header: ${name} → LOG_RECEIPT_COSE_HEADER_INVALID`, () => expectOnly(verify(withLog(opts), w.keys), 'LOG_RECEIPT_COSE_HEADER_INVALID'));
  }
  test('attached payload (the root must be detached) → LOG_RECEIPT_COSE_MALFORMED', () => {
    expectOnly(verify(withLog({ attach: true }), w.keys), 'LOG_RECEIPT_COSE_MALFORMED');
  });
  test('untagged log receipt → LOG_RECEIPT_COSE_MALFORMED', () => {
    expectOnly(verify(w.receiptDocWith(ts.encodeSign1({ ...w.logReceipt, tag: null })), w.keys), 'LOG_RECEIPT_COSE_MALFORMED');
  });
  test('log receipt signature altered → INCLUSION_PROOF_INVALID', () => {
    expectOnly(verify(w.receiptDocWith(ts.encodeSign1({ ...w.logReceipt, signature: flipByte(w.logReceipt.signature) })), w.keys), 'INCLUSION_PROOF_INVALID');
  });
  test('the log signed another root (a tree without this receipt) → INCLUSION_PROOF_INVALID', () => {
    expectOnly(verify(withLog({ root: new Uint8Array(32) }), w.keys), 'INCLUSION_PROOF_INVALID');
  });
  test('wrong leaf-index → INCLUSION_PROOF_INVALID', () => {
    expectOnly(verify(withLog({ proof: [w.leaves.length, w.leafIndex - 1, pathOf()] }), w.keys), 'INCLUSION_PROOF_INVALID');
  });
  test('path one element short → INCLUSION_PROOF_INVALID', () => {
    expectOnly(verify(withLog({ proof: [w.leaves.length, w.leafIndex, pathOf().slice(0, -1)] }), w.keys), 'INCLUSION_PROOF_INVALID');
  });
  test('tree-size larger than the tree the path belongs to → INCLUSION_PROOF_INVALID', () => {
    expectOnly(verify(withLog({ proof: [w.leaves.length + 9, w.leafIndex, pathOf()] }), w.keys), 'INCLUSION_PROOF_INVALID');
  });
  test('receipt signed after the log receipt that includes it → RECEIPT_AFTER_LOG_RECEIPT', () => {
    const v = ts.buildWorld({ logReceiptIat: w.now - 2 * ts.DAY });
    expectOnly(verify(v.receiptDoc, v.keys), 'RECEIPT_AFTER_LOG_RECEIPT');
  });
  for (const [name, doc] of [
    ['receipts header (394) is not an array', statementWith(new Map([[394, w.logReceipt.bytes]]))],
    ['receipts header (394) is empty', statementWith(new Map([[394, []]]))],
    ['two log receipts', w.receiptDocWith(w.logReceipt, w.logReceipt)],
    ['log receipt embedded as a structure, not a byte string', statementWith(new Map([[394, [new ts.Raw(w.logReceipt.bytes)]]]))],
    ['no vdp (396)', withLog({ unprotected: new Map() })],
    ['a consistency proof (vdp -2) is present', withLog({ vdp: new Map([[-1, [ts.cbor(proofOf())]], [-2, [ts.cbor([1, 2, []])]]]) })],
    ['two inclusion proofs', withLog({ vdp: vdpOf(proofOf(), proofOf()) })],
    ['inclusion proof not wrapped in a byte string', withLog({ vdp: new Map([[-1, [proofOf()]]]) })],
    ['inclusion proof bytes are not CBOR', withLog({ vdp: new Map([[-1, [utf8('garbage')]]]) })],
    ['inclusion proof with a fourth element', withLog({ proof: [...proofOf(), 0] })],
    ['leaf-index equal to tree-size', withLog({ proof: [w.leaves.length, w.leaves.length, pathOf()] })],
    ['negative leaf-index', withLog({ proof: [w.leaves.length, -1, pathOf()] })],
    ['tree-size zero', withLog({ proof: [0, 0, []] })],
    ['path element of 31 bytes', withLog({ proof: [w.leaves.length, w.leafIndex, [pathOf()[0].subarray(0, 31), ...pathOf().slice(1)]] })],
    ['empty inclusion-path (RFC 9942: [ + bstr ])', withLog({ proof: [w.leaves.length, w.leafIndex, []] })],
  ]) {
    test(`${name} → INCLUSION_PROOF_MALFORMED (with or without a checkpoint)`, () => {
      expectOnly(verify(doc, w.keys), 'INCLUSION_PROOF_MALFORMED');
      expectOnly(verify(doc, w.keys, w.checkpointDoc), 'INCLUSION_PROOF_MALFORMED');
    });
  }
  test('a log of one entry has no conformant inclusion proof (empty path) → INCLUSION_PROOF_MALFORMED', () => {
    const v = ts.buildWorld({ treeSize: 1, leafIndex: 0 });
    for (const r of [verify(v.receiptDoc, v.keys), verify(v.receiptDoc, v.keys, v.checkpointDoc)]) {
      expectOnly(r, 'INCLUSION_PROOF_MALFORMED');
      assert.match(r.reasons[0].message, /inclusion-path must hold at least one hash/);
    }
  });
  test('checkpoint given but the receipt has no log receipt → INCLUSION_PROOF_MISSING', () => {
    expectOnly(verify(receiptOnly(w.statement), w.keys, w.checkpointDoc), 'INCLUSION_PROOF_MISSING');
  });
  test('receipt claims a signing time after the checkpoint → RECEIPT_AFTER_CHECKPOINT', () => {
    const now = Math.floor(Date.now() / 1000);
    const v = ts.buildWorld({ now, receiptIat: now + 60 });
    expectOnly(verify(v.receiptDoc, v.keys, v.checkpointDoc), 'RECEIPT_AFTER_CHECKPOINT');
  });
});

describe('NEG: receipt file', () => {
  for (const [name, doc] of [
    ['not JSON', '{"format":'],
    ['an array', '[]'],
    ['wrong format', { ...w.receiptDoc, format: 'keelstamp-receipt-file-v0' }],
    ['unknown member', { ...w.receiptDoc, note: 'x' }],
    ['the old JSON inclusion_proof member', { ...w.receiptDoc, inclusion_proof: {} }],
    ['padded base64url', { ...w.receiptDoc, receipt: `${w.receiptDoc.receipt}=` }],
    ['standard base64 alphabet', { ...w.receiptDoc, receipt: `${w.receiptDoc.receipt.slice(0, -4)}+/+/` }],
    ['empty receipt', { ...w.receiptDoc, receipt: '' }],
  ]) {
    test(`receipt file: ${name} → RECEIPT_MALFORMED`, () => expectOnly(verify(doc, w.keys), 'RECEIPT_MALFORMED'));
  }
  test('duplicate member names in any input file → *_MALFORMED', () => {
    const text = (doc) => JSON.stringify(doc);
    const dup = (doc, name, value) => `${text(doc).slice(0, -1)},${JSON.stringify(name)}:${JSON.stringify(value)}}`;
    const forged = ts.encodeSign1({ ...w.statement, payloadBytes: utf8(ts.jcs({ ...w.payload, event: 'action.rejected' })) });
    expectOnly(verify(dup(w.receiptDoc, 'receipt', ts.b64url(forged)), w.keys), 'RECEIPT_MALFORMED');
    expectOnly(verify(dup(w.receiptDoc, 'r\\u0065ceipt', w.receiptDoc.receipt).replace('r\\\\u0065ceipt', 'r\\u0065ceipt'), w.keys), 'RECEIPT_MALFORMED');
    const nested = text(w.keys).replace('"purpose":', '"purpose":"log","purpose":');
    expectOnly(verify(w.receiptDoc, nested), 'KEYS_MALFORMED');
    expectOnly(verify(w.receiptDoc, dup(w.keys, 'keys', [])), 'KEYS_MALFORMED');
    expectOnly(verify(w.receiptDoc, w.keys, dup(w.checkpointDoc, 'checkpoint', w.checkpointDoc.checkpoint)), 'CHECKPOINT_MALFORMED');
    expectOnly(verify(utf8(dup(w.receiptDoc, 'format', 'x')), w.keys), 'RECEIPT_MALFORMED');
  });
});

describe('NEG: checkpoint file', () => {
  test('checkpoint file that is not JSON → CHECKPOINT_MALFORMED', () => expectOnly(verify(w.receiptDoc, w.keys, '{'), 'CHECKPOINT_MALFORMED'));
  test('checkpoint file with the wrong format → CHECKPOINT_MALFORMED', () => {
    expectOnly(verify(w.receiptDoc, w.keys, { ...w.checkpointDoc, format: 'x' }), 'CHECKPOINT_MALFORMED');
  });
  test('checkpoint signed with a statement key → CHECKPOINT_KEY_PURPOSE_MISMATCH', () => {
    const cp = w.signCheckpoint({ key: w.receiptKey });
    expectOnly(verify(w.receiptDoc, w.keys, ts.checkpointFileDoc(cp.bytes)), 'CHECKPOINT_KEY_PURPOSE_MISMATCH');
  });
  test('a receipt passed as the checkpoint → CHECKPOINT_PROFILE_UNKNOWN + CHECKPOINT_KEY_PURPOSE_MISMATCH', () => {
    expectCodes(verify(w.receiptDoc, w.keys, ts.checkpointFileDoc(w.statement.bytes)), ['CHECKPOINT_PROFILE_UNKNOWN', 'CHECKPOINT_KEY_PURPOSE_MISMATCH']);
  });
  test('checkpoint with an unprotected header → CHECKPOINT_COSE_HEADER_INVALID', () => {
    const cp = ts.encodeSign1({ ...w.checkpoint, unprotected: new Map([[394, [w.logReceipt.bytes]]]) });
    expectOnly(verify(w.receiptDoc, w.keys, ts.checkpointFileDoc(cp)), 'CHECKPOINT_COSE_HEADER_INVALID');
  });
  test('checkpoint from an unknown key → CHECKPOINT_KID_UNKNOWN', () => {
    const cp = w.signCheckpoint({ key: ts.newKey({ purpose: 'log', validFrom: w.now - ts.DAY }) });
    expectOnly(verify(w.receiptDoc, w.keys, ts.checkpointFileDoc(cp.bytes)), 'CHECKPOINT_KID_UNKNOWN');
  });
});

describe('NEG: second review (bounded messages, (e) status, reporting order)', () => {
  // An array nested a few thousand deep: decodes as a label, and must never be stringified whole.
  const deep = Uint8Array.from([...new Array(4000).fill(0x81), 0x01]);
  for (const [name, doc, codesAllowed] of [
    ['deeply nested label in the statement\'s unprotected header', statementWith(new Map([[new ts.Raw(deep), 1]])), [['COSE_HEADER_INVALID'], ['COSE_MALFORMED']]],
    ['1 MB byte-string label in the statement\'s unprotected header', statementWith(new Map([[new Uint8Array(1 << 20), 1]])), [['COSE_HEADER_INVALID']]],
    ['deeply nested proof type in vdp', withLog({ vdp: new Map([[new ts.Raw(deep), []]]) }), [['INCLUSION_PROOF_MALFORMED'], ['LOG_RECEIPT_COSE_MALFORMED']]],
    ['deeply nested label in the log receipt\'s unprotected header', withLog({ unprotected: new Map([[ts.HDR_VDP, vdpOf(proofOf())], [new ts.Raw(deep), 1]]) }), [['LOG_RECEIPT_COSE_HEADER_INVALID'], ['LOG_RECEIPT_COSE_MALFORMED']]],
  ]) {
    test(`${name}: a short reason, never INTERNAL_ERROR, keys still reported`, () => {
      const r = verify(doc, w.keys);
      assert.equal(r.ok, false);
      const got = codes(r);
      assert.ok(codesAllowed.some((c) => JSON.stringify(c) === JSON.stringify(got)), `codes ${JSON.stringify(got)}`);
      for (const x of r.reasons) assert.ok(x.message.length < 1000, `message of ${x.message.length} characters`);
      assert.equal(r.details.keys.issuer, w.issuer);
    });
  }
  test('details.inclusion.checkpoint says "not matched" when a given checkpoint does not match', () => {
    const leaves = w.leaves.map((l, i) => (i === 0 ? utf8('different entry') : l));
    const other = ts.checkpointFileDoc(w.signCheckpoint({ payload: ts.checkpointPayload(leaves) }).bytes);
    const tampered = ts.checkpointFileDoc(ts.encodeSign1({ ...w.checkpoint, payloadBytes: utf8(ts.jcs({ ...w.cpPayload, root_hash: flipHex(w.cpPayload.root_hash) })) }));
    for (const cp of [other, tampered, '{']) assert.equal(verify(w.receiptDoc, w.keys, cp).details.inclusion.checkpoint, 'not matched');
    assert.equal(verify(w.receiptDoc, w.keys).details.inclusion.checkpoint, 'not given');
    assert.equal(verify(w.receiptDoc, w.keys, w.checkpointDoc).details.inclusion.checkpoint, 'matched');
  });
  test('a checkpoint was given but the receipt does not decode: (e) fails, it is not skipped', () => {
    const r = verify(ts.receiptFileDoc(utf8('not cbor at all')), w.keys, w.checkpointDoc);
    expectOnly(r, 'COSE_MALFORMED');
    assert.equal(r.checks.inclusion, 'fail');
  });
  test('no log receipt and a malformed checkpoint file: both are reported', () => {
    expectCodes(verify(receiptOnly(w.statement), w.keys, '{'), ['INCLUSION_PROOF_MISSING', 'CHECKPOINT_MALFORMED']);
  });
  test('the keys used are reported even when the receipt file is malformed', () => {
    const r = verify('[]', JSON.stringify(w.keys));
    expectOnly(r, 'RECEIPT_MALFORMED');
    assert.equal(r.details.keys.issuer, w.issuer);
    assert.equal(r.details.keys.keys.length, 3);
  });
  test('inspectKeysFile never throws, even for an input that throws when read', () => {
    const hostile = new Proxy(new Uint8Array(4), { get() { throw new Error('boom'); } });
    let out;
    assert.doesNotThrow(() => { out = inspectKeysFile(hostile); });
    assert.equal(out.given, true);
    assert.ok(out.error.length > 0);
  });
});

describe('unsigned values of the inclusion proof (leaf index, tree size)', () => {
  // The log signs only the root. The same path for leaf 5 of 7 also yields that root as leaf 5 of 8,
  // so a forwarder can change the tree size in the unprotected vdp without breaking anything.
  const resized = (treeSize, leafIndex = w.leafIndex) => {
    const unprotected = new Map([[ts.HDR_VDP, new Map([[-1, [ts.cbor([treeSize, leafIndex, pathOf()])]]])]]);
    return w.receiptDocWith(ts.encodeSign1({ ...w.logReceipt, unprotected }));
  };

  test('tree-size changed from 7 to 8 after signing: inclusion still verifies, the size is reported as unconfirmed', () => {
    const r = verify(resized(8), w.keys);
    expectOk(r);
    assert.equal(r.details.inclusion.tree_size, 8);
    assert.equal(r.details.inclusion.root_hash, w.cpPayload.root_hash, 'the signed root is unchanged');
    assert.equal(r.details.inclusion.checkpoint, 'not given');
    assert.match(leafPosition(r.details.inclusion), /^leaf 5 of 8 \(not signed: from the inclusion proof, informational only\)$/);
  });

  test('with the genuine checkpoint the changed tree-size is caught → CHECKPOINT_TREE_SIZE_MISMATCH', () => {
    const r = verify(resized(8), w.keys, w.checkpointDoc);
    expectOnly(r, 'CHECKPOINT_TREE_SIZE_MISMATCH');
    assert.equal(r.details.inclusion.checkpoint, 'not matched');
  });

  test('a matching checkpoint confirms leaf index and tree size', () => {
    const r = verify(w.receiptDoc, w.keys, w.checkpointDoc);
    expectOk(r);
    assert.equal(leafPosition(r.details.inclusion), 'leaf 5 of 7 (tree size confirmed by the checkpoint)');
  });
});

describe('fail-closed', () => {
  test('a checkpoint or log receipt counts as verified only when every check passed, not merely when no reason was recorded', () => {
    const { allChecksPassed } = internals;
    assert.equal(typeof allChecksPassed, 'function');
    const all = { signature: 'pass', payload_jcs: 'pass', profile: 'pass', key: 'pass' };
    assert.equal(allChecksPassed({ reasons: [], checks: all }), true);
    // A check that never ran leaves no reason behind; it must still block the verdict.
    for (const check of Object.keys(all)) {
      assert.equal(allChecksPassed({ reasons: [], checks: { ...all, [check]: 'skipped' } }), false, `${check} skipped`);
    }
    assert.equal(allChecksPassed({ reasons: [], checks: {} }), false, 'no checks at all');
    assert.equal(allChecksPassed({ reasons: [{ code: 'X' }], checks: all }), false);
  });
  test('hostile or missing inputs never throw and never pass', () => {
    for (const input of [undefined, null, 0, true, [], {}, 'null', new Uint8Array([0xff, 0xfe])]) {
      const r = verify(input, w.keys);
      assert.equal(r.ok, false);
      assert.ok(r.reasons.length > 0);
      assert.equal(verify(w.receiptDoc, input).ok, false);
    }
  });
  test('an exception inside the verifier becomes INTERNAL_ERROR, not a pass', () => {
    const hostile = { get format() { throw new Error('boom'); } };
    expectOnly(verify(hostile, w.keys), 'INTERNAL_ERROR');
    // thrown values whose message cannot be read or printed
    const throwing = (value) => ({ get format() { throw value; } });
    expectOnly(verify(throwing({ get message() { throw new Error('x'); } }), w.keys), 'INTERNAL_ERROR');
    expectOnly(verify(throwing(Object.create(null)), w.keys), 'INTERNAL_ERROR');
    expectOnly(verify(throwing({ message: Object.create(null) }), w.keys), 'INTERNAL_ERROR');
  });
});

test('every reason code, and every log receipt variant, is produced by at least one test above', () => {
  const missing = Object.keys(REASONS).filter((c) => !seen.has(c));
  const missingLog = LOG_RECEIPT_CODES.map((c) => `LOG_RECEIPT_${c}`).filter((c) => !seen.has(c));
  assert.deepEqual([...missing, ...missingLog], []);
});
