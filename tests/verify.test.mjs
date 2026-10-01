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
import { describe, test } from 'node:test';
import { REASONS, verify } from '../src/index.mjs';
import * as ts from './test-signer.mjs';

const seen = new Set();
const codes = (r) => {
  for (const x of r.reasons) seen.add(x.code);
  return r.reasons.map((x) => x.code);
};

function expectOnly(result, code) {
  assert.equal(result.ok, false, 'expected the receipt to be rejected');
  assert.deepEqual(codes(result), [code]);
  for (const r of result.reasons) assert.ok(r.message.length > 0);
}

function expectOk(result) {
  assert.deepEqual(codes(result), []);
  assert.equal(result.ok, true);
}

const utf8 = (s) => new TextEncoder().encode(s);
const clone = (v) => JSON.parse(JSON.stringify(v));
const flipHex = (h) => (h[0] === '0' ? '1' : '0') + h.slice(1);

const w = ts.buildWorld();
const receiptOnly = (statement, proof) => ts.receiptFileDoc(statement.bytes, proof);

describe('POS', () => {
  test('valid receipt without checkpoint: (a)-(d) pass, inclusion skipped', () => {
    const r = verify(w.receiptDoc, w.keys);
    expectOk(r);
    assert.deepEqual(r.checks, { signature: 'pass', payload_jcs: 'pass', profile: 'pass', key: 'pass', inclusion: 'skipped' });
    assert.equal(r.details.receipt.profile, 'keelstamp-aac-v1');
    assert.equal(r.details.receipt.kid, w.receiptKey.kid);
    assert.deepEqual(r.details.receipt.payload, w.payload);
  });

  test('valid receipt with checkpoint: all five checks pass', () => {
    const r = verify(w.receiptDoc, w.keys, w.checkpointDoc);
    expectOk(r);
    assert.deepEqual(r.checks, { signature: 'pass', payload_jcs: 'pass', profile: 'pass', key: 'pass', inclusion: 'pass' });
    assert.equal(r.details.checkpoint.payload.tree_size, w.leaves.length);
  });

  test('inputs may be JSON text or UTF-8 bytes', () => {
    expectOk(verify(JSON.stringify(w.receiptDoc), JSON.stringify(w.keys), JSON.stringify(w.checkpointDoc)));
    expectOk(verify(utf8(JSON.stringify(w.receiptDoc)), utf8(JSON.stringify(w.keys)), utf8(JSON.stringify(w.checkpointDoc))));
  });

  test('every leaf position in logs of size 1..17', () => {
    for (let n = 1; n <= 17; n++) {
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
    const forged = ts.encodeSign1({ ...w.receipt, payloadBytes: utf8(ts.jcs(p)) });
    expectOnly(verify(ts.receiptFileDoc(forged), w.keys), 'SIGNATURE_INVALID');
  });

  test('altered payload with a checkpoint: the log no longer contains it either', () => {
    const p = { ...w.payload, event: 'action.rejected' };
    const forged = ts.encodeSign1({ ...w.receipt, payloadBytes: utf8(ts.jcs(p)) });
    const r = verify(ts.receiptFileDoc(forged, w.proof), w.keys, w.checkpointDoc);
    assert.equal(r.ok, false);
    assert.deepEqual(codes(r), ['SIGNATURE_INVALID', 'INCLUSION_PROOF_INVALID']);
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

  test('wrong inclusion path → INCLUSION_PROOF_INVALID', () => {
    const proof = clone(w.proof);
    proof.inclusion_path[1] = flipHex(proof.inclusion_path[1]);
    expectOnly(verify(ts.receiptFileDoc(w.receipt.bytes, proof), w.keys, w.checkpointDoc), 'INCLUSION_PROOF_INVALID');
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

  test('wrong checkpoint: signed head of a same-size tree without this receipt → INCLUSION_PROOF_INVALID', () => {
    // Indistinguishable from a wrong path: either way the path does not reach this signed root.
    const leaves = w.leaves.map((l, i) => (i === 0 ? utf8('different entry') : l));
    const cp = w.signCheckpoint({ payload: ts.checkpointPayload(leaves) });
    expectOnly(verify(w.receiptDoc, w.keys, ts.checkpointFileDoc(cp.bytes)), 'INCLUSION_PROOF_INVALID');
  });

  test('unknown profile version → PROFILE_UNKNOWN', () => {
    const s = w.signReceipt({ payload: { ...w.payload, profile: 'keelstamp-aac-v2' } });
    expectOnly(verify(receiptOnly(s), w.keys), 'PROFILE_UNKNOWN');
  });
});

describe('NEG: COSE structure and header', () => {
  const sign1 = (over) => ts.receiptFileDoc(ts.encodeSign1({ ...w.receipt, ...over }));
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
  test('non-empty unprotected header → COSE_HEADER_INVALID', () => {
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
  test('alg EdDSA (-8) → ALG_UNSUPPORTED', () => expectOnly(verify(receiptOnly(w.signReceipt({ alg: -8 })), w.keys), 'ALG_UNSUPPORTED'));
  test('alg ES256 (-7) → ALG_UNSUPPORTED', () => expectOnly(verify(receiptOnly(w.signReceipt({ alg: -7 })), w.keys), 'ALG_UNSUPPORTED'));
  test('truncated signature → SIGNATURE_INVALID', () => {
    expectOnly(verify(sign1({ signature: w.receipt.signature.subarray(0, 63) }), w.keys), 'SIGNATURE_INVALID');
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
  test('receipt signed with the checkpoint key → KEY_PURPOSE_MISMATCH', () => {
    expectOnly(verify(receiptOnly(w.signReceipt({ key: w.checkpointKey })), w.keys), 'KEY_PURPOSE_MISMATCH');
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
    ['valid_from not RFC 3339 UTC', (k) => { k.keys[0].valid_from = k.keys[0].valid_from.replace('Z', '+00:00'); }],
    ['valid_from on a day that does not exist', (k) => { k.keys[0].valid_from = k.keys[0].valid_from.replace(/^(\d{4})-\d\d-\d\d/, '$1-02-31'); }],
    ['valid_until before valid_from', (k) => { k.keys[0].valid_until = k.keys[2].valid_from; }],
    ['private key member present', (k) => { k.keys[0].d = 'AAAA'; }],
  ]) {
    test(`keys file: ${name} → KEYS_MALFORMED`, () => {
      const keys = clone(w.keys);
      mutate(keys);
      expectOnly(verify(w.receiptDoc, keys), 'KEYS_MALFORMED');
    });
  }
  test('keys file that is not JSON → KEYS_MALFORMED', () => expectOnly(verify(w.receiptDoc, '{"keys":'), 'KEYS_MALFORMED'));
});

describe('NEG: receipt file and inclusion proof', () => {
  for (const [name, doc] of [
    ['not JSON', '{"format":'],
    ['an array', '[]'],
    ['wrong format', { ...w.receiptDoc, format: 'keelstamp-receipt-file-v0' }],
    ['unknown member', { ...w.receiptDoc, note: 'x' }],
    ['padded base64url', { ...w.receiptDoc, receipt: `${w.receiptDoc.receipt}=` }],
    ['standard base64 alphabet', { ...w.receiptDoc, receipt: `${w.receiptDoc.receipt.slice(0, -4)}+/+/` }],
    ['empty receipt', { ...w.receiptDoc, receipt: '' }],
  ]) {
    test(`receipt file: ${name} → RECEIPT_MALFORMED`, () => expectOnly(verify(doc, w.keys), 'RECEIPT_MALFORMED'));
  }
  for (const [name, mutate] of [
    ['leaf_index equal to tree_size', (p) => { p.leaf_index = p.tree_size; }],
    ['uppercase hex in the path', (p) => { p.inclusion_path[0] = p.inclusion_path[0].toUpperCase(); }],
    ['missing log_id', (p) => { delete p.log_id; }],
    ['tree_size zero', (p) => { p.tree_size = 0; }],
    ['fractional leaf_index', (p) => { p.leaf_index = 1.5; }],
  ]) {
    test(`inclusion proof: ${name} → INCLUSION_PROOF_MALFORMED (with or without a checkpoint)`, () => {
      const proof = clone(w.proof);
      mutate(proof);
      const doc = ts.receiptFileDoc(w.receipt.bytes, proof);
      expectOnly(verify(doc, w.keys), 'INCLUSION_PROOF_MALFORMED');
      expectOnly(verify(doc, w.keys, w.checkpointDoc), 'INCLUSION_PROOF_MALFORMED');
    });
  }
  test('checkpoint given but no inclusion proof → INCLUSION_PROOF_MISSING', () => {
    expectOnly(verify(ts.receiptFileDoc(w.receipt.bytes), w.keys, w.checkpointDoc), 'INCLUSION_PROOF_MISSING');
  });
  test('path one element short → INCLUSION_PROOF_INVALID', () => {
    const proof = { ...w.proof, inclusion_path: w.proof.inclusion_path.slice(0, -1) };
    expectOnly(verify(ts.receiptFileDoc(w.receipt.bytes, proof), w.keys, w.checkpointDoc), 'INCLUSION_PROOF_INVALID');
  });
  test('wrong leaf_index → INCLUSION_PROOF_INVALID', () => {
    const proof = { ...w.proof, leaf_index: w.proof.leaf_index - 1 };
    expectOnly(verify(ts.receiptFileDoc(w.receipt.bytes, proof), w.keys, w.checkpointDoc), 'INCLUSION_PROOF_INVALID');
  });
  test('receipt claims a signing time after the checkpoint → RECEIPT_AFTER_CHECKPOINT', () => {
    const now = Math.floor(Date.now() / 1000);
    const v = ts.buildWorld({ now, receiptIat: now + 60 });
    expectOnly(verify(v.receiptDoc, v.keys, v.checkpointDoc), 'RECEIPT_AFTER_CHECKPOINT');
  });
});

describe('NEG: checkpoint file', () => {
  test('checkpoint file that is not JSON → CHECKPOINT_MALFORMED', () => expectOnly(verify(w.receiptDoc, w.keys, '{'), 'CHECKPOINT_MALFORMED'));
  test('checkpoint file with the wrong format → CHECKPOINT_MALFORMED', () => {
    expectOnly(verify(w.receiptDoc, w.keys, { ...w.checkpointDoc, format: 'x' }), 'CHECKPOINT_MALFORMED');
  });
  test('checkpoint signed with a receipt key → CHECKPOINT_KEY_PURPOSE_MISMATCH', () => {
    const cp = w.signCheckpoint({ key: w.receiptKey });
    expectOnly(verify(w.receiptDoc, w.keys, ts.checkpointFileDoc(cp.bytes)), 'CHECKPOINT_KEY_PURPOSE_MISMATCH');
  });
  test('a receipt passed as the checkpoint → CHECKPOINT_PROFILE_UNKNOWN + CHECKPOINT_KEY_PURPOSE_MISMATCH', () => {
    const r = verify(w.receiptDoc, w.keys, ts.checkpointFileDoc(w.receipt.bytes));
    assert.deepEqual(codes(r), ['CHECKPOINT_PROFILE_UNKNOWN', 'CHECKPOINT_KEY_PURPOSE_MISMATCH']);
  });
  test('checkpoint from an unknown key → CHECKPOINT_KID_UNKNOWN', () => {
    const cp = w.signCheckpoint({ key: ts.newKey({ purpose: 'checkpoint', validFrom: w.now - ts.DAY }) });
    expectOnly(verify(w.receiptDoc, w.keys, ts.checkpointFileDoc(cp.bytes)), 'CHECKPOINT_KID_UNKNOWN');
  });
});

describe('fail-closed', () => {
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
  });
});

test('every reason code is produced by at least one test above', () => {
  const missing = Object.keys(REASONS).filter((c) => !seen.has(c));
  assert.deepEqual(missing, []);
});
