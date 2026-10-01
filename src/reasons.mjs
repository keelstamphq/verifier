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

// Stable reason codes. Codes are the machine-readable contract (tests, CLI --json, the web page);
// messages are for people and may be reworded.

export const REASONS = Object.freeze({
  // Input files
  RECEIPT_MALFORMED: 'The receipt file is not a valid keelstamp-receipt-file-v1 document',
  KEYS_MALFORMED: 'The keys file is not a valid keelstamp-keys-v1 document',
  CHECKPOINT_MALFORMED: 'The checkpoint file is not a valid keelstamp-checkpoint-file-v1 document',

  // Signed statement (receipt; for the checkpoint the same codes are prefixed with CHECKPOINT_)
  COSE_MALFORMED: 'The signed statement is not a well-formed COSE_Sign1 structure',
  COSE_HEADER_INVALID: 'The COSE header does not meet the profile requirements',
  ALG_UNSUPPORTED: 'The signature algorithm is not Ed25519 (COSE alg -19)',
  PAYLOAD_NOT_JCS: 'The payload is not canonical JSON (RFC 8785)',
  PROFILE_UNKNOWN: 'The payload profile is not known to this verifier',
  PAYLOAD_SCHEMA_INVALID: 'The payload does not match its profile',
  SUBJECT_MISMATCH: 'The subject (CWT sub) in the protected header does not match the payload',
  KID_UNKNOWN: 'The key id is not in the keys file',
  KEY_MISMATCH: 'The keys file lists a public key under this key id that the key id does not belong to (kid is not its JWK Thumbprint)',
  KEY_PURPOSE_MISMATCH: 'The key is not meant for this kind of statement',
  ISSUER_MISMATCH: 'The issuer (CWT iss) does not match the keys file',
  KEY_NOT_VALID_AT_TIME: 'The key was not valid at the signing time (CWT iat)',
  SIGNATURE_INVALID: 'The Ed25519 signature does not verify: the signed content was changed, or it was not signed by the named key',
  WRONG_KEY: 'The signature was made by a different key from the keys file than the one the key id names',

  // Inclusion in the log (only when a checkpoint is given)
  INCLUSION_PROOF_MISSING: 'A checkpoint was given but the receipt file has no inclusion proof',
  INCLUSION_PROOF_MALFORMED: 'The inclusion proof is malformed',
  INCLUSION_PROOF_INVALID: 'The inclusion path does not lead from this receipt to the checkpoint root hash (RFC 9162)',
  CHECKPOINT_LOG_MISMATCH: 'The checkpoint is for a different log than the inclusion proof',
  CHECKPOINT_TREE_SIZE_MISMATCH: 'The checkpoint tree size differs from the inclusion proof tree size',
  RECEIPT_AFTER_CHECKPOINT: 'The receipt signing time is later than the checkpoint that includes it',

  INTERNAL_ERROR: 'The verifier hit an unexpected error; the receipt is treated as not verified',
});

/** Codes produced by checkStatement(); prefixed with CHECKPOINT_ when they concern the checkpoint. */
export const STATEMENT_CODES = Object.freeze([
  'COSE_MALFORMED', 'COSE_HEADER_INVALID', 'ALG_UNSUPPORTED', 'PAYLOAD_NOT_JCS', 'PROFILE_UNKNOWN',
  'PAYLOAD_SCHEMA_INVALID', 'SUBJECT_MISMATCH', 'KID_UNKNOWN', 'KEY_MISMATCH', 'KEY_PURPOSE_MISMATCH',
  'ISSUER_MISMATCH', 'KEY_NOT_VALID_AT_TIME', 'SIGNATURE_INVALID', 'WRONG_KEY',
]);

export function reason(code, detail) {
  if (!(code in REASONS)) throw new Error(`unknown reason code ${code}`);
  return { code, message: detail ? `${REASONS[code]} (${detail})` : REASONS[code] };
}

export function checkpointReason(r) {
  return { code: `CHECKPOINT_${r.code}`, message: `Checkpoint: ${r.message}` };
}
