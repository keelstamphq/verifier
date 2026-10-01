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

// Payload profiles. A profile fixes the exact member set and value syntax of a signed payload and
// which header value it is bound to. Every string value is constrained to identifiers, digests or
// salted commitments, so a payload that carries free text (names, e-mail addresses, amounts)
// fails validation instead of being shown as a valid receipt.

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const RECEIPT_ID = /^[A-Za-z0-9_-]{16,64}$/;
const EVENT = /^[a-z][a-z0-9_]{0,31}(?:\.[a-z][a-z0-9_]{0,31}){0,3}$/;
const DIGEST_NAME = /^[a-z][a-z0-9_]{0,31}$/;
const LOG_ID = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;
const ROOT_HASH = /^[0-9a-f]{64}$/;

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function exactMembers(payload, members) {
  const errors = [];
  for (const k of Object.keys(payload)) if (!members.includes(k)) errors.push(`unknown member "${k}"`);
  for (const k of members) if (!(k in payload)) errors.push(`missing member "${k}"`);
  return errors;
}

function check(errors, cond, message) {
  if (!cond) errors.push(message);
}

const aacV1 = {
  name: 'keelstamp-aac-v1',
  kind: 'receipt',
  members: ['profile', 'receipt_id', 'partner', 'tenant', 'event', 'digests'],
  /** CWT "sub" in the protected header must equal this payload member. */
  subjectMember: 'receipt_id',
  validate(p) {
    const errors = exactMembers(p, this.members);
    if (errors.length) return errors;
    check(errors, typeof p.receipt_id === 'string' && RECEIPT_ID.test(p.receipt_id), 'receipt_id must match [A-Za-z0-9_-]{16,64}');
    check(errors, typeof p.partner === 'string' && DIGEST.test(p.partner), 'partner must be a salted commitment "sha256:<64 hex>"');
    check(errors, typeof p.tenant === 'string' && DIGEST.test(p.tenant), 'tenant must be a salted commitment "sha256:<64 hex>"');
    check(errors, typeof p.event === 'string' && EVENT.test(p.event), 'event must be a dotted lowercase identifier');
    if (!isPlainObject(p.digests) || Object.keys(p.digests).length === 0) {
      errors.push('digests must be a non-empty object');
    } else {
      for (const [name, value] of Object.entries(p.digests)) {
        check(errors, DIGEST_NAME.test(name), `digest name "${name}" must be a lowercase identifier`);
        check(errors, typeof value === 'string' && DIGEST.test(value), `digests.${name} must be "sha256:<64 hex>"`);
      }
    }
    return errors;
  },
};

const checkpointV1 = {
  name: 'keelstamp-checkpoint-v1',
  kind: 'checkpoint',
  members: ['profile', 'log_id', 'tree_size', 'root_hash'],
  subjectMember: 'log_id',
  validate(p) {
    const errors = exactMembers(p, this.members);
    if (errors.length) return errors;
    check(errors, typeof p.log_id === 'string' && LOG_ID.test(p.log_id), 'log_id must match [A-Za-z0-9][A-Za-z0-9._/-]{0,127}');
    check(errors, Number.isSafeInteger(p.tree_size) && p.tree_size >= 0, 'tree_size must be a non-negative safe integer');
    check(errors, typeof p.root_hash === 'string' && ROOT_HASH.test(p.root_hash), 'root_hash must be 64 lowercase hex characters');
    return errors;
  },
};

const PROFILES = new Map([aacV1, checkpointV1].map((p) => [p.name, p]));

/** The profile registered under `name` for this kind of statement ("receipt" or "checkpoint"), or undefined. */
export function findProfile(name, kind) {
  const profile = typeof name === 'string' ? PROFILES.get(name) : undefined;
  return profile && profile.kind === kind ? profile : undefined;
}

export const knownProfiles = (kind) => [...PROFILES.values()].filter((p) => p.kind === kind).map((p) => p.name);
