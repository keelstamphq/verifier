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

// Merkle tree hashing and inclusion-proof verification as in RFC 9162 (Certificate Transparency
// v2.0), §2.1.1 and §2.1.3.2, with SHA-256.

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesEqual, concatBytes } from './encoding.mjs';

const LEAF_PREFIX = Uint8Array.of(0x00);
const NODE_PREFIX = Uint8Array.of(0x01);

/** MTH({d}) = SHA-256(0x00 || d) */
export function leafHash(leafData) {
  return sha256(concatBytes(LEAF_PREFIX, leafData));
}

/** SHA-256(0x01 || left || right) */
export function nodeHash(left, right) {
  return sha256(concatBytes(NODE_PREFIX, left, right));
}

/**
 * Root hash implied by an inclusion proof, following RFC 9162 §2.1.3.2 step by step.
 * Returns null when the proof is structurally impossible for (leafIndex, treeSize): index out of
 * range, a path that is too long (sn reaches 0 early) or too short (sn not 0 at the end).
 * Indices are handled as BigInt so tree sizes beyond 2^32 are not truncated by 32-bit shifts.
 */
export function rootFromInclusionProof(leafIndex, treeSize, leaf, inclusionPath) {
  let fn = BigInt(leafIndex);
  let sn = BigInt(treeSize) - 1n;
  // Step 1: leaf_index must be < tree_size.
  if (fn > sn || fn < 0n) return null;
  // Steps 2-3.
  let r = leaf;
  // Step 4.
  for (const p of inclusionPath) {
    if (sn === 0n) return null; // 4a: path longer than the tree is deep
    if ((fn & 1n) === 1n || fn === sn) {
      r = nodeHash(p, r); // 4b.i
      if ((fn & 1n) === 0n) {
        // 4b.ii: skip the levels where this node has no right sibling
        while ((fn & 1n) === 0n && fn !== 0n) {
          fn >>= 1n;
          sn >>= 1n;
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1n; // 4c
    sn >>= 1n;
  }
  // Step 5: the path must have consumed the whole tree.
  return sn === 0n ? r : null;
}

/** RFC 9162 §2.1.3.2: true iff `inclusionPath` proves `leaf` (a leaf hash) at `leafIndex` in the tree with `rootHash`. */
export function verifyInclusion(leafIndex, treeSize, leaf, inclusionPath, rootHash) {
  const r = rootFromInclusionProof(leafIndex, treeSize, leaf, inclusionPath);
  return r !== null && bytesEqual(r, rootHash);
}
