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

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { hexDecode, hexEncode } from '../src/encoding.mjs';
import { leafHash, nodeHash, rootFromInclusionProof, verifyInclusion } from '../src/merkle.mjs';
import { inclusionPath, merkleRoot } from './test-signer.mjs';

// The eight leaves and tree heads used by the Certificate Transparency reference test data
// (RFC 6962 hashing, which RFC 9162 keeps unchanged for SHA-256).
const CT_LEAVES = ['', '00', '10', '2021', '3031', '40414243', '5051525354555657', '606162636465666768696a6b6c6d6e6f'].map(hexDecode);
const CT_ROOTS = [
  '6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d',
  'fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125',
  'aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77',
  'd37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7',
  '4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4',
  '76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef',
  'ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c',
  '5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328',
];

test('test-signer tree heads match the CT reference roots for sizes 1..8', () => {
  for (let n = 1; n <= 8; n++) assert.equal(hexEncode(merkleRoot(CT_LEAVES.slice(0, n))), CT_ROOTS[n - 1], `size ${n}`);
});

test('every leaf of every tree up to size 40 verifies against the recursive tree head', () => {
  const leaves = Array.from({ length: 40 }, (_, i) => Uint8Array.of(i, i * 7 % 256));
  for (let n = 1; n <= leaves.length; n++) {
    const tree = leaves.slice(0, n);
    const root = merkleRoot(tree);
    for (let m = 0; m < n; m++) {
      const path = inclusionPath(m, tree);
      assert.ok(verifyInclusion(m, n, leafHash(tree[m]), path, root), `leaf ${m} of ${n}`);
    }
  }
});

test('CT reference leaves verify in the size-8 tree', () => {
  const root = hexDecode(CT_ROOTS[7]);
  for (let m = 0; m < 8; m++) assert.ok(verifyInclusion(m, 8, leafHash(CT_LEAVES[m]), inclusionPath(m, CT_LEAVES), root));
});

test('wrong index, wrong leaf, altered/short/long path and out-of-range index all fail', () => {
  const tree = CT_LEAVES.slice(0, 7);
  const root = merkleRoot(tree);
  const path = inclusionPath(5, tree);
  const leaf = leafHash(tree[5]);
  assert.ok(verifyInclusion(5, 7, leaf, path, root));
  assert.equal(verifyInclusion(4, 7, leaf, path, root), false);
  assert.equal(verifyInclusion(5, 7, leafHash(tree[4]), path, root), false);
  const altered = path.map((p, i) => (i === 1 ? Uint8Array.from(p, (b, j) => (j === 0 ? b ^ 1 : b)) : p));
  assert.equal(verifyInclusion(5, 7, leaf, altered, root), false);
  assert.equal(rootFromInclusionProof(5, 7, leaf, path.slice(0, -1)), null);
  assert.equal(rootFromInclusionProof(5, 7, leaf, [...path, path[0]]), null);
  assert.equal(rootFromInclusionProof(7, 7, leaf, path), null);
});

test('the same path can fit two tree sizes, so tree_size must come from the signed checkpoint', () => {
  // Leaf 5 has the same audit path in trees of size 7 and 8 when leaf 7 is absent from the hash
  // chain; the verifier therefore requires proof.tree_size === checkpoint.tree_size.
  const tree = CT_LEAVES.slice(0, 7);
  const path = inclusionPath(5, tree);
  assert.ok(verifyInclusion(5, 8, leafHash(tree[5]), path, merkleRoot(tree)));
});

test('single-leaf tree: empty path, root is the leaf hash', () => {
  const leaf = leafHash(Uint8Array.of(1, 2, 3));
  assert.ok(verifyInclusion(0, 1, leaf, [], leaf));
  assert.equal(rootFromInclusionProof(0, 1, leaf, [leaf]), null);
});

test('large tree sizes are not truncated to 32 bits', () => {
  // leaf 2^32 + 1 in a tree of size 2^32 + 2: the last two leaves form a subtree whose root
  // joins the left 2^32 subtree, so the path has two elements.
  const left = new Uint8Array(32).fill(7); // stands in for MTH of the first 2^32 leaves
  const sibling = leafHash(Uint8Array.of(9));
  const leaf = leafHash(Uint8Array.of(8));
  const expected = nodeHash(left, nodeHash(sibling, leaf));
  assert.ok(verifyInclusion(2 ** 32 + 1, 2 ** 32 + 2, leaf, [sibling, left], expected));
  // With 32-bit arithmetic the index would wrap to 1 in a tree of size 2 and need a 1-element path.
  assert.equal(rootFromInclusionProof(2 ** 32 + 1, 2 ** 32 + 2, leaf, [sibling]), null);
});
