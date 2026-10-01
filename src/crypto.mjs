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

// Ed25519 wiring. SHA-512 comes from @noble/hashes so verification is synchronous and does not
// depend on WebCrypto (which some browsers only expose in secure contexts, not on file:// pages).

import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

ed.hashes.sha512 = sha512;

export const { Point } = ed;

/**
 * Strict Ed25519 verification (RFC 8032 / FIPS 186-5 rules: canonical encodings, small-order
 * public keys rejected), not the more permissive ZIP-215 default. Never throws.
 */
export function ed25519Verify(signature, message, publicKey) {
  try {
    return ed.verify(signature, message, publicKey, { zip215: false });
  } catch {
    return false;
  }
}
