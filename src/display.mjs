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

// Text taken from a receipt is attacker-controlled. Before it is shown to a person, escape the
// characters that can rewrite a terminal (control characters, ESC sequences), break lines, or hide
// and reorder text: every code point of the Unicode categories Cc (controls), Cf (format: bidi
// marks and overrides, zero-width characters, soft hyphen, tag characters, BOM), Zl and Zp.

const UNSAFE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu;

const hex4 = (n) => n.toString(16).padStart(4, '0');

/** For human-readable output: unsafe code points become \uXXXX (or \u{XXXXX} above U+FFFF). */
export function printable(value) {
  return String(value).replace(UNSAFE, (c) => {
    const cp = c.codePointAt(0);
    return cp > 0xffff ? `\\u{${cp.toString(16)}}` : `\\u${hex4(cp)}`;
  });
}

// JSON.stringify already escapes U+0000-U+001F inside strings, and JSON's structural whitespace is
// ASCII, so every match of this pattern in JSON.stringify output lies inside a string.
const UNSAFE_IN_JSON = /[\u007f-\u009f\p{Cf}\p{Zl}\p{Zp}]/gu;

/** For JSON.stringify output: unsafe code points become \uXXXX escapes (surrogate pairs above U+FFFF); still the same JSON. */
export function jsonSafe(jsonText) {
  return jsonText.replace(UNSAFE_IN_JSON, (c) => [...Array(c.length).keys()].map((i) => `\\u${hex4(c.charCodeAt(i))}`).join(''));
}

/**
 * The position a log receipt claims for the receipt, for display. The log signs only the Merkle root:
 * the leaf index and tree size come from the inclusion proof, which is not signed, and several
 * (leaf index, tree size) pairs can lead to the same root. They are confirmed only when a checkpoint,
 * which signs the tree size together with the root, matched the log receipt.
 */
export function leafPosition(inclusion) {
  const position = `leaf ${inclusion.leaf_index} of ${inclusion.tree_size}`;
  return inclusion.checkpoint === 'matched'
    ? `${position} (tree size confirmed by the checkpoint)`
    : `${position} (not signed: from the inclusion proof, informational only)`;
}

const PREVIEW = 64;

/**
 * A short, bounded description of a value decoded from an input, for reason messages. A label or
 * value from a receipt can be a huge byte string or a deeply nested array; describing it by type
 * and size keeps messages small and cannot overflow the stack. Never throws.
 */
export function show(value) {
  try {
    if (typeof value === 'string') {
      return value.length > PREVIEW ? `${JSON.stringify(value.slice(0, PREVIEW))}... (${value.length} characters)` : JSON.stringify(value);
    }
    if (value === null || value === undefined || typeof value === 'number' || typeof value === 'boolean') return String(value);
    if (value instanceof Uint8Array) return `byte string (${value.length} bytes)`;
    if (Array.isArray(value)) return `array (${value.length} items)`;
    if (value instanceof Map) return `map (${value.size} entries)`;
    if (typeof value === 'object' && typeof value.tag === 'number') return `tag ${value.tag}`;
    return typeof value;
  } catch {
    return 'value';
  }
}
