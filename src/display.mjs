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
