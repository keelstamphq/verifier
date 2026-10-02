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

// JSON Canonicalization Scheme (RFC 8785).
//
// RFC 8785 is defined in terms of ECMAScript: numbers are serialized with the ES Number-to-String
// algorithm and strings with JSON.stringify's escaping, and object members are sorted by their
// UTF-16 code units. A JavaScript engine therefore provides those primitives directly; this module
// adds the member ordering, the I-JSON restrictions (no lone surrogates, finite numbers only) and
// the "is this byte string already canonical" check the verifier needs.

import { utf8DecodeStrict } from './encoding.mjs';

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export class JcsError extends Error {}

function serializeString(s) {
  if (LONE_SURROGATE.test(s)) throw new JcsError('string contains a lone surrogate (not I-JSON)');
  return JSON.stringify(s);
}

/** Canonical JSON text (RFC 8785) for a JSON value. Throws JcsError for values outside I-JSON. */
export function canonicalize(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new JcsError('non-finite number');
      return JSON.stringify(value); // ES Number serialization; -0 becomes "0" as RFC 8785 requires
    case 'string':
      return serializeString(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
      // Default Array.prototype.sort compares UTF-16 code units, which is the RFC 8785 order.
      const keys = Object.keys(value).sort();
      return `{${keys.map((k) => `${serializeString(k)}:${canonicalize(value[k])}`).join(',')}}`;
    }
    default:
      throw new JcsError(`unsupported type ${typeof value}`);
  }
}

/**
 * Checks that `bytes` is exactly the RFC 8785 canonical form of the JSON value it encodes.
 * Rejects invalid UTF-8, a BOM, whitespace, unsorted or duplicate members, non-canonical numbers
 * (e.g. 1.0, 1e3, -0, integers beyond 2^53) and lone surrogates.
 * Returns { ok: true, value } or { ok: false, detail }.
 */
export function parseCanonicalJson(bytes) {
  let text;
  try {
    text = utf8DecodeStrict(bytes);
  } catch {
    return { ok: false, detail: 'payload is not valid UTF-8' };
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, detail: 'payload is not valid JSON' };
  }
  let canonical;
  try {
    canonical = canonicalize(value);
  } catch (e) {
    return { ok: false, detail: e.message };
  }
  if (canonical !== text) {
    return { ok: false, detail: `payload differs from its canonical form at character ${firstDifference(canonical, text)}` };
  }
  return { ok: true, value };
}

const JSON_WS = new Set([' ', '\t', '\n', '\r']);

/**
 * JSON.parse that also rejects duplicate member names within an object (compared after escape
 * decoding, so "a" and "\u0061" are duplicates). Throws SyntaxError like JSON.parse.
 */
export function parseJsonNoDuplicates(text) {
  const value = JSON.parse(text); // validates the syntax, so the scan below can stay simple
  const objects = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '{') objects.push(new Set());
    else if (c === '}') objects.pop();
    else if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      let k = j + 1;
      while (JSON_WS.has(text[k])) k++;
      if (text[k] === ':') {
        const name = JSON.parse(text.slice(i, j + 1));
        const members = objects[objects.length - 1];
        if (members.has(name)) throw new SyntaxError(`duplicate member name ${JSON.stringify(name)}`);
        members.add(name);
      }
      i = j;
    }
  }
  return value;
}

function firstDifference(a, b) {
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  return i;
}
