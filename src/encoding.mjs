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

// Strict byte/text encodings shared by the verifier. No Node-only APIs (runs in the browser too).

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_INDEX = new Map([...B64URL].map((c, i) => [c, i]));

/** base64url without padding (RFC 4648 §5). */
export function base64urlEncode(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63] + B64URL[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63];
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63];
  }
  return out;
}

/**
 * Strict base64url decode: alphabet [A-Za-z0-9_-] only, no padding, no whitespace, and the
 * input must be the canonical encoding of its bytes (unused trailing bits are zero).
 * Returns null on any violation.
 */
export function base64urlDecode(text) {
  if (typeof text !== 'string' || text.length % 4 === 1) return null;
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let acc = 0;
  let bits = 0;
  let o = 0;
  for (const c of text) {
    const v = B64URL_INDEX.get(c);
    if (v === undefined) return null;
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  const result = out.subarray(0, o);
  return base64urlEncode(result) === text ? result : null;
}

const HEX_RE = /^(?:[0-9a-f]{2})*$/;

/** Lowercase hex, even length. Returns null on any violation (uppercase is rejected). */
export function hexDecode(text) {
  if (typeof text !== 'string' || !HEX_RE.test(text)) return null;
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function hexEncode(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function bytesEqual(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export const utf8Encode = (text) => new TextEncoder().encode(text);

/** Strict UTF-8 decode: invalid sequences throw, a leading BOM is kept (and then fails JSON parsing). */
export const utf8DecodeStrict = (bytes) => new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);

/** RFC 3339 UTC timestamp with second precision, e.g. "YYYY-MM-DDThh:mm:ssZ" → seconds since the epoch, or null. */
export function parseUtcSeconds(text) {
  if (typeof text !== 'string') return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.exec(text);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number);
  const ms = Date.UTC(y, mo - 1, d, h, mi, s);
  const back = new Date(ms);
  // Reject out-of-range fields (e.g. month 13, Feb 30, hour 24) instead of letting Date roll them over.
  if (
    back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d ||
    back.getUTCHours() !== h || back.getUTCMinutes() !== mi || back.getUTCSeconds() !== s
  ) {
    return null;
  }
  return ms / 1000;
}

/** RFC 3339 form of a NumericDate; never throws (values outside the Date range are shown as numbers). */
export function formatUtcSeconds(seconds) {
  const d = new Date(seconds * 1000);
  return Number.isNaN(d.getTime()) ? `${seconds} s after 1970-01-01T00:00:00Z` : d.toISOString().replace('.000Z', 'Z');
}
