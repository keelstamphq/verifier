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

// Browser glue for the single-file verifier page. All output is written with textContent:
// receipt contents are untrusted and never parsed as HTML.
//
// Keys come only from the keys field. The page shows which keys file that is (file name or
// "pasted text", SHA-256, issuer, keys) before and after verification, so a person can compare it
// with the file Keelstamp publishes.

import { inspectKeysFile, printable, verify } from '../src/index.mjs';

const CHECKS = [
  ['signature', '(a) Signature: COSE_Sign1, Ed25519'],
  ['payload_jcs', '(b) Payload is canonical JSON (RFC 8785)'],
  ['profile', '(c) Profile known, payload matches it'],
  ['key', '(d) Key listed and valid at the signing time'],
  ['inclusion', '(e) Included in the log (log receipt, RFC 9942 / RFC 9162)'],
];

/**
 * The keys the page verifies with: only the keys field. While the field still holds exactly the
 * text of a chosen file, that file's bytes are used, so the SHA-256 shown is the file's own;
 * otherwise the text as typed or pasted.
 */
export function selectKeys(fieldText, loaded) {
  if (loaded && fieldText === loaded.text) return { input: loaded.bytes, source: `file "${loaded.name}"` };
  if (fieldText === '') return { input: undefined, source: 'none' };
  return { input: fieldText, source: loaded ? `text edited after loading file "${loaded.name}"` : 'pasted text' };
}

/** Display rows for the keys in use: source, SHA-256, issuer and keys (or the problem). */
export function keysRows(selection) {
  const info = inspectKeysFile(selection.input);
  if (!info.given) return { ok: false, rows: [['Source', 'none: no keys file given']] };
  const rows = [['Source', selection.source], ['SHA-256', info.sha256]];
  if (info.error) return { ok: false, rows: [...rows, ['Problem', `not a valid keys file (${info.error})`]] };
  rows.push(['Issuer', info.issuer]);
  for (const k of info.keys) rows.push([`Key (${k.purpose})`, `${k.kid}, valid ${k.valid_from} .. ${k.valid_until ?? 'open'}`]);
  return { ok: true, rows, info };
}

// Exposed so the built page's exact script can be exercised by tests (tests/build.test.mjs).
globalThis.KeelstampVerifier = Object.freeze({ verify, selectKeys, keysRows });

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

const fillList = (dl, rows) => {
  dl.replaceChildren();
  for (const [k, v] of rows) dl.append(el('dt', k), el('dd', printable(v)));
};

function inclusionText(result) {
  const s = result.checks.inclusion;
  if (s === 'skipped') return 'skipped (no log receipt, no checkpoint)';
  if (s === 'pass') return result.details.inclusion.checkpoint === 'matched' ? 'pass (log receipt; matches checkpoint)' : 'pass (log receipt; no checkpoint given)';
  return s;
}

function render(result, keys) {
  const $ = (id) => document.getElementById(id);
  const status = $('status');
  status.textContent = result.ok ? 'Verified' : 'Not verified';
  status.className = `status ${result.ok ? 'ok' : 'bad'}`;

  fillList($('keys-used'), keys.rows);

  const checks = $('checks');
  checks.replaceChildren();
  for (const [key, label] of CHECKS) {
    const s = result.checks[key];
    const row = el('tr');
    row.append(el('td', label), el('td', key === 'inclusion' ? inclusionText(result) : s, `s ${s}`));
    checks.append(row);
  }

  const reasons = $('reasons');
  reasons.replaceChildren();
  for (const r of result.reasons) {
    const li = el('li');
    li.append(el('code', r.code), document.createTextNode(` ${printable(r.message)}`));
    reasons.append(li);
  }

  const rc = result.details.receipt ?? {};
  const claim = result.ok ? '' : ' (claimed, not verified)';
  const rows = [];
  // Payload fields only after the profile check validated their syntax; everything escaped.
  if (result.checks.profile === 'pass') {
    rows.push(['Receipt id', rc.payload.receipt_id + claim], ['Profile', rc.profile], ['Event', rc.payload.event + claim]);
  }
  if (rc.signed_at) rows.push(['Signed at', rc.signed_at + claim], ['Key id', rc.kid], ['Issuer', rc.iss + claim]);
  const inc = result.details.inclusion;
  if (inc && result.checks.inclusion === 'pass') {
    rows.push(['Log', inc.log_id], ['Leaf', `${inc.leaf_index} of ${inc.tree_size}`], ['Log receipt signed', inc.signed_at], ['Root hash', inc.root_hash]);
    if (inc.checkpoint === 'matched') rows.push(['Checkpoint signed', result.details.checkpoint.signed_at]);
  }
  fillList($('details'), rows);
  $('result').hidden = false;
}

/**
 * The checkpoint field counts as empty only when it holds nothing at all. Whitespace or a BOM is
 * passed on and fails as CHECKPOINT_MALFORMED, as the CLI does for such a file, instead of
 * silently skipping the comparison.
 */
export function checkpointArg(text) {
  return text === '' ? undefined : text;
}

function init() {
  const $ = (id) => document.getElementById(id);
  let loadedKeys = null;
  const keysField = $('keys-text');

  const showKeys = () => {
    const keys = keysRows(selectKeys(keysField.value, loadedKeys));
    const box = $('keys-status');
    box.className = `keys-status ${keys.ok ? 'ok' : 'bad'}`;
    if (keys.ok) {
      const from = keys.rows.find(([k]) => k === 'Source')[1];
      box.textContent = printable(`Keys in use: ${from}, SHA-256 ${keys.info.sha256}, issuer ${keys.info.issuer}, ${keys.info.keys.length} keys`);
    } else {
      box.textContent = printable(keys.rows.map(([k, v]) => `${k}: ${v}`).join('; '));
    }
    return keys;
  };

  const loadKeysFile = async (file) => {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let text;
    try {
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    } catch {
      text = '';
    }
    loadedKeys = { name: file.name, bytes, text };
    keysField.value = text;
    showKeys();
  };

  for (const name of ['receipt', 'keys', 'checkpoint']) {
    const text = $(`${name}-text`);
    const load = name === 'keys' ? loadKeysFile : async (file) => { text.value = await file.text(); };
    $(`${name}-file`).addEventListener('change', async (e) => {
      const file = e.target.files && e.target.files[0];
      if (file) await load(file);
    });
    text.addEventListener('dragover', (e) => e.preventDefault());
    text.addEventListener('drop', async (e) => {
      const file = e.dataTransfer && e.dataTransfer.files[0];
      if (!file) return;
      e.preventDefault();
      await load(file);
    });
  }
  keysField.addEventListener('input', showKeys);

  $('verify').addEventListener('click', () => {
    const selection = selectKeys(keysField.value, loadedKeys);
    const checkpoint = checkpointArg($('checkpoint-text').value);
    render(verify($('receipt-text').value, selection.input, checkpoint), showKeys());
  });
  $('clear').addEventListener('click', () => {
    for (const name of ['receipt', 'keys', 'checkpoint']) {
      $(`${name}-text`).value = '';
      $(`${name}-file`).value = '';
    }
    loadedKeys = null;
    showKeys();
    $('result').hidden = true;
  });
}

if (typeof document !== 'undefined') init();
