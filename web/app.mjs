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

import { printable, verify } from '../src/index.mjs';

// Exposed so the built page's exact script can be exercised by tests (tests/build.test.mjs).
globalThis.KeelstampVerifier = Object.freeze({ verify });

const CHECKS = [
  ['signature', '(a) Signature: COSE_Sign1, Ed25519'],
  ['payload_jcs', '(b) Payload is canonical JSON (RFC 8785)'],
  ['profile', '(c) Profile known, payload matches it'],
  ['key', '(d) Key listed and valid at the signing time'],
  ['inclusion', '(e) Included in the signed checkpoint (RFC 9162)'],
];

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function render(result, hadCheckpoint) {
  const $ = (id) => document.getElementById(id);
  const status = $('status');
  status.textContent = result.ok ? 'Verified' : 'Not verified';
  status.className = `status ${result.ok ? 'ok' : 'bad'}`;

  const checks = $('checks');
  checks.replaceChildren();
  for (const [key, label] of CHECKS) {
    const s = result.checks[key];
    const row = el('tr');
    row.append(el('td', label), el('td', key === 'inclusion' && s === 'skipped' && !hadCheckpoint ? 'skipped (no checkpoint)' : s, `s ${s}`));
    checks.append(row);
  }

  const reasons = $('reasons');
  reasons.replaceChildren();
  for (const r of result.reasons) {
    const li = el('li');
    li.append(el('code', r.code), document.createTextNode(` ${printable(r.message)}`));
    reasons.append(li);
  }

  const details = $('details');
  details.replaceChildren();
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
    rows.push(['Log', inc.log_id], ['Leaf', `${inc.leaf_index} of ${inc.tree_size}`], ['Checkpoint signed', result.details.checkpoint.signed_at]);
  }
  for (const [k, v] of rows) details.append(el('dt', k), el('dd', printable(v)));
  $('result').hidden = false;
}

function init() {
  const $ = (id) => document.getElementById(id);
  for (const name of ['receipt', 'keys', 'checkpoint']) {
    const text = $(`${name}-text`);
    $(`${name}-file`).addEventListener('change', async (e) => {
      const file = e.target.files && e.target.files[0];
      if (file) text.value = await file.text();
    });
    text.addEventListener('dragover', (e) => e.preventDefault());
    text.addEventListener('drop', async (e) => {
      const file = e.dataTransfer && e.dataTransfer.files[0];
      if (!file) return;
      e.preventDefault();
      text.value = await file.text();
    });
  }
  $('verify').addEventListener('click', () => {
    const receipt = $('receipt-text').value.trim();
    const keys = $('keys-text').value.trim();
    const checkpoint = $('checkpoint-text').value.trim();
    render(verify(receipt, keys, checkpoint === '' ? undefined : checkpoint), checkpoint !== '');
  });
  $('clear').addEventListener('click', () => {
    for (const name of ['receipt', 'keys', 'checkpoint']) {
      $(`${name}-text`).value = '';
      $(`${name}-file`).value = '';
    }
    $('result').hidden = true;
  });
}

if (typeof document !== 'undefined') init();
