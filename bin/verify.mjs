#!/usr/bin/env node
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

// node bin/verify.mjs <receipt.json> --keys <keys.json> [--checkpoint <checkpoint.json>] [--json]
// Exit codes: 0 verified, 1 not verified, 2 usage or file error. Reads local files only.
//
// --keys is required and there is no default: a keys file found next to the receipt, or keys
// inside it, could come from whoever sent the receipt, and would let a forged receipt verify.

import { readFileSync } from 'node:fs';
import { jsonSafe, keysFileSha256, leafPosition, printable, verify } from '../src/index.mjs';

const EXIT_OK = 0;
const EXIT_NOT_VERIFIED = 1;
const EXIT_USAGE = 2;

const USAGE = `Usage: node bin/verify.mjs <receipt.json> --keys <keys.json> [--checkpoint <checkpoint.json>] [--json]

Verifies a Keelstamp receipt offline (no network access).
  --keys         required: the public keys file Keelstamp publishes (format keelstamp-keys-v1),
                 from https://<issuer>/.well-known/keelstamp-keys.json or the transparency
                 repository. Never use a keys file that came with the receipt.
  --checkpoint   a signed checkpoint (format keelstamp-checkpoint-file-v1); when given, the root
                 the receipt's log receipt proves must be the one the checkpoint signs
  --json         print the full result as JSON

Exit codes: 0 verified, 1 not verified, 2 usage or file error.`;

function parseArgs(argv) {
  const args = { receipt: undefined, keys: undefined, checkpoint: undefined, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h' || a === '--help') return { help: true };
    if (a === '--json') args.json = true;
    else if (a === '--keys' || a === '--checkpoint') {
      if (i + 1 >= argv.length) throw new Error(`${a} needs a file name`);
      if (args[a.slice(2)] !== undefined) throw new Error(`${a} given twice`);
      args[a.slice(2)] = argv[++i];
    } else if (a.startsWith('-')) throw new Error(`unknown option ${a}`);
    else if (args.receipt === undefined) args.receipt = a;
    else throw new Error(`unexpected argument ${a}`);
  }
  if (args.receipt === undefined) throw new Error('missing <receipt.json>');
  if (args.keys === undefined) {
    throw new Error('--keys <keys.json> is required: give the keys file Keelstamp publishes. The verifier never uses a keys file found next to the receipt, or keys that come with it.');
  }
  return args;
}

function readFile(path, what) {
  try {
    return readFileSync(path);
  } catch (e) {
    throw new Error(`cannot read ${what} file ${path} (${e.code ?? e.message})`);
  }
}

const LABELS = {
  signature: '(a) signature (COSE_Sign1, Ed25519)',
  payload_jcs: '(b) payload is canonical JSON',
  profile: '(c) profile known, payload valid',
  key: '(d) key listed and valid at iat',
  inclusion: '(e) inclusion in the log (RFC 9942/9162)',
};

function inclusionStatus(result) {
  const s = result.checks.inclusion;
  const inc = result.details.inclusion;
  if (s === 'skipped') return 'skipped (no log receipt, no --checkpoint)';
  if (s === 'pass') return inc.checkpoint === 'matched' ? 'pass (log receipt; matches checkpoint)' : 'pass (log receipt; no --checkpoint given)';
  return s;
}

function printHuman(result, files) {
  const out = [];
  out.push(result.ok ? 'VERIFIED' : 'NOT VERIFIED');
  const r = result.details.receipt ?? {};
  // Fields of a receipt that did not verify are only claims; say so next to them. Payload fields are
  // shown only once the profile check has validated their syntax, and all of it is escaped.
  const claim = result.ok ? '' : '  [claimed, not verified]';
  const p = printable;
  if (result.checks.profile === 'pass') out.push(`  receipt    ${p(r.payload.receipt_id)} (${p(r.profile)}, event ${p(r.payload.event)})${claim}`);
  if (r.signed_at) out.push(`  signed     ${r.signed_at} by key ${r.kid} (issuer ${p(r.iss)})${claim}`);
  const inc = result.details.inclusion;
  if (inc && result.checks.inclusion === 'pass') {
    // Only the root, the log id and the time are signed by the log; the position is labelled.
    const cp = inc.checkpoint === 'matched' ? `, same root as checkpoint signed ${result.details.checkpoint.signed_at}` : '';
    out.push(`  log        ${p(inc.log_id)}, root ${inc.root_hash}, log receipt signed ${inc.signed_at}${cp}`);
    out.push(`             ${leafPosition(inc)}`);
  }
  out.push('  checks');
  for (const [check, label] of Object.entries(LABELS)) {
    const status = check === 'inclusion' ? inclusionStatus(result) : result.checks[check];
    out.push(`    ${label.padEnd(42, ' ')} ${status}`);
  }
  if (result.reasons.length) {
    out.push('  reasons');
    for (const reason of result.reasons) out.push(`    ${reason.code}: ${p(reason.message)}`);
  }
  out.push(`  keys file  ${p(files.keys)}`);
  out.push(`             sha256 ${files.keys_sha256}  (compare with the keys file Keelstamp publishes)`);
  const k = result.details.keys;
  if (k) {
    out.push(`             issuer ${p(k.issuer)}, ${k.keys.length} key${k.keys.length === 1 ? '' : 's'}:`);
    for (const x of k.keys) out.push(`             ${x.kid} ${x.purpose}, valid ${x.valid_from} .. ${x.valid_until ?? 'open'}`);
  }
  if (files.checkpoint) out.push(`  checkpoint ${p(files.checkpoint)}`);
  console.log(out.join('\n'));
}

function main(argv) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (e) {
    console.error(`error: ${e.message}\n\n${USAGE}`);
    return EXIT_USAGE;
  }
  if (args.help) {
    console.log(USAGE);
    return EXIT_OK;
  }
  let receipt;
  let keys;
  let checkpoint;
  try {
    receipt = readFile(args.receipt, 'receipt');
    keys = readFile(args.keys, 'keys');
    if (args.checkpoint !== undefined) checkpoint = readFile(args.checkpoint, 'checkpoint');
  } catch (e) {
    console.error(`error: ${e.message}`);
    return EXIT_USAGE;
  }
  const toBytes = (buf) => new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  const keysBytes = toBytes(keys);
  const result = verify(toBytes(receipt), keysBytes, checkpoint === undefined ? undefined : toBytes(checkpoint));
  const files = { receipt: args.receipt, keys: args.keys, keys_sha256: keysFileSha256(keysBytes), checkpoint: args.checkpoint };
  if (args.json) console.log(jsonSafe(JSON.stringify({ ...result, files }, null, 2)));
  else printHuman(result, files);
  return result.ok ? EXIT_OK : EXIT_NOT_VERIFIED;
}

process.exitCode = main(process.argv.slice(2));
