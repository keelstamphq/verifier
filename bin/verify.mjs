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

// node bin/verify.mjs <receipt.json> [--keys <keys.json>] [--checkpoint <checkpoint.json>] [--json]
// Exit codes: 0 verified, 1 not verified, 2 usage or file error. Reads local files only.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { verify } from '../src/index.mjs';

const DEFAULT_KEYS_NAME = 'keelstamp-keys.json';
const EXIT_OK = 0;
const EXIT_NOT_VERIFIED = 1;
const EXIT_USAGE = 2;

const USAGE = `Usage: node bin/verify.mjs <receipt.json> [--keys <keys.json>] [--checkpoint <checkpoint.json>] [--json]

Verifies a Keelstamp receipt offline (no network access).
  --keys         public keys file (format keelstamp-keys-v1); default: ${DEFAULT_KEYS_NAME} next to the receipt
  --checkpoint   signed checkpoint (format keelstamp-checkpoint-file-v1); when given, the receipt's
                 inclusion proof is verified against it (RFC 9162)
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
      args[a.slice(2)] = argv[++i];
    } else if (a.startsWith('-')) throw new Error(`unknown option ${a}`);
    else if (args.receipt === undefined) args.receipt = a;
    else throw new Error(`unexpected argument ${a}`);
  }
  if (args.receipt === undefined) throw new Error('missing <receipt.json>');
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
  inclusion: '(e) inclusion in signed checkpoint',
};

function printHuman(result, files) {
  const out = [];
  out.push(result.ok ? 'VERIFIED' : 'NOT VERIFIED');
  const r = result.details.receipt ?? {};
  // Fields of a receipt that did not verify are only claims; say so next to them.
  const claim = result.ok ? '' : '  [claimed, not verified]';
  if (r.payload && r.profile) out.push(`  receipt    ${r.payload.receipt_id} (${r.profile}, event ${r.payload.event})${claim}`);
  if (r.signed_at) out.push(`  signed     ${r.signed_at} by key ${r.kid} (issuer ${r.iss})${claim}`);
  const inc = result.details.inclusion;
  const cp = result.details.checkpoint;
  if (inc && cp?.payload && result.checks.inclusion === 'pass') {
    out.push(`  log        leaf ${inc.leaf_index} of ${inc.tree_size} in ${inc.log_id}, checkpoint signed ${cp.signed_at}`);
  }
  out.push('  checks');
  for (const [check, label] of Object.entries(LABELS)) {
    let status = result.checks[check];
    if (check === 'inclusion' && status === 'skipped') status = 'skipped (no --checkpoint given)';
    out.push(`    ${label.padEnd(40, ' ')} ${status}`);
  }
  if (result.reasons.length) {
    out.push('  reasons');
    for (const reason of result.reasons) out.push(`    ${reason.code}: ${reason.message}`);
  }
  out.push(`  keys file  ${files.keys}${files.keysDefaulted ? ' (default: next to the receipt; make sure it is the keys file Keelstamp publishes)' : ''}`);
  if (files.checkpoint) out.push(`  checkpoint ${files.checkpoint}`);
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
  const files = {
    receipt: args.receipt,
    keys: args.keys ?? join(dirname(args.receipt), DEFAULT_KEYS_NAME),
    keysDefaulted: args.keys === undefined,
    checkpoint: args.checkpoint,
  };
  let receipt;
  let keys;
  let checkpoint;
  try {
    receipt = readFile(files.receipt, 'receipt');
    keys = readFile(files.keys, files.keysDefaulted ? 'keys (no --keys given; default)' : 'keys');
    if (files.checkpoint !== undefined) checkpoint = readFile(files.checkpoint, 'checkpoint');
  } catch (e) {
    console.error(`error: ${e.message}`);
    return EXIT_USAGE;
  }
  const toBytes = (buf) => new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  const result = verify(toBytes(receipt), toBytes(keys), checkpoint === undefined ? undefined : toBytes(checkpoint));
  if (args.json) console.log(JSON.stringify({ ...result, files }, null, 2));
  else printHuman(result, files);
  return result.ok ? EXIT_OK : EXIT_NOT_VERIFIED;
}

process.exitCode = main(process.argv.slice(2));
