# Keelstamp receipt verifier

> **Pre-release: the format may change before Keelstamp is in operation.**
> (Pre-release: format kan ændre sig, før Keelstamp er i drift.)

An offline verifier for Keelstamp receipts. It runs as a command-line tool (Node.js) and as a single
static HTML page, and makes no network access in either form.

Keelstamp issues a signed receipt for events it records for an end customer. With this verifier the
end customer can check a receipt themselves, using only public files, without relying on the agency
that forwarded it or on Keelstamp's servers.

## What it checks

| | Check | Standard |
|---|---|---|
| (a) | The COSE_Sign1 signature verifies with Ed25519 | RFC 9052, RFC 8032, RFC 9864 |
| (b) | The payload is canonical JSON | RFC 8785 |
| (c) | The payload profile (`keelstamp-aac-v1`) is known and the payload matches it: only identifiers, digests and salted commitments, no plaintext | [SPEC.md](SPEC.md) §5 |
| (d) | The key id is in the keys file, belongs to the key listed there, and the key was valid at the signing time | RFC 7638, [SPEC.md](SPEC.md) §3 |
| (e) | The receipt is in Keelstamp's log: its log receipt (a COSE Receipt in header 394) verifies over the Merkle root computed from the receipt and its inclusion proof. When a checkpoint is given, the root must also match the checkpoint's root. | RFC 9942, RFC 9943, RFC 9162 |

Every failure has its own reason code (for example `SIGNATURE_INVALID`, `KID_UNKNOWN`,
`INCLUSION_PROOF_INVALID`); the full list is in [SPEC.md](SPEC.md) §10. The format itself, the choices
made and the open questions are in [SPEC.md](SPEC.md).

## Where the keys come from

The verifier uses only the keys file you give it. It never reads a keys file that lies next to the
receipt, and never uses keys that come with the receipt. Get the keys file from Keelstamp:
`https://<issuer>/.well-known/keelstamp-keys.json` or the `keelstamphq/transparency` repository.
Whoever supplies the keys file decides which signatures count. The CLI and the web page show the
SHA-256 of the keys file they used, so you can compare it with the published one.

## Command line

Requires Node.js 22 or later (CI runs 22 and 24).

```sh
npm ci
node bin/verify.mjs <receipt.json> --keys <keys.json> [--checkpoint <checkpoint.json>] [--json]
```

- `--keys` (required, no default): the public keys file Keelstamp publishes.
- `--checkpoint`: a signed checkpoint. When given, the root proven by the receipt's log receipt must
  be the root the checkpoint signs for the same tree size.
- `--json`: print the full result as JSON.

Exit codes: `0` verified, `1` not verified (the reasons are printed), `2` usage or file error
(including a missing `--keys`).

Example with the test fixtures in this repository (test keys in `tests/keys/`, kept apart from the
receipts in `tests/fixtures/`):

```console
$ node bin/verify.mjs tests/fixtures/valid.json --keys tests/keys/keelstamp-keys.json --checkpoint tests/fixtures/checkpoint.json
VERIFIED
  receipt    <receipt id> (keelstamp-aac-v1, event action.approved)
  signed     <time> by key <key id> (issuer issuer.test.keelstamp.invalid)
  log        leaf 5 of 7 in log.test.keelstamp.invalid/v1, log receipt signed <time>, same root as checkpoint signed <time>
  checks
    (a) signature (COSE_Sign1, Ed25519)        pass
    (b) payload is canonical JSON              pass
    (c) profile known, payload valid           pass
    (d) key listed and valid at iat            pass
    (e) inclusion in the log (RFC 9942/9162)   pass (log receipt; matches checkpoint)
  keys file  tests/keys/keelstamp-keys.json
             sha256 <sha-256 of the keys file>  (compare with the keys file Keelstamp publishes)
             issuer issuer.test.keelstamp.invalid, 3 keys: <kid> (statement), <kid> (log), <kid> (statement)
  ...

$ node bin/verify.mjs tests/fixtures/invalid-altered-payload.json --keys tests/keys/keelstamp-keys.json
NOT VERIFIED
  ...
  reasons
    SIGNATURE_INVALID: The Ed25519 signature does not verify: ...
    INCLUSION_PROOF_INVALID: The log receipt does not verify over the Merkle root computed from this receipt ...

$ node bin/verify.mjs tests/fixtures/valid.json
error: --keys <keys.json> is required: give the keys file Keelstamp publishes. ...
```

## Web page

```sh
npm ci
npm run build          # writes dist/keelstamp-verifier.html and prints its SHA-256
```

Open `dist/keelstamp-verifier.html` in a browser (no server needed). Paste or choose the receipt, the
keys file Keelstamp publishes and, optionally, a checkpoint, then press Verify.

- **Keys:** only the keys field is used. Under that field, and again in the result, the page shows
  which keys file is in use: the file name (or "pasted text"), its SHA-256, its issuer and its keys.
- **One file:** the page has the verifier inlined.
- **No network:** its Content-Security-Policy is `default-src 'none'` with the script and style pinned
  by hash, so the browser blocks every network connection from the page.
- **Reproducible:** the same commit gives the same file and SHA-256.

## As a library

```js
import { verify } from './src/index.mjs';

const result = verify(receiptJson, keysJson, checkpointJson /* optional */);
// { ok: boolean, reasons: [{ code, message }], checks: { signature, payload_jcs, profile, key, inclusion }, details }
```

Inputs may be parsed JSON, JSON text or UTF-8 bytes. `verify` never throws and reads no clock. The
`keys` argument is the only source of keys; without it the result is `KEYS_MALFORMED`.

## Tests

```sh
npm test               # unit, POS/NEG, CLI, web, build and repository checks
npm run fixtures       # regenerate tests/fixtures/ and tests/keys/ with fresh throw-away keys
```

`tests/test-signer.mjs` is a small signer that builds receipts with their log receipts, checkpoints and
keys files exactly as SPEC.md describes, independently of the verifier code. Its keys are generated
during the test run and never stored; the committed fixtures contain public keys only. No real
Keelstamp key is in this repository.

## Layout

| Path | What |
|---|---|
| `src/` | The verifier: `verify.mjs` (checks a-e), `cose.mjs` (COSE_Sign1, RFC 9942 labels), `jcs.mjs`, `merkle.mjs`, `keys.mjs`, `profiles.mjs`, `reasons.mjs` |
| `bin/verify.mjs` | Command-line tool |
| `web/` | Page template and browser glue; `scripts/build.mjs` turns them into one HTML file |
| `tests/` | Tests, the test signer, the fixtures (`tests/fixtures/`) and their keys files (`tests/keys/`) |
| `SPEC.md` | Format specification, dependencies, open questions |

## License

Apache-2.0. See [LICENSE](LICENSE). Copyright 2026 PowerQuant ApS.
