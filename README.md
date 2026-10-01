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
| (a) | The COSE_Sign1 signature verifies with Ed25519 | RFC 9052, RFC 8032 |
| (b) | The payload is canonical JSON | RFC 8785 |
| (c) | The payload profile (`keelstamp-aac-v1`) is known and the payload matches it: only identifiers, digests and salted commitments, no plaintext | [SPEC.md](SPEC.md) §5 |
| (d) | The key id is in the keys file, belongs to the key listed there, and the key was valid at the signing time | RFC 7638, [SPEC.md](SPEC.md) §3 |
| (e) | When a checkpoint is given: the receipt is included in the log at the size and root hash the checkpoint signs | RFC 9162 |

Every failure has its own reason code (for example `SIGNATURE_INVALID`, `KID_UNKNOWN`,
`INCLUSION_PROOF_INVALID`); the full list is in [SPEC.md](SPEC.md) §9. The format itself, the choices
made and the open questions are in [SPEC.md](SPEC.md).

## Command line

Requires Node.js 22 or later (CI runs 22 and 24).

```sh
npm ci
node bin/verify.mjs <receipt.json> [--keys <keys.json>] [--checkpoint <checkpoint.json>] [--json]
```

- `--keys`: the public keys file. Default: `keelstamp-keys.json` in the receipt's directory, with a
  warning on stderr. Use the keys file the issuer publishes at `/.well-known/keelstamp-keys.json` or in
  the `keelstamphq/transparency` repository, not one that came with the receipt: whoever supplies the
  keys file decides which signatures count.
- `--checkpoint`: a signed checkpoint; when given, the receipt's inclusion proof is checked against it.
- `--json`: print the full result as JSON.

Exit codes: `0` verified, `1` not verified (the reasons are printed), `2` usage or file error.

Example with the test fixtures in this repository:

```console
$ node bin/verify.mjs tests/fixtures/valid.json --checkpoint tests/fixtures/checkpoint.json
VERIFIED
  receipt    <receipt id> (keelstamp-aac-v1, event action.approved)
  signed     <time> by key <key id> (issuer issuer.test.keelstamp.invalid)
  log        leaf 5 of 7 in log.test.keelstamp.invalid/v1, checkpoint signed <time>
  checks
    (a) signature (COSE_Sign1, Ed25519)      pass
    (b) payload is canonical JSON            pass
    (c) profile known, payload valid         pass
    (d) key listed and valid at iat          pass
    (e) inclusion in signed checkpoint       pass
  ...

$ node bin/verify.mjs tests/fixtures/invalid-altered-payload.json
NOT VERIFIED
  ...
  reasons
    SIGNATURE_INVALID: The Ed25519 signature does not verify: the signed content was changed, or it was not signed by the named key (key <key id>)
```

## Web page

```sh
npm ci
npm run build          # writes dist/keelstamp-verifier.html and prints its SHA-256
```

Open `dist/keelstamp-verifier.html` in a browser (no server needed), paste or choose the receipt,
the keys file and optionally a checkpoint, and press Verify. The page is one file with the verifier
inlined. Its Content-Security-Policy is `default-src 'none'` with the script and style pinned by
hash, so the browser blocks every network connection from the page. The build is reproducible: the
same commit gives the same file and SHA-256.

## As a library

```js
import { verify } from './src/index.mjs';

const result = verify(receiptJson, keysJson, checkpointJson /* optional */);
// { ok: boolean, reasons: [{ code, message }], checks: { signature, payload_jcs, profile, key, inclusion }, details }
```

Inputs may be parsed JSON, JSON text or UTF-8 bytes. `verify` never throws and reads no clock.

## Tests

```sh
npm test               # unit, POS/NEG, CLI, build and repository checks
npm run fixtures       # regenerate tests/fixtures/ with fresh throw-away keys
```

`tests/test-signer.mjs` is a small signer that builds receipts, checkpoints and keys files exactly as
SPEC.md describes, independently of the verifier code. Its keys are generated during the test run and
never stored; the committed fixtures contain public keys only. No real Keelstamp key is in this
repository.

## Layout

| Path | What |
|---|---|
| `src/` | The verifier: `verify.mjs` (checks a-e), `cose.mjs`, `jcs.mjs`, `merkle.mjs`, `keys.mjs`, `profiles.mjs`, `reasons.mjs` |
| `bin/verify.mjs` | Command-line tool |
| `web/` | Page template and browser glue; `scripts/build.mjs` turns them into one HTML file |
| `tests/` | Tests, the test signer and the fixtures |
| `SPEC.md` | Format specification, dependencies, open questions |

## License

Apache-2.0. See [LICENSE](LICENSE). Copyright 2026 PowerQuant ApS.
