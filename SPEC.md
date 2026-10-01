# Keelstamp receipt format: `keelstamp-aac-v1` (pre-release)

**Pre-release: the format may change before Keelstamp is in operation.** The signer side is not built
yet. Until it is, this repository is the executable specification: this document, the verifier in
`src/` and the test signer in `tests/test-signer.mjs` describe the same format, and a difference
between them is a bug. Choices that the RFCs leave open, or that had to be made without a decision,
are listed under [Open questions for the CTO](#open-questions-for-the-cto-åbne-spørgsmål-til-cto).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119 / RFC 8174.

## 1. Overview

Keelstamp issues a signed receipt for each event it records for an end customer (for example an
approval in the approval inbox). A receipt can be checked by anyone holding three public files,
without network access and without trusting the agency that forwarded it:

| File | Format id | Published where |
|---|---|---|
| Receipt file | `keelstamp-receipt-file-v1` | Given to the end customer |
| Keys file | `keelstamp-keys-v1` | `https://<issuer>/.well-known/keelstamp-keys.json` and the `keelstamphq/transparency` repository |
| Checkpoint file | `keelstamp-checkpoint-file-v1` | Daily, in the `keelstamphq/transparency` repository |

A receipt is a COSE_Sign1 signed statement (RFC 9052) shaped as an RFC 9943 (SCITT) Signed
Statement, signed with Ed25519. Its payload is JSON in RFC 8785 canonical form and contains only
identifiers, digests and salted commitments, never plaintext. Receipts are appended to a Merkle log
(RFC 9162, SHA-256); a daily checkpoint signs the log's size and root hash, and the receipt file
carries an RFC 9162 inclusion proof against such a checkpoint.

## 2. Conventions

- JSON files are UTF-8 without a byte order mark.
- Binary values in JSON files are **base64url without padding** (RFC 4648 §5). Decoders MUST reject
  padding, characters outside the URL-safe alphabet, and non-canonical encodings (non-zero unused bits).
- Hash values in JSON files are **lowercase hex** (64 characters for SHA-256).
- Times in JSON files are RFC 3339 UTC with second precision: `YYYY-MM-DDThh:mm:ssZ`. Times inside
  signed statements are CWT NumericDate integers (seconds since 1970-01-01T00:00:00Z).
- Every JSON object defined here has a fixed member set. Verifiers MUST reject unknown members; new
  members require a new format or profile id.

## 3. Keys file (`keelstamp-keys-v1`)

```json
{
  "format": "keelstamp-keys-v1",
  "issuer": "<issuer string, equal to the CWT iss of every statement>",
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<32-byte public key, base64url>",
      "kid": "<RFC 7638 JWK Thumbprint of this key, base64url>",
      "purpose": "receipt",
      "valid_from": "YYYY-MM-DDThh:mm:ssZ",
      "valid_until": null
    }
  ]
}
```

- The file is a JWK Set (RFC 7517) whose entries are Ed25519 OKP keys (RFC 8037) with three extra
  members: `purpose`, `valid_from` and `valid_until`.
- `kid` MUST be the RFC 7638 JWK Thumbprint of the key: SHA-256 over the UTF-8 bytes of
  `{"crv":"Ed25519","kty":"OKP","x":"<x>"}`, base64url. A key id is thereby bound to one key, and no
  later version of the keys file can list another key under an existing id. The verifier recomputes
  the thumbprint and reports `KEY_MISMATCH` when it differs.
- `purpose` is `receipt` or `checkpoint`. A key signs only statements of its purpose.
- The validity window is half-open: a statement is accepted when
  `valid_from <= iat < valid_until` (`valid_until: null` means open-ended). Retired keys stay in the
  file with a `valid_until`, so receipts signed while they were valid keep verifying.
- `x` MUST be a canonical encoding of a point that is not of small order; `kid` values MUST be unique;
  a JWK private member (`d`) is an unknown member and makes the file invalid.

## 4. Signed statements (COSE_Sign1)

Receipts and checkpoints are both encoded as:

```
COSE_Sign1_Tagged = #6.18([
  protected:   bstr .cbor { 1: -19, 3: "application/json", 4: kid, 15: { 1: iss, 2: sub, 6: iat } },
  unprotected: {},
  payload:     bstr,        ; attached; RFC 8785 canonical JSON
  signature:   bstr         ; 64 bytes, Ed25519
])
```

- **Tag**: the CBOR tag 18 MUST be present. Untagged structures and other tags are rejected.
- **Protected header**: exactly these parameters (IANA "COSE Header Parameters"):
  - `1` (alg) = `-19`, the fully-specified COSE algorithm identifier for Ed25519 (RFC 9864). The
    polymorphic `-8` (EdDSA) and every other value are rejected (`ALG_UNSUPPORTED`).
  - `3` (content type) = `"application/json"`.
  - `4` (kid) = the 32 raw bytes of the signing key's JWK Thumbprint (section 3).
  - `15` (CWT Claims, RFC 9597) = a map with exactly `1` (iss, text), `2` (sub, text) and `6`
    (iat, non-negative integer).
  Any other parameter, including `2` (crit), is rejected (`COSE_HEADER_INVALID`). Signers SHOULD use
  core deterministic CBOR encoding (RFC 8949 §4.2.1) for the protected header; verifiers decode it as
  is and do not re-encode it.
- **Unprotected header**: MUST be an empty map.
- **Payload**: MUST be attached (detached payloads are rejected).
- **Signature**: Ed25519 (RFC 8032) over the Sig_structure of RFC 9052 §4.4:
  `["Signature1", protected, h'', payload]` with an empty external_aad.
  Verification follows the strict RFC 8032 / FIPS 186-5 rules (canonical encodings, small-order
  public keys rejected), not ZIP-215.
- **Strict CBOR**: verifiers MUST reject non-minimal integer or length encodings, indefinite-length
  items, duplicate map keys, `undefined`, NaN/Infinity, integers outside ±(2^53−1), unknown tags and
  trailing bytes after the structure (`COSE_MALFORMED`). Text strings in the header that do not decode
  as valid UTF-8 are rejected.
- **Issuer, subject, time**: `iss` MUST equal the keys file's `issuer`. `sub` is bound to the payload
  by the profile (sections 5 and 6). `iat` is the signing time used for the key validity check.

## 5. Receipt profile `keelstamp-aac-v1`

The payload is a JSON object, serialized with RFC 8785 (JCS), with exactly these members:

| Member | Syntax | Meaning |
|---|---|---|
| `profile` | `"keelstamp-aac-v1"` | Profile and version. Unknown values are rejected (`PROFILE_UNKNOWN`). |
| `receipt_id` | `[A-Za-z0-9_-]{16,64}` | Identifier of this receipt. MUST equal the CWT `sub`. |
| `partner` | `sha256:<64 hex>` | Salted commitment to the partner (agency) identity. |
| `tenant` | `sha256:<64 hex>` | Salted commitment to the end customer identity. |
| `event` | dotted lowercase identifier, e.g. `action.approved` | What happened. |
| `digests` | non-empty object, names `[a-z][a-z0-9_]{0,31}`, values `sha256:<64 hex>` | Digests of the material the event refers to (for example request and response). |

The syntax leaves no room for free text: a payload carrying names, e-mail addresses, amounts or
other plaintext fails validation (`PAYLOAD_SCHEMA_INVALID`) even when it is correctly signed.

**Canonical form check.** The verifier decodes the payload as strict UTF-8, parses it as JSON,
serializes the result with RFC 8785, and requires the result to be byte-identical to the payload
(`PAYLOAD_NOT_JCS` otherwise). This rejects whitespace, unsorted or duplicate members, non-canonical
numbers (`1.0`, `1e3`, `-0`, integers beyond 2^53), unnecessary escapes and lone surrogates.

## 6. Checkpoint profile `keelstamp-checkpoint-v1`

A checkpoint is a signed statement (section 4), signed with a `checkpoint` key, whose payload has
exactly these members:

| Member | Syntax | Meaning |
|---|---|---|
| `profile` | `"keelstamp-checkpoint-v1"` | Profile and version. |
| `log_id` | `[A-Za-z0-9][A-Za-z0-9._/-]{0,127}` | The log. MUST equal the CWT `sub`. |
| `tree_size` | non-negative integer | Number of entries in the log. |
| `root_hash` | 64 lowercase hex | RFC 9162 Merkle Tree Hash of those entries. |

The checkpoint file wraps it:

```json
{ "format": "keelstamp-checkpoint-file-v1", "checkpoint": "<COSE_Sign1_Tagged bytes, base64url>" }
```

## 7. Log and inclusion proofs (RFC 9162)

- The log is the Merkle tree of RFC 9162 §2.1.1 with SHA-256: leaf hash `SHA-256(0x00 || entry)`,
  interior node `SHA-256(0x01 || left || right)`.
- The log **entry** for a receipt is the exact COSE_Sign1_Tagged byte string from the receipt file.
  The leaf therefore covers the payload, the protected header and the signature.
- The inclusion proof has the fields of RFC 9162 `inclusion_proof_v2` in JSON form:

  ```json
  { "log_id": "...", "tree_size": 7, "leaf_index": 5, "inclusion_path": ["<64 hex>", "..."] }
  ```

  `tree_size >= 1`, `0 <= leaf_index < tree_size`, and the path lists sibling hashes from the leaf
  upward (RFC 9162 §2.1.3.1).
- Verification (check (e)), only when a checkpoint is given:
  1. The checkpoint passes checks (a)-(d) as a `checkpoint` statement; failures are reported with the
     `CHECKPOINT_` prefix and no inclusion is evaluated against an unauthenticated root.
  2. `proof.log_id` MUST equal the checkpoint's `log_id` (`CHECKPOINT_LOG_MISMATCH`).
  3. `proof.tree_size` MUST equal the checkpoint's `tree_size` (`CHECKPOINT_TREE_SIZE_MISMATCH`). The
     same audit path can fit more than one tree size, so the size must come from the signed checkpoint.
  4. The root computed with the algorithm of RFC 9162 §2.1.3.2 from the leaf hash, `leaf_index`,
     `tree_size` and `inclusion_path` MUST equal `root_hash` (`INCLUSION_PROOF_INVALID`). A wrong path,
     a wrong index and a validly signed checkpoint of a tree that does not contain the receipt all end
     here; they cannot be told apart from the proof alone.
  5. The receipt's `iat` MUST NOT be later than the checkpoint's `iat` (`RECEIPT_AFTER_CHECKPOINT`).

## 8. Receipt file (`keelstamp-receipt-file-v1`)

```json
{
  "format": "keelstamp-receipt-file-v1",
  "receipt": "<COSE_Sign1_Tagged bytes, base64url>",
  "inclusion_proof": { "log_id": "...", "tree_size": 7, "leaf_index": 5, "inclusion_path": ["..."] }
}
```

`inclusion_proof` is optional. When present it MUST be well-formed even if no checkpoint is given
(`INCLUSION_PROOF_MALFORMED`). When a checkpoint is given and the proof is absent, verification fails
(`INCLUSION_PROOF_MISSING`).

## 9. Verification result

`verify(receipt, keys, checkpoint?)` takes the three files (parsed JSON, JSON text or UTF-8 bytes) and
returns:

```js
{
  ok: boolean,                // true only if every required check passed and no reason was recorded
  reasons: [{ code, message }],
  checks: { signature, payload_jcs, profile, key, inclusion },   // "pass" | "fail" | "skipped"
  details: { receipt, checkpoint, inclusion, keys_issuer }       // decoded fields, for display
}
```

Checks (a)-(d) are required. Check (e) is `skipped` without a checkpoint. The verifier is
fail-closed: it never throws, an unexpected exception becomes `INTERNAL_ERROR`, and a required check
that did not run makes `ok` false. It reads no clock and makes no network access, so the result
depends only on its inputs. Fields shown for a receipt that did not verify are claims, and the CLI and
the web page label them so.

| Code | Check | Meaning |
|---|---|---|
| `RECEIPT_MALFORMED` | input | Receipt file is not valid JSON or not `keelstamp-receipt-file-v1` |
| `KEYS_MALFORMED` | input | Keys file is not valid JSON or not `keelstamp-keys-v1` |
| `CHECKPOINT_MALFORMED` | (e) | Checkpoint file is not valid JSON or not `keelstamp-checkpoint-file-v1` |
| `COSE_MALFORMED` | (a) | Not a strict COSE_Sign1_Tagged structure with attached payload |
| `COSE_HEADER_INVALID` | (a) | Header parameters or CWT claims do not match section 4 |
| `ALG_UNSUPPORTED` | (a) | `alg` is not `-19` |
| `SIGNATURE_INVALID` | (a) | Signature does not verify with the key the kid names (content changed, or signed by an unlisted key) |
| `WRONG_KEY` | (a) | Signature verifies with a different key from the keys file than the kid names |
| `PAYLOAD_NOT_JCS` | (b) | Payload is not RFC 8785 canonical JSON |
| `PROFILE_UNKNOWN` | (c) | `profile` missing or not a known profile for this kind of statement |
| `PAYLOAD_SCHEMA_INVALID` | (c) | Payload does not match its profile |
| `SUBJECT_MISMATCH` | (c) | CWT `sub` differs from the payload member it is bound to |
| `KID_UNKNOWN` | (d) | kid not in the keys file |
| `KEY_MISMATCH` | (d) | The keys file lists a key under this kid that is not the key's thumbprint |
| `KEY_PURPOSE_MISMATCH` | (d) | Key `purpose` does not match the statement kind |
| `ISSUER_MISMATCH` | (d) | CWT `iss` differs from the keys file `issuer` |
| `KEY_NOT_VALID_AT_TIME` | (d) | `iat` outside `[valid_from, valid_until)` |
| `INCLUSION_PROOF_MISSING` | (e) | Checkpoint given, no inclusion proof |
| `INCLUSION_PROOF_MALFORMED` | (e) | Inclusion proof fields invalid |
| `INCLUSION_PROOF_INVALID` | (e) | Path does not lead to the checkpoint root |
| `CHECKPOINT_LOG_MISMATCH` | (e) | Proof and checkpoint name different logs |
| `CHECKPOINT_TREE_SIZE_MISMATCH` | (e) | Proof and checkpoint have different tree sizes |
| `RECEIPT_AFTER_CHECKPOINT` | (e) | Receipt `iat` later than checkpoint `iat` |
| `CHECKPOINT_<code>` | (e) | Any statement code above (`COSE_MALFORMED` … `WRONG_KEY`), for the checkpoint |
| `INTERNAL_ERROR` | all | Unexpected error; treated as not verified |

## 10. What a successful verification shows, and what it does not

It shows that the payload was signed, unchanged, by the key that the keys file lists under the
receipt's key id, during that key's validity window, and (with a checkpoint) that the receipt is an
entry of the log whose size and root the checkpoint key signed.

It does not show:

- that the keys file is Keelstamp's. The verifier trusts the keys file it is given; obtain it from
  the issuer's `/.well-known/keelstamp-keys.json` or from the transparency repository, not from the
  party that forwarded the receipt.
- that `iat` is the true signing time. A holder of a valid key can choose `iat`. Inclusion in a
  checkpoint bounds it from above (`RECEIPT_AFTER_CHECKPOINT`); nothing here bounds it from below.
- that the log is append-only or that everyone sees the same log. That needs consistency proofs
  between checkpoints (RFC 9162 §2.1.4), which this version does not verify.
- anything about the commitments' underlying values. Checking a commitment requires the salt and
  the value, which the verifier does not have.

## 11. Dependencies

Runtime dependencies are pinned to exact versions, have no dependencies of their own, and are
bundled into the web page together with their license texts.

| Package | Version | License | Why |
|---|---|---|---|
| `@noble/ed25519` | 3.2.0 | MIT | Ed25519 verification in plain JavaScript that runs unchanged in Node and browsers, with a strict RFC 8032 / FIPS 186-5 mode (`zip215: false`) that rejects non-canonical encodings and small-order keys. Node's own `crypto` is not available in browsers. |
| `@noble/hashes` | 2.4.0 | MIT | SHA-256 (Merkle tree, JWK Thumbprint) and SHA-512 (required by Ed25519) as synchronous plain JavaScript. WebCrypto is asynchronous and some browsers expose it only in secure contexts, which a page opened from disk may not be. |
| `cborg` | 6.1.3 | Apache-2.0 | CBOR decoding with the strictness the format requires (minimal-length integers, duplicate-key rejection, no indefinite lengths, tags only when enabled, trailing bytes rejected) and deterministic encoding of the Sig_structure. |
| `esbuild` | 0.28.2 | MIT | Build only (devDependency): bundles the verifier into one inline script for the single-file web page. Not shipped. The output is reproducible (tested). |

RFC 8785 canonicalization (about 40 lines, since RFC 8785 is defined in terms of ECMAScript's own
number and string serialization), the RFC 9162 inclusion check (about 30 lines), base64url and hex are
implemented in `src/` instead of adding packages for them.

## 12. Test vectors

- `tests/test-signer.mjs` produces receipts, checkpoints and keys files from this document. It shares
  no code with `src/`: Ed25519 and SHA-256 come from `node:crypto`, CBOR from its own encoder, and the
  Merkle tree from the recursive definitions of RFC 9162 §2.1.1 and §2.1.3.1.
- `tests/fixtures/` holds committed vectors generated by `npm run fixtures`. Their keys existed only
  while the generator ran; the fixtures contain public keys only. `tests/fixtures/expected.json`
  lists the expected exit code and reason for each case.
- Published vectors used in the tests: RFC 8032 §7.1 test 1 (Ed25519), RFC 8037 Appendix A.3 (JWK
  Thumbprint of that key), RFC 8785 §3.2.2 and §3.2.3 (canonical JSON), and the Certificate
  Transparency reference tree heads for sizes 1-8.

## Open questions for the CTO (Åbne spørgsmål til CTO)

Each item is a choice made in this version so that work could continue. All are reversible by
issuing a new profile or format id.

1. **RFC references could not be re-read here.** rfc-editor.org and datatracker.ietf.org are blocked
   by this environment's network policy, so the RFC 9943, RFC 9864 and RFC 9597 details above are
   from memory and need a check against the published text before the format is frozen. RFC 9942 is
   referenced in project planning; which document it is could not be confirmed here, and it is not
   used.
2. **Algorithm identifier `-19` (Ed25519) only.** Chosen because it names one curve. Many COSE
   libraries still emit `-8` (EdDSA). Does the planned signer library support `-19`? If not: accept
   `-8` with an Ed25519 key, or change library?
3. **SCITT shape.** The protected header carries `iss` and `sub` in CWT Claims, a `kid` and a content
   type, and nothing else; there is no `typ` (label 16) and the content type is the generic
   `application/json`. Should receipts carry an explicit type (e.g. a dedicated media type) so that a
   receipt can never be mistaken for another JSON statement signed by the same key?
4. **Profile id only in the payload.** The `profile` member selects the schema; it is signed but not in
   the protected header. Fine, or also put it in the header?
5. **Inclusion proof outside COSE.** The unprotected header must be empty and the inclusion proof sits
   next to the COSE bytes in the JSON receipt file. The alternative is a COSE Receipt in the
   unprotected header (SCITT label 394, verifiable data structure `RFC9162_SHA256`), which would also
   change what the leaf covers. Which one for v1?
6. **Log entry = the exact COSE_Sign1 bytes.** Not the payload or its hash. Changing a byte of the
   statement (including the unprotected header) therefore changes the leaf. Agreed?
7. **Checkpoint format.** Checkpoints reuse the COSE_Sign1 + JCS machinery (one parser, one signature
   path). The common alternative in transparency logs is the C2SP signed-note checkpoint, which would
   let existing witness tooling cosign Keelstamp checkpoints. Keep COSE, or switch?
8. **`log_id` is a string**, not the DER-encoded OID of RFC 9162. What should the production value be?
9. **No consistency proofs.** An inclusion proof is checked only against a checkpoint of exactly the
   same `tree_size`, so a receipt must be verified with the checkpoint its proof was made for (or the
   log must hand out fresh proofs). Should the verifier accept a consistency proof (RFC 9162 §2.1.4)
   so that any later daily checkpoint can be used?
10. **Key ids are RFC 7638 JWK Thumbprints** (raw 32 bytes in the COSE `kid`). RFC 9679 (COSE Key
    Thumbprint) is the COSE-native alternative. Either binds the id to the key; JWK was chosen because
    the keys file is a JWK Set.
11. **Key compromise.** There is no revocation list. Setting `valid_until` to the compromise time
    rejects later `iat` values, but a holder of the stolen key can back-date `iat`. Should receipts
    signed with a key be accepted only when included in a checkpoint signed before the key's
    `valid_until`? (That would make the checkpoint mandatory for older receipts.)
12. **Default keys file in the CLI.** Without `--keys` the CLI reads `keelstamp-keys.json` next to the
    receipt (the acceptance command `node bin/verify.mjs tests/fixtures/valid.json` needs a default) and
    prints a warning. Once production keys exist, should the verifier pin them, or require `--keys`?
    Should the keys file itself be signed or only published with history in the transparency repo?
13. **Inclusion is optional.** Without a checkpoint the result is `ok` with check (e) `skipped`, as
    specified for this version. Should the CLI get a `--require-checkpoint` flag, or should (e) become mandatory
    once checkpoints are published?
14. **Receipt payload members are a placeholder** (`receipt_id`, `partner`, `tenant`, `event`,
    `digests`). Open: the event vocabulary (closed list?), whether amounts appear as intervals, and
    how commitments are computed (proposal: `SHA-256(salt || value)` with a per-tenant salt, or HMAC).
    Should the verifier also offer an end customer a "check my commitment" step given salt and value?
15. **Production issuer string** (`iss`, keys file `issuer`): `keelstamp.com`? Tests use
    `issuer.test.keelstamp.invalid`.
16. **`iat` in whole seconds**, as an integer. A CBOR float that encodes a whole number is accepted
    because the decoder cannot tell them apart; sub-second times are rejected.
17. **Strict Ed25519.** The verifier uses RFC 8032 / FIPS 186-5 rules. Standard signers produce
    signatures that pass; only crafted edge cases differ from ZIP-215 verifiers.
18. **Invalid UTF-8 in CBOR text** (header `iss`, `sub`, content type) is detected through the
    decoder's replacement character, so a header string containing U+FFFD is rejected. Acceptable, or
    decode text strings byte-exactly?
19. **Distribution of the web page.** `npm run build` writes `dist/keelstamp-verifier.html` (not
    committed). Publish it as a release asset with its SHA-256, and/or on GitHub Pages? Opening it from
    disk works; the CSP blocks network access either way.
20. **No input size limits.** The verifier runs locally on files the user chose; no limits are
    imposed on file size or path length.
