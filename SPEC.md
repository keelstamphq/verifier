# Keelstamp receipt format: `keelstamp-aac-v1` (pre-release)

**Pre-release: the format may change before Keelstamp is in operation.** The signer side is not built
yet. Until it is, this repository is the executable specification: this document, the verifier in
`src/` and the test signer in `tests/test-signer.mjs` describe the same format, and a difference
between them is a bug. Choices that the RFCs leave open, or that had to be made without a decision,
are listed under [Open questions for the CTO](#open-questions-for-the-cto-åbne-spørgsmål-til-cto).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119 / RFC 8174.

## 1. Overview

Keelstamp issues a signed receipt for each event it records for an end customer (for example an
approval in the approval inbox). A receipt can be checked by anyone holding public files, without
network access and without trusting the agency that forwarded it:

| File | Format id | Where it comes from |
|---|---|---|
| Receipt file | `keelstamp-receipt-file-v1` | Given to the end customer |
| Keys file | `keelstamp-keys-v1` | Published by Keelstamp: `https://<issuer>/.well-known/keelstamp-keys.json` and the `keelstamphq/transparency` repository. Never taken from the receipt or from next to it (section 9). |
| Checkpoint file (optional) | `keelstamp-checkpoint-file-v1` | Daily, in the `keelstamphq/transparency` repository |

A receipt is a COSE_Sign1 structure signed with Ed25519, which RFC 9943 calls a Signed Statement. Its
payload is JSON in RFC 8785 canonical form and contains only identifiers, digests and salted
commitments, never plaintext. Keelstamp's log (an RFC 9162 Merkle tree with SHA-256) records the
receipt as an entry and returns a **log receipt**: a COSE Receipt (RFC 9942) that carries an
inclusion proof and the log's signature over the tree's root. The log receipt goes in the receipt's
unprotected header under label 394. Once a day the log also publishes a signed checkpoint with its
tree size and root hash.

### Standards used

| RFC | Title | Used for |
|---|---|---|
| RFC 9052 | CBOR Object Signing and Encryption (COSE): Structures and Process | COSE_Sign1, Sig_structure |
| RFC 9864 | Fully-Specified Algorithms for JOSE and COSE | `alg` -19 = Ed25519 (-53 = Ed448 is not used) |
| RFC 9597 | CWT Claims in COSE Headers | protected header label 15 |
| RFC 9943 | An Architecture for Trustworthy and Transparent Digital Supply Chains (SCITT) | Signed Statements are COSE_Sign1; receipts go in the unprotected header, label 394 |
| RFC 9942 | CBOR Object Signing and Encryption (COSE) Receipts | labels 394 (receipts), 395 (vds), 396 (vdp); vds 1 = RFC9162_SHA256; inclusion proof = vdp -1, consistency proof = vdp -2 |
| RFC 9162 | Certificate Transparency Version 2.0 | Merkle tree hashing and the inclusion proof algorithm |
| RFC 8785 | JSON Canonicalization Scheme (JCS) | payload encoding |
| RFC 8032 | Edwards-Curve Digital Signature Algorithm (EdDSA) | Ed25519 |
| RFC 7638 | JSON Web Key (JWK) Thumbprint | key ids |
| RFC 8392 | CBOR Web Token (CWT) | claim keys `iss` (1), `sub` (2), `iat` (6) |

The titles, labels and values given here for RFC 9942, RFC 9943, RFC 9864 and RFC 9597 come from the
CTO's lookup on rfc-editor.org on 2026-10-01; rfc-editor.org could not be reached from the
environment this document was written in. Details that have not been checked against the published
texts are listed in open question 1.

## 2. Conventions

- JSON files are UTF-8 without a byte order mark.
- Binary values in JSON files are **base64url without padding** (RFC 4648 §5). Decoders MUST reject
  padding, characters outside the URL-safe alphabet, and non-canonical encodings (non-zero unused bits).
- Hash values in JSON files are **lowercase hex** (64 characters for SHA-256).
- Times in JSON files are RFC 3339 UTC with second precision: `YYYY-MM-DDThh:mm:ssZ`. Times inside
  COSE structures are CWT NumericDate integers (seconds since 1970-01-01T00:00:00Z).
- Every JSON object defined here has a fixed member set. Verifiers MUST reject unknown members; new
  members require a new format or profile id.
- JSON files MUST NOT contain duplicate member names in any object (compared after escape decoding).
  Verifiers MUST reject them: parsers disagree on which duplicate wins, so a file with duplicates can
  be read as two different documents.

## 3. Keys file (`keelstamp-keys-v1`)

```json
{
  "format": "keelstamp-keys-v1",
  "issuer": "<issuer string, equal to the CWT iss of every statement and log receipt>",
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "<32-byte public key, base64url>",
      "kid": "<RFC 7638 JWK Thumbprint of this key, base64url>",
      "purpose": "statement",
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
- `purpose` is `statement` (signs receipts) or `log` (signs log receipts and checkpoints). A key signs
  only what its purpose allows.
- The validity window is half-open: a signature is accepted when `valid_from <= iat < valid_until`.
  `valid_until` is required; only an explicit `null` means open-ended (a missing member is an error,
  never an open-ended key). Retired keys stay in the file with a `valid_until`, so receipts signed
  while they were valid keep verifying.
- `x` MUST be a canonical encoding of a point of the prime-order subgroup: not of small order and
  without a torsion component (a genuine Ed25519 public key never has one). A key with a torsion
  component would let this verifier, which uses the cofactored equation, and a cofactorless one
  such as OpenSSL reach different verdicts on the same honest signature, so the keys file is
  rejected (`KEYS_MALFORMED`). `kid` values MUST be unique; a JWK private member (`d`) is an unknown
  member and makes the file invalid.

## 4. Signed statements (COSE_Sign1)

Receipts and checkpoints are both encoded as:

```
COSE_Sign1_Tagged = #6.18([
  protected:   bstr .cbor { 1: -19, 3: "application/json", 4: kid, 15: { 1: iss, 2: sub, 6: iat } },
  unprotected: { ? 394: [ bstr ] },   ; receipts only: the log receipt (section 7); checkpoints: {}
  payload:     bstr,                  ; attached; RFC 8785 canonical JSON
  signature:   bstr                   ; 64 bytes, Ed25519
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
  Any other parameter, including `2` (crit) and any key material such as a COSE_Key or a certificate
  chain, is rejected (`COSE_HEADER_INVALID`). Signers SHOULD use core deterministic CBOR encoding
  (RFC 8949 §4.2.1) for the protected header; verifiers decode it as is and do not re-encode it.
- **Unprotected header**: a receipt's unprotected header MAY contain label 394 (receipts, RFC 9942 /
  RFC 9943) and nothing else; a checkpoint's MUST be empty (`COSE_HEADER_INVALID`). The unprotected
  header is not covered by the signature; the log receipt in it is verified on its own (section 7).
- **Payload**: MUST be attached (detached payloads are rejected).
- **Signature**: Ed25519 (RFC 8032) over the Sig_structure of RFC 9052 §4.4:
  `["Signature1", protected, h'', payload]` with an empty external_aad.
  Verification follows the strict RFC 8032 / FIPS 186-5 rules (canonical encodings, small-order
  public keys rejected), not ZIP-215. Public keys with a torsion component are already rejected when
  the keys file is read (section 3).
- **Strict CBOR**: verifiers MUST reject non-minimal integer or length encodings, indefinite-length
  items, duplicate map keys, `undefined`, NaN/Infinity, integers outside ±(2^53−1), unknown tags,
  trailing bytes after the structure, **any floating-point value** (a float `1.0` must not pass as the
  integer label `1`), and **text strings that are not valid UTF-8 or that a decoder would alter**
  (for example by dropping a leading U+FEFF) (`COSE_MALFORMED`).
- **Issuer, subject, time**: `iss` MUST equal the keys file's `issuer`. `sub` is bound to the payload
  by the profile (sections 5 and 6). `iat` is the signing time used for the key validity check.
- **Key purpose**: receipts are signed with a `statement` key, checkpoints with a `log` key
  (`KEY_PURPOSE_MISMATCH`).

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

A checkpoint is a signed statement (section 4), signed with a `log` key, whose payload has exactly
these members:

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

## 7. Log, log receipts (RFC 9942) and checkpoints

### 7.1 Log and log entry

- The log is the Merkle tree of RFC 9162 §2.1.1 with SHA-256: leaf hash `SHA-256(0x00 || entry)`,
  interior node `SHA-256(0x01 || left || right)`.
- The log **entry** for a receipt is the receipt as it was signed: its COSE_Sign1_Tagged encoding
  with the unprotected header replaced by the empty map,
  `#6.18([protected, {}, payload, signature])`. These are the bytes of the receipt before any log
  receipt is attached. The leaf thus covers the protected header, the payload and the signature,
  but not the log receipts that prove it. Strict decoding (minimal-length heads) means these bytes
  have exactly one encoding.

### 7.2 Log receipt (COSE Receipt)

The receipt's unprotected header carries the log receipt under label 394:

```
394: [ bstr .cbor COSE_Receipt ]       ; exactly one in this version

COSE_Receipt = #6.18([
  protected:   bstr .cbor { 1: -19, 4: kid, 15: { 1: iss, 2: log_id, 6: iat }, 395: 1 },
  unprotected: { 396: { -1: [ bstr .cbor inclusion-proof ] } },
  payload:     nil,        ; detached: the RFC 9162 root hash (32 bytes), recomputed by the verifier
  signature:   bstr        ; Ed25519 by a `log` key over ["Signature1", protected, h'', root]
])

inclusion-proof = [ tree-size: uint, leaf-index: uint, inclusion-path: [ * bstr .size 32 ] ]
```

- `395` (vds) MUST be `1`, RFC9162_SHA256.
- `396` (vdp) MUST hold exactly one inclusion proof under `-1`. A consistency proof (`-2`) or any other
  proof type is rejected (`INCLUSION_PROOF_MALFORMED`): consistency proofs are not supported in this
  version (open question 9).
- `tree-size >= 1` and `0 <= leaf-index < tree-size`. The path lists sibling hashes from the leaf
  upward (RFC 9162 §2.1.3.1); it is empty for a tree of size 1.
- The protected header holds exactly `alg`, `kid`, CWT Claims and `vds`; there is no content type.
  `iss` MUST equal the keys file's `issuer`; `sub` is the log id (same syntax as `log_id` in section 6);
  `iat` is when the log signed. The key MUST be a `log` key valid at `iat`.
- The unprotected header holds only `396`. The strict CBOR rules of section 4 apply to the log
  receipt and to the inclusion proof.

### 7.3 Verification of check (e)

Without a log receipt and without a checkpoint, check (e) is `skipped`. Otherwise:

1. Label 394 MUST be an array holding exactly one byte string (`INCLUSION_PROOF_MALFORMED`).
2. The log receipt is decoded with a detached payload, and its header is checked
   (`LOG_RECEIPT_COSE_MALFORMED`, `LOG_RECEIPT_COSE_HEADER_INVALID`, `LOG_RECEIPT_ALG_UNSUPPORTED`).
   The inclusion proof is parsed (`INCLUSION_PROOF_MALFORMED`).
3. The verifier computes the entry (section 7.1), its leaf hash, and from `leaf-index`, `tree-size` and
   `inclusion-path` the root with the algorithm of RFC 9162 §2.1.3.2. A path that cannot fit the tree
   size gives `INCLUSION_PROOF_INVALID`.
4. The log key is checked as in section 3 (`LOG_RECEIPT_KID_UNKNOWN`, `LOG_RECEIPT_KEY_MISMATCH`,
   `LOG_RECEIPT_KEY_PURPOSE_MISMATCH`, `LOG_RECEIPT_ISSUER_MISMATCH`, `LOG_RECEIPT_KEY_NOT_VALID_AT_TIME`).
5. The signature MUST verify over `["Signature1", protected, h'', root]`. If it does not, the result is
   `INCLUSION_PROOF_INVALID`: a changed receipt, a wrong path, a wrong leaf index or tree size and a
   forged log signature cannot be told apart from the receipt alone. A signature that verifies with a
   different listed key than the kid names gives `LOG_RECEIPT_WRONG_KEY`.
6. The receipt's `iat` MUST NOT be later than the log receipt's `iat` (`RECEIPT_AFTER_LOG_RECEIPT`).

When a checkpoint is given:

7. A receipt without a log receipt fails (`INCLUSION_PROOF_MISSING`), whether or not the checkpoint
   file itself is valid.
8. The checkpoint passes checks (a)-(d) as a checkpoint statement signed by a `log` key. Failures
   are reported with the `CHECKPOINT_` prefix.
9. Only when both the log receipt and the checkpoint verified:
   - the log id MUST equal the checkpoint's `log_id` (`CHECKPOINT_LOG_MISMATCH`);
   - the tree size MUST equal the checkpoint's `tree_size` (`CHECKPOINT_TREE_SIZE_MISMATCH`),
     because there are no consistency proofs yet. The log receipt's tree size is not signed
     (section 11), so a mismatch can also mean it was changed after the log signed the root;
   - the root MUST equal the checkpoint's `root_hash` (`CHECKPOINT_ROOT_MISMATCH`). A mismatch
     means the log signed two different roots for the same tree size, which is evidence of an
     inconsistent log.
10. The receipt's `iat` MUST NOT be later than the checkpoint's `iat` (`RECEIPT_AFTER_CHECKPOINT`).

## 8. Receipt file (`keelstamp-receipt-file-v1`)

```json
{
  "format": "keelstamp-receipt-file-v1",
  "receipt": "<COSE_Sign1_Tagged bytes of the receipt, with its log receipt in header 394, base64url>"
}
```

The receipt file holds these two members and nothing else (`RECEIPT_MALFORMED`). In particular it
never carries keys. Earlier pre-release drafts had a JSON `inclusion_proof` member; it has been
replaced by the log receipt (section 7) and is now an unknown member.

## 9. Where keys come from

- The only source of keys is the keys file the person verifying passes explicitly:
  - in the CLI, `--keys`, which is required and has no default;
  - on the web page, the keys field;
  - in the library, the `keys` argument of `verify()`. A missing keys file gives `KEYS_MALFORMED`.
- Keys are never taken from:
  - a file next to the receipt;
  - the receipt file (a `keys` member is an unknown member);
  - any COSE header of the receipt or its log receipt, since no header parameter that could carry a
    key is accepted.
- The CLI prints, and the web page shows before and after verifying, which keys file is in use:
  - its name (or "pasted text");
  - the SHA-256 of its exact bytes;
  - its issuer;
  - each key id with its purpose and validity.

  A person can compare the SHA-256 with the keys file Keelstamp publishes.
- On the web page, a file chosen for any field is verified as its exact bytes, as the CLI reads it,
  until the field is edited. The text area's own handling (dropping a BOM, normalizing CRLF line
  endings) therefore changes neither the verdict nor the SHA-256 shown.
- **Why this rule exists:** the internal review reproduced a forgery against an earlier pre-release
  CLI, which read `keelstamp-keys.json` next to the receipt by default. An attacker's keys file placed
  next to a forged receipt verified with exit 0. `tests/cli.test.mjs` re-creates that attack, and it
  now fails:
  - without `--keys`: exit 2;
  - with the published keys: `KID_UNKNOWN` and `LOG_RECEIPT_KID_UNKNOWN`.

## 10. Verification result

`verify(receipt, keys, checkpoint?)` takes the three files (parsed JSON, JSON text or UTF-8 bytes) and
returns:

```js
{
  ok: boolean,                // true only if every required check passed and no reason was recorded
  reasons: [{ code, message }],
  checks: { signature, payload_jcs, profile, key, inclusion },   // "pass" | "fail" | "skipped"
  details: { receipt, inclusion, checkpoint, keys }              // decoded fields, for display
}
```

**Checks.** Checks (a)-(d) are required. Check (e):
- is `skipped` when the receipt has no log receipt and no checkpoint is given;
- is `pass` when the log receipt verifies, and when given, the checkpoint matches it;
- is `fail` otherwise, including when a checkpoint is given but could not be compared (for example
  because the receipt itself does not decode).

**Details.**
- `details.inclusion` holds the log id, root hash and signing time of the log receipt, which the log
  signed, and the tree size and leaf index from its inclusion proof, which the log did not sign
  (section 11). Its `checkpoint` member is `not given`, `matched` or `not matched`; only `matched`
  confirms the tree size and leaf index.
- `details.keys` holds the keys file's issuer and keys, and its SHA-256 when the keys file was given
  as text or bytes (not when the library is given an already parsed object).
- The receipt file and the keys file are both read before either error is reported, so the keys in
  use are reported even when the receipt file is malformed.

**Fail-closed.**
- The verifier never throws; an unexpected exception becomes `INTERNAL_ERROR`.
- A required check that did not run makes `ok` false.
- It reads no clock and makes no network access, so the result depends only on its inputs.

**Display.**
- Fields shown for a receipt that did not verify are claims, and the CLI and the web page label them
  so.
- The leaf index and tree size of a verified log receipt are shown as not signed and informational,
  unless a checkpoint matched (section 11). The CLI and the web page show the signed root hash next
  to them.
- Text taken from inputs is attacker-controlled. Before display, reason messages, the CLI (including
  `--json`) and the web page escape every code point of the Unicode categories Cc, Cf, Zl and Zp
  (controls, bidi and zero-width characters, tag characters).
- Payload fields are shown only after the profile check has validated their syntax.
- Reason messages describe a header label or value taken from an input by its type and size
  (for example `byte string (1048576 bytes)` or `array (1 items)`), never by its full content, so a
  crafted label cannot produce a huge message or exhaust the stack.

| Code | Check | Meaning |
|---|---|---|
| `RECEIPT_MALFORMED` | input | Receipt file is not valid JSON or not `keelstamp-receipt-file-v1` |
| `KEYS_MALFORMED` | input | No keys file given, or it is not valid JSON or not `keelstamp-keys-v1` |
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
| `KEY_PURPOSE_MISMATCH` | (d) | Key `purpose` does not match what it signed |
| `ISSUER_MISMATCH` | (d) | CWT `iss` differs from the keys file `issuer` |
| `KEY_NOT_VALID_AT_TIME` | (d) | `iat` outside `[valid_from, valid_until)` |
| `INCLUSION_PROOF_MISSING` | (e) | Checkpoint given, but the receipt has no log receipt |
| `INCLUSION_PROOF_MALFORMED` | (e) | Header 394 or the inclusion proof in vdp (396) is malformed, or a consistency proof is present |
| `INCLUSION_PROOF_INVALID` | (e) | The log receipt does not verify over the root computed from the receipt and its inclusion proof |
| `CHECKPOINT_LOG_MISMATCH` | (e) | Log receipt and checkpoint name different logs |
| `CHECKPOINT_TREE_SIZE_MISMATCH` | (e) | Log receipt and checkpoint have different tree sizes (the log receipt's tree size is not signed, so it may also have been changed in transit) |
| `CHECKPOINT_ROOT_MISMATCH` | (e) | The log signed different roots for the same tree size |
| `RECEIPT_AFTER_LOG_RECEIPT` | (e) | Receipt `iat` later than log receipt `iat` |
| `RECEIPT_AFTER_CHECKPOINT` | (e) | Receipt `iat` later than checkpoint `iat` |
| `LOG_RECEIPT_<code>` | (e) | `COSE_MALFORMED`, `COSE_HEADER_INVALID`, `ALG_UNSUPPORTED`, `KID_UNKNOWN`, `KEY_MISMATCH`, `KEY_PURPOSE_MISMATCH`, `ISSUER_MISMATCH`, `KEY_NOT_VALID_AT_TIME` or `WRONG_KEY`, for the log receipt |
| `CHECKPOINT_<code>` | (e) | Any statement code above (`COSE_MALFORMED` … `WRONG_KEY`), for the checkpoint |
| `INTERNAL_ERROR` | all | Unexpected error; treated as not verified |

## 11. What a successful verification shows, and what it does not

It shows that:
- the payload was signed, unchanged, by the key that the keys file lists under the receipt's key id,
  during that key's validity window;
- with a log receipt: a `log` key from the same keys file signed a Merkle root, and this receipt is a
  leaf of the tree with that root. The leaf index and tree size come from the inclusion proof, which
  the log does not sign (RFC 9942 carries it in the unprotected header). Several (leaf index, tree
  size) pairs lead to the same root, for example leaf 5 of 7 and leaf 5 of 8, so without a
  checkpoint the two numbers are informational and are shown as not signed;
- with a checkpoint as well: that root is the one the log signed for the checkpoint's tree size. That
  confirms the tree size and, with it, the leaf index: in a tree of a given size, each leaf position
  has its own path.

It does not show:

- that the keys file is Keelstamp's. The verifier trusts the keys file it is given; obtain it from
  the issuer's `/.well-known/keelstamp-keys.json` or from the transparency repository, and compare the
  SHA-256 the verifier shows (section 9).
- that `iat` is the true signing time. A holder of a valid key can choose `iat`. The log receipt's and
  the checkpoint's `iat` bound it from above; nothing here bounds it from below.
- that the log is append-only or that everyone sees the same log. That needs consistency proofs
  between tree sizes (RFC 9162 §2.1.4, vdp -2 in RFC 9942), which this version does not verify.
- anything about the commitments' underlying values. Checking a commitment requires the salt and
  the value, which the verifier does not have.

## 12. Dependencies

Runtime dependencies are pinned to exact versions, have no dependencies of their own, and are
bundled into the web page together with their license texts.

| Package | Version | License | Why |
|---|---|---|---|
| `@noble/ed25519` | 3.2.0 | MIT | Ed25519 verification in plain JavaScript that runs unchanged in Node and browsers, with a strict RFC 8032 / FIPS 186-5 mode (`zip215: false`) that rejects non-canonical encodings and small-order keys. Node's own `crypto` is not available in browsers. |
| `@noble/hashes` | 2.4.0 | MIT | SHA-256 (Merkle tree, JWK Thumbprint, keys file fingerprint) and SHA-512 (required by Ed25519) as synchronous plain JavaScript. WebCrypto is asynchronous and some browsers expose it only in secure contexts, which a page opened from disk may not be. |
| `cborg` | 6.1.3 | Apache-2.0 | CBOR decoding with the strictness the format requires (minimal-length integers, duplicate-key rejection, no indefinite lengths, tags only when enabled, trailing bytes rejected), extended in `src/cose.mjs` to reject floats and inexact text; deterministic encoding of the Sig_structure and the log entry. |
| `esbuild` | 0.28.2 | MIT | Build only (devDependency): bundles the verifier into one inline script for the single-file web page. Not shipped. The output is reproducible (tested). |

The following are implemented in `src/` rather than taken from packages:
- RFC 8785 canonicalization: about 40 lines, since RFC 8785 is defined in terms of ECMAScript's own
  number and string serialization;
- the RFC 9162 inclusion check: about 30 lines;
- the RFC 9942 receipt checks;
- base64url and hex.

## 13. Test vectors

- `tests/test-signer.mjs` produces receipts with log receipts, checkpoints and keys files from this
  document. It shares no code with `src/`:
  - Ed25519 and SHA-256 come from `node:crypto`;
  - CBOR comes from its own encoder;
  - the Merkle tree comes from the recursive definitions of RFC 9162 §2.1.1 and §2.1.3.1.
- `tests/fixtures/` holds committed receipts and checkpoints, and `tests/keys/` holds their keys files,
  kept apart from the receipts (section 9).
  - Both are generated by `npm run fixtures`. Their keys existed only while the generator ran; the
    files contain public keys only.
  - `tests/fixtures/expected.json` lists the expected exit code and reasons for each case.
- Published vectors used in the tests:
  - RFC 8032 §7.1 test 1 (Ed25519);
  - RFC 8037 Appendix A.3 (JWK Thumbprint of that key);
  - RFC 8785 §3.2.2 and §3.2.3 (canonical JSON);
  - the Certificate Transparency reference tree heads for sizes 1-8.

## Open questions for the CTO (Åbne spørgsmål til CTO)

Each item is a choice made in this version so that work could continue. All are reversible by
issuing a new profile or format id. Items resolved by a decision keep their number and say so.

1. **RFC details still to check against the published texts.** Partly resolved on 2026-10-01: the
   CTO's lookup on rfc-editor.org confirmed the titles, labels and values listed in section 1. The
   following were chosen here without the RFC text at hand; please check them against RFC 9942 and
   RFC 9943:
   - (a) the inclusion proof encoding `bstr .cbor [tree-size, leaf-index, inclusion-path]`, including
     an empty path for a tree of size 1;
   - (b) label 394 holding byte strings that each encode a tagged COSE_Sign1, rather than embedded
     structures;
   - (c) which parameters the receipt's protected header must or may carry. Here it is exactly alg,
     kid, CWT Claims (iss, sub = log id, iat) and vds; nothing else is allowed;
   - (d) the detached payload being the raw 32-byte root hash.
2. **Algorithm identifier `-19` (Ed25519) only.** Chosen because it names one curve (RFC 9864; Ed448
   is -53). Many COSE libraries still emit `-8` (EdDSA). Does the planned signer library support
   `-19`? If not: accept `-8` with an Ed25519 key, or change library?
3. **SCITT shape.** The protected header carries `iss` and `sub` in CWT Claims, a `kid` and a content
   type, and nothing else; there is no `typ` (label 16) and the content type is the generic
   `application/json`. Should receipts carry an explicit type (e.g. a dedicated media type) so that a
   receipt can never be mistaken for another JSON statement signed by the same key?
4. **Profile id only in the payload.** The `profile` member selects the schema; it is signed but not in
   the protected header. Fine, or also put it in the header?
5. **Resolved 2026-10-01: inclusion is a COSE Receipt.** The proof is an RFC 9942 COSE Receipt in the
   receipt's unprotected header 394, with vds 1 and the inclusion proof in vdp -1 (section 7). The
   JSON `inclusion_proof` member is gone.
6. **Log entry = the receipt as signed, with an empty unprotected header** (section 7.1). The log
   receipts a receipt carries cannot be part of the entry they prove. The alternatives are a hash of
   the statement, or a leaf format prescribed by RFC 9943 or a SCITT profile if one exists. Agreed?
7. **Checkpoint format.** Checkpoints reuse the COSE_Sign1 + JCS machinery (one parser, one signature
   path). The common alternative in transparency logs is the C2SP signed-note checkpoint, which would
   let existing witness tooling cosign Keelstamp checkpoints. Since log receipts now carry signed
   roots, checkpoints serve publication and split-view detection (`CHECKPOINT_ROOT_MISMATCH`). Keep
   COSE, or switch?
8. **`log_id` is a string**, not the DER-encoded OID of RFC 9162. It appears as the log receipt's CWT
   `sub` and the checkpoint's `log_id`. What should the production value be?
9. **Consistency proofs (vdp -2) are not supported yet** (decision 2026-10-01: they can wait).
   - A log receipt that carries one is rejected as malformed.
   - A checkpoint must have the same tree size as the log receipt, so a receipt can only be checked
     against the checkpoint of its own tree size.
   - Using any later daily checkpoint requires an RFC 9162 §2.1.4 consistency proof from the log
     receipt's tree size to the checkpoint's.
   - Open: where that proof comes from (vdp -2 in a refreshed log receipt, or the checkpoint file),
     and whether it is needed before v1.
10. **Key ids are RFC 7638 JWK Thumbprints** (raw 32 bytes in the COSE `kid`). RFC 9679 (COSE Key
    Thumbprint) is the COSE-native alternative. Either binds the id to the key; JWK was chosen because
    the keys file is a JWK Set.
11. **Key compromise.** There is no revocation list.
    - Setting `valid_until` to the compromise time rejects later `iat` values, but a holder of the
      stolen key can back-date `iat`.
    - Should receipts signed with a key be accepted only when their log receipt was signed before the
      key's `valid_until`? (That would make the log receipt mandatory for older receipts.)
    - A receipt's `iat` is now bounded from above by its log receipt's `iat` and, when given, by the
      checkpoint's. Without either, a far-future `iat` verifies with an open-ended key.
12. **Resolved 2026-10-01: `--keys` is required, with no default.** Keys never come from the receipt
    or from next to it, and the CLI and the web page show the keys file used, with its SHA-256
    (section 9). Still open:
    - Should the verifier pin the SHA-256 (or the keys) of the production keys file?
    - Should the keys file itself be signed, or only published with history in the transparency
      repository?
13. **Inclusion is optional.** A receipt with no log receipt and no checkpoint verifies, with check (e)
    `skipped`. The log receipt sits in the unprotected header, so anyone forwarding a receipt can
    strip it without breaking the signature (the second internal review confirmed this); the result
    then shows (e) as `skipped`. Should a log receipt become mandatory once the log runs, or should the
    CLI get a `--require-inclusion` flag?
14. **Receipt payload members are a placeholder** (`receipt_id`, `partner`, `tenant`, `event`,
    `digests`). Open:
    - the event vocabulary (a closed list?);
    - whether amounts appear as intervals;
    - how commitments are computed (proposal: `SHA-256(salt || value)` with a per-tenant salt, or
      HMAC);
    - whether the verifier should also offer an end customer a "check my commitment" step, given the
      salt and the value.
15. **Production issuer string** (`iss`, keys file `issuer`): `keelstamp.com`? Tests use
    `issuer.test.keelstamp.invalid`.
16. **No floating-point values in COSE structures**, so `iat` is whole seconds as an integer. The
    verifier rejects floats outright (its CBOR library would otherwise return `1.0` as the same number
    as `1`). Confirm the signer never emits floats.
17. **Strict Ed25519.** The verifier uses RFC 8032 / FIPS 186-5 rules. Standard signers produce
    signatures that pass; only crafted edge cases differ from ZIP-215 verifiers.
18. **Header text is compared byte-exactly**: `iss`, `sub` and the content type must be valid UTF-8
    and are not normalized (no BOM stripping, no Unicode normalization). An issuer string therefore has
    exactly one encoding. Agreed?
19. **Distribution of the web page.** `npm run build` writes `dist/keelstamp-verifier.html` (not
    committed). Publish it as a release asset with its SHA-256, and/or on GitHub Pages? Opening it from
    disk works; the CSP blocks network access either way.
20. **No input size limits.** The verifier runs locally on files the user chose; no limits are
    imposed on file size or path length.
21. **One log receipt per receipt.** Label 394 must hold exactly one. SCITT allows several, for example
    from different logs. Is more than one needed?
22. **Time order of receipt and log receipt.** `RECEIPT_AFTER_LOG_RECEIPT` requires the receipt's
    `iat` to be no later than its log receipt's `iat`. Agreed, or should clock skew be tolerated?
