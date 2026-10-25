# Supplemental batch attestation and RFC 3161 verifier

2026-10-26. **Executable, opt-in, first-party implementation extension.** This is
not an adopted VCP/VAP wire format, an INT-008 conformance implementation, a
certification result, or independent reproduction. The default
`vcp_verifier.py`, original evidence, old signatures and release artifacts are
unchanged. The new entry point is `verify_attested_batch.py`.

## What is implemented

The supplemental verifier authenticates a separately supplied statement with an
explicitly trusted Ed25519 public key, compares it with the supplied batch, and
checks an RFC 3161 response for the **entire signed statement**, using the
caller's CA bundle and expected TSA policy OID. It never trusts an embedded key,
producer `CONFIRMED` flag, or evidence-supplied executable/configuration.

The statement binds the root, count, endpoint identifiers, sequence range,
PolicyID, and snapshots of the complete parsed event array and security object.
The snapshots also cover each complete PolicyIdentification object, signatures
and paths; changing a VerificationDepth flag while retaining PolicyID does not
escape this check. Duplicate event identifiers are rejected. Context identity
must match `--expected-context`, obtained outside the evidence.

This tool **verifies only**. It does not generate/sign statements, request a
stamp, or contact a service. An operator must create a new supplemental
statement, have its actual attestor sign it, and obtain the timestamp separately.
Signing keys must stay in the operator's approved signing system. Verification
receives public keys only.

## Do not backdate or rewrite evidence

A newly issued supplemental signature or stamp cannot establish when the old
log was created, when its original root was anchored, or whether an event was
never recorded. `issued_at` is a signed assertion, not an independently verified
logging time. The RFC 3161 imprint covers the supplemental envelope, not an
original 2025/2026 OTS proof. No missing historical proof is manufactured.

The original event file and security object are read-only inputs. Their legacy
JSON concatenation and duplicate-odd Merkle semantics are preserved. This
extension does not turn those constructions into JCS or strict RFC 6962 MTH.

## Run

Tested locally with Python 3.13.5, cryptography 46.0.4, asn1crypto 1.5.1,
pytest 9.0.2 and OpenSSL 3.5.5. Use an OpenSSL 3.x executable on PATH;
other versions/platforms were not exercised here.

```sh
python -m pip install cryptography==46.0.4 asn1crypto==1.5.1
python tools/verifier/verify_attested_batch.py /path/to/events.jsonl \
  --security-object /path/to/security_object.json \
  --public-key /trusted/event-signer.pub \
  --attestation /path/to/supplemental.json \
  --attestor-key /trusted/supplemental-attestor.pub \
  --expected-context 'your-established-batch-context' \
  --tsa-response /path/to/response.tsr \
  --tsa-ca-file /trusted/tsa-ca-bundle.pem \
  --tsa-policy-oid 'YOUR.EXPECTED.NUMERIC.OID' \
  --json --output /path/to/new-report.json
```

The policy argument above is a placeholder: supply the numeric OID agreed with
the trusted TSA. `--tsa-untrusted /path/to/intermediates.pem` can provide
additional **untrusted** certificates for chain construction; it does not add
trust anchors. The response must be DER **TimeStampResp**, not a bare CMS token.
`--signature-message ascii_hex` selects the other legacy event/root signature
encoding explicitly; supplemental signatures always use the contract below.

As in the default CLI: exit 1 means INVALID, 2 means INDETERMINATE, and 3 means
unreadable event input/output failure. An unavailable optional file adds an
INDETERMINATE check without hiding an independent mismatch. Argparse usage
errors remain 2. The original CLI and report format 2 remain unchanged;
opt-in reports add `supplemental_format` and additional named checks.

## Implementation-specific byte contract

The JSON envelope has **exactly** `statement` and `signature`. The signature is
canonical standard Base64 encoding of a 64-byte Ed25519 signature. Unknown or
extra fields are not silently excluded.

`statement` has exactly these fields, all nonempty strings of at most 4096
characters:

| Field | Required value / interpretation |
| --- | --- |
| `format` | `vcp-rta-supplemental-batch-v1` |
| `evidence_format` | `vcp-rta-legacy-1.1` |
| `hash_encoding` | `python-json-concat-v1` |
| `tree_algorithm` | `sha256-duplicate-odd-v1` |
| `snapshot_encoding` | `python-json-sort-ascii-compact-v1` |
| `context_id` | Caller-established context; not inferred from the statement |
| `merkle_root` | 64 lowercase hexadecimal characters |
| `event_count` | Number of supplied events as a positive decimal string |
| `first_event_id`, `last_event_id` | Endpoint Header.EventID strings |
| `first_sequence`, `last_sequence` | Endpoint Header.Sequence values as positive decimal strings |
| `policy_id` | Must match the security object and every event's PolicyID |
| `issued_at` | Signed assertion in UTC `YYYY-MM-DDTHH:MM:SSZ` |
| `events_snapshot_sha256` | SHA-256 of the complete event-array snapshot |
| `security_object_sha256` | SHA-256 of the complete security-object snapshot |

Decimal strings contain 1 to 19 digits and no leading zero. Snapshot bytes are
Python `json.dumps(value, sort_keys=True, ensure_ascii=True,
separators=(',', ':'), allow_nan=False).encode('ascii')`. They represent parsed
JSON values, **not** the original file's whitespace/escape spelling. This local
Python serialization is explicitly named; it is not an RFC 8785 claim. It
preserves Python integer digits without converting them to binary64. Duplicate
JSON keys and non-finite JSON constants are rejected by the input loaders.

The Ed25519 signing input is, byte for byte:

```python
b'VCP-RTA-SUPPLEMENTAL-STATEMENT\x00v1\x00' + json.dumps(
    statement, sort_keys=True, ensure_ascii=False,
    separators=(',', ':'), allow_nan=False
).encode('utf-8')
```

Use the exported `statement_bytes(statement)` to construct this input. All
statement keys are the fixed ASCII names above; values are strings only.
Neither the legacy raw-digest nor ASCII-hex signature convention is used here.

The timestamp data is, byte for byte:

```python
b'VCP-RTA-SUPPLEMENTAL-ANCHOR\x00v1\x00' + signing_input + raw_64_byte_signature
```

Use `anchor_bytes(envelope)` to construct it. The RFC 3161 message imprint must
use SHA-256 over these data bytes. Timestamping the root alone, the printable
root hex, or the JSON file's display bytes is **not** equivalent.

## What each result means

`supplemental_signature` checks the Ed25519 signature. `supplemental_batch_binding`
compares every binding against supplied inputs. `authenticated_batch_metadata`
combines those two, so a good signature alone cannot authenticate a different
batch. `rfc3161_token` independently checks the exact signed-envelope imprint,
expected policy, token signature, and certificate chain. `external_anchor`
combines that token check with authenticated batch bindings.

OpenSSL runs without a shell, with fixed arguments, a 15-second timeout, copied
local inputs, an explicit CA file and empty CA directory/store fallbacks. A
2 MiB limit applies to supplemental envelopes, timestamp and certificate files.
No code, configuration, URL or trust root is loaded from statement fields.
Unknown verifier/certificate-chain failures stay INDETERMINATE. A malformed
response or demonstrated imprint/policy mismatch is INVALID. A failed exit is
never overridden by success-looking output text.

**Important exclusions:** archived-token checking does not check live request
nonce/freshness, CRL/OCSP revocation, historical certificate validity at signing
time, qualified-TSA status, operator independence, or legal evidentiary effect.
Certificate chains are checked at the verifier's current time, not at a
producer-selected `issued_at`. No relaxed certificate-time flag is used.

New per-check VALID results do not force overall VALID. The existing verifier's
unresolved first-link/PrevHash boundary remains INDETERMINATE; full schema
verification is still absent. This extension does not weaken those checks to
manufacture a green overall result.

## Tests and scope of evidence

```sh
python -m pip install cryptography==46.0.4 asn1crypto==1.5.1 pytest==9.0.2
python -m pytest -q tests/test_verifier.py tests/test_attested_batch.py
```

The local run on 2026-10-26 passed **215 tests: 135 unchanged + 80 new**.
Tests use synthetic batches, actual Ed25519 signatures, and an ephemeral local
CA/TSA issuing actual signed RFC 3161 responses through OpenSSL. They check
imprint/policy mismatch, wrong trust root, signature alteration, missing input,
timeout/failed exits, snapshot and context binding, duplicate-odd root aliasing,
CLI integration, and preservation of input bytes. Timeout/exit-error tests use
explicit stubs; the positive timestamp/chain tests do not stub verification.

No live commercial TSA, OTS, blockchain, SCITT service, full historical
40-event pack, or independent third party was validated in this change. Test
keys/certificates are synthetic and temporary, not production credentials.

## References

- [RFC 3161, sections 2.2 and 2.4.2](https://www.rfc-editor.org/rfc/rfc3161.html)
- [OpenSSL 3.5 ts verification options](https://docs.openssl.org/3.5/man1/openssl-ts/)

## 日本語

実際に動く追加検証コマンドであり、提案書だけの変更ではありません。件数・範囲・
ポリシー・イベント全体とSecurity Objectのスナップショットを、別途信頼した鍵の
署名と照合します。RFC 3161応答も、署名済み補助記録そのものへの証明かを確認します。
元の証拠は書き換えず、後から作った補助記録を過去のアンカー実績と扱いません。
新しい二つの検査が成功しても、先頭のPrevHash境界などが未確認なら全体は未検証です。
VCP/VAPの正式仕様・適合認証・独立再現の成立を意味するものではありません。
