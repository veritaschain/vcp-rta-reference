# Ed25519 public-key admission

Updated 2026-10-26. Implementation correction for the legacy event/root verifier
and opt-in supplemental verifier. Not a VCP/VAP normative revision.

## Reproduced behavior and prerequisites

At baseline `2084e015c80d2a8731cc3b23b98fb5dbe4128ada`, both signature helpers
checked a caller-supplied Ed25519 key's length but not its group membership.
With the encoded identity point as the public key, the fixed value consisting
of an identity R and a zero S was accepted as a signature for different input
messages without any private-key signing operation. The default helper's raw
digest and ASCII-hex modes and the supplemental signature helper reproduced
this in ten local regression cases under cryptography 46.0.4.

This requires the caller to supply an unusable key. It is NOT a way to forge
signatures under a legitimate prime-order public key. Evidence files still
cannot select a trusted key automatically. The reproduction established false
per-signature VALID results, not an overall VALID historical Evidence Pack.
No production private key, historical signature or archived evidence was changed.
This is an application key-admission correction, not a claim that RFC 8032 or
the cryptography package promises this extra application policy.

## Admission rule

Before event, root or supplemental signature verification, require a 32-byte
canonical encoding of a point on edwards25519, other than the identity, whose
order divides the prime subgroup order L. This rejects small-order points,
points with a nonzero torsion component, noncanonical encodings and off-curve
encodings. Normal Ed25519-generated keys are in the admitted subgroup.

The shared helper `ed25519_public_key_problem` performs strict point decoding
and the public calculation [L]A. It does not sign, handle secret material, or
replace the existing cryptography/OpenSSL signature verifier. Its arithmetic
uses the curve parameters and extended-coordinate group law in RFC 8032
sections 5.1.3 and 5.1.4. The key-admission rule is consistent with the policy
already used by this organization's separate vcp-sdk implementation; no SDK
package or new dependency is imported.

A bounded LRU cache retains at most 128 results for immutable 32-byte public
keys. Cached mathematical admissibility is not identity, authorization, key
revocation status, or successful signature verification. Every signature still
passes through the existing backend. The Python arithmetic is for public data
only, not a constant-time signing or secret-scalar primitive.

## Verdicts and compatibility

A rejected caller trust key yields INDETERMINATE with
`TRUSTED_KEY_REJECTED:<reason>` or `SUPPLEMENTAL_TRUSTED_KEY_REJECTED:<reason>`.
It is not proof that the evidence itself was altered. Other independently
executable checks continue, and a demonstrated payload/hash mismatch still
produces INVALID. This does not relax missing-evidence or failure handling.

The two signature helpers are the only changed pre-existing runtime functions.
The signing inputs, signature encodings, hash/Merkle algorithms, file loaders,
output protection, CLI arguments, aggregate precedence and report schema are
unchanged. The file key loader remains a decoder; admission also runs for
in-memory API callers so bypassing that loader does not skip validation.

This intentionally narrows which caller-supplied public keys can be used.
An old per-signature VALID result obtained with a rejected key is not reliable
and should be re-examined. Do not silently substitute or generate a new key
for existing signed evidence. Establish the actual valid key and its identity
outside this tool. This correction alone establishes neither key ownership
nor the original anchor, chain boundary, conformance, or independent reproduction.

## Tests

`tests/test_ed25519_key_admission.py` adds 78 cases: identity-value false passes,
all eight torsion points, seven mixed-order points, noncanonical/off-curve
encodings, type/length checks, RFC 8032 example keys, the published historical
reference key, generated signatures and tampering, both CLI key encodings,
supplemental attestor handling, input preservation, cache bounds and missing
cryptographic dependencies. A separate affine-arithmetic oracle checks the
negative fixtures' classes; it is not an independent-party audit.

The ten targeted false-pass cases fail against the exact baseline runtime;
all 78 new cases pass locally after this correction. The main runner requires
520 cases (442 previous + 78 new). The 15 historical-pack cases remain in their
separate workflow. The first CI attempt found that the historical wrong-key
test used an all-zero key, which is a small-order point. That test now uses a
generated valid but unrelated key and retains its INVALID assertions, including
a new root-signature assertion. The all-zero case remains in the same test with
explicit INDETERMINATE/key-rejected assertions and input-preservation checks.
The actual reference-key replay output was unchanged in the initial run.
No test was removed or skipped. Full CI outcomes are recorded in the PR after
execution; dependencies and workflows are unchanged.

## 日本語

指定された公開鍵が32バイトでも、署名検証に使える数学的性質を持つとは限りません。
通常のイベント・ルート署名と補助署名の両方で、非正規の符号化、曲線外の点、単位元、
小位数やねじれ成分を持つ鍵を拒否します。鍵が不適切な場合は「未検証」であり、別に
確認できたログの改変は引き続きINVALIDです。鍵の所有者確認や外部アンカーの回復とは
別の処理で、過去の証拠や署名を再生成しません。

## Sources

- RFC 8032 point decoding/addition and example keys: https://www.rfc-editor.org/rfc/rfc8032.html
- Existing SDK key policy (comparison, not a runtime dependency): https://github.com/veritaschain/vcp-sdk/blob/026d11af43ba161a8b3bf9f7a8ef3328c3802e9e/python/src/veritaschain_vcp/signing.py
- cryptography Ed25519 public-key interface: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/
