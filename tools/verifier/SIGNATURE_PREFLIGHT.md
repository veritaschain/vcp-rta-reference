# Signature syntax before cryptographic prerequisites

Updated 2026-10-26. Implementation correction for the legacy event/root helper,
which is also used by the supplemental verifier. Not a VCP/VAP normative change.

## Reproduced classification gap

At baseline `9f9cec26d54a7ef00442d6a93b2005a8283377d2`, a missing or rejected
caller key, or unavailable digest, caused `verify_digest_signature` to return
before examining a supplied signature's representation. A numeric/object/array
signature, invalid Base64, or an encoded value of the wrong byte length therefore
became INDETERMINATE, even though its malformed ED25519 representation could be
identified without the key. This was not false cryptographic VALID or evidence
that a legitimate signature could be forged.

## Narrow correction

For an explicitly declared ED25519 algorithm, inspect a present, nonempty
signature's type, existing hex/Base64 decoding, and 64-byte length before
cryptographic prerequisites. These are the same checks as before, reordered
rather than a new signature format or new backend. Unknown algorithms still
return INDETERMINATE without imposing ED25519's length rules on them.

A malformed supplied signature is INVALID with the existing MALFORMED_SIGNATURE,
MALFORMED_SIGNATURE_ENCODING or MALFORMED_SIGNATURE_LENGTH reason. INVALID means
the supplied representation is unusable under the selected algorithm; it does
not establish malicious alteration, who produced it, or a cryptographic mismatch.

Successfully decoding 64 bytes does NOT validate the signature. Missing/unusable
keys, missing message digests, unavailable dependencies and unsupported message
encodings still prevent success. All real signature verification and public-key
admission remain mandatory. None and the empty string retain their existing
missing-input behavior and precedence. A well-formed signature with an inadmissible
key is still INDETERMINATE, as documented in KEY_ADMISSION.md.

Only `verify_digest_signature` changes among runtime functions. Both event and
root checks use it; the supplemental source is unchanged. The supplemental
statement's envelope syntax already precedes key validation. There is no change
to hash/Merkle algorithms, signing inputs, signature encodings, key admission,
file limits, no-clobber output protection, CLI arguments or report schema.

## Regression evidence and limits

The exact current default/supplemental runtime and runner were reconstructed
from retained source copies and matched against the corresponding live Git blob
IDs before testing. The full new test suite used those modules, not extracted
functions. Network checkout was unavailable, so the entire repository was not
executed locally.

New suite `tests/test_signature_preflight.py`: 53 cases, with 39 failed and 14
passed against the baseline, then 53 passed after correction. The local combined
run of this suite plus the existing key-admission and timestamp-policy suites
passed 181 cases on Python 3.13.5, pytest 9.0.2, cryptography 46.0.4, asn1crypto
1.5.1 and OpenSSL 3.5.5. The final whole-repository CI result is recorded in the PR
only after execution. No previous test is removed or relaxed.

Tests include missing/rejected keys, unavailable digests/backend, unknown
algorithms, absent signatures, actual positive/tampered Ed25519 signatures in
both message encodings and both wire encodings, missing proofs, both CLIs and
unreadable optional key files. All keys/events are synthetic; archived evidence
is never modified. Expected CI baseline: 623 regression cases plus 15 separate
historical replay cases per environment. Test success is not certification,
independent reproduction, key-owner identity or an overall VALID historical pack.

## 日本語

署名が存在するのに形式が壊れている場合は、公開鍵がなくても判別できる範囲で
INVALIDを報告します。形式が正しいだけで合格にせず、鍵・メッセージ・実際の
暗号検証が必要です。署名そのものが未提供の場合や未知のアルゴリズムは従来どおり
未検証です。形式エラーを悪意ある改変や署名者の不正と断定するものではありません。

## Reference

RFC 8032 sections 5.1.6, 5.1.7 and 7: Ed25519 signatures contain 64 octets.
https://www.rfc-editor.org/rfc/rfc8032.html
