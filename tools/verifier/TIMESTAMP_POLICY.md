# Timestamp policy: incomplete checks and caller configuration

Updated 2026-10-26. Implementation correction to the opt-in supplemental
verifier, not a VCP/VAP normative revision or a new supported hash algorithm.

## Two reproduced classifications

At baseline `3ce6ba049e81119a182d8c7f771699c37acd4ba8`, an unsupported imprint
algorithm caused `verify_rfc3161` to return before comparing the token's policy
with the caller's expected policy. A real, locally signed SHA-384 response
with a different policy therefore returned INDETERMINATE instead of reporting
the independently observable policy mismatch. This was not a false VALID.

The caller policy regex also admitted impossible OIDs such as `1.99` and
noncanonical spellings such as `1.02.3`. A valid SHA-256 token then appeared
to have a policy mismatch even though the caller's expected policy was unusable.
The correction separates unavailable caller configuration from evidence mismatch.

## Current behavior

The supported SHA-256 imprint comparison still runs first. An established
imprint mismatch remains INVALID, including when the expected policy or CA
is absent. A usable expected policy is compared even when the token's imprint
algorithm is unsupported; an unequal policy is INVALID. Without a demonstrated
mismatch, an unsupported algorithm remains INDETERMINATE. No SHA-384 verification
support has been enabled by using SHA-384 in the negative tests.

Expected policy identifiers must use canonical ASCII dotted-decimal spelling,
with at least two arcs, a first arc of 0, 1 or 2, and a second arc no greater
than 39 when the first is 0 or 1. Leading zeros, whitespace, named identifiers
and invalid types are not silently normalized. A local 4096-character limit
bounds this caller configuration; it is not a normative protocol OID limit.
Missing/unusable policy configuration remains INDETERMINATE unless an independent
supported-imprint mismatch has already been demonstrated.

All matching SHA-256 inputs still require the original OpenSSL signature and
certificate-chain checks under the caller's explicit CA bundle. A policy
comparison does not authenticate the TSA or prove that the TSA issued a bad
response. INVALID here rejects the supplied token against the caller's selected
policy; it is not attribution of misconduct. Missing CA/backend and generic
signature/chain execution failures still remain INDETERMINATE, never success.

## Regression evidence

`tests/test_timestamp_policy.py` contains 50 cases. Temporary synthetic CA/TSA
certificates issue actual RSA-signed SHA-256 and SHA-384 RFC 3161 responses.
The fixture checks both issued responses against their queries with OpenSSL,
and the positive SHA-256 verifier test performs real cryptographic verification.
The three backend-exclusion tests deliberately use a failure stub to assert
that incomplete or mismatching inputs cannot reach the success path.
There is no commercial TSA request, production key, or network operation.

The exact baseline supplemental source was reconstructed and matched Git blob
`67a2c854c1bc9ccd3ffcf482228d44466df1425d`. Local Python 3.13.5,
cryptography 46.0.4, asn1crypto 1.5.1, pytest 9.0.2 and OpenSSL 3.5.5:
12 failed / 38 passed before correction, then 50 passed after correction.
This local execution used an AST-extracted timestamp-function slice and a
status-constructor adapter because a full repository checkout was unavailable.
It is not a full local import/CLI or whole-repository test. The complete real
modules and existing suites are exercised by CI, whose observed results are
recorded in the PR before integration.

The regression runner requires 570 cases (520 existing plus 50 new); historical
replay remains 15 separate cases per environment. No earlier test is removed,
skipped or relaxed. Only `verify_rfc3161` changes among existing runtime functions;
one caller-policy syntax helper is added. Default verifier, signed bytes,
key admission, file limits, output protection, report schema, trust stores,
workflows/dependencies, original evidence, fixed kits/releases and specifications
are unchanged. Revocation/freshness, chain boundary, historical-anchor and
full-schema limitations remain; no independent reproduction is claimed.

## 日本語

未対応のハッシュ方式でも、別に確認できるポリシー不一致は報告します。
一方、利用者が指定したポリシー番号そのものが不正な場合は、証拠の改変と決めつけず
未検証とします。正しいポリシーの指定だけで合格にせず、従来の署名・証明書検証も
必要です。SHA-384対応、元の外部アンカーの回復、正式仕様の採択ではありません。

## References

- RFC 3161, sections 2.2 and 2.4.2 (policy and message imprint): https://www.rfc-editor.org/rfc/rfc3161.html
- OpenSSL timestamp verification: https://docs.openssl.org/3.0/man1/openssl-ts/
