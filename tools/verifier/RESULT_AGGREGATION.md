# Malformed result isolation

Updated 2026-10-26. A narrow implementation correction, not VCP/VAP normative adoption.

## Reproduced defect

At baseline `29a27f295f1f7e797c2e6ca011ee10394be0a352`, the shared `combine`
helper tested dictionary membership before checking the type of `status`.
A result such as `{"status": [], "reason": "bad helper output"}` raised
`TypeError` even if another result was explicitly INVALID. A surrounding
`_guard` then returned INDETERMINATE for the entire subgroup, concealing that
subgroup's already reported mismatch. Both input orders reproduced the bug.
It did not turn this case into VALID.

The issue is at the Python helper/caller-adapter result boundary. It is not a
claim that merely adding a `status` property to an event file bypasses the CLI.
Evidence files cannot supply executable callbacks. Caller adapters remain
trusted code and must actually perform the checks they report.

## Correction and unchanged behavior

`check` and `combine` now confirm that status is a string before dictionary
membership testing. A malformed result cannot prevent the aggregator from
preserving another explicitly reported INVALID. With no INVALID result,
malformed entries remain INDETERMINATE, not VALID and not an invented mismatch.
Nested strings inside lists/objects are not treated as verdicts.

Normal result shape, reason strings, empty-list behavior and precedence
`INVALID > INDETERMINATE > VALID` are unchanged. The constructor rejects wrong
status types with ValueError instead of an incidental TypeError. Consumers
must not depend on that old exception type. The pre-existing conservative
aggregation of an explicit INVALID tag is preserved even if its reason is
malformed; an aggregate is a summary, not cryptographic proof of its inputs.

Only these two existing runtime functions change. Hashing, signature checking,
Merkle construction, file loading, output protection, CLI control flow and
report schemas are unchanged. The supplemental verifier imports the same
helpers; its source file is unchanged. The supported boundary is a list of
plain JSON-shaped result values, not arbitrary executable Python subclasses,
generators, or a sandbox for untrusted callback code.

## Regression evidence

`tests/test_result_aggregation.py` contains 66 cases. Against the exact baseline
runtime blob, the suite produced 29 failures and 37 passes. With the two type
guards, all 66 passed locally under Python 3.13.5, pytest 9.0.2 and cryptography
46.0.4. No local full-repository run is claimed: a network checkout was not
available in this environment.

Tests cover malformed statuses/reasons, both result orders, nonobject entries,
input preservation, the existing well-formed aggregation contract and 2,000
seeded JSON result arrays. Integration cases obtain a real local Ed25519
mismatch from an altered synthetic signature, then aggregate it with a malformed
sibling inside a synthetic caller callback. This callback is NOT an external
anchor implementation and does not validate timestamps or external services.

The main runner includes all 66 new cases: 442 regression cases plus the
unchanged, separately executed 15 historical-pack cases per environment.
Actual CI results are recorded in the PR after execution, not assumed here.
Original evidence, signatures, keys, prior tests, workflow files, dependencies,
fixed releases, specifications, CHANGE-001, K3 and reproduction-kit baselines
are unchanged. The historical pack's unresolved checks are not resolved by
this fix. No independent reproduction, identity or conformance claim is made.

## 日本語

検査結果のstatus欄が配列やオブジェクトの場合、集約処理が例外になり、別の検査で
検出した不一致まで判定不能に落ちる問題を修正しました。不正な形式の結果を合格に
することなく、他の検査が明示したINVALIDを維持します。検証アルゴリズムや証拠は
変更しません。実際の外部証明を検証した、正式仕様として採択した、という意味では
ありません。結果を返すPython連携コードは引き続き利用者が信頼するコードです。
