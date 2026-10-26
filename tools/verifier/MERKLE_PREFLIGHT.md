# Merkle path preflight for the legacy full-batch verifier

Updated 2026-10-26. Implementation correction, not VCP/VAP normative adoption.

## Reproduced classification gap

At baseline `80c50fedde89009230676f787cf892c81cbcbf83`, the `audit_path`
check returned before inspecting supplied proof fields when the expected root
was unavailable. Within each event, an absent path or leaf digest could also
hide a malformed or contradictory MerkleIndex. A malformed path could therefore
be classified only as INDETERMINATE. This did not produce a false VALID or prove
that an attacker could forge a valid inclusion proof.

## Narrow correction

Check the supplied path's container, sibling hashes, directions and length,
and independently check the declared MerkleIndex against the supplied order.
These checks precede root/leaf availability. A demonstrated representation or
position mismatch remains INVALID even when other proof material is missing.
Missing material alone remains INDETERMINATE, not an invented mismatch.

The existing API requires the complete ordered batch and uses this repository's
historical duplicate-odd tree. The expected path length and directions are
computed from that supplied batch size/order, not an authenticated population.
This is not a subset-inclusion API, an RFC 6962 verifier, a VAP completeness
assessment or a new format. Passing a partial batch as the full batch was and
remains unsupported. Do not split a signed batch to fit this interface.

A passing preflight is NOT a passing audit_path result. Actual inclusion still
requires the declared index, expected root, leaf digest, original hash fold and
odd-leaf duplication checks. The existing calculation and expected-root
comparison are retained. No self-computed root replaces a missing expected root.
An empty path is present, not missing: it can match only a single-event batch
with the corresponding root. Missing paths (including null) remain unavailable.

Only the nested audit_paths function inside verify_chain changes in the runtime.
No top-level function is added. All hash/tree primitives, event/root signatures,
public-key admission, timestamp verification, file limits, no-clobber output,
CLI arguments and report schema remain unchanged. The supplemental CLI uses
this same check without changes to its own source file. All existing tests
remain unchanged.

## Verification record

The new `tests/test_merkle_preflight.py` suite has 72 cases. Against the exact
baseline runtime blob `95dad75ead4a278ad73613a948a041ac07d8f9f4`, it produced
52 failures and 20 passes. After the correction all 72 passed. A combined local
run with existing signature-preflight, key-admission, timestamp-policy and
result-aggregation suites passed 319 cases without skips.

The local source was reconstructed from retained source artifacts and matched
to live GitHub blob IDs. Network checkout was unavailable. These were real
module/CLI executions, but not a full local repository run. Fixtures are
synthetic, with independently assembled legacy tree paths and actual local
Ed25519 signatures. No production key or archived evidence was changed.

Expected CI baseline: 695 regression cases (623 existing plus 72 new), plus
15 separately executed historical-pack cases. Actual full CI outcomes and
artifact hash comparisons are recorded in the pull request after execution,
not assumed from local test results.

The historical anchor, preceding-chain boundary, authenticated metadata,
full-schema, identity and independent-reproduction limitations remain. Syntax
INVALID identifies incompatibility with the selected legacy full-batch input;
it does not attribute malicious alteration or authenticate a producer's actions.
No historical proof is generated or recovered by this change.

## 日本語

ルートや葉ハッシュがなくても、提示された経路の形式や位置番号の矛盾は確認します。
不足している材料が別の形式エラーを隠すことなく、形式が正しいだけで包含証明を
合格にすることもありません。全件・順序付きバッチと過去の木の構築方式を前提とし、
部分バッチの検証や正式仕様の採択には拡張しません。元の証拠・署名は変更しません。
