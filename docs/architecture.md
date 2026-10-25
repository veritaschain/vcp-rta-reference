# Legacy evidence verification architecture

Informative implementation description, updated 26 October 2026.
The earlier three-layer design narrative is preserved in
[Git history at the pre-replay baseline](https://github.com/veritaschain/vcp-rta-reference/blob/6818bf3d08f8c24b31798d8ab0f0a60af8c22b4b/docs/architecture.md).
It must not be read as evidence that every layer was independently verified.
This page changes no VCP/VAP requirement or historical signed bytes.

## Inputs and trust

The archived pack contains 40 records declaring `Security.Version = 1.1`, a
security object with a root-only signature, a public reference key and an anchor
reference. The last two are producer-supplied material, not automatically trusted
identity or proof of external anchoring. No original `.ots` proof is present.

The default runtime accepts a caller-selected key. The separate replay command
requires explicit opt-in to compare against the public reference key and labels
that comparison as mathematical only. Neither process establishes the key owner's
identity, trading-system behavior, or correctness of recorded decisions.

## Event integrity

The historical `EventHash` is SHA-256 of the UTF-8 concatenation of Python's
sorted-key JSON for Header and Payload, using the historical default separators.
This is **not RFC 8785 JCS** and does not cover the PolicyIdentification object.
The default verifier preserves this encoding instead of rewriting old records.
It verifies Ed25519 signatures over raw digest bytes for this corpus. The other
legacy ASCII-hex convention must be selected explicitly for other inputs.

Sequence checks describe the supplied file's continuity. PrevHash comparisons
check available links but do not invent the missing first-link boundary. Missing
material is `INDETERMINATE`, not a claim of nonconformance where chaining may be
optional in a protocol.

## Collection integrity

Leaves use SHA-256(0x00 || raw EventHash); internal nodes use SHA-256(0x01 || left || right).
The historical builder duplicates an odd final node at each level. Those prefixes
do not make its shape the strict RFC 6962 Merkle Tree Hash construction. The
[fixed-pack replay](../tools/verifier/HISTORICAL.md) records different roots for
the historical 40-event construction and the strict split construction.

Current inclusion checks use full-batch order, path length, sibling side,
MerkleIndex and the historical odd-node rule. A supplied empty path is not missing
and is accepted only for a consistent single-leaf tree. Matching a supplied root
does not establish that all real-world events were captured.

The security-object signature authenticates the root, **not** event count,
sequence range or policy. `batch_bounds_local` is a local consistency comparison,
not authenticated completeness or VAP INT-008 conformance.

## External evidence and the optional extension

The default CLI does not verify external timestamps. Its Python API permits a
trusted caller-provided adapter; adapter code is never selected by evidence.
Missing or unusable checks do not pass. A producer's `CONFIRMED` label is ignored
as an assertion, not treated as a timestamp verification result.

The separate [supplemental verifier](../tools/verifier/SUPPLEMENTAL.md) authenticates
a new signed statement binding context, root, count, endpoint IDs, sequence range,
policy and parsed snapshots of the entire events/security object. Its RFC 3161
check covers the whole signed envelope and uses an explicit caller CA bundle and
policy. It does not recover or replace the original historical anchor.

Later attestation cannot establish original log time. The stated checks exclude
revocation, live freshness, historical certificate validity, qualified-TSA status
and legal evidentiary effect. They do not constitute a normative format adoption.

## Aggregation and test evidence

Each independent available check runs. Aggregation gives `INVALID` priority over
`INDETERMINATE`, then `VALID`; missing material cannot hide a demonstrated mismatch.
No general VCP schema/conformance assessment is implemented. The archived corpus
therefore retains an overall `INDETERMINATE` verdict even when its individual
hashes and signatures match the reference material.

[Current regression instructions](../tools/verifier/REPRODUCING.md) cover synthetic
cryptographic tests. [Historical replay](../tools/verifier/HISTORICAL.md) separately
covers the fixed published data. Both are first-party tests. Neither their green
CI status nor a per-check `VALID` result establishes independent reproduction,
production suitability, certification or full evidence verification.
