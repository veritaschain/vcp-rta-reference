# Read-only replay of the historical 40-event pack

Recorded 26 October 2026 JST. This is a first-party replay of fixed published
bytes, not independent reproduction, identity validation, certification or a
VCP/VAP conformance result. Both runtime verifiers are unchanged by this replay.

## Reproduce

```sh
python -m pip install -r requirements-verifier-test.txt
python tools/verifier/inspect_historical_pack.py
python tools/verifier/inspect_historical_pack.py --compare-reference-key
python -m pytest -q tests/test_historical_evidence.py
```

The inspector writes JSON to stdout only. The public reference key is used for
signature comparison **only** when `--compare-reference-key` is supplied. The
result explicitly sets `key_identity_established`, `original_anchor_confirmed`,
`conformance_claim` and `independent_reproduction` to false. It does not establish
who owns the key or that a trusted identity originally recorded the events.

For this corpus the inspector exits **2**, preserving the `INDETERMINATE` evidence
verdict. Exit 1 means mismatch; exit 3 means incomplete inspection or a changed
baseline. A passing regression that expects exit 2 does not change that verdict.

## Pinned baseline

Repository baseline: `6818bf3d08f8c24b31798d8ab0f0a60af8c22b4b`.
The following Git blob IDs pin the original inputs; exact SHA-256 hashes and byte
lengths of all ten evidence files are recorded before and after each replay.

| File | Git blob |
| --- | --- |
| `evidence/01_trade_logs/vcp_rta_events.jsonl` | `b27d1c0d6449ff6d492fb2609c4681e44f6865ad` |
| `evidence/04_anchor/security_object.json` | `cd00fd6422e8a680b01cf0daef2e625dc039bec1` |
| `evidence/04_anchor/public_key.json` | `696fabc9b8a19f50fb7904131efef3fc229a7671` |
| `evidence/04_anchor/anchor_reference.json` | `4bb8d6b32bea69b811a6fa7a8f7b8172997755e7` |

Input changes are not silently accepted or rebaselined. No archived script is
executed. No historical report, signature, key, tag or release is replaced.

## Observed initial replay

Source head: `53d020f17ad18cb21e43ec8f9b2e6490a1a16f30`.
[Initial CI run 40218449174](https://github.com/veritaschain/vcp-rta-reference/actions/runs/40218449174)
ran on Python 3.11 and 3.13.5. The Python 3.13.5 report artifact was downloaded,
its ZIP SHA-256 and internal manifest checked, and its contents inspected:
15 tests passed, zero failures/errors/skips, all 40 event hashes and signatures
matched, and all ten evidence-file hashes were identical before and after.

The reference-key fingerprint (SHA-256 of raw 32-byte key) is
`65ea2f698c8cd0750a274493b044fc31c4a5ec84db612ce05a1b48a0a2a9d051`.
This fingerprints supplied test material; it does not certify an identity.

| Observation | Result |
| --- | --- |
| Records | 40: SIG 20, EXE 20 (executions, not ORD submissions) |
| Event hashes | 40/40 match historical encoding |
| Event signatures | 40/40 match the explicitly selected reference key |
| Root signature and all inclusion paths | Match published root in the historical construction |
| Sequence and local batch-bound comparisons | Match; metadata remains unauthenticated by root-only signing |
| `prev_hash` | INDETERMINATE: missing original first-link context |
| `authenticated_batch_metadata` | INDETERMINATE: not authenticated by the historical root signature |
| `external_anchor` | INDETERMINATE: no original OTS proof verified |
| Overall | **INDETERMINATE** |

Historical duplicate-odd root:
`86c05dbad79ffe6fdb5c3063128df0af0bcb5a3e95f4586348f13ca49778a47e`.
Strict RFC 6962 split-tree comparison root:
`4fba6e25694a4c7c0a13fae55d5fe2e538c69036cd5a45c30ef2ca799bd785c3`.
The strict root is diagnostic only, never substituted into historical evidence
or used to re-sign it. Full schema verification also remains unimplemented.

## CI and limits

The existing Verifier regression workflow retains its 250-case baseline. A
separate Historical pack replay workflow runs 15 additional cases on both Python
versions. It rejects skipped/failed/partial results, unexpected inspector exit
codes, source/evidence changes and a changed HEAD. It retains JSON, JUnit, logs,
input hashes and an artifact manifest, not private keys. Artifacts expire after
30 days; the pinned inputs, code and this interpretation remain reproducible.

Mutation tests alter only memory copies or temporary copies. Their synthetic
negative cases are not additional incidents in the original records. This work
does not demonstrate original anchoring time, repair missing historical proofs,
prove all real-world events were captured, or establish independent reproduction.
