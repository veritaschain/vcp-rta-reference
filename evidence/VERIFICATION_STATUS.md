# What this evidence pack can and cannot show

This note is a later correction. It does not replace `04_anchor/security_object.json`, `04_anchor/anchor_reference.json`, or the event log. Those files were not edited. The published Merkle root is still:

`86c05dbad79ffe6fdb5c3063128df0af0bcb5a3e95f4586348f13ca49778a47e`

This repository is VCP v1.1 format. v1.2 is not claimed here.

## Coverage of `evidence_index.json`

`evidence_index.json` is not an input to the event hashes, the Merkle tree, or the Ed25519 signatures.

- Each `EventHash` is SHA-256 of sorted-key JSON for that event's Header concatenated with its Payload.
- The Merkle root is computed from those event hashes.
- Event signatures are Ed25519 over the raw 32-byte `EventHash`. The security-object signature is Ed25519 over the raw Merkle root.

The SHA-256 of `evidence_index.json` does not appear in the event log, the security object, or the anchor reference. Descriptive fields in the index were adjusted in this correction. `MerkleRoot`, identifiers, counts, timestamps, and file paths in the index were left as published.

## What the verifier checks

With `tools/verifier/vcp_verifier.py`, the trusted public key, and the security object:

- Ed25519 signatures of the 40 events verify against `04_anchor/public_key.json`.
- The recomputed Merkle root matches the published root.
- That tree is the VCP v1.1 construction: SHA-256, `0x00` on leaves, `0x01` on internal nodes, odd nodes duplicated. It is not a strict RFC 6962 §2.1 Merkle Tree Hash (largest power of two less than the node count). For these 40 leaves the strict root is different (`4fba6e25694a4c7c0a13fae55d5fe2e538c69036cd5a45c30ef2ca799bd785c3`) and is not the verdict.

## External anchor

`04_anchor/anchor_reference.json` names `merkle_root.ots` and status `ANCHORED`. That status was not used as confirmation.

Search on 2026-10-21 found no `merkle_root.ots` and no OpenTimestamps proof for root `86c05dba…a47e`. `ots verify` was not run, because there is no proof file to verify. No new timestamp was created.

Places searched:

- This clone after `git fetch --all --tags`: branches `main` and `cursor/vcp-verifier-three-valued-faf6`; tags `v1.0.0` and `v1.1.0`; every reachable blob. No path ending in `.ots`.
- Tag trees contain `evidence/04_anchor/merkle_root.txt` only. v1.0.0 records root `e0a1a56c35c63b0ea33754f000ecdc73c1130c2cb9997b5deb728ba1a2ba69b9` (150 events). v1.1.0 records root `131122183f52080721883d01cdd4cf0fe3ddbd0085b8d98b1b2cb3d52d631bab`. Neither is `86c05dba…`. The v1.1.0 `anchor_record.json` sets `AnchorTarget.Proof` to `OTS_PENDING_131122183f520807` and says the anchor was simulated for public release.
- GitHub releases for `veritaschain/vcp-rta-reference`: `v1.1.0` and `v1.0.0`, both with empty asset lists.
- Default-branch file trees of the public `veritaschain` repositories listed by the GitHub user API (27 repositories), plus a shallow clone of each repository other than this one. No `*.ots` file, no `merkle_root.ots`, and no copy of root `86c05dba…`. Other repositories mention `.ots` only as sample code that would write a proof.
- `docs/VCP_Worlds_First_Evidence_Report.pdf` (same bytes as the copy at the repository root) contains neither `.ots` nor `86c05`.

The external anchor cannot be verified from the public materials.

## Older wording left in place

`02_verification/verification_report.txt` still says "Fully Compliant" and "Merkle Root (RFC 6962)". That file is an older generated report. It was not rewritten. The current verifier does not use that wording.

`02_verification/verification_report.txt` is a historical output kept unchanged. Its "Fully Compliant" wording is superseded. The current result is `02_verification/verification_report_2026-10-22.txt` (JSON: `02_verification/verification_report_2026-10-22.json`).
