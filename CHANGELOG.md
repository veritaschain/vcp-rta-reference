# Changelog

All notable changes to this project will be documented in this file.

## Later correction — 2026-10-28

Documentation only. This entry does not rewrite the notes below. Signed event data, the published Merkle root, anchor files, existing git tags, and `evidence/02_verification/verification_report.txt` were not changed. The 2026-10-22 verifier output was not regenerated.

- Reader-facing wording states what is implemented, what is known-unresolved, and what is not claimed. This repository is a first-party reference pack. It is not a certified product and it is not Production Ready. There is no claim of VCP v1.2 full conformity.
- `evidence/VERIFICATION_STATUS.md` records the three-valued verifier, that a missing `merkle_root.ots` makes the external anchor UNVERIFIABLE, and that the Merkle tree is the VCP v1.1 duplicate-odd-node construction rather than strict RFC 6962. External implementations recorded here: zero. Evidence Pack procedural acceptances recorded here: zero.
- `KNOWN_ISSUES.md` records schema and norm gaps, and signature, Merkle, and numeric-precision issues still under review for VCP v1.2.
- Descriptive fields in `evidence/evidence_index.json` carry the same limits. `MerkleRoot`, identifiers, counts, timestamps, and file paths were left as published.
- The historical report and the older tamper-detection demo still contain superseded "Fully Compliant" wording. Those files were not edited.

## Later correction — 2026-10-22

A new verification report only. This entry does not rewrite the notes below. Signed event data, the published Merkle root, anchor files, existing git tags, and `evidence/02_verification/verification_report.txt` were not changed.

- `tools/verifier/vcp_verifier.py` at commit `c3167eb43761498a625e1626e7ad64957d8f2d3a` was run on 2026-10-22 19:05:25 JST against the published evidence pack (event log, security object, trusted public key, and anchor reference). `--json` wrote the JSON report.
- Output: `evidence/02_verification/verification_report_2026-10-22.txt` and `evidence/02_verification/verification_report_2026-10-22.json`. Overall result UNVERIFIABLE, exit code 2. The anchor reference was checked; `merkle_root.ots` is not present, so the external anchor is UNVERIFIABLE. Event signatures (sequence 1 .. 40, 40 events) and the VCP v1.1 duplicate-odd-node Merkle root matched. That tree is not a strict RFC 6962 Merkle Tree Hash.
- `evidence/02_verification/verification_report.txt` is a historical output kept unchanged. Its "Fully Compliant" wording is superseded. The 2026-10-22 files are the current result.

## Later correction — 2026-10-21

Documentation and the verifier only. This entry does not rewrite the notes below. Signed event data, the published Merkle root, anchor files, and existing git tags were not changed.

- The verifier checks Ed25519 signatures against an explicit trusted public key.
- The published Merkle root matches the VCP v1.1 duplicate-odd-node tree (0x00 / 0x01 prefixes, odd node duplicated). It is not a strict RFC 6962 §2.1 Merkle Tree Hash.
- `merkle_root.ots` was not found in public git history, tags, GitHub release assets, or other public veritaschain repositories. The external anchor cannot be verified from those materials. No new timestamp was created.
- Reader-facing wording no longer calls this pack fully compliant or production-grade. This repository is v1.1 format. v1.2 is not claimed here.

## [1.1.0] - 2025-12-31

### Added
- **Three-Layer Architecture** - Event, Chain, and Anchor layers
- **Policy Identification** - Required `policy_id` field in all events
- **Merkle Tree** - Required for chain integrity verification
- **External Anchor Reference** - Required for Silver tier
- **Completeness Guarantees** - Detection of omission attacks
- **Anonymization** - Ticket numbers and position IDs are SHA-256 hashed

### Changed
- **PrevHash** - Now optional (was required in v1.0)
- **Silver Tier Requirements** - External anchor now mandatory
- Folder structure aligned with VCP specification
  - `01_trade_logs/`
  - `02_verification/`
  - `03_tamper_detection/`
  - `04_anchor/`

### Fixed
- Merkle root calculation consistency between generator and verifier

## [1.0.0] - 2025-11-25

### Added
- Initial VCP v1.0 evidence pack
- Basic chain verification
- Ed25519 digital signatures
- PrevHash linking
