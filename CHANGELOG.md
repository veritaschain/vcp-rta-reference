# Changelog

All notable changes to this project will be documented in this file.

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
