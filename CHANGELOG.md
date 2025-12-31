# Changelog

All notable changes to this project will be documented in this file.

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
