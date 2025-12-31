# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-12-30

### Added
- **Three-Layer Architecture** implementation
  - Layer 1: Event Integrity (EventHash, PrevHash)
  - Layer 2: Collection Integrity (Merkle Tree)
  - Layer 3: External Verifiability (Signatures, Anchors)
- **Policy Identification** in all events (REQUIRED in v1.1)
- **External Anchor Reference** in all events (REQUIRED in v1.1)
- **MerkleIndex** field in Security object
- **MerkleRoot** field in Security object (REQUIRED in v1.1)
- **AnchorReference** field in Security object
- New verification checks for v1.1 requirements
- `THREE_LAYER_ARCHITECTURE.md` documentation
- `MIGRATION_v1.0_to_v1.1.md` migration guide
- Tamper demo now shows three-layer detection

### Changed
- VCP version updated from 1.0 to 1.1
- PrevHash is now OPTIONAL (was REQUIRED in v1.0)
- Verifier updated for three-layer verification
- README updated with v1.1 features
- Sample events regenerated with v1.1 schema

### Fixed
- N/A (new features release)

### Deprecated
- N/A

### Removed
- N/A

### Security
- External Anchor now REQUIRED for all tiers (strengthens integrity guarantees)

---

## [1.0.0] - 2025-12-28

### Added
- Initial release of VCP Reference Trading Agent
- VCP v1.0 Silver Tier compliance
- 150 sample events (30 trade cycles × 5 events)
- Ed25519 digital signatures on all events
- Merkle Root computation (RFC 6962)
- Hash chain with PrevHash linking
- Zero-dependency Python verifier
- Tamper detection demonstration
- Multi-language README (EN, JA, ZH-CN, ES)
- VCP-CORE module implementation
- VCP-TRADE module implementation
- VCP-GOV module (AI consensus recording)
- VCP-RISK module (risk parameters)
- VCP-SEC module (security layer)

### Security
- SHA-256 hash algorithm (RFC 8785 canonicalization)
- Ed25519 digital signatures
- RFC 6962 compliant Merkle tree

---

## Version Compatibility

| Version | VCP Spec | Status |
|---------|----------|--------|
| 1.1.0 | v1.1 | Current |
| 1.0.0 | v1.0 | Supported (tag: v1.0.0) |

---

## Migration Notes

### v1.0.0 → v1.1.0

**Required Changes:**
1. Add `PolicyIdentification` to all event payloads
2. Add `MerkleRoot` to Security object
3. Add `AnchorReference` to Security object
4. Implement external anchoring (daily for Silver)

**Optional Changes:**
- PrevHash can be removed (now OPTIONAL)

**Grace Period:**
- Policy Identification: March 25, 2026
- External Anchor (Silver): June 25, 2026

See [MIGRATION_v1.0_to_v1.1.md](docs/MIGRATION_v1.0_to_v1.1.md) for detailed instructions.
