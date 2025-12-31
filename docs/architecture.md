# VCP v1.1 Three-Layer Architecture

## Overview

VCP v1.1 employs a three-layer architecture to ensure complete integrity of trading logs. Each layer provides distinct guarantees that combine to create a cryptographically verifiable audit trail.

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  LAYER 3: External Verifiability                                    │
│  ─────────────────────────────────                                  │
│  Purpose: Third-party verification without trusting the producer    │
│                                                                     │
│  Components:                                                        │
│  ├─ Digital Signature (Ed25519): REQUIRED                          │
│  ├─ Timestamp (dual format ISO+int64): REQUIRED                    │
│  └─ External Anchor (OpenTimestamps): REQUIRED                     │
│                                                                     │
│  Frequency: Daily (Silver Tier)                                    │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  LAYER 2: Collection Integrity    ← Core for external verifiability │
│  ────────────────────────────────                                   │
│  Purpose: Prove completeness of event batches                       │
│                                                                     │
│  Components:                                                        │
│  ├─ Merkle Tree (RFC 6962): REQUIRED                               │
│  ├─ Merkle Root: REQUIRED                                          │
│  └─ Audit Path (for verification): REQUIRED                        │
│                                                                     │
│  Note: Enables third-party verification of batch completeness      │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  LAYER 1: Event Integrity                                           │
│  ────────────────────────                                           │
│  Purpose: Individual event completeness                             │
│                                                                     │
│  Components:                                                        │
│  ├─ EventHash (SHA-256 of canonical event): REQUIRED               │
│  └─ PrevHash (link to previous event): OPTIONAL                    │
│                                                                     │
│  Note: PrevHash provides real-time detection (OPTIONAL in v1.1)    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Event Integrity

Each event follows the VCP v1.1 schema with Header, Security, and PolicyIdentification:

```json
{
  "Header": {
    "EventID": "uuid",
    "EventType": "SIG",
    "TimestampISO": "2025-11-20T20:38:25.482205+09:00",
    "TimestampInt": 1763638705482204928,
    "Sequence": 1,
    "AgentID": "VCP-RTA-Reference"
  },
  "Payload": {
    "SignalRef": "39f1bdc5a35ac4b5",
    "Direction": "BUY",
    "Confidence": 0.72,
    "ConsensusSummary": {
      "ModelCount": 5,
      "BuyVotes": 3,
      "SellVotes": 1,
      "AbstainVotes": 1,
      "AvgConfidence": 0.68
    },
    "Symbol": "USDJPY"
  },
  "Security": {
    "Version": "1.1",
    "EventHash": "89e14a2f3651ecabe7e201ca4a20ab0a...",
    "HashAlgo": "SHA256",
    "SignAlgo": "ED25519",
    "Signature": "1dd5ed5434e33fc13559a669815009ab...",
    "PrevHash": "7d3c6b5a4e8f2a1d...",
    "MerkleRoot": "86c05dbad79ffe6fdb5c3063128df0af...",
    "MerkleIndex": 0,
    "AnchorReference": "uuid"
  },
  "PolicyIdentification": {
    "PolicyID": "org.veritaschain.rta:silver-reference-v1",
    "ConformanceTier": "SILVER",
    "RegistrationPolicy": {
      "Issuer": "VeritasChain Standards Organization",
      "PolicyURI": "https://veritaschain.org/policies/silver-reference",
      "EffectiveDate": 1767052800000000000
    },
    "VerificationDepth": {
      "HashChainValidation": true,
      "MerkleProofRequired": true,
      "ExternalAnchorRequired": true
    }
  }
}
```

**Security features:**
- SHA-256 event hashing (canonical JSON serialization)
- Ed25519 digital signatures
- Required PolicyIdentification (v1.1)
- Dual timestamp format (ISO + int64 nanoseconds)

---

## Layer 2: Collection Integrity

### RFC 6962 Merkle Tree

Constructs a Merkle Tree from all event hashes with domain separation:

```
                    Merkle Root
                        │
            ┌───────────┴───────────┐
            │                       │
    H(0x01 || H0 || H1)     H(0x01 || H2 || H3)
            │                       │
      ┌─────┴─────┐           ┌─────┴─────┐
      │           │           │           │
  H(0x00||E0)  H(0x00||E1)  H(0x00||E2)  H(0x00||E3)
```

**RFC 6962 Domain Separation:**
- Leaf nodes: `0x00` prefix
- Internal nodes: `0x01` prefix

**Benefits:**
- Prevents second preimage attacks
- Efficient verification of any event integrity
- Partial verification possible (audit path only)

### PrevHash Linking

Each event may reference the previous event's hash:

```
Event 1 ──PrevHash──> Event 2 ──PrevHash──> Event 3
```

**v1.1 change:** PrevHash is now OPTIONAL. Merkle Tree provides equivalent completeness guarantees.

---

## Layer 3: External Verifiability

### External Timestamp Anchoring

Anchors Merkle Root to external services for third-party verification:

```
[Merkle Root] ──submit──> [OpenTimestamps] ──anchor──> [Bitcoin]
```

**Silver Tier requirements:**
- External anchor is REQUIRED (was optional in v1.0)
- Daily anchoring frequency
- Third parties can independently verify timestamps

---

## Attack Scenarios and Defense

| Attack | Detection Method | Layer |
|--------|------------------|-------|
| **Event modification** | EventHash + Merkle Root mismatch | L1 + L2 |
| **Event deletion** | Sequence Gap + Merkle Root mismatch | L1 + L2 |
| **Event insertion** | PrevHash mismatch + Merkle Root mismatch | L1 + L2 |
| **Reordering** | PrevHash mismatch + Sequence Gap | L1 |
| **Timestamp manipulation** | External anchor mismatch | L3 |
| **Post-hoc log fabrication** | External anchor proves existence time | L3 |

---

## v1.0 → v1.1 Changes

| Item | v1.0 | v1.1 |
|------|------|------|
| Merkle Tree | Optional | **Required** |
| External Anchor | Optional | **Silver: Required** |
| Policy Identification | None | **Required** |
| PrevHash | Required | Optional |
| Completeness Guarantees | None | **Available** |
| Dual Timestamp Format | None | **Required** |
| RFC 6962 Compliance | None | **Required** |

---

## References

- [VCP Specification v1.1](https://github.com/veritaschain/vcp-spec/tree/main/spec/v1.1)
- [OpenTimestamps](https://opentimestamps.org/)
- [RFC 6962 - Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [RFC 8785 - JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
