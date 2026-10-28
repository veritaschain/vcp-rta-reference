# VCP v1.1 Three-Layer Architecture

## Overview

VCP v1.1 describes a three-layer architecture for trading logs. In this repository the three-valued verifier checks Layer 1 signatures and the Layer 2 Merkle root. Layer 3, the external anchor, is UNVERIFIABLE because `merkle_root.ots` is missing. This document describes v1.1 only. There is no claim of VCP v1.2 full conformity. This is a first-party reference pack, not a certified product, and it is not Production Ready. See [KNOWN_ISSUES.md](../KNOWN_ISSUES.md).

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
│  └─ External Anchor (OpenTimestamps): named here, not confirmed   │
│                                                                     │
│  Frequency: Daily in the v1.1 text. Anchor here is not confirmed   │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  LAYER 2: Collection Integrity    ← Core for external verifiability │
│  ────────────────────────────────                                   │
│  Purpose: Compare a batch with a published Merkle root              │
│                                                                     │
│  Components:                                                        │
│  ├─ Merkle Tree (VCP v1.1 duplicate-odd-node): REQUIRED            │
│  ├─ Merkle Root: REQUIRED                                          │
│  └─ Audit Path (for verification): REQUIRED                        │
│                                                                     │
│  Note: Recomputes the v1.1 duplicate-odd-node root, not RFC 6962   │
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
- SHA-256 event hashing (sorted-key `json.dumps` of Header concatenated with Payload; not full RFC 8785)
- Ed25519 digital signatures, checked by `tools/verifier/vcp_verifier.py` against `evidence/04_anchor/public_key.json`
- Required PolicyIdentification (v1.1)
- Dual timestamp format (ISO + int64 nanoseconds)

---

## Layer 2: Collection Integrity

### VCP v1.1 Merkle tree

The published root `86c05dbad79ffe6fdb5c3063128df0af0bcb5a3e95f4586348f13ca49778a47e` matches this construction, which is what `security_object.json` records as `RFC6962` and what the VCP v1.1 pseudocode specifies:

- Leaf: `SHA-256(0x00 || raw EventHash)`
- Internal node: `SHA-256(0x01 || left || right)`
- An odd node is duplicated

That odd-node rule is not strict RFC 6962 §2.1. RFC 6962 splits at the largest power of two smaller than the node count. For these 40 leaves the strict root is `4fba6e25694a4c7c0a13fae55d5fe2e538c69036cd5a45c30ef2ca799bd785c3`, and the verifier does not treat it as the expected root.

The tree, with domain separation:

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

**Domain separation (shared with RFC 6962):**
- Leaf nodes: `0x00` prefix
- Internal nodes: `0x01` prefix
- Odd nodes in this pack: duplicated, not the RFC 6962 power-of-two split

**Benefits:**
- Prevents second preimage attacks
- Efficient verification of any event integrity
- Partial verification possible (audit path only)

### PrevHash Linking

Each event may reference the previous event's hash:

```
Event 1 ──PrevHash──> Event 2 ──PrevHash──> Event 3
```

**v1.1 change:** PrevHash is now OPTIONAL. When an expected root is supplied, the verifier can compare the file with the VCP v1.1 duplicate-odd-node root. That comparison is not a completeness guarantee beyond the checks that actually run, and it is not an external timestamp.

---

## Layer 3: External Verifiability

### External Timestamp Anchoring

Anchors Merkle Root to external services for third-party verification:

```
[Merkle Root] ──submit──> [OpenTimestamps] ──anchor──> [Bitcoin]
```

The v1.1 text treats an external anchor as required for Silver. This repository names OpenTimestamps in `evidence/04_anchor/anchor_reference.json` and sets status `ANCHORED`. `merkle_root.ots` is not among the public files, tags, release assets, or other public veritaschain repositories searched on 2026-10-21. The anchor cannot be verified from those materials, and no replacement proof was created. See [evidence/VERIFICATION_STATUS.md](../evidence/VERIFICATION_STATUS.md).

---

## Attack Scenarios and Defense

| Attack | Detection Method | Layer |
|--------|------------------|-------|
| **Event modification** | EventHash + Merkle Root mismatch | L1 + L2 |
| **Event deletion** | Sequence Gap + Merkle Root mismatch | L1 + L2 |
| **Event insertion** | PrevHash mismatch + Merkle Root mismatch | L1 + L2 |
| **Reordering** | PrevHash mismatch + Sequence Gap | L1 |
| **Timestamp manipulation** | Would require a confirmed external anchor. This repository does not include one. | L3 |
| **Post-hoc log fabrication** | A confirmed external anchor would bound existence time. That proof is not in the public files. | L3 |

---

## v1.0 → v1.1 Changes

| Item | v1.0 | v1.1 |
|------|------|------|
| Merkle tree | Optional | **VCP v1.1 duplicate-odd-node tree. Not strict RFC 6962 §2.1** |
| External anchor | Optional in the v1.0 text | **Named in this pack. The proof file is not public, so it is not confirmed** |
| Policy Identification | None | **Fields present** |
| PrevHash | Required | Optional |
| Batch comparison | None | **Against a supplied expected root** |
| Dual Timestamp Format | None | **Present on these events** |

---

## References

- [VCP Specification v1.1](https://github.com/veritaschain/vcp-spec/tree/main/spec/v1.1)
- [OpenTimestamps](https://opentimestamps.org/)
- [RFC 6962 - Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [RFC 8785 - JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785) — referenced by the v1.1 text. This pack's EventHash uses sorted-key `json.dumps`, not a full JCS implementation.
