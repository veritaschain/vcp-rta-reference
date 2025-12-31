# VCP v1.1 Three-Layer Architecture

## Overview

VCP v1.1 employs a three-layer architecture to ensure complete integrity of trading logs.

```
┌─────────────────────────────────────────────────────────────┐
│                    Layer 3: Anchor Layer                     │
│              External Timestamp Service Integration          │
│                     (OpenTimestamps, etc.)                   │
├─────────────────────────────────────────────────────────────┤
│                    Layer 2: Chain Layer                      │
│                Merkle Tree + PrevHash Linking                │
│               (Completeness & Order Guarantees)              │
├─────────────────────────────────────────────────────────────┤
│                    Layer 1: Event Layer                      │
│              Individual Event Hash & Signature               │
│                   (Tamper Detection)                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Event Layer

Each event has the following structure:

```json
{
  "vcp_version": "1.1",
  "event_id": "uuid",
  "event_type": "SIGNAL_GENERATED",
  "timestamp": "2025-11-20T10:30:00+09:00",
  "sequence": 1,
  "agent_id": "VCP-RTA-Reference",
  "policy_id": "vcp-rta-silver-v1",
  "payload": { ... },
  "prev_hash": "abc123...",
  "event_hash": "def456...",
  "signature": "sig789..."
}
```

**Security features:**
- SHA-256 event hashing
- Ed25519 digital signatures
- Required policy_id (v1.1)

---

## Layer 2: Chain Layer

### Merkle Tree

Constructs a Merkle Tree from all event hashes:

```
                    Merkle Root
                        │
            ┌───────────┴───────────┐
            │                       │
         Hash(0+1)              Hash(2+3)
            │                       │
      ┌─────┴─────┐           ┌─────┴─────┐
      │           │           │           │
   Event 0    Event 1     Event 2     Event 3
```

**Benefits:**
- Efficient verification of any event integrity
- Partial verification possible (full data not required)

### PrevHash Linking

Each event references the previous event's hash:

```
Event 1 ──prev_hash──> Event 2 ──prev_hash──> Event 3
```

**v1.1 change:** PrevHash is now OPTIONAL. Merkle Tree provides equivalent guarantees.

---

## Layer 3: Anchor Layer

### External Timestamp

Anchors Merkle Root to external services:

```
[Merkle Root] ──submit──> [OpenTimestamps] ──anchor──> [Bitcoin]
```

**Silver Tier requirements:**
- External anchor is REQUIRED (was optional in v1.0)
- Third parties can independently verify timestamps

---

## Attack Scenarios and Defense

| Attack | Detection Method |
|--------|------------------|
| **Event modification** | Event Hash + Merkle Root mismatch |
| **Event deletion** | Sequence Gap + Merkle Root mismatch |
| **Event insertion** | PrevHash mismatch + Merkle Root mismatch |
| **Reordering** | PrevHash mismatch + Sequence Gap |
| **Timestamp manipulation** | External anchor mismatch |

---

## v1.0 → v1.1 Changes

| Item | v1.0 | v1.1 |
|------|------|------|
| Merkle Tree | Optional | **Required** |
| External Anchor | Optional | **Silver: Required** |
| Policy ID | None | **Required** |
| PrevHash | Required | Optional |
| Completeness Guarantees | None | **Available** |

---

## References

- [VCP Specification v1.1](https://github.com/veritaschain/vcp-spec/tree/main/spec/v1.1)
- [OpenTimestamps](https://opentimestamps.org/)
- [RFC 6962 - Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
