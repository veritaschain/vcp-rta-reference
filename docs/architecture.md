# VCP-RTA System Architecture

**Document ID:** ARCH-2025-001  
**Version:** 1.0  
**Date:** 2025-12-29  

---

## Overview

VCP Reference Trading Agent (VCP-RTA) is a demonstration system that implements the VeritasChain Protocol (VCP) v1.0 Silver Tier specification. This document describes the system architecture and data flow.

---

## System Components

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         VCP-RTA Architecture                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────────────────┐ │
│  │   Market     │     │     AI       │     │      Trading             │ │
│  │    Data      │────▶│  Consensus   │────▶│      Platform            │ │
│  │   Source     │     │   Engine     │     │      (Demo)              │ │
│  └──────────────┘     └──────────────┘     └──────────────────────────┘ │
│         │                    │                        │                  │
│         ▼                    ▼                        ▼                  │
│  ┌─────────────────────────────────────────────────────────────────────┐│
│  │                      VCP Event Logger                                ││
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐   ││
│  │  │   SIG   │─▶│   ORD   │─▶│   ACK   │─▶│   EXE   │─▶│   CLS   │   ││
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘   ││
│  │       │            │            │            │            │         ││
│  │       └────────────┴────────────┴────────────┴────────────┘         ││
│  │                              │                                       ││
│  │                              ▼                                       ││
│  │                    ┌─────────────────┐                              ││
│  │                    │   Hash Chain    │                              ││
│  │                    │   (SHA-256)     │                              ││
│  │                    └─────────────────┘                              ││
│  │                              │                                       ││
│  │                              ▼                                       ││
│  │                    ┌─────────────────┐                              ││
│  │                    │  Merkle Tree    │                              ││
│  │                    │  (RFC 6962)     │                              ││
│  │                    └─────────────────┘                              ││
│  │                              │                                       ││
│  │                              ▼                                       ││
│  │                    ┌─────────────────┐                              ││
│  │                    │ OpenTimestamps  │                              ││
│  │                    │    Anchor       │                              ││
│  │                    └─────────────────┘                              ││
│  └─────────────────────────────────────────────────────────────────────┘│
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Event Flow

### 1. Signal Generation (SIG)

```
Market Data → AI Models → Consensus Vote → SIG Event
                │
                ├── Gemini: direction + confidence
                ├── GPT: direction + confidence
                ├── Claude: direction + confidence
                ├── Grok: direction + confidence
                └── Perplexity: direction + confidence
```

### 2. Order Lifecycle

```
SIG → ORD → ACK → EXE → ... → CLS
 │     │     │     │           │
 │     │     │     │           └── Position closed
 │     │     │     └── Order filled
 │     │     └── Broker acknowledged
 │     └── Order submitted
 └── Signal generated
```

### 3. Hash Chain Construction

```
Genesis: PrevHash = "0" × 64
    │
    ▼
Event #1 ───┐
    │       │
    ▼       │  EventHash = SHA-256(
Event #2 ◀─┘    canonical(Header) +
    │           canonical(Payload) +
    ▼           PrevHash
Event #3       )
    │
    ▼
   ...
```

---

## VCP Module Implementation

### VCP-CORE

| Field | Implementation |
|-------|----------------|
| EventID | UUID v7 (time-sortable) |
| TraceID | Signal ID (lifecycle tracking) |
| Timestamp | Unix milliseconds |
| TimestampPrecision | MILLISECOND |
| ClockSyncStatus | BEST_EFFORT |
| HashAlgo | SHA-256 |

### VCP-TRADE

| Field | Implementation |
|-------|----------------|
| OrderID | Broker ticket number |
| Side | BUY / SELL |
| Price | String (decimal precision) |
| Quantity | String (lot size) |
| OrderType | MARKET |

### VCP-GOV

| Field | Implementation |
|-------|----------------|
| AlgoID | VCP-RTA |
| AlgoVersion | 1.0.0 |
| DecisionType | AI_CONSENSUS |
| AIModels | 5 models with direction/confidence |
| ConsensusDirection | BUY / SELL / NONE |
| ConsensusScore | Weighted average |

### VCP-RISK

| Field | Implementation |
|-------|----------------|
| TPPips | Take Profit (pips) |
| SLPips | Stop Loss (pips) |
| TTLMinutes | Time-To-Live |
| MaxSpreadPips | Maximum spread filter |

### VCP-SEC

| Field | Implementation |
|-------|----------------|
| EventHash | SHA-256 (64 hex chars) |
| PrevHash | Previous EventHash |
| SignAlgo | ED25519 (prepared) |
| Signature | null (Silver Tier) |
| KeyID | vcp-rta-key-2025-001 |

---

## Data Formats

### Event Structure (JSON)

```json
{
  "Header": {
    "EventID": "UUID v7",
    "TraceID": "signal_id",
    "Timestamp": 1234567890123,
    "EventType": "SIG|ORD|ACK|EXE|CLS",
    "Symbol": "USDJPY",
    ...
  },
  "Payload": {
    "VCP_GOV": { ... },
    "VCP_TRADE": { ... },
    "VCP_RISK": { ... }
  },
  "Security": {
    "EventHash": "64-char hex",
    "PrevHash": "64-char hex",
    ...
  }
}
```

### Chain File (JSONL)

One event per line, ordered by timestamp.

```
{"Header":{...},"Payload":{...},"Security":{...}}
{"Header":{...},"Payload":{...},"Security":{...}}
...
```

---

## Verification Process

```
┌─────────────────────────────────────────────────┐
│              Verification Flow                   │
├─────────────────────────────────────────────────┤
│                                                  │
│  1. Load JSONL file                             │
│         │                                        │
│         ▼                                        │
│  2. Check Genesis (PrevHash = zeros)            │
│         │                                        │
│         ▼                                        │
│  3. For each event:                             │
│     ├── Verify PrevHash matches previous        │
│     ├── Recalculate EventHash                   │
│     └── Verify hash matches stored              │
│         │                                        │
│         ▼                                        │
│  4. Check timestamp monotonicity                │
│         │                                        │
│         ▼                                        │
│  5. Calculate Merkle Root                       │
│         │                                        │
│         ▼                                        │
│  6. Report: PASS or FAIL                        │
│                                                  │
└─────────────────────────────────────────────────┘
```

---

## Security Considerations

### Immutability

- Each event's hash depends on all previous events
- Modifying any event invalidates all subsequent hashes
- Genesis hash (64 zeros) anchors the chain

### Transparency

- All AI model votes are recorded
- Decision factors are preserved
- Audit trail is complete

### Verifiability

- Third parties can verify independently
- No trust in VCP-RTA system required
- Offline verification supported

---

## Compliance Mapping

| Regulation | VCP Implementation |
|------------|-------------------|
| MiFID II Art. 17 | VCP-GOV AlgoID |
| MiFID II RTS 24 | 7-year retention capable |
| MiFID II RTS 25 | ClockSyncStatus field |
| EU AI Act Art. 12 | VCP-CORE automatic logging |
| EU AI Act Art. 13 | VCP-GOV DecisionFactors |
| EU AI Act Art. 14 | OperatorID field |
| GDPR | AccountID pseudonymized |

---

## References

- [VCP Specification v1.0](https://github.com/veritaschain/vcp-spec)
- [RFC 8785 - JSON Canonicalization Scheme](https://tools.ietf.org/html/rfc8785)
- [RFC 6962 - Certificate Transparency](https://tools.ietf.org/html/rfc6962)

---

**VCP-RTA - VCP v1.0 Silver Tier Reference Implementation**
