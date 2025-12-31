# VCP Reference Trading Agent (VCP-RTA)

[**English**](README.md) | [日本語](README.ja.md) | [中文](README.zh-CN.md) | [Español](README.es.md)

![VCP v1.1](https://img.shields.io/badge/VCP-v1.1-blue)
![Tier Silver](https://img.shields.io/badge/Tier-Silver-silver)
![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)

> **"Verify, Don't Trust."**

VCP-RTA is a reference implementation demonstrating **VCP v1.1 Silver Tier** compliance for algorithmic trading systems. This repository provides a complete, verifiable evidence pack that third parties can independently validate.

---

## 🆕 What's New in v1.1

| Feature | v1.0 | v1.1 |
|---------|------|------|
| **Three-Layer Architecture** | - | ✅ NEW |
| **External Anchor (Silver)** | OPTIONAL | **REQUIRED** |
| **Policy Identification** | - | **REQUIRED** |
| **PrevHash** | REQUIRED | OPTIONAL |
| **Completeness Guarantees** | - | ✅ NEW |

> **v1.1 Core Enhancement:** Extends tamper-evidence to **completeness guarantees** — third parties can now verify not only that events were not altered, but that **no required events were omitted**.

---

## 🎯 Purpose

This reference implementation demonstrates:

- **Three-Layer Integrity Architecture**
  - Layer 1: Event Integrity (EventHash, PrevHash)
  - Layer 2: Collection Integrity (Merkle Tree, RFC 6962)
  - Layer 3: External Verifiability (Signatures, Anchors)
- **Policy Identification** for multi-tier deployments
- **External Anchoring** with OpenTimestamps (required for all tiers in v1.1)
- **Ed25519 Digital Signatures** on all events
- **AI Consensus Recording** (VCP-GOV) with multi-model voting

---

## 📁 Repository Structure

```
vcp-rta-reference/
├── README.md                    # This file
├── README.ja.md                 # Japanese
├── README.zh-CN.md              # Chinese (Simplified)
├── README.es.md                 # Spanish
├── CHANGELOG.md                 # Version history
├── DISCLAIMER.md                # Legal disclaimer
├── LICENSE                      # CC BY 4.0
│
├── docs/
│   ├── architecture.md          # Three-layer architecture (v1.1)
│   ├── VERIFICATION_GUIDE.md    # Step-by-step verification
│   └── MIGRATION_v1.0_to_v1.1.md    # Migration guide
│
├── evidence/
│   ├── 00_raw/                  # Raw signal data (preserved)
│   ├── 01_sample_logs/
│   │   └── vcp_rta_demo_events.jsonl    # 150 signed events
│   ├── 02_verification/
│   │   └── verification_report.txt       # Pre-run verification
│   ├── 03_tamper_demo/
│   │   ├── tamper_demo.py               # Tamper detection demo
│   │   └── tamper_demo_output.txt       # Demo results
│   ├── 04_anchor/
│   │   ├── merkle_root.txt              # Merkle Root
│   │   ├── anchor_record.json           # External Anchor Record
│   │   └── public_key.json              # Ed25519 public key
│   ├── 05_environment/          # Environment info (preserved)
│   └── evidence_index.json      # Evidence manifest
│
└── tools/
    └── verifier/
        └── vcp_verifier.py              # Zero-dependency verifier
```

---

## 🔐 Three-Layer Architecture (v1.1)

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 3: External Verifiability                                    │
│  ├─ Digital Signature (Ed25519): REQUIRED                          │
│  ├─ Timestamp (dual format): REQUIRED                              │
│  └─ External Anchor: REQUIRED (24hr for Silver)                    │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 2: Collection Integrity    ← Core for completeness          │
│  ├─ Merkle Tree (RFC 6962): REQUIRED                               │
│  ├─ Merkle Root: REQUIRED                                          │
│  └─ Audit Path: REQUIRED                                           │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 1: Event Integrity                                           │
│  ├─ EventHash (SHA-256): REQUIRED                                  │
│  └─ PrevHash (hash chain): OPTIONAL                                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ✅ Quick Verification

### Prerequisites

- Python 3.8+ (standard library only)
- No external dependencies required

### Run Verification

```bash
# Clone repository
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference

# Verify chain integrity
python tools/verifier/vcp_verifier.py \
    evidence/01_sample_logs/vcp_rta_demo_events.jsonl \
    evidence/04_anchor/public_key.json
```

### Expected Output

```
======================================================================
VCP v1.1 Chain Verification Report
======================================================================
File: evidence/01_sample_logs/vcp_rta_demo_events.jsonl
VCP Version: 1.1
Total Events: 150
Unique TraceIDs: 30

Event Types:
  SIG: 30    ORD: 30    ACK: 30    EXE: 30    CLS: 30

Three-Layer Verification Results:
  [Layer 1: Event Integrity]
    Genesis: PASS
    Event Hashes: PASS
    Hash Chain: PASS

  [Layer 2: Collection Integrity]
    Merkle Root: PASS

  [Layer 3: External Verifiability]
    Timestamp Monotonicity: PASS
    Policy Identification: PASS
    Anchor Reference: PASS
    Signatures: PASS (150/150 valid)

======================================================================
VERIFICATION: PASS - VCP v1.1 Chain integrity verified
======================================================================

Merkle Root: 131122183f52080721883d01cdd4cf0fe3ddbd0085b8d98b1b2cb3d52d631bab
```

---

## 🔍 Tamper Detection Demo

Demonstrates that removing even ONE event is immediately detected:

```bash
python evidence/03_tamper_demo/tamper_demo.py \
    evidence/01_sample_logs/vcp_rta_demo_events.jsonl
```

**Result**: Deletion of event #76 detected via:
- Layer 1: PrevHash mismatch at event #76
- Layer 2: Merkle Root mismatch (computed vs stored)
- Layer 3: Anchor reference invalidation

---

## 📝 Sample Event Structure (v1.1)

```json
{
  "Header": {
    "EventID": "019b72fb-xxxx-7xxx-xxxx-xxxxxxxxxxxx",
    "TraceID": "20251118_020000_BUY",
    "Timestamp": 1731898800000000,
    "TimestampISO": "2025-11-18T02:00:00.000000Z",
    "EventType": "SIG",
    "Symbol": "USDJPY",
    "VCPVersion": "1.1",
    "Tier": "SILVER",
    "ClockSyncStatus": "BEST_EFFORT"
  },
  "Payload": {
    "VCP_GOV": {
      "AlgoID": "VCP-RTA-Demo",
      "AIModels": {
        "gemini": {"direction": "BUY", "confidence": 0.82},
        "gpt": {"direction": "BUY", "confidence": 0.78},
        "claude": {"direction": "BUY", "confidence": 0.85},
        "grok": {"direction": "BUY", "confidence": 0.80},
        "pplx": {"direction": "NONE", "confidence": 0.55}
      },
      "ConsensusDirection": "BUY",
      "ConsensusScore": "0.850"
    },
    "PolicyIdentification": {
      "Version": "1.1",
      "PolicyID": "org.veritaschain.demo:vcp-rta-silver-001",
      "ConformanceTier": "SILVER",
      "VerificationDepth": {
        "HashChainValidation": true,
        "MerkleProofRequired": true,
        "ExternalAnchorRequired": true
      }
    }
  },
  "Security": {
    "EventHash": "abc123...",
    "PrevHash": "000000...",
    "HashAlgo": "SHA256",
    "SignAlgo": "ED25519",
    "Signature": "def456...",
    "KeyID": "vcp-rta-key-2025-002",
    "MerkleIndex": 0,
    "MerkleRoot": "131122...",
    "AnchorReference": {
      "AnchorID": "019b72fc-...",
      "AnchorTarget": "PUBLIC_SERVICE",
      "AnchorTimestamp": 1735520400000
    }
  }
}
```

---

## 📊 VCP Module Compliance

| Module | Description | Status |
|--------|-------------|--------|
| **VCP-CORE** | Event identification, timestamps | ✅ Implemented |
| **VCP-TRADE** | Order lifecycle events | ✅ Implemented |
| **VCP-GOV** | AI governance, multi-model voting | ✅ Implemented |
| **VCP-RISK** | Risk parameters snapshot | ✅ Implemented |
| **VCP-SEC** | Three-layer security | ✅ Implemented |

### v1.1 Specific Features

| Feature | Requirement | Status |
|---------|-------------|--------|
| Policy Identification | REQUIRED | ✅ All events |
| External Anchor | REQUIRED | ✅ Daily (Silver) |
| Merkle Root | REQUIRED | ✅ All events |
| Anchor Reference | REQUIRED | ✅ All events |

---

## 🔄 Migration from v1.0

See [MIGRATION_v1.0_to_v1.1.md](docs/MIGRATION_v1.0_to_v1.1.md) for detailed guidance.

**Quick Summary:**

| v1.0 → v1.1 Change | Action |
|--------------------|--------|
| Add Policy Identification | Add to all events |
| Add External Anchor | Implement daily anchoring |
| Add MerkleRoot to Security | Add to all events |
| Add AnchorReference | Add to all events |
| PrevHash | Now OPTIONAL (can keep or remove) |

**Grace Period:**
- Policy Identification: March 25, 2026
- External Anchor (Silver): June 25, 2026

---

## ⚠️ Important Disclaimer

This repository is provided **for educational and demonstration purposes only**.

- ✅ Reference implementation of VCP v1.1 Silver Tier
- ✅ Suitable for learning and integration testing
- ❌ **NOT** a product, certification, or compliance determination
- ❌ **NOT** investment advice or trading recommendation
- ❌ **NOT** intended for production without proper key management

See [DISCLAIMER.md](DISCLAIMER.md) for full legal notice.

---

## 📚 Related Resources

| Resource | Link |
|----------|------|
| VCP Specification | [github.com/veritaschain/vcp-spec](https://github.com/veritaschain/vcp-spec) |
| VCP Explorer | [explorer.veritaschain.org](https://explorer.veritaschain.org) |
| Documentation | [docs.veritaschain.org](https://docs.veritaschain.org) |
| Website | [veritaschain.org](https://veritaschain.org) |

---

## 📄 License

This work is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

## 📧 Contact

**VeritasChain Standards Organization (VSO)**  
- Email: standards@veritaschain.org  
- GitHub: [github.com/veritaschain](https://github.com/veritaschain)  
- Support: support@veritaschain.org

---

*"Encoding Trust in the Algorithmic Age"*
