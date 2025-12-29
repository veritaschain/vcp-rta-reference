# VCP Reference Trading Agent (VCP-RTA)

[![VCP Version](https://img.shields.io/badge/VCP-v1.0-blue)](https://github.com/veritaschain/vcp-spec)
[![Tier](https://img.shields.io/badge/Tier-Silver-silver)](https://github.com/veritaschain/vcp-spec)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-green)](LICENSE)

**VCP-RTA** is a reference implementation demonstrating VCP v1.0 Silver Tier compliance for algorithmic trading systems. This repository provides a complete, verifiable evidence pack that third parties can independently validate.

---

## 🎯 Purpose

This reference implementation demonstrates:

- **Immutable Audit Trail**: SHA-256 hash-chained event logs
- **AI Governance Transparency**: Multi-model consensus decision recording (VCP-GOV)
- **Third-Party Verifiability**: Anyone can verify chain integrity offline
- **Tamper Evidence**: Single-line deletion immediately breaks verification

---

## 📦 Repository Structure

```
vcp-rta-reference/
├── README.md                    # This file
├── DISCLAIMER.md                # Legal disclaimer
├── LICENSE                      # CC BY 4.0
├── evidence/
│   ├── 00_raw/                  # Raw source data (anonymized)
│   ├── 01_sample_logs/          # VCP event chain (JSONL)
│   ├── 02_verification/         # Verification procedures & scripts
│   ├── 03_tamper_demo/          # Tamper detection demonstration
│   ├── 04_anchor/               # Merkle root & timestamps
│   └── 05_environment/          # Execution environment specs
├── tools/
│   ├── log_converter/           # Convert raw logs to VCP format
│   └── verifier/                # Chain verification tool
└── docs/
    └── architecture.md          # System architecture
```

---

## 🚀 Quick Start

### Verify the Evidence Pack

```bash
# Clone the repository
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference

# Run verification (Python 3.8+, no dependencies required)
python tools/verifier/vcp_verifier.py evidence/01_sample_logs/vcp_rta_demo_events.jsonl
```

**Expected Output:**
```
============================================================
VCP Chain Verification Report
============================================================
File: vcp_rta_demo_events.jsonl
Total Events: 150
Unique TraceIDs: 30

Verification Results:
  Genesis: PASS
  Hash Chain: PASS
  Timestamp Monotonicity: PASS

============================================================
VERIFICATION: PASS - Chain integrity verified
============================================================

Merkle Root: 4b1385041d05fe167ced67135d707ad8250a5c19afb47f850be97fb108f2c6ff
```

### Run Tamper Detection Demo

```bash
cd evidence/03_tamper_demo
python tamper_demo.py
```

This demonstrates that deleting **just one line** breaks the entire hash chain.

---

## 📊 Evidence Pack Contents

| Component | Description | Events |
|-----------|-------------|--------|
| SIG | AI Consensus Signal | 30 |
| ORD | Order Submission | 30 |
| ACK | Broker Acknowledgment | 30 |
| EXE | Execution | 30 |
| CLS | Position Close | 30 |
| **Total** | | **150** |

### Merkle Root

```
4b1385041d05fe167ced67135d707ad8250a5c19afb47f850be97fb108f2c6ff
```

---

## 🔐 VCP Compliance

| Module | Requirement | Status |
|--------|-------------|--------|
| VCP-CORE | UUID v7, Timestamps, Hash Chain | ✅ PASS |
| VCP-TRADE | Order/Execution Recording | ✅ PASS |
| VCP-GOV | AI Decision Transparency | ✅ PASS |
| VCP-RISK | Risk Parameters | ✅ PASS |
| VCP-SEC | SHA-256, Ed25519 Structure | ✅ PASS |

---

## 🛡️ Security Model

### Hash Chain
```
Genesis (PrevHash = 64 zeros)
    ↓
Event #1 → EventHash #1
    ↓
Event #2 → EventHash #2 (PrevHash = #1)
    ↓
  ...
    ↓
Event #N → EventHash #N (PrevHash = #N-1)
    ↓
Merkle Root
```

### Tamper Resistance
- **1 byte changed** → Hash mismatch → Detected
- **1 line deleted** → PrevHash mismatch → Detected
- **Events reordered** → Chain broken → Detected

---

## 📋 Requirements

- Python 3.8 or higher
- No external dependencies (standard library only)
- Works offline

---

## 📜 License

This work is licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE).

You may copy, redistribute, or adapt this work as long as proper attribution is provided.

---

## 🔗 References

- [VCP Specification v1.0](https://github.com/veritaschain/vcp-spec)
- [VeritasChain Standards Organization](https://veritaschain.org)
- [RFC 8785 - JSON Canonicalization Scheme](https://tools.ietf.org/html/rfc8785)
- [RFC 6962 - Certificate Transparency](https://tools.ietf.org/html/rfc6962)

---

## 📧 Contact

- **Organization**: VeritasChain Standards Organization (VSO)
- **Website**: https://veritaschain.org
- **Specification**: https://github.com/veritaschain/vcp-spec

---

**Verify, Don't Trust.**  
**VCP - Establishing Truth in Algorithmic Trading**
