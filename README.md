# VCP Reference Trading Agent (VCP-RTA)

[**English**](README.md) | [日本語](README.ja.md)

![VCP v1.1](https://img.shields.io/badge/VCP-v1.1-blue)
![Tier Silver](https://img.shields.io/badge/Tier-Silver-silver)
![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)

> **"Verify, Don't Trust."**

VCP-RTA is a reference implementation demonstrating **VCP v1.1 Silver Tier** compliance for algorithmic trading systems. This repository provides a complete, verifiable evidence pack that third parties can independently validate.

---

## Overview

This Evidence Pack demonstrates a production-grade implementation of VCP in a live MT5 environment. The implementation captures AI-driven trading decisions and execution events using a non-invasive sidecar architecture that operates independently of the core trading platform.

AI decision signals, order lifecycle events, and execution outcomes are recorded externally, cryptographically hashed, organized into Merkle trees, and anchored to enable independent third-party verification.

---

## What's New in v1.1

| Feature | v1.0 | v1.1 |
|---------|------|------|
| **Three-Layer Architecture** | - | ✅ NEW |
| **External Anchor (Silver)** | OPTIONAL | **REQUIRED** |
| **Policy Identification** | - | **REQUIRED** |
| **PrevHash** | REQUIRED | OPTIONAL |
| **Completeness Guarantees** | - | ✅ NEW |

> **v1.1 Core Enhancement:** Extends tamper-evidence to **completeness guarantees** — third parties can now verify not only that events were not altered, but that **no required events were omitted**.

---

## Repository Structure

```
vcp_v1_1_repo_aligned/
├── evidence/
│   ├── evidence_index.json          # Evidence manifest
│   ├── 01_trade_logs/
│   │   └── vcp_rta_events.jsonl     # VCP v1.1 event chain (40 events)
│   ├── 02_verification/
│   │   └── verification_report.txt  # Verification results
│   ├── 03_tamper_detection/
│   │   ├── tamper_detection_test.py # Tamper detection test
│   │   └── tampered_chain.jsonl     # Tampered sample for testing
│   └── 04_anchor/
│       ├── security_object.json     # Merkle tree & signatures
│       ├── anchor_reference.json    # External anchor info
│       └── public_key.json          # Verification public key
├── tools/
│   └── verifier/
│       └── vcp_verifier.py          # Chain verification tool
├── docs/
│   ├── VERIFICATION_GUIDE.md        # Step-by-step verification
│   └── architecture.md              # Three-layer architecture
├── CHANGELOG.md
├── DISCLAIMER.md
└── LICENSE
```

---

## Quick Verification

### Prerequisites
- Python 3.8+
- No external dependencies required (standard library only)

### Run Verification

```bash
# Clone the repository
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference

# Run verification
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_rta_events.jsonl \
    -s evidence/04_anchor/security_object.json

# Run tamper detection test
python evidence/03_tamper_detection/tamper_detection_test.py
```

### Expected Output

```
======================================================================
VCP v1.1 Verification Report
======================================================================
[Verification Results]
  Overall Status: [PASS] VALID
  Total Events: 40
  Valid Events: 40
  Invalid Events: 0

[Chain Integrity]
  Sequence Continuity: [PASS]
  PrevHash Integrity: [PASS]
  Merkle Root: [PASS]
======================================================================
Verification complete: All checks passed
======================================================================
```

---

## Evidence Summary

| Metric | Value |
|--------|-------|
| **Total Events** | 40 |
| **Signal Events** | 20 |
| **Order Events** | 20 |
| **VCP Version** | 1.1 |
| **Tier** | Silver |

### Anonymization

This evidence pack anonymizes sensitive information:
- Ticket numbers: SHA-256 hashed
- Position IDs: SHA-256 hashed
- Trade amounts: Excluded
- Account identifiers: Excluded

---

## Security Features

### Three-Layer Architecture (v1.1)

1. **Event Layer** - Individual event integrity with SHA-256 hashes
2. **Chain Layer** - Sequential integrity with prev_hash linking
3. **Anchor Layer** - External timestamp anchoring (OpenTimestamps)

### Tamper Detection Capabilities

- ✅ **Event Omission** (Deletion Attack) - Detected via sequence gaps + Merkle mismatch
- ✅ **Event Modification** (Alteration Attack) - Detected via Merkle root mismatch
- ✅ **Event Insertion** (Injection Attack) - Detected via prev_hash + Merkle mismatch

---

## License

This evidence pack is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

## Related Links

- [VCP Specification v1.1](https://github.com/veritaschain/vcp-spec/tree/main/spec/v1.1)
- [VeritasChain Standards Organization](https://github.com/veritaschain)

---

**VeritasChain Standards Organization (VSO)**
*Developing cryptographically verifiable audit standards for algorithmic and AI-driven systems.*
