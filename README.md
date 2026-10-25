> **Status correction — 25 October 2026**
>
> - This is first-party proof-of-concept code by VeritasChain Co., Ltd., which operates the VeritasChain Standards Organization (VSO). It targets VCP v1.1 (Silver tier). VCP v1.1 has no tagged release and is superseded by VCP v1.2 (Released, tag `v1.2.0`).
> - Conformance to any VCP tier, or to VAP, has not been independently established. There are zero external implementations of VAP or any of its profiles, including VCP.
> - Not certified. VSO does not issue certifications itself. The certification scheme requires a Conformity Assessment Body (CAB) independent of the scheme owner; the only registered CAB, VeritasChain Co., Ltd., is not independent (VAP v1.2 ERRATA E-2026-10-21).
> - Known limitations: `evidence/04_anchor/anchor_reference.json` refers to an OpenTimestamps proof file (`merkle_root.ots`) that is not in this repository, so the anchor cannot be checked from the repository. `tools/verifier/vcp_verifier.py` does not verify the Ed25519 signatures or any OpenTimestamps proof. The Merkle builder duplicates the last node at odd-sized levels; it uses the RFC 6962 hash prefixes but not the RFC 6962 tree algorithm.
> - Texts inside the evidence pack (`evidence/`, for example "Fully Compliant" in `verification_report.txt` and `evidence_index.json`) predate this correction and are left unchanged. Read them as design targets, not results.

## 🔗 Related Reference Implementations (Other Platforms)

### cTrader

> 📌 **World-First Evidence**  
> Publicly documented, independently verifiable cryptographic audit trail PoC  
> 👉 https://github.com/veritaschain/vcp-ctrader-rta-reference

### FIX Protocol

> 📌 **World-First Evidence**  
> Publicly documented, independently verifiable cryptographic audit trail PoC  
> 👉 https://github.com/veritaschain/vcp-fix-rta-reference

### Interactive Brokers (IBKR)

> 📌 **World-First Evidence**  
> Publicly documented, independently verifiable cryptographic audit trail PoC  
> 👉 https://github.com/veritaschain/vcp-ibkr-rta-reference

### Nasdaq

> 📌 **World-First Evidence**  
> Publicly documented, independently verifiable cryptographic audit trail PoC  
> 👉 https://github.com/veritaschain/vcp-nasdaq-rta-reference

### cloudflare

> 📌 **World-First Evidence**  
> Publicly documented, independently verifiable cryptographic audit trail PoC  
> 👉 https://github.com/veritaschain/vcp-cloudflare-rta-reference

# VCP Reference Trading Agent (VCP-RTA)

[**English**](README.md) | [日本語](README.ja.md)

![VCP v1.1](https://img.shields.io/badge/VCP-v1.1-blue)
![Non-certified PoC](https://img.shields.io/badge/Status-Non--certified_PoC-orange)
![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)

> **"Verify, Don't Trust."**

VCP-RTA is a proof of concept for algorithmic trading audit trails that targets **VCP v1.1 Silver Tier**; Silver conformance has not been established. This repository provides an evidence pack whose hash, sequence and Merkle-root checks third parties can reproduce (see the status correction above for what is not checked).

📄 **A detailed "World's First" Evidence Report documenting independent prior-art analyses is included in this repository.**

---

## Overview

This Evidence Pack demonstrates a PoC implementation of VCP in a live MT5 environment. The implementation captures AI-driven trading decisions and execution events using a non-invasive sidecar architecture that operates independently of the core trading platform.

AI decision signals, order lifecycle events, and execution outcomes are recorded externally, cryptographically hashed, organized into Merkle trees, and anchored to enable independent third-party verification.

---

## What's New in v1.1

| Feature | v1.0 | v1.1 |
|---------|------|------|
| **Three-Layer Architecture** | - | ✅ NEW |
| **External Anchor (Silver)** | OPTIONAL | **REQUIRED** |
| **Policy Identification** | - | **REQUIRED** |
| **PrevHash** | REQUIRED | OPTIONAL |
| **Completeness (omission detection)** | - | ✅ NEW |

> **v1.1 Core Enhancement:** Extends tamper-evidence to completeness: post-anchor omission is detectable at anchor granularity. This does not show that every real-world event was captured before anchoring.

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
├── examples/
│   └── ai-trading-integration/
│       ├── README.md                # Integration guide
│       ├── vcp_logger.py            # VCP v1.1 logger module
│       └── vcp_poc_demo.py          # PoC demonstration
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

# Run verification (Linux/macOS)
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_rta_events.jsonl \
    -s evidence/04_anchor/security_object.json

# Run verification (Windows)
python tools\verifier\vcp_verifier.py evidence\01_trade_logs\vcp_rta_events.jsonl -s evidence\04_anchor\security_object.json

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
| **Target tier** | Silver (not established) |

### Anonymization

This evidence pack anonymizes sensitive information:
- Ticket numbers: SHA-256 hashed
- Position IDs: SHA-256 hashed
- Trade amounts: Excluded
- Account identifiers: Excluded
- AI model names: Excluded (vote counts only)

---

## Security Features

### Three-Layer Architecture (VCP v1.1)

1. **Layer 1: Event Integrity** - Individual event hash & signature (SHA-256 + Ed25519)
2. **Layer 2: Collection Integrity** - RFC 6962 Merkle Tree + PrevHash linking
3. **Layer 3: External Verifiability** - External timestamp anchoring (OpenTimestamps)

### Tamper Detection Capabilities

- ✅ **Event Omission** (Deletion Attack) - Detected via sequence gaps + Merkle mismatch
- ✅ **Event Modification** (Alteration Attack) - Detected via Merkle root mismatch
- ✅ **Event Insertion** (Injection Attack) - Detected via prev_hash + Merkle mismatch

---

## License

This evidence pack is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

## Integration Examples

The `examples/` directory contains reference implementations for integrating VCP into your own systems:

- **[AI Trading Integration](examples/ai-trading-integration/)** - Python module for logging trading events, targeting VCP v1.1 (conformance not established)

---

## Related Links

- [VCP Specification v1.1](https://github.com/veritaschain/vcp-spec/tree/main/spec/v1.1)
- [VeritasChain Standards Organization](https://github.com/veritaschain)
