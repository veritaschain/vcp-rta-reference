> **Verifier runtime update, 26 October 2026.** The default CLI now evaluates
> Ed25519 signatures with an explicitly trusted key and reports VALID, INVALID or
> INDETERMINATE per check. Missing inputs no longer become passes or hide other
> mismatches. This is a first-party legacy-format tool, not a conformance claim.
> The CLI does not verify external anchors, and authenticated batch metadata is
> not implemented, so it does not return an overall VALID result. Historical
> evidence and reports are unchanged; their old all-pass output is not current.
> See [current behavior, limitations and migration](tools/verifier/README.md).
>
> **検証器更新（2026-10-26）:** 提案書だけでなく実行コードを更新しました。
> 検証材料不足は未検証とし、検出できた不一致を隠しません。外部アンカーの実証明検証・
> バッチメタデータの認証は未実装です。旧レポートは保存し、現在の適合証明とは扱いません。

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
![Tier Silver](https://img.shields.io/badge/Tier-Silver-silver)
![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)

> **"Verify, Don't Trust."**

VCP-RTA is a reference implementation demonstrating **VCP v1.1 Silver Tier** compliance for algorithmic trading systems. This repository provides a complete, verifiable evidence pack that third parties can independently validate.

📄 **A detailed "World's First" Evidence Report documenting independent prior-art analyses is included in this repository.**

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
- Standard-library checks can run alone; install `cryptography` for Ed25519 verification.
- No key is trusted automatically. See [verifier instructions](tools/verifier/README.md).

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

### Reading the Result

The previous all-pass example was removed on 26 October 2026. The commands above
supply neither an explicitly trusted key nor an external-anchor verifier. Those
checks are INDETERMINATE, not successful verification. A demonstrated mismatch
in any executed check takes precedence and produces INVALID.

Exit codes are 1 for INVALID, 2 for INDETERMINATE, and 3 for unreadable event input
or output failure. Add `--json` for report format version 2. `--public-key PATH`
enables real Ed25519 verification under the caller's key-trust decision; it does
not establish key ownership. No VCP/VAP conformance or certification is asserted.

The historical reports and test scripts under `evidence/` are preserved, not
rewritten as new verification results. Current regression tests are separate:

```sh
python -m pip install pytest cryptography
python -m pytest -q tests/test_verifier.py
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

- **[AI Trading Integration](examples/ai-trading-integration/)** - Python module for logging trading events with VCP v1.1 compliance

---

## Related Links

- [VCP Specification v1.1](https://github.com/veritaschain/vcp-spec/tree/main/spec/v1.1)
- [VeritasChain Standards Organization](https://github.com/veritaschain)
