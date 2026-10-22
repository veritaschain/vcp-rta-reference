## Related reference implementations

Other public repositories, listed without a claim about priority or certification:

- cTrader: https://github.com/veritaschain/vcp-ctrader-rta-reference
- FIX Protocol: https://github.com/veritaschain/vcp-fix-rta-reference
- Interactive Brokers (IBKR): https://github.com/veritaschain/vcp-ibkr-rta-reference
- Nasdaq: https://github.com/veritaschain/vcp-nasdaq-rta-reference
- Cloudflare: https://github.com/veritaschain/vcp-cloudflare-rta-reference

# VCP Reference Trading Agent (VCP-RTA)

[**English**](README.md) | [日本語](README.ja.md)

![VCP v1.1](https://img.shields.io/badge/VCP-v1.1-blue)
![Tier Silver](https://img.shields.io/badge/Tier-Silver-silver)
![License CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)

> **"Verify, Don't Trust."**

VCP-RTA is a VCP **v1.1** evidence pack for an algorithmic-trading log. v1.2 is not claimed here. Third parties can check the Ed25519 signatures and the published Merkle root with `tools/verifier/vcp_verifier.py`. The external OpenTimestamps anchor cannot be checked from the files in this repository. See [evidence/VERIFICATION_STATUS.md](evidence/VERIFICATION_STATUS.md).

`docs/VCP_Worlds_First_Evidence_Report.pdf` (the same file as `VCP_Worlds_First_Evidence_Report.pdf` at the repository root) is kept unchanged. Its filename is not a verification result for this pack, and the PDF was not modified.

---

## Overview

The pack records AI decision signals, order events, and execution events from an MT5 sidecar. Events are hashed, signed with Ed25519, and combined into a VCP v1.1 Merkle tree. A third party can recompute that tree and check the signatures. The named OpenTimestamps proof is not in the public files, so the external anchor stays unverified.

---

## What's New in v1.1

| Feature | v1.0 | v1.1 |
|---------|------|------|
| **Three-Layer Architecture** | - | ✅ NEW |
| **External Anchor (Silver)** | OPTIONAL | Named in this pack; `merkle_root.ots` is not published |
| **Policy Identification** | - | **REQUIRED** |
| **PrevHash** | REQUIRED | OPTIONAL |
| **Omission check** | - | Against the published Merkle root, when that root is supplied |

With the published security object, a missing or altered event changes the recomputed Merkle root. That check does not extend to an external timestamp: `merkle_root.ots` is not available.

---

## Repository Structure
```
vcp_v1_1_repo_aligned/
├── evidence/
│   ├── evidence_index.json          # Evidence manifest (descriptive fields; not signed)
│   ├── VERIFICATION_STATUS.md       # What can and cannot be verified
│   ├── 01_trade_logs/
│   │   └── vcp_rta_events.jsonl     # VCP v1.1 event chain (40 events)
│   ├── 02_verification/
│   │   ├── verification_report.txt  # Historical output, kept unchanged
│   │   ├── verification_report_2026-10-22.txt  # Current verifier result
│   │   └── verification_report_2026-10-22.json
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
- The `cryptography` package (`python3 -m pip install cryptography`). Without it, signature checks are UNVERIFIABLE.

### Run Verification

```bash
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference

python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_rta_events.jsonl \
    -s evidence/04_anchor/security_object.json \
    -k evidence/04_anchor/public_key.json \
    -a evidence/04_anchor/anchor_reference.json
```

Windows:

```cmd
python tools\verifier\vcp_verifier.py evidence\01_trade_logs\vcp_rta_events.jsonl -s evidence\04_anchor\security_object.json -k evidence\04_anchor\public_key.json -a evidence\04_anchor\anchor_reference.json
```

Exit codes: `0` VALID, `1` INVALID, `2` UNVERIFIABLE. `--json` prints the same result as JSON. Details are in [docs/VERIFICATION_GUIDE.md](docs/VERIFICATION_GUIDE.md).

### Expected result on the published pack

Overall **UNVERIFIABLE** (exit 2), because the external anchor is not confirmed.

- Ed25519 signatures: **VALID** (40 events; the trusted-key fingerprint is printed)
- Merkle root: **VALID** against `86c05dbad79ffe6fdb5c3063128df0af0bcb5a3e95f4586348f13ca49778a47e`
- External anchor: **UNVERIFIABLE**. `merkle_root.ots` is not in the public files

`evidence/03_tamper_detection/tampered_chain.jsonl`, with the same `-s` and `-k`, is **INVALID** (exit 1). The script `tamper_detection_test.py` is an older demo; its banner still says RFC 6962. Use the verifier above for the three-valued result.

`evidence/02_verification/verification_report.txt` is a historical output kept unchanged. Its "Fully Compliant" wording is superseded. The current result is [`evidence/02_verification/verification_report_2026-10-22.txt`](evidence/02_verification/verification_report_2026-10-22.txt) (JSON: [`verification_report_2026-10-22.json`](evidence/02_verification/verification_report_2026-10-22.json)).

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

1. **Layer 1: Event integrity** — SHA-256 event hash and Ed25519 signature. The verifier checks both when `--public-key` is supplied.
2. **Layer 2: Collection integrity** — VCP v1.1 Merkle tree (SHA-256, `0x00` leaf prefix, `0x01` node prefix, odd node duplicated) plus optional PrevHash. This matches the published root. It is not a strict RFC 6962 §2.1 tree.
3. **Layer 3: External anchor** — `anchor_reference.json` names OpenTimestamps and `merkle_root.ots`. That proof is not in the public files, so this layer is not verified.

### Tamper detection against the published root

When the security object is supplied, the verifier reports INVALID for:

- an omitted event (sequence gap, PrevHash break, Merkle root mismatch)
- a modified event whose recomputed hash no longer matches
- an inserted event that changes the recomputed root

Those checks do not show that an external timestamp exists.

---

## License

This evidence pack is licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).

---

## Integration Examples

The `examples/` directory contains reference implementations for integrating VCP into your own systems:

- **[AI Trading Integration](examples/ai-trading-integration/)** — Python logger that emits v1.1-shaped events. Its hash and anchor-signature encoding differ from this evidence pack; use the verifier on `evidence/` for the published chain.

---

## Related Links

- [VCP Specification v1.1](https://github.com/veritaschain/vcp-spec/tree/main/spec/v1.1)
- [VeritasChain Standards Organization](https://github.com/veritaschain)
