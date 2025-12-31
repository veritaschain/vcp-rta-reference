# VCP v1.1 Verification Guide

This guide explains how third parties can independently verify the VCP v1.1 Evidence Pack.

---

## Prerequisites

- Python 3.8 or higher
- Git (for cloning the repository)
- No external libraries required

---

## Verification Steps

### Step 1: Obtain the Repository

```bash
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference
```

### Step 2: Review the Evidence Index

```bash
cat evidence/evidence_index.json
```

This displays:
- VCP version: 1.1
- Tier: Silver
- Event count and date range
- Merkle Root

### Step 3: Verify Chain Integrity

```bash
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_rta_events.jsonl \
    -s evidence/04_anchor/security_object.json
```

**Verification items:**
- Event hash integrity
- Sequence number continuity
- PrevHash link integrity
- Merkle Root match

### Step 4: Run Tamper Detection Test

```bash
python evidence/03_tamper_detection/tamper_detection_test.py
```

This test simulates the following attack scenarios:
1. **Omission Attack** - Event deletion
2. **Modification Attack** - Event content alteration
3. **Insertion Attack** - Fake event injection

Verify that all cases report detection.

### Step 5: Manually Verify Tampered Sample

```bash
python tools/verifier/vcp_verifier.py \
    evidence/03_tamper_detection/tampered_chain.jsonl \
    -s evidence/04_anchor/security_object.json
```

Verifying the tampered file should report errors.

---

## Verification Checklist

| Item | Expected Result |
|------|-----------------|
| Event count | 40 |
| Valid events | 40 |
| Sequence continuity | PASS |
| PrevHash integrity | PASS |
| Merkle Root | PASS |
| Tampered sample | FAIL (detection successful) |

---

## External Anchor Verification (Optional)

Silver Tier requires external anchoring.

1. Review `evidence/04_anchor/anchor_reference.json`
2. Submit `merkle_root` to OpenTimestamps
3. Verify timestamp with the .ots file

---

## Troubleshooting

### Python version issues
```bash
python3 --version  # Must be 3.8 or higher
```

### Encoding issues
```bash
export PYTHONIOENCODING=utf-8
```

---

## Contact

For verification questions, contact the VeritasChain Standards Organization.
