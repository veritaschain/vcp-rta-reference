# VCP v1.1 Verification Guide

This guide verifies cryptographic integrity and completeness guarantees as defined in VCP v1.1, corresponding to the publicly released Evidence Pack.

Third parties can independently reproduce all verification steps without requiring access to the original trading system.

---

## Prerequisites

- Python 3.8 or higher
- Git (for cloning the repository)
- No external libraries required (standard library only)

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

**Linux / macOS:**
```bash
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_rta_events.jsonl \
    -s evidence/04_anchor/security_object.json
```

**Windows:**
```cmd
python tools\verifier\vcp_verifier.py evidence\01_trade_logs\vcp_rta_events.jsonl -s evidence\04_anchor\security_object.json
```

**Verification items (Three-Layer Architecture):**

| Layer | Check | Method |
|-------|-------|--------|
| Layer 1: Event Integrity | Event hash | SHA-256 recomputation |
| Layer 1: Event Integrity | Sequence continuity | Sequential number check |
| Layer 1: Event Integrity | PrevHash chain | Hash linking verification |
| Layer 2: Collection Integrity | Merkle Root | RFC 6962 tree rebuild |
| Layer 3: External Verifiability | Anchor reference | Presence check |

### Step 4: Run Tamper Detection Test

**Linux / macOS:**
```bash
python evidence/03_tamper_detection/tamper_detection_test.py
```

**Windows:**
```cmd
python evidence\03_tamper_detection\tamper_detection_test.py
```

This test simulates the following attack scenarios:
1. **Omission Attack** - Event deletion
2. **Modification Attack** - Event content alteration
3. **Insertion Attack** - Fake event injection

Verify that all cases report **[DETECTED]**.

### Step 5: Manually Verify Tampered Sample

**Linux / macOS:**
```bash
python tools/verifier/vcp_verifier.py \
    evidence/03_tamper_detection/tampered_chain.jsonl \
    -s evidence/04_anchor/security_object.json
```

**Windows:**
```cmd
python tools\verifier\vcp_verifier.py evidence\03_tamper_detection\tampered_chain.jsonl -s evidence\04_anchor\security_object.json
```

Verifying the tampered file **should report errors** (FAIL is the correct result).

---

## Verification Checklist

| Item | Expected Result |
|------|-----------------|
| Event count | 40 |
| Valid events | 40 |
| Sequence continuity | PASS |
| PrevHash integrity | PASS |
| Merkle Root (RFC 6962) | PASS |
| Tampered sample verification | FAIL (detection successful) |

---

## External Anchor Verification

Silver Tier requires external anchoring. To verify:

1. Review `evidence/04_anchor/anchor_reference.json`
2. Note the `MerkleRoot` value
3. Submit to OpenTimestamps for independent verification
4. Verify timestamp with the .ots proof file (if available)

**Anchor Target:** OpenTimestamps (Bitcoin-backed)

---

## Understanding Verification Results

### PASS Results
- **Event Hash: PASS** - All events have valid SHA-256 hashes
- **Sequence: PASS** - No gaps in event numbering
- **PrevHash: PASS** - Hash chain is unbroken
- **Merkle Root: PASS** - Computed root matches stored root

### FAIL Results (Expected for Tampered Data)
When verifying `tampered_chain.jsonl`:
- **Sequence error** - Missing event detected
- **PrevHash mismatch** - Chain broken by omission
- **Merkle Root mismatch** - Tree integrity violated

**Important:** FAIL on tampered data confirms the detection system works correctly.

---

## Troubleshooting

### Python version issues
```bash
python3 --version  # Must be 3.8 or higher
```

### Encoding issues (Windows)
```cmd
set PYTHONIOENCODING=utf-8
```

### Encoding issues (Linux/macOS)
```bash
export PYTHONIOENCODING=utf-8
```

### Hash mismatch on legitimate data
Ensure you are using the unmodified evidence files from the repository.

---

## Contact

For verification questions, contact the VeritasChain Standards Organization.
