# Verification Procedures

This document describes how third parties can independently verify the VCP event chain.

## Prerequisites

- Python 3.8 or higher
- No external dependencies required (stdlib only)
- Optional: `pynacl` for Ed25519 signature verification

```bash
# Optional: Install signature verification support
pip install pynacl
```

## Procedure A: Hash Chain Verification

### Step 1: Navigate to Repository

```bash
cd vcp-rta-reference
```

### Step 2: Run Verifier

```bash
python tools/verifier/vcp_verifier.py evidence/01_sample_logs/vcp_rta_demo_events.jsonl
```

### Expected Output

```
============================================================
VCP Chain Verification Report
============================================================
File: vcp_rta_demo_events.jsonl
Total Events: 150
Unique TraceIDs: 30

Event Types:
  ACK: 30
  CLS: 30
  EXE: 30
  ORD: 30
  SIG: 30

Verification Results:
  Genesis: PASS
  Hash Chain: PASS
  Timestamp Monotonicity: PASS
  Signatures: SKIPPED (pynacl not installed)

============================================================
VERIFICATION: PASS - Chain integrity verified
============================================================

Merkle Root: e0a1a56c35c63b0ea33754f000ecdc73c1130c2cb9997b5deb728ba1a2ba69b9
```

### Verification Exit Codes

| Exit Code | Meaning |
|-----------|---------|
| 0 | PASS - Chain verified |
| 1 | FAIL - Chain compromised |

## Procedure B: Signature Verification

### Step 1: Install PyNaCl

```bash
pip install pynacl
```

### Step 2: Run Verifier with Public Key

```bash
python tools/verifier/vcp_verifier.py \
  evidence/01_sample_logs/vcp_rta_demo_events.jsonl \
  --pubkey evidence/04_anchor/public_key.json
```

### Expected Output (with signatures)

```
Verification Results:
  Genesis: PASS
  Hash Chain: PASS
  Timestamp Monotonicity: PASS
  Signatures: PASS (150/150 valid)

VERIFICATION: PASS - Chain integrity verified
```

## Procedure C: Tamper Detection Demo

### Step 1: Run Tamper Demo

```bash
cd evidence/03_tamper_demo
python tamper_demo.py
```

### Step 2: Verify Tampered Chain

```bash
python ../../tools/verifier/vcp_verifier.py vcp_rta_demo_events_tampered.jsonl
```

### Expected Output (FAIL)

```
Verification Results:
  Genesis: PASS
  Hash Chain: FAIL
  Timestamp Monotonicity: PASS

Errors (1):
  [X] Line 5: PrevHash mismatch
      expected: 92247509818194448970311c1d638b5e...
      got: 0b762775ad74d708ca26a17ecd1ad371...

============================================================
VERIFICATION: FAIL - Chain integrity compromised
============================================================
```

## Procedure D: Manual Verification (No Python)

### Step 1: Verify Genesis Event

First event's `PrevHash` must be 64 zeros:

```bash
head -1 vcp_rta_demo_events.jsonl | jq -r '.Security.PrevHash'
# Expected: 0000000000000000000000000000000000000000000000000000000000000000
```

### Step 2: Verify Hash Chain Linkage

For any event N, its `EventHash` must equal event N+1's `PrevHash`:

```bash
# Get EventHash of line 1
sed -n '1p' vcp_rta_demo_events.jsonl | jq -r '.Security.EventHash'

# Get PrevHash of line 2
sed -n '2p' vcp_rta_demo_events.jsonl | jq -r '.Security.PrevHash'

# These must match
```

### Step 3: Recalculate EventHash

For any event, recompute the hash:

```
EventHash = SHA-256(
  canonical(Header) +
  canonical(Payload) +
  PrevHash
)
```

Where `canonical()` follows RFC 8785 JCS (sorted keys, no whitespace).

## Procedure E: Merkle Root Verification

### Step 1: Get Expected Root

```bash
cat evidence/04_anchor/merkle_root.txt | grep -v '^#'
# Expected: e0a1a56c35c63b0ea33754f000ecdc73c1130c2cb9997b5deb728ba1a2ba69b9
```

### Step 2: Calculate from Verifier

```bash
python tools/verifier/vcp_verifier.py evidence/01_sample_logs/vcp_rta_demo_events.jsonl | grep "Merkle Root"
```

### Step 3: Compare

Both values must match exactly.

## Procedure F: OpenTimestamps Verification (Optional)

If an `.ots` file is present:

```bash
ots verify evidence/04_anchor/merkle_root.txt.ots
```

This proves the Merkle Root existed before a specific Bitcoin block.

## What Each Verification Proves

| Check | What It Proves |
|-------|---------------|
| Genesis | Chain starts correctly |
| Hash Chain | No events modified, deleted, or reordered |
| Timestamps | Correct temporal ordering |
| Signatures | Events signed by claimed key |
| Merkle Root | Summary hash matches |
| OpenTimestamps | Existence before specific time |

## Troubleshooting

### "pynacl not installed"

This is expected if you don't have PyNaCl. Signature verification is optional.

```bash
pip install pynacl
```

### "File not found"

Make sure you're in the correct directory:

```bash
cd vcp-rta-reference
ls evidence/01_sample_logs/
```

### "JSON parse error"

Ensure the JSONL file is not corrupted:

```bash
head -1 evidence/01_sample_logs/vcp_rta_demo_events.jsonl | python -m json.tool
```

## Security Notes

- The verifier uses only Python standard library for core verification
- No network connections are made during verification
- All proofs are self-contained in the evidence pack
- Verification can be performed offline

---

**Verify, Don't Trust.**
