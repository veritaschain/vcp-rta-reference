# VCP v1.1 Integration Examples

This directory contains reference implementations demonstrating how to integrate VCP v1.1 event logging into AI-driven trading systems.

## Files

| File | Description |
|------|-------------|
| `vcp_logger.py` | VCP v1.1 Silver Tier event logger module |
| `vcp_poc_demo.py` | Demonstration script simulating trade lifecycles |

## Quick Start

### Prerequisites

```bash
# Required
pip install uuid6 canonicaljson cryptography
```

### Run Demo

```bash
cd examples
python vcp_poc_demo.py
```

### Expected Output

```
+======================================================================+
|           VCP v1.1 PoC Demonstration                                 |
+======================================================================+

Initializing VCP Logger...

Initial State:
   VCP Version: 1.1
   Tier: SILVER
   Signatures: Enabled
   Existing Events: 0

============================================================
Simulating Trade Lifecycle Events...
============================================================

Trade #1: trace_20251220_143015_a1b2c3d4
   Result: TP (WIN)
...

============================================================
Verifying Event Chain...
============================================================

   Total Events: 36
   Valid Events: 36
   Invalid Events: 0
   Overall: VALID

============================================================
Generating Merkle Anchor...
============================================================

   Merkle Root: 1ea7b2984645df6ddf9dd3a4...
   Event Count: 36
   Anchor Status: PENDING
```

## Integration Guide

### Step 1: Add vcp_logger.py to Your Project

```
your_trading_system/
├── main.py
├── vcp_logger.py        # Add this file
└── vcp/                 # Auto-created
    ├── vcp_events.jsonl
    ├── private_key.pem
    └── anchors/
```

### Step 2: Initialize Logger

```python
from vcp_logger import VCPLogger

# Initialize with anonymized identifiers
vcp = VCPLogger(
    base_path=Path('.'),
    venue_id="VENUE_A",      # Your venue (anonymized)
    symbol="INSTRUMENT_A"    # Your symbol (anonymized)
)
```

### Step 3: Log Events

```python
# Signal Generation (SIG)
vcp.log_signal(
    trace_id="unique_trace_id",
    direction="BUY",
    confidence=0.85,
    model_results={
        'model_a': {'direction': 'BUY', 'confidence': 0.8, 'weight': 2.0},
        'model_b': {'direction': 'BUY', 'confidence': 0.7, 'weight': 2.0},
    },
    config_id="config_001"
)

# Order Submission (ORD)
vcp.log_order(
    trace_id="unique_trace_id",
    direction="BUY",
    quantity=0.1,
    price=150.123,
    tp=150.373,
    sl=149.973
)

# Execution (EXE)
vcp.log_execution(
    trace_id="unique_trace_id",
    order_id=12345678,
    direction="BUY",
    executed_price=150.125,
    executed_qty=0.1
)

# Position Close (CLS)
vcp.log_close(
    trace_id="unique_trace_id",
    order_id=12345678,
    exit_price=150.350,
    pnl=22.5,  # pips
    exit_reason="TP"
)

# Rejection/VETO (REJ)
vcp.log_reject(
    trace_id="unique_trace_id",
    reason="Risk threshold exceeded",
    veto_source="model_b"
)
```

### Step 4: Generate Merkle Anchor

```python
# Generate daily anchor (recommended: run at 02:00 UTC)
anchor = vcp.generate_merkle_anchor()
if anchor:
    print(f"Merkle Root: {anchor['MerkleTree']['Root']}")
```

### Step 5: Verify Chain

```bash
# Command line verification
python vcp_logger.py vcp/vcp_events.jsonl

# With anchor verification
python vcp_logger.py vcp/vcp_events.jsonl -a vcp/anchors/anchor_*.json
```

## Anonymization

The logger automatically anonymizes sensitive information:

| Data | Anonymization Method |
|------|---------------------|
| Order IDs | SHA-256 hash (first 12 chars) |
| Config IDs | SHA-256 hash (first 8 chars) |
| Prices | Stored as relative values |
| Quantities | Marked as "REDACTED" |
| P&L | Converted to WIN/LOSS/BREAKEVEN |
| Model names | Converted to Model_A, Model_B, etc. |

## Event Types

| Code | Type | Description |
|------|------|-------------|
| SIG | Signal | AI decision generated |
| ORD | Order | Order submitted |
| EXE | Execute | Order filled |
| CLS | Close | Position closed |
| REJ | Reject | Order rejected / VETO applied |

## Security Features

- **SHA-256 Hashing**: RFC 8785 canonicalized JSON
- **Ed25519 Signatures**: Per-event digital signatures
- **RFC 6962 Merkle Tree**: Batch integrity proof
- **PrevHash Chain**: Real-time tamper detection
- **External Anchoring**: OpenTimestamps compatible

## License

CC BY 4.0

## See Also

- [VCP Specification v1.1](https://github.com/veritaschain/vcp-spec)
- [Verification Guide](../docs/VERIFICATION_GUIDE.md)
