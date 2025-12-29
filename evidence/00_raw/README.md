# Raw Data Directory

This directory contains anonymized raw source data used to generate the VCP event chain.

## Contents

| File | Description |
|------|-------------|
| (empty) | Raw data excluded from public release |

## Data Sources

The VCP event chain was generated from:

1. **AI Signal Logs**: Multi-model consensus decisions
2. **Order Execution Logs**: Broker order/fill records
3. **Position Management Logs**: Entry/exit records

## Privacy

All raw data has been:
- Pseudonymized (Account IDs hashed)
- Anonymized (Broker names removed)
- Sanitized (Personal information excluded)

## Regeneration

To regenerate the VCP chain from raw data:

```bash
cd ../tools/log_converter
python log_converter.py ../evidence/00_raw/signals.csv output.jsonl
```

---

**Note**: Raw data is intentionally excluded to maintain operator anonymity.
