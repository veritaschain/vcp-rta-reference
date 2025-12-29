# VCP Sample Logs

This directory contains the VCP v1.0 Silver Tier compliant event chain.

## Contents

| File | Description |
|------|-------------|
| `vcp_rta_demo_events.jsonl` | 150 VCP events (30 trade lifecycles × 5 event types) |

## Data Characteristics

### Authenticity

- **AI Decisions**: Real consensus votes from 5 AI models (Gemini, GPT, Claude, Grok, Perplexity)
- **Trade Lifecycle**: Authentic signal-to-close event sequences
- **Timestamps**: Original signal generation times (JST)

### Anonymization / Sanitization

- **AccountID**: SHA-256 hashed (first 12 chars)
- **Prices**: Synthesized values for public release (not actual execution prices)
- **VenueID**: Anonymized to `VENUE_DEMO` (MIC: `XDMO`)

> **Note**: Prices in this evidence pack are synthesized for anonymization purposes.
> They demonstrate the VCP structure and hash chain integrity, not actual market executions.

## Trade Lifecycle

Each trade generates 5 events with a shared `TraceID`:

```
TraceID: 20251118_022757_BUY
    │
    ├── SIG (1) ─ AI consensus signal generated
    │
    ├── ORD (2) ─ Order submitted to broker
    │
    ├── ACK (3) ─ Broker acknowledgment received
    │
    ├── EXE (4) ─ Order executed (filled)
    │
    └── CLS (9) ─ Position closed
```

## Event Statistics

| Event Type | Code | Count | Description |
|------------|------|-------|-------------|
| SIG | 1 | 30 | AI consensus signal |
| ORD | 2 | 30 | Order submission |
| ACK | 3 | 30 | Broker acknowledgment |
| EXE | 4 | 30 | Order execution |
| CLS | 9 | 30 | Position close |
| **Total** | | **150** | |

## Hash Chain Structure

```
Genesis (PrevHash = 64 zeros)
    │
    ▼
Event #1 ───┐
    │       │  EventHash = SHA-256(
    ▼       │    canonical(Header) +
Event #2 ◀─┘    canonical(Payload) +
    │           PrevHash
    ▼         )
   ...        Signature = Ed25519(EventHash)
    │
    ▼
Event #150
    │
    ▼
Merkle Root (RFC 6962)
```

## Sample Event (SIG)

```json
{
  "Header": {
    "EventID": "019a92db-ece7-73df-a65c-af1ffd18e198",
    "TraceID": "20251118_022757_BUY",
    "Timestamp": 1763400477927,
    "TimestampPrecision": "MILLISECOND",
    "ClockSyncStatus": "BEST_EFFORT",
    "EventTypeCode": 1,
    "EventType": "SIG",
    "HashAlgo": "SHA-256",
    "VenueID": "VENUE_DEMO",
    "MICCode": "XDMO",
    "Symbol": "USDJPY",
    "AccountID": "3662c67e3a86",
    "VCPVersion": "1.0",
    "Tier": "SILVER"
  },
  "Payload": {
    "VCP_GOV": {
      "AlgoID": "VCP-RTA",
      "AlgoVersion": "1.0.0",
      "DecisionType": "AI_CONSENSUS",
      "AIModels": {
        "gemini": {"direction": "BUY", "confidence": 0.85},
        "gpt": {"direction": "BUY", "confidence": 0.70},
        "claude": {"direction": "BUY", "confidence": 0.85},
        "grok": {"direction": "SELL", "confidence": 0.75},
        "pplx": {"direction": "BUY", "confidence": 0.80}
      },
      "ConsensusDirection": "BUY",
      "ConsensusScore": 0.779,
      "PromptHash": ""
    },
    "VCP_RISK": {
      "TPPips": "25",
      "SLPips": "15",
      "TTLMinutes": "30",
      "MaxSpreadPips": "2.0"
    }
  },
  "Security": {
    "EventHash": "affda6b3709b7bfefaba6832de2c8da392081fd34117f496cc54d9df243f290f",
    "PrevHash": "0000000000000000000000000000000000000000000000000000000000000000",
    "SignAlgo": "ED25519",
    "Signature": "41075972152e3fe18dfe6dbe2eaf2591c5e89da599fd1265b7e9adc96f222c401f91e36f6364142c52e01ab051512e4666c46b67ea6ab0267e5ea531f9a0940f",
    "KeyID": "vcp-rta-key-2025-001"
  }
}
```

## Implementation Notes

### PromptHash Field

The `PromptHash` field is intentionally empty in this public release:

- Prompt content is proprietary and excluded from public evidence packs
- The field structure is preserved to demonstrate VCP-GOV schema compliance
- Production implementations should populate this with SHA-256 of the actual prompt

### Digital Signatures

All events are signed with Ed25519:

- **SignAlgo**: `ED25519`
- **Signature**: 64-byte Ed25519 signature (128 hex chars)
- **KeyID**: `vcp-rta-key-2025-001`
- **Public Key**: Available in `../04_anchor/public_key.json`

Signature verification formula:
```
Ed25519.verify(
  public_key,
  signature,
  bytes.fromhex(EventHash)
)
```

### AI Model Transparency

Model names are preserved (not anonymized) to demonstrate VCP-GOV transparency:

- This is a key differentiator of VCP: recording which AI models made which decisions
- Anonymizing model names would undermine the governance audit trail
- Real implementations should record actual model identifiers

## Verification

```bash
# Verify hash chain integrity
python ../02_verification/verifier/vcp_verifier.py vcp_rta_demo_events.jsonl

# Expected output: VERIFICATION: PASS
```

## References

- [VCP Specification v1.0](https://github.com/veritaschain/vcp-spec)
- [RFC 8785 - JSON Canonicalization Scheme](https://tools.ietf.org/html/rfc8785)
- [RFC 6962 - Certificate Transparency](https://tools.ietf.org/html/rfc6962)
