# Migration Guide: VCP v1.0 → v1.1

This guide helps implementers upgrade from VCP v1.0 to v1.1.

## Executive Summary

VCP v1.1 is a **protocol-compatible / certification-stricter** update. Existing v1.0 implementations remain protocol-compatible but require additional components for v1.1 VC-Certified status.

| Change Type | Count | Impact |
|-------------|-------|--------|
| Breaking (Certification) | 2 | Silver tier needs updates |
| New Features | 3 | Optional or auto-enabled |
| Relaxations | 1 | PrevHash now OPTIONAL |

---

## Timeline

| Requirement | Grace Period | Hard Deadline |
|-------------|--------------|---------------|
| Policy Identification | 3 months | **March 25, 2026** |
| External Anchor (Silver) | 6 months | **June 25, 2026** |
| Merkle fields in Security | 3 months | **March 25, 2026** |

After deadlines, v1.0-only implementations cannot receive v1.1 VC-Certified status.

---

## Required Changes

### 1. Add Policy Identification (All Tiers)

**v1.0 Event:**
```json
{
  "Header": { ... },
  "Payload": {
    "VCP_GOV": { ... },
    "VCP_TRADE": { ... }
  },
  "Security": { ... }
}
```

**v1.1 Event:**
```json
{
  "Header": { ... },
  "Payload": {
    "VCP_GOV": { ... },
    "VCP_TRADE": { ... },
    "PolicyIdentification": {
      "Version": "1.1",
      "PolicyID": "org.example:my-system-001",
      "ConformanceTier": "SILVER",
      "RegistrationPolicy": {
        "Issuer": "Your Organization",
        "PolicyURI": "https://example.org/policies/silver"
      },
      "VerificationDepth": {
        "HashChainValidation": true,
        "MerkleProofRequired": true,
        "ExternalAnchorRequired": true
      }
    }
  },
  "Security": { ... }
}
```

**PolicyID Format:**
```
<reverse_domain>:<local_identifier>

Examples:
  org.veritaschain.prod:hft-system-001
  com.example.trading:gold-algo-v2
  jp.co.broker:silver-mt5-bridge
```

---

### 2. Add External Anchoring (Silver Tier)

**v1.0:** External Anchor was OPTIONAL for Silver
**v1.1:** External Anchor is REQUIRED for ALL tiers

**Silver Tier Options:**
- OpenTimestamps (free, Bitcoin-backed)
- FreeTSA (free RFC 3161)
- OriginStamp (commercial with free tier)

**Implementation Example:**
```python
def anchor_merkle_root(merkle_root: str) -> dict:
    """Daily anchoring for Silver tier"""
    import opentimestamps
    
    timestamp = opentimestamps.create_timestamp(
        bytes.fromhex(merkle_root)
    )
    
    return {
        "AnchorID": generate_uuid7(),
        "MerkleRoot": merkle_root,
        "AnchorTarget": {
            "Type": "PUBLIC_SERVICE",
            "Identifier": "opentimestamps.org",
            "Proof": timestamp.serialize().hex()
        },
        "Timestamp": int(time.time() * 1000)
    }
```

---

### 3. Add Merkle Fields to Security Object

**v1.0 Security:**
```json
{
  "Security": {
    "EventHash": "abc123...",
    "PrevHash": "def456...",
    "HashAlgo": "SHA256",
    "SignAlgo": "ED25519",
    "Signature": "...",
    "KeyID": "key-001"
  }
}
```

**v1.1 Security:**
```json
{
  "Security": {
    "EventHash": "abc123...",
    "PrevHash": "def456...",
    "HashAlgo": "SHA256",
    "SignAlgo": "ED25519",
    "Signature": "...",
    "KeyID": "key-001",
    "MerkleIndex": 0,
    "MerkleRoot": "131122...",
    "AnchorReference": {
      "AnchorID": "019b72fc-...",
      "AnchorTarget": "PUBLIC_SERVICE",
      "AnchorTimestamp": 1735520400000
    }
  }
}
```

**New Fields:**
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| MerkleIndex | Integer | Yes | Position in Merkle tree (0-indexed) |
| MerkleRoot | String | Yes | Hex-encoded Merkle root |
| AnchorReference | Object | Yes | Link to external anchor |

---

## Optional Changes

### PrevHash (Now OPTIONAL)

**v1.0:** PrevHash was REQUIRED for all events except INIT
**v1.1:** PrevHash is OPTIONAL

**You can:**
- Keep PrevHash for real-time tamper detection (recommended for HFT)
- Remove PrevHash to simplify implementation

**Rationale:** Merkle + External Anchor provides equivalent integrity guarantees.

---

## Migration Checklist

### For Silver Tier

```
[ ] Update VCPVersion to "1.1" in headers
[ ] Add PolicyIdentification to all event payloads
[ ] Implement daily Merkle anchoring
[ ] Add MerkleIndex to Security object
[ ] Add MerkleRoot to Security object
[ ] Add AnchorReference to Security object
[ ] Update verifier to check v1.1 requirements
[ ] Test with vcp_verifier.py
```

### For Gold Tier

```
[ ] Update VCPVersion to "1.1" in headers
[ ] Add PolicyIdentification to all event payloads
[ ] Verify hourly anchoring is operational
[ ] Add MerkleIndex to Security object
[ ] Add MerkleRoot to Security object
[ ] Add AnchorReference to Security object
[ ] Update verifier to check v1.1 requirements
```

### For Platinum Tier

```
[ ] Update VCPVersion to "1.1" in headers
[ ] Add PolicyIdentification to all event payloads
[ ] Verify 10-minute anchoring is operational
[ ] Add MerkleIndex to Security object
[ ] Add MerkleRoot to Security object
[ ] Add AnchorReference to Security object
[ ] Consider PQC dual signatures (optional)
```

---

## Verification

After migration, verify with the updated verifier:

```bash
python tools/verifier/vcp_verifier.py \
    evidence/sample_logs/vcp_rta_demo_events.jsonl \
    evidence/anchor/public_key.json
```

**Expected v1.1 verification output:**
```
Three-Layer Verification Results:
  [Layer 1: Event Integrity]
    Genesis: PASS
    Event Hashes: PASS
    Hash Chain: PASS

  [Layer 2: Collection Integrity]
    Merkle Root: PASS

  [Layer 3: External Verifiability]
    Timestamp Monotonicity: PASS
    Policy Identification: PASS    ← NEW in v1.1
    Anchor Reference: PASS         ← NEW in v1.1
    Signatures: PASS
```

---

## FAQ

### Q: Is v1.0 still supported?

Yes. v1.0 implementations remain protocol-compatible. However:
- New certifications after grace period require v1.1
- v1.0 tag preserved at `v1.0.0`

### Q: Can I mix v1.0 and v1.1 events?

Not recommended. Migration should be atomic:
1. Complete v1.0 event chain
2. Archive with final anchor
3. Start fresh v1.1 chain with INIT event

### Q: What if my anchor target is unavailable?

See VCP Spec v1.1 §6.3.3:
- Queue requests; retry with exponential backoff
- Retain local AnchorRecord as backup
- Migrate to alternative target within 30 days if permanent

---

## Support

- Documentation: [docs.veritaschain.org](https://docs.veritaschain.org)
- GitHub Issues: [github.com/veritaschain/vcp-rta-reference/issues](https://github.com/veritaschain/vcp-rta-reference/issues)
- Email: support@veritaschain.org
