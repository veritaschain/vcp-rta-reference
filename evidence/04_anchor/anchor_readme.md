# Anchor & Cryptographic Material

This directory contains cryptographic anchors for the VCP event chain.

## Contents

| File | Description |
|------|-------------|
| `merkle_root.txt` | Merkle Root hash of the event chain |
| `public_key.json` | Ed25519 public key for signature verification |

## Merkle Root

```
e0a1a56c35c63b0ea33754f000ecdc73c1130c2cb9997b5deb728ba1a2ba69b9
```

**Algorithm**: RFC 6962 Certificate Transparency

### Generation Formula

```
MerkleRoot = BuildTree([LeafHash(event_1), ..., LeafHash(event_n)])

where:
  LeafHash(e) = SHA-256(0x00 || EventHash(e))
  InternalHash(L, R) = SHA-256(0x01 || L || R)
```

## Digital Signatures

All events in the chain are signed with Ed25519.

### Public Key

```json
{
  "KeyID": "vcp-rta-key-2025-001",
  "Algorithm": "ED25519",
  "PublicKey": "cb1fc548399df6a36c935ab82eae8901467b02fd51ae6948447d111f4494c0d9"
}
```

### Signature Verification

To verify a signature:

```python
from nacl.signing import VerifyKey

# Load public key
pubkey = bytes.fromhex("cb1fc548399df6a36c935ab82eae8901467b02fd51ae6948447d111f4494c0d9")
verify_key = VerifyKey(pubkey)

# Verify signature
event_hash = bytes.fromhex(event["Security"]["EventHash"])
signature = bytes.fromhex(event["Security"]["Signature"])
verify_key.verify(event_hash, signature)  # Raises BadSignature on failure
```

### Key Management Note

- This public key is for demonstration purposes only
- Production systems should use proper key management (HSM, KMS)
- Key rotation procedures should be documented

## OpenTimestamps Anchoring (Optional)

To anchor the Merkle Root to the Bitcoin blockchain:

### Step 1: Create Timestamp

```bash
ots stamp merkle_root.txt
```

This creates `merkle_root.txt.ots` containing the timestamp proof.

### Step 2: Wait for Confirmation

Bitcoin confirmation typically requires 10-60 minutes.

```bash
ots upgrade merkle_root.txt.ots
```

### Step 3: Verify Timestamp

```bash
ots verify merkle_root.txt.ots
```

### Expected Output

```
Success! Bitcoin block XXXXXX attests existence as of YYYY-MM-DD
```

## VCP Tier Compliance

| Tier | Anchor Frequency | Required |
|------|------------------|----------|
| Bronze | Not required | ❌ |
| Silver | Daily (24h) | ✅ |
| Gold | Hourly (1h) | ✅ |
| Platinum | Real-time | ✅ |

This evidence pack targets **Silver Tier** with daily anchoring capability.

## References

- [RFC 6962 - Certificate Transparency](https://tools.ietf.org/html/rfc6962)
- [OpenTimestamps](https://opentimestamps.org/)
- [Ed25519 Specification](https://ed25519.cr.yp.to/)
