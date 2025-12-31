# VCP v1.1 Three-Layer Architecture

This document explains the three-layer integrity architecture introduced in VCP v1.1.

## Overview

VCP v1.1 introduces a clear separation of concerns for integrity and security mechanisms:

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 3: External Verifiability                                    │
│  ─────────────────────────────────                                  │
│  Purpose: Third-party verification without trusting the producer    │
│                                                                     │
│  Components:                                                        │
│  ├─ Digital Signature (Ed25519/Dilithium): REQUIRED                │
│  ├─ Timestamp (dual format ISO+int64): REQUIRED                    │
│  └─ External Anchor (Blockchain/TSA): REQUIRED                     │
│                                                                     │
│  Frequency: Tier-dependent (10min / 1hr / 24hr)                    │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 2: Collection Integrity    ← Core for completeness          │
│  ────────────────────────────────                                   │
│  Purpose: Prove completeness of event batches                       │
│                                                                     │
│  Components:                                                        │
│  ├─ Merkle Tree (RFC 6962): REQUIRED                               │
│  ├─ Merkle Root: REQUIRED                                          │
│  └─ Audit Path (for verification): REQUIRED                        │
│                                                                     │
│  Note: Enables third-party verification of batch completeness      │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│  LAYER 1: Event Integrity                                           │
│  ────────────────────────                                           │
│  Purpose: Individual event completeness                             │
│                                                                     │
│  Components:                                                        │
│  ├─ EventHash (SHA-256 of canonical event): REQUIRED               │
│  └─ PrevHash (link to previous event): OPTIONAL                    │
│                                                                     │
│  Note: PrevHash provides real-time detection (OPTIONAL in v1.1)    │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: Event Integrity

### Purpose

Ensure that individual events have not been modified since creation.

### Components

#### EventHash (REQUIRED)

Every VCP event must include an EventHash computed over its canonical form:

```
EventHash = SHA-256(canonical(Header) + canonical(Payload) + PrevHash)
```

**Canonicalization**: RFC 8785 JSON Canonicalization Scheme (JCS)

```python
def compute_event_hash(header, payload, prev_hash):
    canonical_header = RFC8785_canonicalize(header)
    canonical_payload = RFC8785_canonicalize(payload)
    hash_input = canonical_header + canonical_payload + prev_hash.encode()
    return SHA256(hash_input).hexdigest()
```

#### PrevHash (OPTIONAL in v1.1)

Links to the previous event's EventHash, creating a hash chain.

**v1.0**: REQUIRED (except for INIT events)
**v1.1**: OPTIONAL

**When to use PrevHash:**
| Use Case | Recommended? | Rationale |
|----------|--------------|-----------|
| HFT Systems | Yes | Real-time detection of event loss |
| Regulatory Submission | Yes | Familiar to auditors |
| Development/Testing | No | Simplifies implementation |
| MT4/MT5 Integration | No | Reduces DLL complexity |

---

## Layer 2: Collection Integrity

### Purpose

Prove that a batch of events is complete — no events were omitted or added.

### Components

#### Merkle Tree (REQUIRED)

All VCP implementations must construct Merkle Trees over event batches using RFC 6962 method with domain separation:

```python
def merkle_leaf_hash(event_hash: bytes) -> bytes:
    return SHA256(b'\x00' + event_hash)

def merkle_internal_hash(left: bytes, right: bytes) -> bytes:
    return SHA256(b'\x01' + left + right)
```

**Why domain separation?** Prevents second preimage attacks where internal nodes could be confused with leaf nodes.

#### Merkle Root (REQUIRED)

The root of the Merkle tree, included in every event's Security object and externally anchored.

#### Audit Path (REQUIRED)

Implementations must be able to generate audit paths for verifying individual events:

```python
def generate_audit_path(tree, leaf_index):
    """Generate proof that leaf is included in tree"""
    path = []
    for level in tree.levels:
        sibling = get_sibling(level, leaf_index)
        path.append(sibling)
        leaf_index //= 2
    return path
```

---

## Layer 3: External Verifiability

### Purpose

Enable third parties to verify integrity without trusting the log producer.

### Components

#### Digital Signatures (REQUIRED)

All events must be signed. Supported algorithms:

| Algorithm | Status | Use Case |
|-----------|--------|----------|
| ED25519 | DEFAULT | Standard use |
| ECDSA_SECP256K1 | SUPPORTED | Bitcoin compatibility |
| DILITHIUM2 | FUTURE | Post-quantum |

#### Timestamps (REQUIRED)

Dual-format for maximum compatibility:

```json
{
  "Timestamp": 1735520400000000,
  "TimestampISO": "2025-12-30T00:00:00.000000Z"
}
```

#### External Anchor (REQUIRED in v1.1)

**Critical Change**: External Anchoring is now REQUIRED for all tiers.

| Tier | Frequency | Target |
|------|-----------|--------|
| Platinum | 10 min | Blockchain, RFC 3161 TSA |
| Gold | 1 hour | RFC 3161 TSA, Attested DB |
| Silver | 24 hours | OpenTimestamps, FreeTSA |

**Why Required?** Without external anchoring, a log producer could modify the Merkle Root before anchoring, undermining "Verify, Don't Trust".

---

## How the Layers Work Together

### Detection Scenarios

| Attack | Layer 1 | Layer 2 | Layer 3 |
|--------|---------|---------|---------|
| Modify event content | ✅ EventHash mismatch | ✅ Merkle path invalid | ✅ Signature invalid |
| Delete an event | ✅ PrevHash break (if used) | ✅ Merkle Root mismatch | ✅ Anchor mismatch |
| Add fake event | ✅ Signature missing | ✅ Merkle Root mismatch | ✅ Anchor mismatch |
| Reorder events | ✅ PrevHash break (if used) | ✅ MerkleIndex mismatch | ✅ Timestamp violation |

### Completeness Guarantee

**Definition**: Third parties can cryptographically verify not only that events were not altered, but that **no required events were omitted**.

**How it works:**
1. Events are hashed (Layer 1)
2. Hashes form Merkle tree leaves (Layer 2)
3. Merkle Root is externally anchored (Layer 3)

Once anchored, the log producer cannot:
- Remove events (changes Merkle Root)
- Add events (changes Merkle Root)
- Modify events (changes EventHash → Merkle Root)

---

## Implementation Example

### Event Creation

```python
def create_vcp_v11_event(header, payload, prev_hash, merkle_root, anchor_ref):
    # Layer 1: Compute EventHash
    event_hash = compute_event_hash(header, payload, prev_hash)
    
    # Sign the event
    signature = ed25519_sign(event_hash, private_key)
    
    # Build Security object with all three layers
    security = {
        # Layer 1
        "EventHash": event_hash,
        "PrevHash": prev_hash,  # OPTIONAL but included
        "HashAlgo": "SHA256",
        
        # Layer 2
        "MerkleIndex": current_index,
        "MerkleRoot": merkle_root,
        
        # Layer 3
        "SignAlgo": "ED25519",
        "Signature": signature,
        "KeyID": key_id,
        "AnchorReference": anchor_ref
    }
    
    return {"Header": header, "Payload": payload, "Security": security}
```

### Batch Anchoring

```python
def anchor_batch(events):
    # Layer 1: Collect EventHashes
    event_hashes = [e["Security"]["EventHash"] for e in events]
    
    # Layer 2: Build Merkle Tree
    merkle_root = compute_merkle_root(event_hashes)
    
    # Layer 3: External Anchor
    anchor_record = external_anchor(merkle_root)
    
    # Update all events with Merkle info
    for i, event in enumerate(events):
        event["Security"]["MerkleIndex"] = i
        event["Security"]["MerkleRoot"] = merkle_root
        event["Security"]["AnchorReference"] = {
            "AnchorID": anchor_record["AnchorID"],
            "AnchorTarget": anchor_record["AnchorTarget"]["Type"],
            "AnchorTimestamp": anchor_record["Timestamp"]
        }
    
    return events, anchor_record
```

---

## Verification Process

```python
def verify_vcp_v11_chain(events, public_key, anchor_record):
    results = {}
    
    # Layer 1: Verify EventHashes and chain
    results["layer1"] = verify_event_integrity(events)
    
    # Layer 2: Verify Merkle Root
    event_hashes = [e["Security"]["EventHash"] for e in events]
    computed_root = compute_merkle_root(event_hashes)
    stored_root = events[0]["Security"]["MerkleRoot"]
    results["layer2"] = computed_root == stored_root
    
    # Layer 3: Verify signatures and anchor
    results["layer3_signatures"] = verify_all_signatures(events, public_key)
    results["layer3_anchor"] = verify_anchor(anchor_record, computed_root)
    
    return all(results.values()), results
```

---

## FAQ

### Why is PrevHash OPTIONAL now?

PrevHash provides real-time tamper detection but is redundant with Merkle + External Anchor for external verifiability. Making it optional:
1. Simplifies Silver tier implementations
2. Reduces complexity for platforms like MT4/MT5
3. Maintains full backward compatibility (can still use if desired)

### What if I skip Layer 1 PrevHash?

You lose **real-time** tamper detection but retain **batch-level** integrity through Layer 2. For most use cases (especially Silver tier), this is acceptable.

### Can an attacker regenerate the Merkle Root?

Not after external anchoring. The anchor creates a timestamp proof that the specific Merkle Root existed at a specific time. Regenerating would require:
1. Compromising the anchor service
2. OR rewriting blockchain history
3. OR both parties colluding (if using VCP-XREF)

---

## Related Documents

- [VCP Specification v1.1](https://github.com/veritaschain/vcp-spec)
- [VERIFICATION_GUIDE.md](VERIFICATION_GUIDE.md)
- [MIGRATION_v1.0_to_v1.1.md](MIGRATION_v1.0_to_v1.1.md)
