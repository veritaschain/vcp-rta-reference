# VCP v1.1 Verification Guide

Step-by-step guide to verify VCP v1.1 event chain integrity.

## Prerequisites

- Python 3.8 or higher
- No external dependencies (stdlib only)
- Optional: PyNaCl for Ed25519 signature verification

## Quick Start

```bash
# Clone the repository
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference

# Run verification
python tools/verifier/vcp_verifier.py \
    evidence/01_sample_logs/vcp_rta_demo_events.jsonl \
    evidence/04_anchor/public_key.json
```

---

## What Gets Verified

### Layer 1: Event Integrity

| Check | Description | Failure Meaning |
|-------|-------------|-----------------|
| Genesis | First event has PrevHash = 64 zeros | Chain start invalid |
| EventHash | Recomputed hash matches stored | Event was modified |
| Hash Chain | PrevHash matches previous EventHash | Event deleted/reordered |

### Layer 2: Collection Integrity

| Check | Description | Failure Meaning |
|-------|-------------|-----------------|
| Merkle Root | Computed root matches stored | Events added/removed |

### Layer 3: External Verifiability

| Check | Description | Failure Meaning |
|-------|-------------|-----------------|
| Timestamps | Monotonically increasing | Events reordered |
| Policy ID | Present in all events | v1.1 requirement missing |
| Anchor Ref | Present in all events | v1.1 requirement missing |
| Signatures | Valid Ed25519 signatures | Forgery or corruption |

---

## Manual Verification Steps

### Step 1: Load Events

```python
import json

events = []
with open('evidence/01_sample_logs/vcp_rta_demo_events.jsonl', 'r') as f:
    for line in f:
        if line.strip():
            events.append(json.loads(line))

print(f"Loaded {len(events)} events")
```

### Step 2: Verify Genesis Event

```python
first_event = events[0]
prev_hash = first_event["Security"]["PrevHash"]

if prev_hash == "0" * 64:
    print("✅ Genesis: PASS")
else:
    print("❌ Genesis: FAIL - Invalid PrevHash")
```

### Step 3: Verify EventHashes

```python
import hashlib

def canonical_json(obj):
    """RFC 8785 JSON Canonicalization"""
    def sort_keys(item):
        if isinstance(item, dict):
            return {k: sort_keys(v) for k, v in sorted(item.items())}
        elif isinstance(item, list):
            return [sort_keys(i) for i in item]
        return item
    return json.dumps(sort_keys(obj), ensure_ascii=False, separators=(',', ':')).encode()

def compute_event_hash(header, payload, prev_hash):
    hash_input = canonical_json(header) + canonical_json(payload) + prev_hash.encode()
    return hashlib.sha256(hash_input).hexdigest()

# Verify each event
prev_hash = "0" * 64
for i, event in enumerate(events):
    expected = compute_event_hash(
        event["Header"], 
        event["Payload"], 
        prev_hash
    )
    actual = event["Security"]["EventHash"]
    
    if expected != actual:
        print(f"❌ Event {i+1}: EventHash mismatch")
        break
    
    prev_hash = actual
else:
    print("✅ EventHashes: PASS")
```

### Step 4: Verify Merkle Root

```python
def compute_merkle_root(event_hashes):
    """RFC 6962 Merkle tree"""
    def leaf_hash(h):
        return hashlib.sha256(b'\x00' + bytes.fromhex(h)).hexdigest()
    
    def internal_hash(left, right):
        return hashlib.sha256(b'\x01' + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()
    
    current = [leaf_hash(h) for h in event_hashes]
    
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            if i + 1 < len(current):
                next_level.append(internal_hash(current[i], current[i+1]))
            else:
                next_level.append(current[i])
        current = next_level
    
    return current[0]

# Collect EventHashes and compute root
event_hashes = [e["Security"]["EventHash"] for e in events]
computed_root = compute_merkle_root(event_hashes)
stored_root = events[0]["Security"]["MerkleRoot"]

if computed_root == stored_root:
    print(f"✅ Merkle Root: PASS")
    print(f"   Root: {computed_root}")
else:
    print(f"❌ Merkle Root: FAIL")
    print(f"   Computed: {computed_root}")
    print(f"   Stored:   {stored_root}")
```

### Step 5: Verify v1.1 Requirements

```python
# Check Policy Identification
for i, event in enumerate(events):
    policy = event["Payload"].get("PolicyIdentification", {})
    if not policy.get("PolicyID"):
        print(f"❌ Policy Identification: FAIL at event {i+1}")
        break
else:
    print("✅ Policy Identification: PASS")

# Check Anchor Reference
for i, event in enumerate(events):
    anchor = event["Security"].get("AnchorReference")
    if not anchor:
        print(f"❌ Anchor Reference: FAIL at event {i+1}")
        break
else:
    print("✅ Anchor Reference: PASS")
```

### Step 6: Verify Signatures (Optional)

```python
# Requires: pip install pynacl
try:
    from nacl.signing import VerifyKey
    
    with open('evidence/04_anchor/public_key.json', 'r') as f:
        key_data = json.load(f)
    
    verify_key = VerifyKey(bytes.fromhex(key_data["PublicKey"]))
    
    valid_count = 0
    for event in events:
        event_hash = event["Security"]["EventHash"]
        signature = event["Security"]["Signature"]
        try:
            verify_key.verify(bytes.fromhex(event_hash), bytes.fromhex(signature))
            valid_count += 1
        except:
            pass
    
    print(f"✅ Signatures: {valid_count}/{len(events)} valid")
except ImportError:
    print("⚠️ Signatures: SKIPPED (PyNaCl not installed)")
```

---

## Understanding Results

### PASS Result

```
======================================================================
VCP v1.1 Chain Verification Report
======================================================================
...
VERIFICATION: PASS - VCP v1.1 Chain integrity verified
======================================================================
```

**Meaning**: All events are intact, properly linked, and meet v1.1 requirements.

### FAIL Result

```
======================================================================
VERIFICATION: FAIL - Chain integrity check failed
======================================================================
Errors:
  - Event 76: EventHash mismatch
  - Event 76: PrevHash mismatch
```

**Meaning**: Chain has been tampered with. Error messages indicate the first point of failure.

---

## Common Issues

### "EventHash mismatch"

**Cause**: Event content was modified after signing.
**Check**: Compare Header/Payload with expected values.

### "PrevHash mismatch"

**Cause**: An event was deleted or events were reordered.
**Check**: Verify event sequence is complete.

### "Merkle Root mismatch"

**Cause**: Events were added or removed after anchoring.
**Check**: Event count should match anchor record.

### "Policy Identification missing"

**Cause**: v1.0 events without v1.1 upgrade.
**Fix**: Add PolicyIdentification to all events.

### "Anchor Reference missing"

**Cause**: Events not properly linked to anchor.
**Fix**: Run anchoring process and update events.

---

## Anchor Verification

To verify the external anchor:

```python
with open('evidence/04_anchor/anchor_record.json', 'r') as f:
    anchor = json.load(f)

print(f"Anchor ID: {anchor['AnchorID']}")
print(f"Merkle Root: {anchor['MerkleRoot']}")
print(f"Event Count: {anchor['EventCount']}")
print(f"Target: {anchor['AnchorTarget']['Type']}")
print(f"Timestamp: {anchor['TimestampISO']}")

# Verify Merkle Root matches
if anchor['MerkleRoot'] == computed_root:
    print("✅ Anchor matches computed Merkle Root")
```

For OpenTimestamps anchors, use the `ots` CLI:
```bash
ots verify anchor_proof.ots
```

---

## Automated Testing

Run the full test suite:

```bash
# Basic verification
python tools/verifier/vcp_verifier.py evidence/01_sample_logs/vcp_rta_demo_events.jsonl

# With signature verification
python tools/verifier/vcp_verifier.py \
    evidence/01_sample_logs/vcp_rta_demo_events.jsonl \
    evidence/04_anchor/public_key.json

# Tamper detection demo
python evidence/tamper_demo/tamper_demo.py \
    evidence/01_sample_logs/vcp_rta_demo_events.jsonl
```

---

## Integration with Your System

To integrate verification into your pipeline:

```python
from vcp_verifier import verify_chain

success, report = verify_chain(
    events_file="path/to/events.jsonl",
    public_key_file="path/to/public_key.json"
)

if success:
    print("Chain verified successfully")
else:
    print("Verification failed:")
    for error in report["errors"]:
        print(f"  - {error}")
```

---

## Support

- Issues: [GitHub Issues](https://github.com/veritaschain/vcp-rta-reference/issues)
- Email: support@veritaschain.org
- Docs: [docs.veritaschain.org](https://docs.veritaschain.org)
