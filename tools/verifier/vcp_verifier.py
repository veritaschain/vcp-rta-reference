#!/usr/bin/env python3
"""
VCP v1.1 Chain Verifier
Verifies VCP v1.1 Silver Tier compliant event chains including:
- Event Integrity (Layer 1): EventHash, PrevHash (optional)
- Collection Integrity (Layer 2): Merkle Tree
- External Verifiability (Layer 3): Signatures, Anchor Reference
- Policy Identification (v1.1 requirement)
"""

import json
import hashlib
import sys
from typing import List, Dict, Tuple, Optional
from collections import Counter

# Optional Ed25519 verification
try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignature
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False


def canonical_json(obj: dict) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme"""
    def sort_keys(item):
        if isinstance(item, dict):
            return {k: sort_keys(v) for k, v in sorted(item.items())}
        elif isinstance(item, list):
            return [sort_keys(i) for i in item]
        return item
    
    sorted_obj = sort_keys(obj)
    return json.dumps(sorted_obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def compute_event_hash(header: dict, payload: dict, prev_hash: str) -> str:
    """Compute EventHash = SHA-256(canonical(Header) + canonical(Payload) + PrevHash)"""
    canonical_header = canonical_json(header)
    canonical_payload = canonical_json(payload)
    hash_input = canonical_header + canonical_payload + prev_hash.encode('utf-8')
    return hashlib.sha256(hash_input).hexdigest()


def compute_merkle_root(event_hashes: List[str]) -> str:
    """Compute Merkle Root using RFC 6962 method"""
    def leaf_hash(h: str) -> str:
        return hashlib.sha256(b'\x00' + bytes.fromhex(h)).hexdigest()
    
    def internal_hash(left: str, right: str) -> str:
        return hashlib.sha256(b'\x01' + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()
    
    if not event_hashes:
        return "0" * 64
    
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


def verify_signature(event_hash: str, signature: str, public_key_hex: str) -> bool:
    """Verify Ed25519 signature"""
    if not NACL_AVAILABLE:
        return True  # Skip if PyNaCl not available
    
    try:
        verify_key = VerifyKey(bytes.fromhex(public_key_hex))
        verify_key.verify(bytes.fromhex(event_hash), bytes.fromhex(signature))
        return True
    except (BadSignature, Exception):
        return False


def load_public_key(key_file: str) -> Optional[str]:
    """Load public key from file"""
    try:
        with open(key_file, 'r') as f:
            key_data = json.load(f)
            return key_data.get("PublicKey")
    except Exception:
        return None


def verify_chain(events_file: str, public_key_file: str = None) -> Tuple[bool, dict]:
    """
    Verify VCP v1.1 event chain
    
    Returns:
        Tuple of (success: bool, report: dict)
    """
    report = {
        "file": events_file,
        "vcp_version": "1.1",
        "total_events": 0,
        "unique_traces": 0,
        "event_types": {},
        "verification": {
            "genesis": None,
            "hash_chain": None,
            "event_hashes": None,
            "timestamp_monotonicity": None,
            "merkle_root": None,
            "policy_identification": None,
            "signatures": None,
            "anchor_reference": None
        },
        "merkle_root": None,
        "errors": []
    }
    
    # Load events
    events = []
    try:
        with open(events_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        report["errors"].append(f"Line {line_num}: JSON parse error - {e}")
    except FileNotFoundError:
        report["errors"].append(f"File not found: {events_file}")
        return False, report
    
    if not events:
        report["errors"].append("No events found in file")
        return False, report
    
    report["total_events"] = len(events)
    
    # Count event types and traces
    event_types = Counter()
    trace_ids = set()
    
    for event in events:
        header = event.get("Header", {})
        event_types[header.get("EventType", "UNKNOWN")] += 1
        trace_ids.add(header.get("TraceID", ""))
    
    report["event_types"] = dict(event_types)
    report["unique_traces"] = len(trace_ids)
    
    # Load public key if provided
    public_key = None
    if public_key_file:
        public_key = load_public_key(public_key_file)
    
    # === LAYER 1: Event Integrity ===
    
    # Check Genesis
    first_security = events[0].get("Security", {})
    first_prev_hash = first_security.get("PrevHash", "")
    genesis_valid = first_prev_hash == "0" * 64
    report["verification"]["genesis"] = "PASS" if genesis_valid else "FAIL"
    if not genesis_valid:
        report["errors"].append(f"Genesis PrevHash invalid: expected 64 zeros, got {first_prev_hash[:20]}...")
    
    # Verify EventHashes and Hash Chain
    event_hashes = []
    hash_chain_valid = True
    event_hash_valid = True
    prev_hash = "0" * 64
    
    for i, event in enumerate(events):
        header = event.get("Header", {})
        payload = event.get("Payload", {})
        security = event.get("Security", {})
        
        # Compute expected hash
        expected_hash = compute_event_hash(header, payload, prev_hash)
        actual_hash = security.get("EventHash", "")
        
        if expected_hash != actual_hash:
            event_hash_valid = False
            report["errors"].append(f"Event {i+1}: EventHash mismatch")
        
        event_hashes.append(actual_hash)
        
        # Check chain linkage (PrevHash is OPTIONAL in v1.1)
        actual_prev_hash = security.get("PrevHash", "")
        if actual_prev_hash and actual_prev_hash != prev_hash:
            hash_chain_valid = False
            report["errors"].append(f"Event {i+1}: PrevHash mismatch")
        
        prev_hash = actual_hash
    
    report["verification"]["event_hashes"] = "PASS" if event_hash_valid else "FAIL"
    report["verification"]["hash_chain"] = "PASS" if hash_chain_valid else "FAIL (OPTIONAL in v1.1)"
    
    # === LAYER 2: Collection Integrity ===
    
    # Compute and verify Merkle Root
    computed_merkle_root = compute_merkle_root(event_hashes)
    report["merkle_root"] = computed_merkle_root
    
    # Check if events have MerkleRoot field (v1.1 REQUIRED)
    merkle_valid = True
    for i, event in enumerate(events):
        security = event.get("Security", {})
        event_merkle_root = security.get("MerkleRoot")
        if event_merkle_root and event_merkle_root != computed_merkle_root:
            merkle_valid = False
            report["errors"].append(f"Event {i+1}: MerkleRoot mismatch")
    
    report["verification"]["merkle_root"] = "PASS" if merkle_valid else "FAIL"
    
    # === LAYER 3: External Verifiability ===
    
    # Check Timestamp Monotonicity
    timestamps = [event.get("Header", {}).get("Timestamp", 0) for event in events]
    monotonic = all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1))
    report["verification"]["timestamp_monotonicity"] = "PASS" if monotonic else "FAIL"
    if not monotonic:
        report["errors"].append("Timestamp monotonicity violation detected")
    
    # Check Policy Identification (REQUIRED in v1.1)
    policy_valid = True
    for i, event in enumerate(events):
        payload = event.get("Payload", {})
        policy_id = payload.get("PolicyIdentification", {})
        if not policy_id or not policy_id.get("PolicyID"):
            policy_valid = False
            if i == 0:  # Only report first occurrence
                report["errors"].append("PolicyIdentification missing (REQUIRED in v1.1)")
            break
    
    report["verification"]["policy_identification"] = "PASS" if policy_valid else "FAIL"
    
    # Check Anchor Reference (REQUIRED in v1.1)
    anchor_valid = True
    for i, event in enumerate(events):
        security = event.get("Security", {})
        anchor_ref = security.get("AnchorReference")
        if not anchor_ref:
            anchor_valid = False
            if i == 0:
                report["errors"].append("AnchorReference missing (REQUIRED in v1.1)")
            break
    
    report["verification"]["anchor_reference"] = "PASS" if anchor_valid else "FAIL"
    
    # Verify Signatures (if public key available)
    if public_key and NACL_AVAILABLE:
        sig_valid_count = 0
        for event in events:
            security = event.get("Security", {})
            event_hash = security.get("EventHash", "")
            signature = security.get("Signature", "")
            
            if verify_signature(event_hash, signature, public_key):
                sig_valid_count += 1
        
        all_sigs_valid = sig_valid_count == len(events)
        report["verification"]["signatures"] = f"PASS ({sig_valid_count}/{len(events)} valid)" if all_sigs_valid else f"FAIL ({sig_valid_count}/{len(events)} valid)"
    else:
        report["verification"]["signatures"] = "SKIPPED (no public key or PyNaCl)"
    
    # Determine overall result
    critical_checks = [
        report["verification"]["genesis"] == "PASS",
        report["verification"]["event_hashes"] == "PASS",
        report["verification"]["merkle_root"] == "PASS",
        report["verification"]["timestamp_monotonicity"] == "PASS",
        report["verification"]["policy_identification"] == "PASS",
        report["verification"]["anchor_reference"] == "PASS"
    ]
    
    overall_pass = all(critical_checks)
    
    return overall_pass, report


def print_report(success: bool, report: dict):
    """Print verification report"""
    print("=" * 70)
    print("VCP v1.1 Chain Verification Report")
    print("=" * 70)
    print(f"File: {report['file']}")
    print(f"VCP Version: {report['vcp_version']}")
    print(f"Total Events: {report['total_events']}")
    print(f"Unique TraceIDs: {report['unique_traces']}")
    print()
    
    print("Event Types:")
    for event_type, count in sorted(report['event_types'].items()):
        print(f"  {event_type}: {count}")
    print()
    
    print("Three-Layer Verification Results:")
    print("  [Layer 1: Event Integrity]")
    print(f"    Genesis: {report['verification']['genesis']}")
    print(f"    Event Hashes: {report['verification']['event_hashes']}")
    print(f"    Hash Chain: {report['verification']['hash_chain']}")
    print()
    print("  [Layer 2: Collection Integrity]")
    print(f"    Merkle Root: {report['verification']['merkle_root']}")
    print()
    print("  [Layer 3: External Verifiability]")
    print(f"    Timestamp Monotonicity: {report['verification']['timestamp_monotonicity']}")
    print(f"    Policy Identification: {report['verification']['policy_identification']}")
    print(f"    Anchor Reference: {report['verification']['anchor_reference']}")
    print(f"    Signatures: {report['verification']['signatures']}")
    print()
    
    if report['errors']:
        print("Errors:")
        for error in report['errors'][:10]:  # Limit to 10 errors
            print(f"  - {error}")
        if len(report['errors']) > 10:
            print(f"  ... and {len(report['errors']) - 10} more errors")
        print()
    
    print("=" * 70)
    if success:
        print("VERIFICATION: PASS - VCP v1.1 Chain integrity verified")
    else:
        print("VERIFICATION: FAIL - Chain integrity check failed")
    print("=" * 70)
    print()
    print(f"Merkle Root: {report['merkle_root']}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python vcp_v1_1_verifier.py <events.jsonl> [public_key.json]")
        print()
        print("Arguments:")
        print("  events.jsonl    - VCP v1.1 event chain file")
        print("  public_key.json - Optional: Ed25519 public key for signature verification")
        sys.exit(1)
    
    events_file = sys.argv[1]
    public_key_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    success, report = verify_chain(events_file, public_key_file)
    print_report(success, report)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
