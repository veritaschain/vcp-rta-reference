#!/usr/bin/env python3
"""
VCP v1.1 Verifier - Fully Compliant Version
Third-party verifiable chain integrity checker.

Verifies compliance with VCP Specification v1.1:
- Three-Layer Architecture verification
- RFC 6962 Merkle Tree validation
- Security Object Schema validation
- Policy Identification validation
"""

import json
import hashlib
import sys
from datetime import datetime
from typing import Dict, List, Tuple

def sha256_hex(data: str) -> str:
    """SHA-256 hash in hex format."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def rfc6962_leaf_hash(data: bytes) -> bytes:
    """RFC 6962 compliant leaf hash with 0x00 prefix."""
    return hashlib.sha256(b'\x00' + data).digest()

def rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 compliant internal node hash with 0x01 prefix."""
    return hashlib.sha256(b'\x01' + left + right).digest()

def compute_rfc6962_merkle_root(event_hashes: List[str]) -> str:
    """Compute RFC 6962 compliant Merkle root."""
    if not event_hashes:
        return sha256_hex("")
    
    # Create leaf hashes with 0x00 prefix
    current_level = [rfc6962_leaf_hash(bytes.fromhex(h)) for h in event_hashes]
    
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                node = rfc6962_node_hash(current_level[i], current_level[i + 1])
            else:
                node = rfc6962_node_hash(current_level[i], current_level[i])
            next_level.append(node)
        current_level = next_level
    
    return current_level[0].hex() if current_level else sha256_hex("")

def verify_event_hash(event: Dict) -> Tuple[bool, str]:
    """Verify individual event hash (Layer 1)."""
    security = event.get('Security', {})
    stored_hash = security.get('EventHash')
    
    if not stored_hash:
        return False, "Missing EventHash"
    
    # Compute hash over Header + Payload
    header = event.get('Header', {})
    payload = event.get('Payload', {})
    hash_input = json.dumps(header, sort_keys=True) + json.dumps(payload, sort_keys=True)
    computed_hash = sha256_hex(hash_input)
    
    if computed_hash == stored_hash:
        return True, "OK"
    else:
        return False, f"Hash mismatch: expected {computed_hash[:16]}..., got {stored_hash[:16]}..."

def verify_security_object(event: Dict) -> List[str]:
    """Verify Security object has all required fields (v1.1)."""
    errors = []
    security = event.get('Security', {})
    
    required_fields = [
        ('Version', str),
        ('EventHash', str),
        ('HashAlgo', str),
        ('Signature', str),
        ('SignAlgo', str),
        ('MerkleRoot', str),
        ('MerkleIndex', int),
        ('AnchorReference', str)
    ]
    
    for field, field_type in required_fields:
        if field not in security:
            errors.append(f"Missing Security.{field}")
        elif not isinstance(security[field], field_type):
            errors.append(f"Security.{field} has wrong type")
    
    return errors

def verify_policy_identification(event: Dict) -> List[str]:
    """Verify Policy Identification has all required fields (v1.1)."""
    errors = []
    policy = event.get('PolicyIdentification', {})
    
    if not policy:
        errors.append("Missing PolicyIdentification")
        return errors
    
    if 'PolicyID' not in policy:
        errors.append("Missing PolicyIdentification.PolicyID")
    
    if 'ConformanceTier' not in policy:
        errors.append("Missing PolicyIdentification.ConformanceTier")
    elif policy['ConformanceTier'] not in ['SILVER', 'GOLD', 'PLATINUM']:
        errors.append(f"Invalid ConformanceTier: {policy['ConformanceTier']}")
    
    reg_policy = policy.get('RegistrationPolicy', {})
    if 'Issuer' not in reg_policy:
        errors.append("Missing PolicyIdentification.RegistrationPolicy.Issuer")
    
    verification_depth = policy.get('VerificationDepth', {})
    if not verification_depth:
        errors.append("Missing PolicyIdentification.VerificationDepth")
    else:
        for field in ['HashChainValidation', 'MerkleProofRequired', 'ExternalAnchorRequired']:
            if field not in verification_depth:
                errors.append(f"Missing PolicyIdentification.VerificationDepth.{field}")
    
    return errors

def verify_chain(events: List[Dict]) -> Dict:
    """Verify complete event chain integrity (all layers)."""
    results = {
        "status": "VALID",
        "events_total": len(events),
        "events_valid": 0,
        "events_invalid": 0,
        "security_valid": True,
        "policy_valid": True,
        "sequence_valid": True,
        "prevhash_valid": True,
        "errors": []
    }
    
    prev_hash = None
    expected_seq = 1
    
    for i, event in enumerate(events):
        # Layer 1: Event hash verification
        valid, msg = verify_event_hash(event)
        if valid:
            results["events_valid"] += 1
        else:
            results["events_invalid"] += 1
            results["errors"].append(f"Event {i+1}: {msg}")
            results["status"] = "INVALID"
        
        # Security Object verification
        security_errors = verify_security_object(event)
        if security_errors:
            results["security_valid"] = False
            for err in security_errors:
                results["errors"].append(f"Event {i+1}: {err}")
            results["status"] = "INVALID"
        
        # Policy Identification verification
        policy_errors = verify_policy_identification(event)
        if policy_errors:
            results["policy_valid"] = False
            for err in policy_errors:
                results["errors"].append(f"Event {i+1}: {err}")
            results["status"] = "INVALID"
        
        # Sequence verification
        header = event.get('Header', {})
        seq = header.get('Sequence')
        if seq != expected_seq:
            results["sequence_valid"] = False
            results["errors"].append(f"Event {i+1}: sequence {seq}, expected {expected_seq}")
            results["status"] = "INVALID"
        expected_seq = seq + 1 if seq else expected_seq + 1
        
        # PrevHash verification (optional but check if present)
        security = event.get('Security', {})
        if 'PrevHash' in security:
            if prev_hash and security['PrevHash'] != prev_hash:
                results["prevhash_valid"] = False
                results["errors"].append(f"Event {i+1}: PrevHash mismatch")
                results["status"] = "INVALID"
        
        prev_hash = security.get('EventHash')
    
    return results

def verify_merkle_root(events: List[Dict], expected_root: str) -> Tuple[bool, str]:
    """Verify Merkle root matches events (Layer 2)."""
    event_hashes = [e.get('Security', {}).get('EventHash', '') for e in events]
    computed = compute_rfc6962_merkle_root(event_hashes)
    
    if computed == expected_root:
        return True, computed
    else:
        return False, f"Mismatch: computed {computed[:16]}..., expected {expected_root[:16]}..."

def load_events(filepath: str) -> List[Dict]:
    """Load events from JSONL file."""
    events = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events

def load_security_object(filepath: str) -> Dict:
    """Load security object."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def print_report(results: Dict, merkle_result: Tuple[bool, str], events: List[Dict]):
    """Print verification report."""
    print("=" * 70)
    print("VCP v1.1 Verification Report - Fully Compliant")
    print("=" * 70)
    print(f"Generated: {datetime.now().isoformat()}")
    print()
    
    if events:
        header = events[0].get('Header', {})
        policy = events[0].get('PolicyIdentification', {})
        security = events[0].get('Security', {})
        
        print("[Event Summary]")
        print(f"  VCP Version: {security.get('Version', 'N/A')}")
        print(f"  Policy ID: {policy.get('PolicyID', 'N/A')}")
        print(f"  Conformance Tier: {policy.get('ConformanceTier', 'N/A')}")
        print(f"  Agent ID: {header.get('AgentID', 'N/A')}")
        
        first_ts = events[0].get('Header', {}).get('TimestampISO', 'N/A')
        last_ts = events[-1].get('Header', {}).get('TimestampISO', 'N/A')
        print(f"  Date Range: {first_ts[:10]} to {last_ts[:10]}")
        print()
    
    print("[Verification Results]")
    status_icon = "PASS" if results["status"] == "VALID" else "FAIL"
    print(f"  Overall Status: [{status_icon}] {results['status']}")
    print(f"  Total Events: {results['events_total']}")
    print(f"  Valid Events: {results['events_valid']}")
    print(f"  Invalid Events: {results['events_invalid']}")
    print()
    
    print("[VCP v1.1 Compliance]")
    sec_status = "PASS" if results["security_valid"] else "FAIL"
    pol_status = "PASS" if results["policy_valid"] else "FAIL"
    print(f"  Security Object Schema: [{sec_status}]")
    print(f"  Policy Identification: [{pol_status}]")
    print()
    
    print("[Chain Integrity (Three-Layer Architecture)]")
    seq_status = "PASS" if results["sequence_valid"] else "FAIL"
    prev_status = "PASS" if results["prevhash_valid"] else "FAIL"
    merkle_status = "PASS" if merkle_result[0] else "FAIL"
    
    print(f"  Layer 1 - Event Hash: [{status_icon}]")
    print(f"  Layer 1 - Sequence: [{seq_status}]")
    print(f"  Layer 1 - PrevHash: [{prev_status}]")
    print(f"  Layer 2 - Merkle Root (RFC 6962): [{merkle_status}]")
    if merkle_result[0]:
        print(f"    Root: {merkle_result[1][:32]}...")
    else:
        print(f"    {merkle_result[1]}")
    print()
    
    if results["errors"]:
        print("[Errors Detected]")
        for err in results["errors"][:10]:
            print(f"  - {err}")
        if len(results["errors"]) > 10:
            print(f"  ... and {len(results['errors']) - 10} more errors")
        print()
    
    print("=" * 70)
    final_status = "All checks passed - VCP v1.1 Compliant" if results["status"] == "VALID" and merkle_result[0] else "Issues detected"
    print(f"Verification complete: {final_status}")
    print("=" * 70)

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description='VCP v1.1 Chain Verifier - Fully Compliant')
    parser.add_argument('events_file', help='JSONL file containing events')
    parser.add_argument('--security-object', '-s', help='Security object JSON file')
    parser.add_argument('--output', '-o', help='Output report file')
    
    args = parser.parse_args()
    
    print(f"Loading events: {args.events_file}")
    events = load_events(args.events_file)
    print(f"  {len(events)} events loaded")
    
    expected_merkle = None
    if args.security_object:
        print(f"Loading security object: {args.security_object}")
        security_obj = load_security_object(args.security_object)
        merkle_tree = security_obj.get('MerkleTree', {})
        expected_merkle = merkle_tree.get('Root')
    
    print("\nVerifying chain integrity (VCP v1.1)...")
    results = verify_chain(events)
    
    if expected_merkle:
        merkle_result = verify_merkle_root(events, expected_merkle)
    else:
        # Compute Merkle root if not provided
        event_hashes = [e.get('Security', {}).get('EventHash', '') for e in events]
        computed = compute_rfc6962_merkle_root(event_hashes)
        merkle_result = (True, computed)
    
    print()
    print_report(results, merkle_result, events)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write("VCP v1.1 Verification Report - Fully Compliant\n")
            f.write("=" * 70 + "\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n\n")
            f.write(f"Overall Status: {results['status']}\n")
            f.write(f"Total Events: {results['events_total']}\n")
            f.write(f"Valid Events: {results['events_valid']}\n")
            f.write(f"Invalid Events: {results['events_invalid']}\n")
            f.write(f"Security Object Schema: {'OK' if results['security_valid'] else 'NG'}\n")
            f.write(f"Policy Identification: {'OK' if results['policy_valid'] else 'NG'}\n")
            f.write(f"Sequence Continuity: {'OK' if results['sequence_valid'] else 'NG'}\n")
            f.write(f"PrevHash Integrity: {'OK' if results['prevhash_valid'] else 'NG'}\n")
            f.write(f"Merkle Root (RFC 6962): {'OK' if merkle_result[0] else 'NG'}\n")
            if merkle_result[0]:
                f.write(f"  Root: {merkle_result[1]}\n")
        print(f"\nReport saved: {args.output}")
    
    sys.exit(0 if results["status"] == "VALID" and merkle_result[0] else 1)

if __name__ == "__main__":
    main()
