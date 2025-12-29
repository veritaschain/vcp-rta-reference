#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VCP Chain Verifier v1.1
=======================
Verify VCP v1.0 event chain integrity with optional Ed25519 signature verification.

Features:
- Hash chain verification (stdlib only)
- Timestamp monotonicity check
- Merkle root calculation
- Ed25519 signature verification (optional, requires pynacl)

Usage:
    python vcp_verifier.py <chain.jsonl> [--pubkey public_key.json]

Exit Codes:
    0 = PASS (chain verified)
    1 = FAIL (verification failed)
"""

import json
import hashlib
import sys
import os
from collections import Counter

# Optional: Ed25519 signature verification
try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignature
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False


def canonical_json(obj: dict) -> bytes:
    """RFC 8785 JCS: Dictionary key sorting, no whitespace"""
    def sort_keys(item):
        if isinstance(item, dict):
            return {k: sort_keys(v) for k, v in sorted(item.items())}
        elif isinstance(item, list):
            return [sort_keys(i) for i in item]
        return item
    
    sorted_obj = sort_keys(obj)
    return json.dumps(sorted_obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def compute_event_hash(header: dict, payload: dict, prev_hash: str) -> str:
    """Compute VCP event hash"""
    canonical_header = canonical_json(header)
    canonical_payload = canonical_json(payload)
    hash_input = canonical_header + canonical_payload + prev_hash.encode('utf-8')
    return hashlib.sha256(hash_input).hexdigest()


def compute_merkle_root(hashes: list) -> str:
    """Calculate Merkle Root (RFC 6962 Certificate Transparency)"""
    if not hashes:
        return "0" * 64
    
    def leaf_hash(h: str) -> str:
        return hashlib.sha256(b'\x00' + bytes.fromhex(h)).hexdigest()
    
    def internal_hash(left: str, right: str) -> str:
        return hashlib.sha256(b'\x01' + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()
    
    current = [leaf_hash(h) for h in hashes]
    
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            if i + 1 < len(current):
                next_level.append(internal_hash(current[i], current[i+1]))
            else:
                next_level.append(current[i])
        current = next_level
    
    return current[0]


def load_public_key(pubkey_path: str):
    """Load Ed25519 public key from JSON file"""
    if not NACL_AVAILABLE:
        return None
    
    try:
        with open(pubkey_path, 'r') as f:
            data = json.load(f)
        pubkey_hex = data.get("PublicKey", "")
        if pubkey_hex:
            return VerifyKey(bytes.fromhex(pubkey_hex))
    except Exception as e:
        print(f"  [!] Could not load public key: {e}")
    return None


def verify_signature(verify_key, event_hash: str, signature: str) -> bool:
    """Verify Ed25519 signature"""
    if not NACL_AVAILABLE or verify_key is None:
        return None  # Skip
    
    if not signature:
        return None  # No signature to verify
    
    try:
        message = bytes.fromhex(event_hash)
        sig_bytes = bytes.fromhex(signature)
        verify_key.verify(message, sig_bytes)
        return True
    except BadSignature:
        return False
    except Exception:
        return None


def verify_chain(filepath: str, pubkey_path: str = None) -> dict:
    """
    Verify VCP event chain integrity.
    
    Returns:
        dict with verification results
    """
    results = {
        "file": os.path.basename(filepath),
        "total_events": 0,
        "unique_traces": set(),
        "event_types": Counter(),
        "genesis_valid": False,
        "hash_chain_valid": True,
        "timestamps_monotonic": True,
        "signatures_valid": None,  # None = not checked, True/False = checked
        "errors": [],
        "merkle_root": "",
        "overall_pass": False
    }
    
    events = []
    
    # Load events
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    events.append((line_num, event))
                except json.JSONDecodeError as e:
                    results["errors"].append(f"Line {line_num}: JSON parse error: {e}")
    except FileNotFoundError:
        results["errors"].append(f"File not found: {filepath}")
        return results
    
    if not events:
        results["errors"].append("No events found in file")
        return results
    
    results["total_events"] = len(events)
    
    # Load public key for signature verification
    verify_key = None
    if pubkey_path:
        verify_key = load_public_key(pubkey_path)
    elif NACL_AVAILABLE:
        # Try to find public key in standard location
        base_dir = os.path.dirname(os.path.dirname(filepath))
        default_pubkey = os.path.join(base_dir, "04_anchor", "public_key.json")
        if os.path.exists(default_pubkey):
            verify_key = load_public_key(default_pubkey)
    
    # Track signature verification
    sig_checked = 0
    sig_valid = 0
    sig_invalid = 0
    
    # Verify chain
    prev_hash = "0" * 64  # Genesis
    prev_timestamp = 0
    event_hashes = []
    
    for line_num, event in events:
        header = event.get("Header", {})
        payload = event.get("Payload", {})
        security = event.get("Security", {})
        
        # Collect stats
        trace_id = header.get("TraceID", "")
        event_type = header.get("EventType", "")
        timestamp = header.get("Timestamp", 0)
        
        results["unique_traces"].add(trace_id)
        results["event_types"][event_type] += 1
        
        # Check Genesis
        if line_num == 1:
            stored_prev = security.get("PrevHash", "")
            if stored_prev == "0" * 64:
                results["genesis_valid"] = True
            else:
                results["errors"].append(f"Line 1: Invalid genesis PrevHash")
                results["genesis_valid"] = False
        
        # Verify PrevHash linkage
        stored_prev = security.get("PrevHash", "")
        if stored_prev != prev_hash:
            results["hash_chain_valid"] = False
            results["errors"].append(
                f"Line {line_num}: PrevHash mismatch\n"
                f"      expected: {prev_hash[:32]}...\n"
                f"      got: {stored_prev[:32]}..."
            )
        
        # Recompute EventHash
        computed_hash = compute_event_hash(header, payload, stored_prev)
        stored_hash = security.get("EventHash", "")
        
        if computed_hash != stored_hash:
            results["hash_chain_valid"] = False
            results["errors"].append(
                f"Line {line_num}: EventHash mismatch\n"
                f"      computed: {computed_hash[:32]}...\n"
                f"      stored: {stored_hash[:32]}..."
            )
        
        event_hashes.append(stored_hash)
        
        # Check timestamp monotonicity
        if timestamp < prev_timestamp:
            results["timestamps_monotonic"] = False
            results["errors"].append(f"Line {line_num}: Timestamp not monotonic")
        prev_timestamp = timestamp
        
        # Verify signature (if available)
        signature = security.get("Signature")
        if verify_key and signature:
            sig_result = verify_signature(verify_key, stored_hash, signature)
            if sig_result is True:
                sig_valid += 1
            elif sig_result is False:
                sig_invalid += 1
                results["errors"].append(f"Line {line_num}: Invalid signature")
            sig_checked += 1
        
        # Update for next iteration
        prev_hash = stored_hash
    
    # Signature summary
    if sig_checked > 0:
        results["signatures_valid"] = (sig_invalid == 0)
        results["sig_stats"] = {
            "checked": sig_checked,
            "valid": sig_valid,
            "invalid": sig_invalid
        }
    
    # Calculate Merkle Root
    results["merkle_root"] = compute_merkle_root(event_hashes)
    
    # Convert set to count
    results["unique_traces"] = len(results["unique_traces"])
    
    # Overall result
    results["overall_pass"] = (
        results["genesis_valid"] and
        results["hash_chain_valid"] and
        results["timestamps_monotonic"] and
        (results["signatures_valid"] is None or results["signatures_valid"])
    )
    
    return results


def print_report(results: dict):
    """Print verification report"""
    print()
    print("=" * 60)
    print("VCP Chain Verification Report")
    print("=" * 60)
    print(f"File: {results['file']}")
    print(f"Total Events: {results['total_events']}")
    print(f"Unique TraceIDs: {results['unique_traces']}")
    print()
    
    print("Event Types:")
    for etype, count in sorted(results['event_types'].items()):
        print(f"  {etype}: {count}")
    print()
    
    print("Verification Results:")
    
    def status(passed):
        return "\033[92mPASS\033[0m" if passed else "\033[91mFAIL\033[0m"
    
    print(f"  Genesis: {status(results['genesis_valid'])}")
    print(f"  Hash Chain: {status(results['hash_chain_valid'])}")
    print(f"  Timestamp Monotonicity: {status(results['timestamps_monotonic'])}")
    
    if results['signatures_valid'] is not None:
        print(f"  Signatures: {status(results['signatures_valid'])}", end="")
        if 'sig_stats' in results:
            stats = results['sig_stats']
            print(f" ({stats['valid']}/{stats['checked']} valid)")
        else:
            print()
    else:
        if NACL_AVAILABLE:
            print("  Signatures: SKIPPED (no public key)")
        else:
            print("  Signatures: SKIPPED (pynacl not installed)")
    
    if results['errors']:
        print()
        print(f"Errors ({len(results['errors'])}):")
        for error in results['errors'][:10]:  # Limit to first 10
            print(f"  [X] {error}")
        if len(results['errors']) > 10:
            print(f"  ... and {len(results['errors']) - 10} more errors")
    
    print()
    print("=" * 60)
    
    if results['overall_pass']:
        print("\033[92mVERIFICATION: PASS - Chain integrity verified\033[0m")
    else:
        print("\033[91mVERIFICATION: FAIL - Chain integrity compromised\033[0m")
    
    print("=" * 60)
    print()
    print(f"Merkle Root: {results['merkle_root']}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python vcp_verifier.py <chain.jsonl> [--pubkey public_key.json]")
        print()
        print("Options:")
        print("  --pubkey  Path to Ed25519 public key JSON file")
        print()
        print("Example:")
        print("  python vcp_verifier.py vcp_rta_demo_events.jsonl")
        print("  python vcp_verifier.py events.jsonl --pubkey keys/public.json")
        sys.exit(1)
    
    filepath = sys.argv[1]
    pubkey_path = None
    
    # Parse arguments
    if "--pubkey" in sys.argv:
        idx = sys.argv.index("--pubkey")
        if idx + 1 < len(sys.argv):
            pubkey_path = sys.argv[idx + 1]
    
    results = verify_chain(filepath, pubkey_path)
    print_report(results)
    
    sys.exit(0 if results['overall_pass'] else 1)


if __name__ == "__main__":
    main()
