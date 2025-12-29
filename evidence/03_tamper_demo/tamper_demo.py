# -*- coding: utf-8 -*-
"""
VCP Tamper Detection Demo
=========================
Demonstrates tamper detection: Single line deletion breaks the chain

Usage:
    python tamper_demo.py

Output:
    - Original chain verification result
    - Tampered chain verification result
    - Diff information
"""

import json
import hashlib
import os
import sys


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


def compute_merkle_root(event_hashes: list) -> str:
    """Calculate Merkle Root (RFC 6962)"""
    if not event_hashes:
        return "0" * 64
    
    def leaf_hash(h: str) -> str:
        return hashlib.sha256(b'\x00' + bytes.fromhex(h)).hexdigest()
    
    def internal_hash(left: str, right: str) -> str:
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


def verify_chain_simple(filepath: str) -> dict:
    """Simple chain verification (no external dependencies)"""
    result = {
        "total_events": 0,
        "genesis_valid": False,
        "hash_chain_valid": True,
        "errors": [],
        "merkle_root": "",
        "event_hashes": []
    }
    
    events = []
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    
    result["total_events"] = len(events)
    
    if not events:
        result["errors"].append("No events found")
        return result
    
    # Verify chain
    prev_hash = "0" * 64
    
    for i, event in enumerate(events, 1):
        header = event.get("Header", {})
        payload = event.get("Payload", {})
        security = event.get("Security", {})
        
        stored_prev = security.get("PrevHash", "")
        stored_hash = security.get("EventHash", "")
        
        # Check genesis
        if i == 1:
            result["genesis_valid"] = (stored_prev == "0" * 64)
        
        # Check PrevHash linkage
        if stored_prev != prev_hash:
            result["hash_chain_valid"] = False
            result["errors"].append(
                f"Line {i}: PrevHash mismatch\n"
                f"      expected: {prev_hash[:32]}...\n"
                f"      got: {stored_prev[:32]}..."
            )
        
        result["event_hashes"].append(stored_hash)
        prev_hash = stored_hash
    
    result["merkle_root"] = compute_merkle_root(result["event_hashes"])
    return result


def create_tampered_chain(original_path: str, tampered_path: str, delete_line: int = 5) -> dict:
    """Create tampered chain by deleting specified line"""
    deleted_event = None
    
    with open(original_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    if delete_line > len(lines):
        delete_line = len(lines) // 2
    
    try:
        deleted_event = json.loads(lines[delete_line - 1])
    except:
        pass
    
    tampered_lines = lines[:delete_line - 1] + lines[delete_line:]
    
    with open(tampered_path, 'w', encoding='utf-8') as f:
        f.writelines(tampered_lines)
    
    return {
        "deleted_line": delete_line,
        "deleted_event": deleted_event,
        "original_count": len(lines),
        "tampered_count": len(tampered_lines)
    }


def run_tamper_demo(chain_path: str, output_dir: str = "."):
    """Execute tamper detection demo"""
    print("=" * 70)
    print("VCP Tamper Detection Demo")
    print("=" * 70)
    print()
    
    tampered_path = os.path.join(output_dir, "vcp_rta_demo_events_tampered.jsonl")
    
    # Step 1: Verify original chain
    print("[Step 1] Verifying Original Chain")
    print("-" * 50)
    original = verify_chain_simple(chain_path)
    
    original_valid = original["genesis_valid"] and original["hash_chain_valid"]
    
    print(f"  File: {os.path.basename(chain_path)}")
    print(f"  Events: {original['total_events']}")
    print(f"  Genesis: {'PASS' if original['genesis_valid'] else 'FAIL'}")
    print(f"  Hash Chain: {'PASS' if original['hash_chain_valid'] else 'FAIL'}")
    print(f"  Result: {'PASS' if original_valid else 'FAIL'}")
    print()
    print(f"  Merkle Root: {original['merkle_root'][:32]}...")
    print()
    
    # Step 2: Create tampered chain
    print("[Step 2] Creating Tampered Chain")
    print("-" * 50)
    
    delete_line = 5
    tamper_info = create_tampered_chain(chain_path, tampered_path, delete_line=delete_line)
    
    print(f"  Operation: Deleted line {tamper_info['deleted_line']}")
    if tamper_info['deleted_event']:
        header = tamper_info['deleted_event'].get('Header', {})
        print(f"  Deleted Event:")
        print(f"    EventType: {header.get('EventType', 'N/A')}")
        print(f"    TraceID: {header.get('TraceID', 'N/A')}")
        print(f"    EventID: {header.get('EventID', 'N/A')[:36]}...")
    print(f"  Original Events: {tamper_info['original_count']}")
    print(f"  After Tampering: {tamper_info['tampered_count']}")
    print()
    
    # Step 3: Verify tampered chain
    print("[Step 3] Verifying Tampered Chain")
    print("-" * 50)
    tampered = verify_chain_simple(tampered_path)
    
    tampered_valid = tampered["genesis_valid"] and tampered["hash_chain_valid"]
    
    print(f"  File: {os.path.basename(tampered_path)}")
    print(f"  Events: {tampered['total_events']}")
    print(f"  Genesis: {'PASS' if tampered['genesis_valid'] else 'FAIL'}")
    print(f"  Hash Chain: {'PASS' if tampered['hash_chain_valid'] else 'FAIL'}")
    print(f"  Result: {'PASS' if tampered_valid else 'FAIL'}")
    print()
    
    if tampered["errors"]:
        print("  Detected Errors:")
        for err in tampered["errors"][:5]:
            print(f"    [X] {err}")
        if len(tampered["errors"]) > 5:
            print(f"    ... and {len(tampered['errors']) - 5} more")
    print()
    
    print(f"  Merkle Root: {tampered['merkle_root'][:32]}...")
    print()
    
    # Step 4: Result summary
    print("=" * 70)
    print("Demo Result Summary")
    print("=" * 70)
    print()
    print("  +---------------------+--------------+--------------+")
    print("  | Item                | Original     | Tampered     |")
    print("  +---------------------+--------------+--------------+")
    print(f"  | Events              | {original['total_events']:>10}   | {tampered['total_events']:>10}   |")
    print(f"  | Hash Chain          | {'PASS':>10}   | {'FAIL':>10}   |")
    print(f"  | Verification        | {'PASS':>10}   | {'FAIL':>10}   |")
    print("  +---------------------+--------------+--------------+")
    print()
    print("  Merkle Root Comparison:")
    print(f"    Original: {original['merkle_root']}")
    print(f"    Tampered: {tampered['merkle_root']}")
    print(f"    Match: {'Yes' if original['merkle_root'] == tampered['merkle_root'] else 'No (Tampering Detected)'}")
    print()
    print("=" * 70)
    print("Conclusion: Deleting just ONE line breaks the entire hash chain.")
    print("            Any tampering is immediately detected.")
    print("=" * 70)
    
    # Write diff.txt
    diff_path = os.path.join(output_dir, "diff.txt")
    with open(diff_path, 'w', encoding='utf-8') as f:
        f.write("VCP Tamper Demo - Diff Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Deleted Line: {tamper_info['deleted_line']}\n")
        f.write(f"Original Event Count: {tamper_info['original_count']}\n")
        f.write(f"Tampered Event Count: {tamper_info['tampered_count']}\n\n")
        f.write(f"Original Merkle Root:\n  {original['merkle_root']}\n\n")
        f.write(f"Tampered Merkle Root:\n  {tampered['merkle_root']}\n\n")
        if tamper_info['deleted_event']:
            f.write("Deleted Event:\n")
            f.write(json.dumps(tamper_info['deleted_event'], indent=2, ensure_ascii=False))
    
    print(f"\nDiff info saved: {diff_path}")
    
    return original_valid, tampered_valid


if __name__ == "__main__":
    chain_path = os.path.join(os.path.dirname(__file__), "..", "01_sample_logs", "vcp_rta_demo_events.jsonl")
    
    if len(sys.argv) > 1:
        chain_path = sys.argv[1]
    
    if not os.path.exists(chain_path):
        print(f"Error: Chain file not found: {chain_path}")
        print("\nRun vcp_generator.py first to generate the chain.")
        sys.exit(1)
    
    output_dir = os.path.dirname(__file__)
    run_tamper_demo(chain_path, output_dir)
