#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
VCP v1.1 PoC Demo - Reference Implementation Demo

This script demonstrates VCP v1.1 Silver Tier compliance
for AI-driven trading systems. All identifying information
is anonymized for public demonstration.

Usage:
    python vcp_poc_demo.py

Output:
    - vcp_demo/vcp/vcp_events.jsonl  (Event chain)
    - vcp_demo/vcp/anchors/          (Merkle anchors)
    - vcp_demo/vcp/public_key.json   (Public key)

License: CC BY 4.0
"""

import sys
import json
import time
import random
import hashlib
from pathlib import Path
from datetime import datetime

try:
    from vcp_logger import VCPLogger, compute_merkle_root, GENESIS_HASH
except ImportError:
    print("Error: vcp_logger.py not found")
    print("Please ensure vcp_logger.py is in the same directory")
    sys.exit(1)


def generate_trace_id() -> str:
    """Generate anonymized trace ID."""
    now = datetime.utcnow()
    random_suffix = hashlib.sha256(str(random.random()).encode()).hexdigest()[:8]
    return f"trace_{now.strftime('%Y%m%d_%H%M%S')}_{random_suffix}"


def simulate_trade_lifecycle(vcp: VCPLogger, trade_num: int):
    """
    Simulate a complete trade lifecycle: SIG -> ORD -> EXE -> CLS
    """
    trace_id = generate_trace_id()
    direction = random.choice(['BUY', 'SELL'])
    
    print(f"\n{'='*60}")
    print(f"Trade #{trade_num}: {trace_id}")
    print('='*60)
    
    # 1. SIG - AI Signal Generation
    confidence = round(random.uniform(0.70, 0.95), 2)
    
    # Anonymized model results (Model_A, Model_B, etc.)
    model_results = {
        'model_a': {'direction': direction, 'confidence': random.uniform(0.6, 0.9), 'weight': 2.0},
        'model_b': {'direction': direction, 'confidence': random.uniform(0.6, 0.9), 'weight': 2.0},
        'model_c': {'direction': direction, 'confidence': random.uniform(0.6, 0.9), 'weight': 2.0},
        'model_d': {'direction': random.choice([direction, 'NONE']), 'confidence': random.uniform(0.4, 0.7), 'weight': 1.0},
        'veto_applied': False
    }
    
    vcp.log_signal(trace_id, direction, confidence, model_results, "config_xxx")
    time.sleep(0.05)
    
    # 2. ORD - Order Submission
    # Prices are anonymized (relative values only)
    base_price = 100.0 + random.uniform(-5, 5)
    tp_offset = 0.25 if direction == 'BUY' else -0.25
    sl_offset = -0.15 if direction == 'BUY' else 0.15
    
    vcp.log_order(
        trace_id, 
        direction, 
        quantity=0.0,  # Anonymized
        price=base_price,
        tp=base_price + tp_offset,
        sl=base_price + sl_offset
    )
    time.sleep(0.05)
    
    # 3. EXE - Execution
    order_id = random.randint(10000000, 99999999)
    executed_price = base_price + random.uniform(-0.01, 0.01)
    
    vcp.log_execution(trace_id, order_id, direction, executed_price, 0.0)
    time.sleep(0.05)
    
    # 4. CLS - Position Close
    outcome = random.choice(['TP', 'SL', 'TIMEOUT'])
    
    if outcome == 'TP':
        pnl = abs(tp_offset) * 100  # Positive
    elif outcome == 'SL':
        pnl = -abs(sl_offset) * 100  # Negative
    else:
        pnl = random.uniform(-10, 10)  # Variable
    
    exit_price = base_price + random.uniform(-0.2, 0.2)
    vcp.log_close(trace_id, order_id, exit_price, pnl, outcome)
    
    pnl_status = "WIN" if pnl > 0 else ("LOSS" if pnl < 0 else "BREAKEVEN")
    print(f"   Result: {outcome} ({pnl_status})")
    
    return trace_id


def simulate_veto_scenario(vcp: VCPLogger, trade_num: int):
    """Simulate a VETO rejection scenario."""
    trace_id = generate_trace_id()
    direction = random.choice(['BUY', 'SELL'])
    
    print(f"\n{'='*60}")
    print(f"Trade #{trade_num} (VETO): {trace_id}")
    print('='*60)
    
    # Signal with VETO
    confidence = round(random.uniform(0.65, 0.80), 2)
    model_results = {
        'model_a': {'direction': direction, 'confidence': 0.7, 'weight': 2.0},
        'model_b': {'direction': direction, 'confidence': 0.65, 'weight': 2.0, 'veto': True},
        'model_c': {'direction': direction, 'confidence': 0.6, 'weight': 2.0},
        'veto_applied': True
    }
    
    vcp.log_signal(trace_id, direction, confidence, model_results, "config_xxx")
    time.sleep(0.05)
    
    # Rejection due to VETO
    vcp.log_reject(trace_id, "Risk threshold exceeded", veto_source="model_b")
    
    print(f"   Result: VETO (Risk threshold)")
    return trace_id


def main():
    """Main execution."""
    print("""
+======================================================================+
|           VCP v1.1 PoC Demonstration                                 |
|                                                                      |
|  This demo simulates VCP event logging for AI-driven trading.        |
|  All identifying information is anonymized.                          |
+======================================================================+
""")
    
    # Demo directory
    demo_dir = Path('./vcp_demo')
    demo_dir.mkdir(exist_ok=True)
    
    # Initialize VCP Logger with anonymized venue/symbol
    print("Initializing VCP Logger...")
    vcp = VCPLogger(
        demo_dir,
        venue_id="VENUE_A",
        symbol="INSTRUMENT_A"
    )
    
    # Display initial state
    stats = vcp.get_stats()
    print(f"\nInitial State:")
    print(f"   VCP Version: {stats['vcp_version']}")
    print(f"   Tier: {stats['tier']}")
    print(f"   Signatures: {'Enabled' if stats['signatures_enabled'] else 'Disabled'}")
    print(f"   Existing Events: {stats['total_events']}")
    
    # Simulate trades
    print("\n" + "="*60)
    print("Simulating Trade Lifecycle Events...")
    print("="*60)
    
    # Normal trades
    for i in range(1, 6):
        simulate_trade_lifecycle(vcp, i)
        time.sleep(0.1)
    
    # VETO scenarios
    for i in range(6, 8):
        simulate_veto_scenario(vcp, i)
        time.sleep(0.1)
    
    # More normal trades
    for i in range(8, 11):
        simulate_trade_lifecycle(vcp, i)
        time.sleep(0.1)
    
    # Verify chain
    print("\n" + "="*60)
    print("Verifying Event Chain...")
    print("="*60)
    
    is_valid, report = vcp.verify_chain()
    
    print(f"\n   Total Events: {report['total_events']}")
    print(f"   Valid Events: {report['valid_events']}")
    print(f"   Invalid Events: {report['invalid_events']}")
    print(f"   Hash Errors: {len(report['hash_errors'])}")
    print(f"   Sequence Errors: {len(report['sequence_errors'])}")
    print(f"   Chain Errors: {len(report['chain_errors'])}")
    print(f"\n   Overall: {'VALID' if is_valid else 'INVALID'}")
    
    # Generate Merkle Anchor
    print("\n" + "="*60)
    print("Generating Merkle Anchor...")
    print("="*60)
    
    anchor = vcp.generate_merkle_anchor()
    if anchor:
        print(f"\n   Merkle Root: {anchor['MerkleTree']['Root'][:32]}...")
        print(f"   Event Count: {anchor['EventCount']}")
        print(f"   Anchor Status: {anchor['AnchorStatus']}")
    
    # Final statistics
    stats = vcp.get_stats()
    print("\n" + "="*60)
    print("Final Statistics")
    print("="*60)
    print(f"\n   Total Events: {stats['total_events']}")
    print(f"   Event Types: {json.dumps(stats['event_types'], indent=6)}")
    
    # Output files
    print("\n" + "="*60)
    print("Output Files")
    print("="*60)
    print(f"\n   Chain File: {demo_dir / 'vcp' / 'vcp_events.jsonl'}")
    print(f"   Public Key: {demo_dir / 'vcp' / 'public_key.json'}")
    print(f"   Anchors: {demo_dir / 'vcp' / 'anchors' / '*.json'}")
    
    # Verification commands
    print("\n" + "="*60)
    print("Verification Commands")
    print("="*60)
    print("""
   # Verify chain integrity
   python vcp_logger.py vcp_demo/vcp/vcp_events.jsonl

   # Verify with anchor
   python vcp_logger.py vcp_demo/vcp/vcp_events.jsonl -a vcp_demo/vcp/anchors/anchor_*.json
""")
    
    print("\nPoC Demo Complete!")
    print("The generated events demonstrate VCP v1.1 Silver Tier compliance.")
    print()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
