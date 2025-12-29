# -*- coding: utf-8 -*-
"""
VCP Log Converter
=================
Convert raw trading logs to VCP v1.0 format

Usage:
    python log_converter.py <input.csv> <output.jsonl>

Input Format:
    CSV with columns: signal_id, datetime, ticket, direction, confidence, etc.

Output Format:
    VCP v1.0 JSONL (one event per line)
"""

import json
import hashlib
import csv
import os
import sys
from datetime import datetime, timezone, timedelta
from typing import Dict, List
import uuid

# --- VCP Constants ---
VCP_VERSION = "1.0"
VCP_TIER = "SILVER"
GENESIS_HASH = "0" * 64
HASH_ALGO = "SHA-256"
SIGN_ALGO = "ED25519"


def uuid7_from_time(ts: float) -> str:
    """Generate UUID v7-style time-based UUID"""
    ms = int(ts * 1000)
    ms_hex = format(ms, '012x')
    rand_hex = format(uuid.uuid4().int & ((1 << 74) - 1), '019x')
    return f"{ms_hex[:8]}-{ms_hex[8:12]}-7{rand_hex[:3]}-{format(0x8 | (int(rand_hex[3], 16) & 0x3), 'x')}{rand_hex[4:7]}-{rand_hex[7:19]}"


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
    """Calculate VCP event hash"""
    canonical_header = canonical_json(header)
    canonical_payload = canonical_json(payload)
    hash_input = canonical_header + canonical_payload + prev_hash.encode('utf-8')
    return hashlib.sha256(hash_input).hexdigest()


def hash_account_id(account_id: str) -> str:
    """Pseudonymize account ID"""
    return hashlib.sha256(account_id.encode()).hexdigest()[:12]


class VCPConverter:
    """Convert raw logs to VCP format"""
    
    def __init__(self, venue_id: str = "VENUE_DEMO", symbol: str = "USDJPY",
                 algo_id: str = "VCP-RTA", algo_version: str = "1.0.0"):
        self.venue_id = venue_id
        self.symbol = symbol
        self.algo_id = algo_id
        self.algo_version = algo_version
        self.account_hash = hash_account_id("DEMO_ACCOUNT")
        self.prev_hash = GENESIS_HASH
        self.events = []
    
    def create_header(self, event_type: str, timestamp: datetime, trace_id: str,
                      event_type_code: int) -> dict:
        """Create VCP-CORE header"""
        return {
            "EventID": uuid7_from_time(timestamp.timestamp()),
            "TraceID": trace_id,
            "Timestamp": int(timestamp.timestamp() * 1000),
            "TimestampPrecision": "MILLISECOND",
            "ClockSyncStatus": "BEST_EFFORT",
            "EventTypeCode": event_type_code,
            "EventType": event_type,
            "HashAlgo": HASH_ALGO,
            "VenueID": self.venue_id,
            "Symbol": self.symbol,
            "AccountID": self.account_hash,
            "VCPVersion": VCP_VERSION,
            "Tier": VCP_TIER
        }
    
    def add_event(self, header: dict, payload: dict) -> dict:
        """Add event to chain"""
        event_hash = compute_event_hash(header, payload, self.prev_hash)
        
        event = {
            "Header": header,
            "Payload": payload,
            "Security": {
                "EventHash": event_hash,
                "PrevHash": self.prev_hash,
                "SignAlgo": SIGN_ALGO,
                "Signature": None,
                "KeyID": f"{self.algo_id.lower()}-key-2025-001"
            }
        }
        
        self.events.append(event)
        self.prev_hash = event_hash
        return event
    
    def export(self, filepath: str):
        """Export to JSONL"""
        # Sort by timestamp
        sorted_events = sorted(self.events, key=lambda e: e["Header"]["Timestamp"])
        
        # Rebuild hash chain
        prev_hash = GENESIS_HASH
        for event in sorted_events:
            event["Security"]["PrevHash"] = prev_hash
            new_hash = compute_event_hash(event["Header"], event["Payload"], prev_hash)
            event["Security"]["EventHash"] = new_hash
            prev_hash = new_hash
        
        with open(filepath, 'w', encoding='utf-8') as f:
            for event in sorted_events:
                f.write(json.dumps(event, ensure_ascii=False) + '\n')
        
        print(f"[VCP] Exported {len(sorted_events)} events to {filepath}")
        return sorted_events


def convert_csv(input_path: str, output_path: str):
    """Convert CSV to VCP JSONL"""
    converter = VCPConverter()
    
    with open(input_path, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            # Parse timestamp
            dt_str = row.get('datetime', row.get('time', ''))
            if not dt_str:
                continue
            
            dt_str = dt_str.replace('T', ' ')
            if '.' in dt_str:
                timestamp = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
            else:
                timestamp = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
            timestamp = timestamp.replace(tzinfo=timezone(timedelta(hours=9)))
            
            trace_id = row.get('signal_id', row.get('trace_id', ''))
            event_type = row.get('event_type', 'SIG')
            
            # Create header
            event_codes = {"SIG": 1, "ORD": 2, "ACK": 3, "EXE": 4, "CLS": 9}
            header = converter.create_header(
                event_type, timestamp, trace_id, event_codes.get(event_type, 0)
            )
            
            # Create payload based on event type
            payload = {}
            
            if event_type == "SIG":
                payload["VCP_GOV"] = {
                    "AlgoID": converter.algo_id,
                    "AlgoVersion": converter.algo_version,
                    "DecisionType": "AI_CONSENSUS",
                    "ConsensusDirection": row.get('direction', 'NONE'),
                    "ConsensusScore": float(row.get('confidence', 0) or 0)
                }
            else:
                payload["VCP_TRADE"] = {
                    "OrderID": row.get('ticket', row.get('order_id', '')),
                    "Side": row.get('direction', row.get('side', '')),
                    "Price": row.get('price', '0'),
                    "Quantity": row.get('quantity', row.get('volume', '0.01'))
                }
            
            converter.add_event(header, payload)
    
    converter.export(output_path)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python log_converter.py <input.csv> <output.jsonl>")
        print()
        print("Example:")
        print("  python log_converter.py raw_signals.csv vcp_events.jsonl")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    
    if not os.path.exists(input_path):
        print(f"Error: Input file not found: {input_path}")
        sys.exit(1)
    
    convert_csv(input_path, output_path)
