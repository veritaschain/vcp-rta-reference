# -*- coding: utf-8 -*-
"""
VCP Evidence Pack Generator (Signed Version)
=============================================
Generate VCP v1.0 Silver Tier compliant event chains with Ed25519 signatures

Features:
- Real Ed25519 digital signatures
- RFC 8785 JCS canonicalization
- SHA-256 hash chain
- UUID v7 event IDs
"""

import json
import hashlib
import csv
import os
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple
import uuid

# Ed25519 signing
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

# --- VCP Constants ---
VCP_VERSION = "1.0"
VCP_TIER = "SILVER"
GENESIS_HASH = "0" * 64
HASH_ALGO = "SHA-256"
SIGN_ALGO = "ED25519"
VENUE_ID = "VENUE_DEMO"
MIC_CODE = "XDMO"
SYMBOL = "USDJPY"
ALGO_ID = "VCP-RTA"
ALGO_VERSION = "1.0.0"

# Event Type Codes
EVENT_TYPES = {
    "SIG": 1,
    "ORD": 2,
    "ACK": 3,
    "EXE": 4,
    "CLS": 9,
    "REJ": 6,
}

JST = timezone(timedelta(hours=9))


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
    """VCP Event Hash: SHA-256(canonical(header) + canonical(payload) + prev_hash)"""
    canonical_header = canonical_json(header)
    canonical_payload = canonical_json(payload)
    hash_input = canonical_header + canonical_payload + prev_hash.encode('utf-8')
    return hashlib.sha256(hash_input).hexdigest()


def hash_account_id(account_id: str) -> str:
    """Pseudonymize Account ID"""
    return hashlib.sha256(account_id.encode()).hexdigest()[:12]


def parse_jst_datetime(dt_str: str) -> datetime:
    """Parse JST datetime string"""
    dt_str = dt_str.replace('T', ' ')
    if '.' in dt_str:
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S.%f")
    else:
        dt = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
    return dt.replace(tzinfo=JST)


class VCPSigner:
    """Ed25519 Key Management and Signing"""
    
    def __init__(self, key_id: str = "vcp-rta-key-2025-001"):
        self.key_id = key_id
        self.signing_key = SigningKey.generate()
        self.verify_key = self.signing_key.verify_key
        
        # Export keys (hex encoded)
        self.private_key_hex = self.signing_key.encode(encoder=HexEncoder).decode()
        self.public_key_hex = self.verify_key.encode(encoder=HexEncoder).decode()
    
    def sign(self, message: bytes) -> str:
        """Sign message and return hex-encoded signature"""
        signed = self.signing_key.sign(message)
        # Return only the signature part (first 64 bytes), hex encoded
        return signed.signature.hex()
    
    def get_public_key_info(self) -> dict:
        """Return public key info for verification"""
        return {
            "KeyID": self.key_id,
            "Algorithm": "ED25519",
            "PublicKey": self.public_key_hex
        }


class VCPEventChain:
    """VCP Event Chain Generator with Ed25519 Signatures"""
    
    def __init__(self, account_id: str = "DEMO_ACCOUNT", signer: Optional[VCPSigner] = None):
        self.events: List[dict] = []
        self.prev_hash = GENESIS_HASH
        self.account_id_hash = hash_account_id(account_id)
        self.sequence = 0
        self.signer = signer or VCPSigner()
    
    def _create_header(self, event_type: str, timestamp: datetime, trace_id: str) -> dict:
        """Generate VCP-CORE Header"""
        ts_ms = int(timestamp.timestamp() * 1000)
        return {
            "EventID": uuid7_from_time(timestamp.timestamp()),
            "TraceID": trace_id,
            "Timestamp": ts_ms,
            "TimestampPrecision": "MILLISECOND",
            "ClockSyncStatus": "BEST_EFFORT",
            "EventTypeCode": EVENT_TYPES.get(event_type, 0),
            "EventType": event_type,
            "HashAlgo": HASH_ALGO,
            "VenueID": VENUE_ID,
            "MICCode": MIC_CODE,
            "Symbol": SYMBOL,
            "AccountID": self.account_id_hash,
            "VCPVersion": VCP_VERSION,
            "Tier": VCP_TIER
        }
    
    def _sign_event(self, event_hash: str) -> str:
        """Sign EventHash with Ed25519"""
        message = bytes.fromhex(event_hash)
        return self.signer.sign(message)
    
    def add_signal_event(self, signal_data: dict) -> dict:
        """Add SIG (Signal) Event"""
        trace_id = signal_data.get("signal_id", "")
        dt_str = signal_data.get("datetime", "")
        timestamp = parse_jst_datetime(dt_str) if dt_str else datetime.now(JST)
        
        header = self._create_header("SIG", timestamp, trace_id)
        
        ai_votes = {}
        for model in ["gemini", "gpt", "claude", "grok", "pplx"]:
            dir_key = f"{model}_dir"
            conf_key = f"{model}_conf"
            if dir_key in signal_data:
                ai_votes[model] = {
                    "direction": signal_data.get(dir_key, "NONE") or "NONE",
                    "confidence": float(signal_data.get(conf_key, 0) or 0)
                }
        
        payload = {
            "VCP_GOV": {
                "AlgoID": ALGO_ID,
                "AlgoVersion": ALGO_VERSION,
                "DecisionType": "AI_CONSENSUS",
                "AIModels": ai_votes,
                "ConsensusDirection": signal_data.get("final_direction", "NONE"),
                "ConsensusScore": float(signal_data.get("final_confidence", 0) or 0),
                "PromptHash": "",  # Intentionally empty for public release
            },
            "VCP_RISK": {
                "TPPips": "25",
                "SLPips": "15",
                "TTLMinutes": "30",
                "MaxSpreadPips": "2.0"
            }
        }
        
        event_hash = compute_event_hash(header, payload, self.prev_hash)
        signature = self._sign_event(event_hash)
        
        event = {
            "Header": header,
            "Payload": payload,
            "Security": {
                "EventHash": event_hash,
                "PrevHash": self.prev_hash,
                "SignAlgo": SIGN_ALGO,
                "Signature": signature,
                "KeyID": self.signer.key_id
            }
        }
        
        self.events.append(event)
        self.prev_hash = event_hash
        self.sequence += 1
        return event
    
    def add_order_event(self, ticket: int, side: str, price: float, quantity: float,
                        timestamp: datetime, trace_id: str) -> dict:
        """Add ORD (Order) Event"""
        header = self._create_header("ORD", timestamp, trace_id)
        
        payload = {
            "VCP_TRADE": {
                "OrderID": str(ticket),
                "BrokerOrderID": str(ticket),
                "Side": side.upper(),
                "OrderType": "MARKET",
                "Price": f"{price:.3f}",
                "Quantity": f"{quantity:.2f}",
                "TimeInForce": "IOC"
            }
        }
        
        event_hash = compute_event_hash(header, payload, self.prev_hash)
        signature = self._sign_event(event_hash)
        
        event = {
            "Header": header,
            "Payload": payload,
            "Security": {
                "EventHash": event_hash,
                "PrevHash": self.prev_hash,
                "SignAlgo": SIGN_ALGO,
                "Signature": signature,
                "KeyID": self.signer.key_id
            }
        }
        
        self.events.append(event)
        self.prev_hash = event_hash
        self.sequence += 1
        return event
    
    def add_ack_event(self, ticket: int, timestamp: datetime, trace_id: str) -> dict:
        """Add ACK (Acknowledgment) Event"""
        ack_time = timestamp + timedelta(milliseconds=50)
        header = self._create_header("ACK", ack_time, trace_id)
        
        payload = {
            "VCP_TRADE": {
                "OrderID": str(ticket),
                "BrokerOrderID": str(ticket),
                "AckStatus": "ACCEPTED",
                "VenueTimestamp": int(ack_time.timestamp() * 1000)
            }
        }
        
        event_hash = compute_event_hash(header, payload, self.prev_hash)
        signature = self._sign_event(event_hash)
        
        event = {
            "Header": header,
            "Payload": payload,
            "Security": {
                "EventHash": event_hash,
                "PrevHash": self.prev_hash,
                "SignAlgo": SIGN_ALGO,
                "Signature": signature,
                "KeyID": self.signer.key_id
            }
        }
        
        self.events.append(event)
        self.prev_hash = event_hash
        self.sequence += 1
        return event
    
    def add_execute_event(self, ticket: int, side: str, price: float, quantity: float,
                          timestamp: datetime, trace_id: str) -> dict:
        """Add EXE (Execution) Event"""
        exe_time = timestamp + timedelta(milliseconds=100)
        header = self._create_header("EXE", exe_time, trace_id)
        
        payload = {
            "VCP_TRADE": {
                "OrderID": str(ticket),
                "BrokerOrderID": str(ticket),
                "ExecutionID": f"EXE-{ticket}",
                "Side": side.upper(),
                "ExecutedPrice": f"{price:.3f}",
                "ExecutedQuantity": f"{quantity:.2f}",
                "ExecutionType": "TRADE",
                "LeavesQuantity": "0.00"
            }
        }
        
        event_hash = compute_event_hash(header, payload, self.prev_hash)
        signature = self._sign_event(event_hash)
        
        event = {
            "Header": header,
            "Payload": payload,
            "Security": {
                "EventHash": event_hash,
                "PrevHash": self.prev_hash,
                "SignAlgo": SIGN_ALGO,
                "Signature": signature,
                "KeyID": self.signer.key_id
            }
        }
        
        self.events.append(event)
        self.prev_hash = event_hash
        self.sequence += 1
        return event
    
    def add_close_event(self, ticket: int, side: str, price: float, quantity: float,
                        profit: float, timestamp: datetime, trace_id: str,
                        exit_reason: str = "TTL_EXPIRE") -> dict:
        """Add CLS (Close) Event"""
        header = self._create_header("CLS", timestamp, trace_id)
        
        payload = {
            "VCP_TRADE": {
                "OrderID": str(ticket),
                "BrokerOrderID": str(ticket),
                "Side": "SELL" if side.upper() == "BUY" else "BUY",
                "ClosePrice": f"{price:.3f}",
                "CloseQuantity": f"{quantity:.2f}",
                "RealizedPnL": f"{profit:.0f}",
                "Currency": "JPY"
            },
            "VCP_GOV": {
                "ExitReason": exit_reason,
                "AlgoID": ALGO_ID
            }
        }
        
        event_hash = compute_event_hash(header, payload, self.prev_hash)
        signature = self._sign_event(event_hash)
        
        event = {
            "Header": header,
            "Payload": payload,
            "Security": {
                "EventHash": event_hash,
                "PrevHash": self.prev_hash,
                "SignAlgo": SIGN_ALGO,
                "Signature": signature,
                "KeyID": self.signer.key_id
            }
        }
        
        self.events.append(event)
        self.prev_hash = event_hash
        self.sequence += 1
        return event
    
    def export_jsonl(self, filepath: str):
        """Export event chain to JSONL (sorted by timestamp, re-sign)"""
        sorted_events = sorted(self.events, key=lambda e: e["Header"]["Timestamp"])
        
        # Rebuild hash chain and re-sign after sorting
        prev_hash = GENESIS_HASH
        for event in sorted_events:
            event["Security"]["PrevHash"] = prev_hash
            new_hash = compute_event_hash(event["Header"], event["Payload"], prev_hash)
            event["Security"]["EventHash"] = new_hash
            event["Security"]["Signature"] = self._sign_event(new_hash)
            prev_hash = new_hash
        
        with open(filepath, 'w', encoding='utf-8') as f:
            for event in sorted_events:
                f.write(json.dumps(event, ensure_ascii=False) + '\n')
        
        self.events = sorted_events
        self.prev_hash = prev_hash
        
        print(f"[VCP] {len(sorted_events)} signed events exported: {filepath}")
    
    def get_merkle_root(self) -> str:
        """Calculate Merkle Root (RFC 6962)"""
        if not self.events:
            return GENESIS_HASH
        
        leaves = [e["Security"]["EventHash"] for e in self.events]
        
        def leaf_hash(h: str) -> str:
            return hashlib.sha256(b'\x00' + bytes.fromhex(h)).hexdigest()
        
        def internal_hash(left: str, right: str) -> str:
            return hashlib.sha256(b'\x01' + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()
        
        current = [leaf_hash(leaf) for leaf in leaves]
        
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    next_level.append(internal_hash(current[i], current[i+1]))
                else:
                    next_level.append(current[i])
            current = next_level
        
        return current[0]


def load_signals_csv(filepath: str) -> List[dict]:
    """Load signals CSV"""
    signals = []
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            signals.append(row)
    return signals


def generate_evidence_pack(signals_csv: str, output_dir: str, event_count: int = 30):
    """Generate Evidence Pack with Ed25519 signatures"""
    print("=" * 60)
    print("VCP Evidence Pack Generator (Signed)")
    print("=" * 60)
    
    signals = load_signals_csv(signals_csv)
    print(f"[DATA] Signals: {len(signals)} records")
    print(f"[GEN] Generating signed VCP chain from {min(event_count, len(signals))} signals")
    
    # Create signer
    signer = VCPSigner(key_id="vcp-rta-key-2025-001")
    print(f"[KEY] Generated Ed25519 keypair")
    print(f"[KEY] Public Key: {signer.public_key_hex[:32]}...")
    
    chain = VCPEventChain(account_id="DEMO_ACCOUNT_12345", signer=signer)
    
    event_stats = {"SIG": 0, "ORD": 0, "ACK": 0, "EXE": 0, "CLS": 0}
    
    for sig in signals[:event_count]:
        trace_id = sig.get('signal_id', '')
        ticket = int(sig.get('exec_ticket', 0) or 0)
        direction = sig.get('final_direction', 'NONE')
        
        if not ticket or direction == 'NONE':
            continue
        
        dt_str = sig.get('datetime', '')
        if not dt_str:
            continue
        
        entry_time = parse_jst_datetime(dt_str)
        side = direction.upper()
        
        # Synthesized prices (clearly documented as such)
        import random
        random.seed(ticket)
        price = 155.5 + random.random() * 1.5
        quantity = 0.01
        
        # Events
        chain.add_signal_event(sig)
        event_stats["SIG"] += 1
        
        chain.add_order_event(ticket, side, price, quantity, entry_time, trace_id)
        event_stats["ORD"] += 1
        
        chain.add_ack_event(ticket, entry_time, trace_id)
        event_stats["ACK"] += 1
        
        chain.add_execute_event(ticket, side, price, quantity, entry_time, trace_id)
        event_stats["EXE"] += 1
        
        exit_time = entry_time + timedelta(minutes=30)
        close_price = price + (random.random() - 0.5) * 0.5
        profit = (close_price - price) * 1000 if side == "BUY" else (price - close_price) * 1000
        exit_reason = "TP_HIT" if profit > 0 else "SL_HIT" if profit < 0 else "TTL_EXPIRE"
        chain.add_close_event(ticket, side, close_price, quantity, profit, exit_time, trace_id, exit_reason)
        event_stats["CLS"] += 1
    
    # Export
    output_file = os.path.join(output_dir, "01_sample_logs", "vcp_rta_demo_events.jsonl")
    chain.export_jsonl(output_file)
    
    merkle_root = chain.get_merkle_root()
    
    # Save public key
    pubkey_file = os.path.join(output_dir, "04_anchor", "public_key.json")
    with open(pubkey_file, 'w', encoding='utf-8') as f:
        json.dump(signer.get_public_key_info(), f, indent=2)
    print(f"[KEY] Public key saved: {pubkey_file}")
    
    print("\n[STATS] Event Statistics:")
    for etype, count in event_stats.items():
        print(f"  {etype}: {count}")
    print(f"  Total: {len(chain.events)}")
    print(f"\n[MERKLE] Root: {merkle_root}")
    
    return chain, merkle_root, event_stats, signer


if __name__ == "__main__":
    import sys
    
    signals_csv = "signals_with_ticket_and_models.csv"
    output_dir = "."
    
    if len(sys.argv) > 1:
        signals_csv = sys.argv[1]
    if len(sys.argv) > 2:
        output_dir = sys.argv[2]
    
    generate_evidence_pack(signals_csv, output_dir, event_count=30)
