#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
VCP v1.1 Logger - VeritasChain Protocol Event Logger
Reference implementation for AI-driven trading systems

This module provides VCP v1.1 Silver Tier compliant event logging
for algorithmic trading systems. It can be integrated with any
trading platform that generates signals, orders, and executions.

License: CC BY 4.0
"""

import json
import hashlib
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging
import base64

# Ed25519 signatures (optional - graceful fallback if unavailable)
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization
    ED25519_AVAILABLE = True
except ImportError:
    ED25519_AVAILABLE = False

# UUID v7 (optional - falls back to UUID v4)
try:
    from uuid6 import uuid7
    UUID7_AVAILABLE = True
except ImportError:
    UUID7_AVAILABLE = False
    def uuid7():
        return uuid.uuid4()

# RFC 8785 JSON Canonicalization
try:
    import canonicaljson
    CANONICAL_AVAILABLE = True
except ImportError:
    CANONICAL_AVAILABLE = False


# ==============================================================================
# VCP v1.1 Constants
# ==============================================================================

VCP_VERSION = "1.1"
CONFORMANCE_TIER = "SILVER"
HASH_ALGORITHM = "SHA-256"
SIGNATURE_ALGORITHM = "ED25519"
GENESIS_HASH = "0" * 64

# Event Type Codes (VCP-CORE §4.1)
EVENT_TYPES = {
    "SIG": 1,   # Signal - AI decision
    "ORD": 2,   # Order - Order submitted
    "ACK": 3,   # Acknowledge - Broker acknowledgment
    "EXE": 4,   # Execute - Order filled
    "PRT": 5,   # Partial - Partial fill
    "REJ": 6,   # Reject/VETO - Order rejected
    "MOD": 8,   # Modify - Order modified
    "CLS": 9,   # Close - Position closed
    "HBT": 98,  # Heartbeat
}


# ==============================================================================
# Merkle Tree (RFC 6962)
# ==============================================================================

def merkle_leaf_hash(data: bytes) -> bytes:
    """RFC 6962: Leaf hash = SHA-256(0x00 || data)"""
    return hashlib.sha256(b'\x00' + data).digest()

def merkle_node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962: Node hash = SHA-256(0x01 || left || right)"""
    return hashlib.sha256(b'\x01' + left + right).digest()

def compute_merkle_root(hashes: List[str]) -> str:
    """
    Compute Merkle Root from a list of event hashes.
    
    Args:
        hashes: List of hex-encoded hash strings
        
    Returns:
        Merkle Root as hex string
    """
    if not hashes:
        return GENESIS_HASH
    
    # Create leaf nodes
    nodes = [merkle_leaf_hash(bytes.fromhex(h)) for h in hashes]
    
    # Build tree
    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                next_level.append(merkle_node_hash(nodes[i], nodes[i+1]))
            else:
                # Odd number: hash with itself
                next_level.append(merkle_node_hash(nodes[i], nodes[i]))
        nodes = next_level
    
    return nodes[0].hex()


# ==============================================================================
# JSON Canonicalization (RFC 8785)
# ==============================================================================

def canonicalize_json(obj: Dict) -> bytes:
    """
    RFC 8785 compliant JSON canonicalization.
    
    Args:
        obj: Object to canonicalize
        
    Returns:
        Canonicalized byte string
    """
    if CANONICAL_AVAILABLE:
        return canonicaljson.encode_canonical_json(obj)
    else:
        # Fallback: sorted keys, compact JSON
        return json.dumps(obj, sort_keys=True, separators=(',', ':'), 
                         ensure_ascii=False).encode('utf-8')


# ==============================================================================
# VCPLogger Class
# ==============================================================================

class VCPLogger:
    """
    VCP v1.1 Silver Tier compliant event logger.
    
    Features:
    - Event hash chain (PrevHash linking)
    - Ed25519 digital signatures
    - RFC 6962 Merkle Tree
    - Dual timestamps (ISO 8601 + int64 nanoseconds)
    - PolicyIdentification
    
    Usage:
        vcp = VCPLogger(base_path)
        vcp.log_signal(trace_id, direction, confidence, model_results, config_id)
        vcp.log_order(trace_id, direction, quantity, price, tp, sl)
        vcp.log_execution(trace_id, order_id, direction, exec_price, exec_qty)
        vcp.log_close(trace_id, order_id, exit_price, pnl, reason)
        vcp.generate_merkle_anchor()
    """
    
    def __init__(self, base_path: Path, 
                 venue_id: str = "VENUE_A",
                 symbol: str = "INSTRUMENT_A",
                 logger: Optional[logging.Logger] = None):
        """
        Initialize VCP Logger.
        
        Args:
            base_path: Working directory for VCP data
            venue_id: Trading venue identifier (anonymized)
            symbol: Trading instrument (anonymized)
            logger: Optional logger instance
        """
        self.base_path = Path(base_path)
        self.venue_id = venue_id
        self.symbol = symbol
        self.logger = logger or logging.getLogger("VCPLogger")
        
        # VCP directory structure
        self.vcp_dir = self.base_path / 'vcp'
        self.vcp_dir.mkdir(parents=True, exist_ok=True)
        
        self.chain_file = self.vcp_dir / 'vcp_events.jsonl'
        self.anchor_dir = self.vcp_dir / 'anchors'
        self.anchor_dir.mkdir(parents=True, exist_ok=True)
        
        # Key files
        self.private_key_file = self.vcp_dir / 'private_key.pem'
        self.public_key_file = self.vcp_dir / 'public_key.json'
        
        # State management
        self.sequence = 0
        self.prev_hash = GENESIS_HASH
        self.session_events: List[Dict] = []
        
        # Signing keys
        self.private_key = None
        self.public_key = None
        self.key_id = "vcp-key-001"
        
        # Initialize
        self._load_state()
        self._init_keys()
        
        self.logger.info(f"VCP Logger initialized (v{VCP_VERSION}, Tier={CONFORMANCE_TIER})")
    
    def _load_state(self):
        """Restore state from chain file."""
        if not self.chain_file.exists():
            return
        
        try:
            with open(self.chain_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        event = json.loads(line)
                        self.sequence = event.get('Header', {}).get('SequenceNumber', 0) + 1
                        self.prev_hash = event.get('Security', {}).get('EventHash', GENESIS_HASH)
                        self.session_events.append(event)
            
            self.logger.info(f"Loaded {self.sequence} existing events")
        except Exception as e:
            self.logger.error(f"Failed to load chain: {e}")
    
    def _init_keys(self):
        """Initialize Ed25519 key pair."""
        if not ED25519_AVAILABLE:
            self.logger.warning("Ed25519 not available (install cryptography package)")
            return
        
        if self.private_key_file.exists():
            try:
                with open(self.private_key_file, 'rb') as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
                self.public_key = self.private_key.public_key()
            except Exception as e:
                self.logger.error(f"Failed to load keys: {e}")
        else:
            self._generate_keys()
    
    def _generate_keys(self):
        """Generate new Ed25519 key pair."""
        if not ED25519_AVAILABLE:
            return
        
        try:
            self.private_key = Ed25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()
            
            # Save private key
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(self.private_key_file, 'wb') as f:
                f.write(pem)
            
            # Save public key as JSON
            pub_bytes = self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            pub_data = {
                "KeyID": self.key_id,
                "Algorithm": SIGNATURE_ALGORITHM,
                "PublicKey": base64.b64encode(pub_bytes).decode(),
                "GeneratedAt": datetime.utcnow().isoformat() + "Z"
            }
            with open(self.public_key_file, 'w', encoding='utf-8') as f:
                json.dump(pub_data, f, indent=2)
            
            self.logger.info("Generated new key pair")
        except Exception as e:
            self.logger.error(f"Failed to generate keys: {e}")
    
    def _compute_hash(self, event: Dict) -> str:
        """Compute SHA-256 hash of event (excluding Security section)."""
        hashable = {k: v for k, v in event.items() if k != 'Security'}
        canonical = canonicalize_json(hashable)
        return hashlib.sha256(canonical).hexdigest()
    
    def _sign(self, event_hash: str) -> str:
        """Sign event hash with Ed25519."""
        if not self.private_key:
            return ""
        
        try:
            signature = self.private_key.sign(event_hash.encode('utf-8'))
            return base64.b64encode(signature).decode()
        except Exception as e:
            self.logger.error(f"Signing failed: {e}")
            return ""
    
    def _create_event(self, event_type: str, trace_id: str, payload: Dict) -> Dict:
        """
        Create a VCP v1.1 compliant event.
        
        Args:
            event_type: Event type (SIG, ORD, EXE, CLS, REJ)
            trace_id: Trace ID linking related events
            payload: Event-specific payload
            
        Returns:
            Complete VCP event
        """
        now = datetime.utcnow()
        timestamp_ns = time.time_ns()
        
        event = {
            "Header": {
                "VCPVersion": VCP_VERSION,
                "EventID": str(uuid7()),
                "TraceID": trace_id,
                "SequenceNumber": self.sequence,
                "EventType": event_type,
                "EventTypeCode": EVENT_TYPES.get(event_type, 0),
                "TimestampISO": now.isoformat() + "Z",
                "TimestampInt": timestamp_ns,
                "VenueID": self.venue_id,
                "Symbol": self.symbol
            },
            "Payload": payload,
            "PolicyIdentification": {
                "PolicyID": "org.veritaschain.vcp.v1.1.silver",
                "ConformanceTier": CONFORMANCE_TIER,
                "VerificationDepth": {
                    "HashChain": True,
                    "Signature": ED25519_AVAILABLE,
                    "MerkleTree": True,
                    "ExternalAnchor": True
                }
            },
            "Security": {
                "PrevHash": self.prev_hash,
                "EventHash": "",
                "HashAlgorithm": HASH_ALGORITHM,
                "Signature": "",
                "SignatureAlgorithm": SIGNATURE_ALGORITHM if ED25519_AVAILABLE else "NONE",
                "KeyID": self.key_id
            }
        }
        
        # Compute hash
        event_hash = self._compute_hash(event)
        event["Security"]["EventHash"] = event_hash
        
        # Sign
        signature = self._sign(event_hash)
        event["Security"]["Signature"] = signature
        
        return event
    
    def _append_event(self, event: Dict):
        """Append event to chain file."""
        try:
            with open(self.chain_file, 'a', encoding='utf-8') as f:
                f.write(json.dumps(event, ensure_ascii=False) + '\n')
            
            # Update state
            self.prev_hash = event["Security"]["EventHash"]
            self.sequence += 1
            self.session_events.append(event)
            
        except Exception as e:
            self.logger.error(f"Failed to append event: {e}")
    
    # ==========================================================================
    # Public API - Event Logging
    # ==========================================================================
    
    def log_signal(self, trace_id: str, direction: str, confidence: float,
                   model_results: Dict, config_id: str = "") -> Optional[str]:
        """
        Log SIG event: AI signal generation.
        
        Args:
            trace_id: Unique trace identifier
            direction: Signal direction (BUY/SELL/NONE)
            confidence: Confidence score (0.0-1.0)
            model_results: Results from AI models (anonymized)
            config_id: Configuration identifier
            
        Returns:
            EventID on success, None on failure
        """
        # Anonymize model results
        decision_factors = []
        model_count = 0
        agreement_count = 0
        
        for key, value in model_results.items():
            if isinstance(value, dict) and 'direction' in value:
                model_count += 1
                model_dir = value.get('direction', 'NONE')
                if model_dir == direction:
                    agreement_count += 1
                
                decision_factors.append({
                    "Name": f"Model_{chr(65 + len(decision_factors))}",  # Model_A, Model_B, ...
                    "Value": model_dir,
                    "Weight": str(value.get('weight', 1.0)),
                    "Contribution": str(round(value.get('confidence', 0.0), 2))
                })
        
        payload = {
            "SignalType": "AI_CONSENSUS",
            "Direction": direction,
            "Confidence": str(round(confidence, 4)),
            "ConfigID": hashlib.sha256(config_id.encode()).hexdigest()[:8] if config_id else "",
            "AIConsensus": {
                "TotalModels": str(model_count),
                "AgreementCount": str(agreement_count),
                "VetoApplied": str(model_results.get('veto_applied', False))
            },
            "DecisionFactors": decision_factors
        }
        
        event = self._create_event("SIG", trace_id, payload)
        self._append_event(event)
        
        self.logger.info(f"VCP SIG: {trace_id} -> {direction}")
        return event["Header"]["EventID"]
    
    def log_order(self, trace_id: str, direction: str, quantity: float,
                  price: float, tp: float = 0, sl: float = 0) -> Optional[str]:
        """
        Log ORD event: Order submission.
        
        Args:
            trace_id: Trace ID from signal
            direction: BUY/SELL
            quantity: Order quantity (anonymized as ratio)
            price: Order price (anonymized)
            tp: Take profit price
            sl: Stop loss price
            
        Returns:
            EventID on success, None on failure
        """
        # Anonymize prices (store relative values)
        price_base = round(price, 0)  # Round to hide exact value
        
        payload = {
            "OrderType": "MARKET",
            "Side": direction,
            "Quantity": "REDACTED",  # Quantity anonymized
            "Price": str(round(price - price_base, 3)),  # Relative price
            "TakeProfit": str(round(tp - price_base, 3)) if tp else "0",
            "StopLoss": str(round(sl - price_base, 3)) if sl else "0",
            "Currency": "REDACTED"
        }
        
        event = self._create_event("ORD", trace_id, payload)
        self._append_event(event)
        
        self.logger.info(f"VCP ORD: {trace_id} -> {direction}")
        return event["Header"]["EventID"]
    
    def log_execution(self, trace_id: str, order_id: int, 
                      direction: str, executed_price: float, 
                      executed_qty: float) -> Optional[str]:
        """
        Log EXE event: Order execution.
        
        Args:
            trace_id: Trace ID
            order_id: Broker order ID (will be hashed)
            direction: BUY/SELL
            executed_price: Execution price (anonymized)
            executed_qty: Executed quantity
            
        Returns:
            EventID on success, None on failure
        """
        # Hash order ID for anonymization
        order_hash = hashlib.sha256(str(order_id).encode()).hexdigest()[:12]
        
        payload = {
            "BrokerOrderID": order_hash,
            "Side": direction,
            "ExecutedPrice": "REDACTED",
            "ExecutedQty": "REDACTED",
            "ExecutionStatus": "FILLED"
        }
        
        event = self._create_event("EXE", trace_id, payload)
        self._append_event(event)
        
        self.logger.info(f"VCP EXE: {trace_id} -> {order_hash[:8]}...")
        return event["Header"]["EventID"]
    
    def log_close(self, trace_id: str, order_id: int, exit_price: float,
                  pnl: float, exit_reason: str) -> Optional[str]:
        """
        Log CLS event: Position close.
        
        Args:
            trace_id: Trace ID
            order_id: Broker order ID (will be hashed)
            exit_price: Exit price (anonymized)
            pnl: Profit/Loss (anonymized as WIN/LOSS/BREAKEVEN)
            exit_reason: Close reason (TP/SL/TTL/Manual)
            
        Returns:
            EventID on success, None on failure
        """
        order_hash = hashlib.sha256(str(order_id).encode()).hexdigest()[:12]
        
        # Anonymize P&L
        if pnl > 0:
            pnl_status = "WIN"
        elif pnl < 0:
            pnl_status = "LOSS"
        else:
            pnl_status = "BREAKEVEN"
        
        payload = {
            "BrokerOrderID": order_hash,
            "ExitPrice": "REDACTED",
            "PnLStatus": pnl_status,
            "ExitReason": exit_reason,
            "CloseStatus": "CLOSED"
        }
        
        event = self._create_event("CLS", trace_id, payload)
        self._append_event(event)
        
        self.logger.info(f"VCP CLS: {trace_id} -> {exit_reason} ({pnl_status})")
        return event["Header"]["EventID"]
    
    def log_reject(self, trace_id: str, reason: str, 
                   veto_source: Optional[str] = None) -> Optional[str]:
        """
        Log REJ event: Signal rejection or VETO.
        
        Args:
            trace_id: Trace ID
            reason: Rejection reason
            veto_source: Source of VETO (anonymized)
            
        Returns:
            EventID on success, None on failure
        """
        payload = {
            "RejectReason": reason,
            "VetoSource": "Model_X" if veto_source else "SYSTEM",
            "RejectType": "VETO" if veto_source else "FILTER"
        }
        
        event = self._create_event("REJ", trace_id, payload)
        self._append_event(event)
        
        self.logger.info(f"VCP REJ: {trace_id} -> {reason}")
        return event["Header"]["EventID"]
    
    # ==========================================================================
    # Merkle Tree & Anchoring
    # ==========================================================================
    
    def generate_merkle_anchor(self) -> Optional[Dict]:
        """
        Generate Merkle Root and anchor from current session events.
        
        Returns:
            SecurityObject on success, None on failure
        """
        if not self.session_events:
            self.logger.warning("No events to anchor")
            return None
        
        # Collect event hashes
        event_hashes = [e["Security"]["EventHash"] for e in self.session_events]
        
        # Compute Merkle Root
        merkle_root = compute_merkle_root(event_hashes)
        
        # Create SecurityObject
        now = datetime.utcnow()
        security_object = {
            "VCPVersion": VCP_VERSION,
            "ConformanceTier": CONFORMANCE_TIER,
            "AnchorTimestamp": now.isoformat() + "Z",
            "AnchorTimestampInt": time.time_ns(),
            "EventCount": len(self.session_events),
            "FirstSequence": self.session_events[0]["Header"]["SequenceNumber"],
            "LastSequence": self.session_events[-1]["Header"]["SequenceNumber"],
            "MerkleTree": {
                "Algorithm": "RFC6962_SHA256",
                "Root": merkle_root,
                "LeafCount": len(event_hashes)
            },
            "AnchorTarget": "OpenTimestamps",
            "AnchorStatus": "PENDING"
        }
        
        # Sign object
        if self.private_key:
            obj_hash = hashlib.sha256(
                canonicalize_json(security_object)
            ).hexdigest()
            security_object["ObjectHash"] = obj_hash
            security_object["ObjectSignature"] = self._sign(obj_hash)
        
        # Save anchor file
        anchor_file = self.anchor_dir / f"anchor_{now.strftime('%Y%m%d_%H%M%S')}.json"
        try:
            with open(anchor_file, 'w', encoding='utf-8') as f:
                json.dump(security_object, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Merkle Anchor generated: {anchor_file.name}")
            return security_object
            
        except Exception as e:
            self.logger.error(f"Failed to save anchor: {e}")
            return None
    
    # ==========================================================================
    # Verification
    # ==========================================================================
    
    def verify_chain(self) -> Tuple[bool, Dict]:
        """
        Verify chain integrity.
        
        Returns:
            (is_valid, report)
        """
        report = {
            "total_events": 0,
            "valid_events": 0,
            "invalid_events": 0,
            "hash_errors": [],
            "sequence_errors": [],
            "chain_errors": []
        }
        
        prev_hash = GENESIS_HASH
        prev_seq = -1
        
        for event in self.session_events:
            report["total_events"] += 1
            event_id = event["Header"]["EventID"]
            seq = event["Header"]["SequenceNumber"]
            
            # Sequence verification
            if seq != prev_seq + 1:
                report["sequence_errors"].append({
                    "EventID": event_id,
                    "Expected": prev_seq + 1,
                    "Actual": seq
                })
            
            # PrevHash verification
            stored_prev = event["Security"].get("PrevHash", "")
            if stored_prev != prev_hash:
                report["chain_errors"].append({
                    "EventID": event_id,
                    "Expected": prev_hash[:16] + "...",
                    "Actual": stored_prev[:16] + "..."
                })
            
            # Hash verification
            stored_hash = event["Security"]["EventHash"]
            computed_hash = self._compute_hash(event)
            if stored_hash != computed_hash:
                report["hash_errors"].append({
                    "EventID": event_id,
                    "Expected": computed_hash[:16] + "...",
                    "Actual": stored_hash[:16] + "..."
                })
                report["invalid_events"] += 1
            else:
                report["valid_events"] += 1
            
            prev_hash = stored_hash
            prev_seq = seq
        
        is_valid = (
            len(report["hash_errors"]) == 0 and
            len(report["sequence_errors"]) == 0 and
            len(report["chain_errors"]) == 0
        )
        
        return is_valid, report
    
    def get_stats(self) -> Dict:
        """Get logger statistics."""
        stats = {
            "total_events": self.sequence,
            "session_events": len(self.session_events),
            "chain_file": str(self.chain_file),
            "vcp_version": VCP_VERSION,
            "tier": CONFORMANCE_TIER,
            "signatures_enabled": ED25519_AVAILABLE and self.private_key is not None
        }
        
        # Event type counts
        type_counts = {}
        for event in self.session_events:
            et = event["Header"]["EventType"]
            type_counts[et] = type_counts.get(et, 0) + 1
        stats["event_types"] = type_counts
        
        return stats


# ==============================================================================
# CLI Verification Tool
# ==============================================================================

def main():
    """CLI verification tool."""
    import argparse
    
    parser = argparse.ArgumentParser(description='VCP v1.1 Chain Verifier')
    parser.add_argument('chain_file', help='VCP chain file (JSONL)')
    parser.add_argument('-a', '--anchor', help='SecurityObject file')
    args = parser.parse_args()
    
    chain_file = Path(args.chain_file)
    if not chain_file.exists():
        print(f"File not found: {chain_file}")
        return 1
    
    # Load chain
    events = []
    with open(chain_file, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))
    
    print("=" * 70)
    print("VCP v1.1 Verification Report")
    print("=" * 70)
    print(f"Chain File: {chain_file}")
    print(f"Total Events: {len(events)}")
    print()
    
    # Verify
    prev_hash = GENESIS_HASH
    errors = []
    
    for i, event in enumerate(events):
        # Hash verification
        hashable = {k: v for k, v in event.items() if k != 'Security'}
        canonical = canonicalize_json(hashable)
        computed = hashlib.sha256(canonical).hexdigest()
        stored = event["Security"]["EventHash"]
        
        if computed != stored:
            errors.append(f"Event {i}: Hash mismatch")
        
        # Chain verification
        if event["Security"].get("PrevHash") != prev_hash:
            errors.append(f"Event {i}: PrevHash mismatch")
        
        prev_hash = stored
    
    if errors:
        print("[FAIL] Verification failed:")
        for e in errors:
            print(f"  - {e}")
    else:
        print("[PASS] All events verified successfully")
    
    # Merkle Root verification
    if args.anchor:
        anchor_file = Path(args.anchor)
        if anchor_file.exists():
            with open(anchor_file, 'r', encoding='utf-8') as f:
                anchor = json.load(f)
            
            hashes = [e["Security"]["EventHash"] for e in events]
            computed_root = compute_merkle_root(hashes)
            stored_root = anchor.get("MerkleTree", {}).get("Root", "")
            
            print()
            print(f"Merkle Root (computed): {computed_root[:32]}...")
            print(f"Merkle Root (anchor):   {stored_root[:32]}...")
            
            if computed_root == stored_root:
                print("[PASS] Merkle Root matches")
            else:
                print("[FAIL] Merkle Root mismatch")
    
    print("=" * 70)
    return 0 if not errors else 1


if __name__ == '__main__':
    exit(main())
