#!/usr/bin/env python3
"""VCP v1.1 chain verifier.

Spec version is fixed at v1.1. This program does not implement or claim
VCP v1.2.

Each check is one of:

- VALID: the check completed and matched
- INVALID: the check completed and did not match
- UNVERIFIABLE (検証不能): the check could not be completed

A missing expected Merkle root, trusted public key, or external anchor
proof is UNVERIFIABLE for that check. It is not reported as a pass.
The overall result is INVALID if any check is INVALID, otherwise
UNVERIFIABLE if any check is UNVERIFIABLE, otherwise VALID.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

SPEC_VERSION = "1.1"

VALID = "VALID"
INVALID = "INVALID"
UNVERIFIABLE = "UNVERIFIABLE"

EXIT_CODES = {
    VALID: 0,
    INVALID: 1,
    UNVERIFIABLE: 2,
}

CHECK_ORDER = [
    "spec_version",
    "event_hash",
    "sequence",
    "prev_hash",
    "security_schema",
    "policy",
    "signature",
    "merkle_root",
    "audit_path",
    "batch_bounds",
    "security_object_signature",
    "external_anchor",
]

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX_ANY = re.compile(r"^[0-9a-fA-F]+$")

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    ED25519_AVAILABLE = True
    _ED25519_IMPORT_ERROR = ""
except ImportError as exc:  # pragma: no cover - environment dependent
    InvalidSignature = Exception  # type: ignore
    Ed25519PublicKey = None  # type: ignore
    ED25519_AVAILABLE = False
    _ED25519_IMPORT_ERROR = str(exc)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _check(result: str, detail: str, **extra: Any) -> Dict[str, Any]:
    item: Dict[str, Any] = {
        "result": result,
        "detail": detail,
    }
    if result == UNVERIFIABLE:
        item["result_ja"] = "検証不能"
    item.update(extra)
    return item


def _combine(results: Sequence[str]) -> str:
    if any(result == INVALID for result in results):
        return INVALID
    if any(result == UNVERIFIABLE for result in results):
        return UNVERIFIABLE
    return VALID


def _summary(overall: str, checks: Dict[str, Dict[str, Any]]) -> str:
    failed = [name for name, check in checks.items() if check["result"] == INVALID]
    open_checks = [name for name, check in checks.items() if check["result"] == UNVERIFIABLE]
    if overall == INVALID:
        text = "At least one check failed: " + ", ".join(failed) + "."
        if open_checks:
            text += " Other checks could not be completed: " + ", ".join(open_checks) + "."
        return text
    if overall == UNVERIFIABLE:
        return (
            "No check failed, but at least one check could not be completed "
            "(検証不能): " + ", ".join(open_checks) + ". "
            "Unconfirmed checks are not treated as passes."
        )
    return (
        "Every check this verifier knows how to run completed and matched. "
        "This is not a certification that the data meets every VCP requirement."
    )


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def public_key_fingerprint(public_key: bytes) -> str:
    """SHA-256 fingerprint of the raw 32-byte Ed25519 public key."""
    return "sha256:" + hashlib.sha256(public_key).hexdigest()


def rfc6962_leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def compute_vcp11_merkle_root(event_hashes: Sequence[str]) -> Optional[str]:
    """Merkle root used by the VCP v1.1 evidence pack.

    Leaf = SHA-256(0x00 || raw 32-byte EventHash).
    Internal node = SHA-256(0x01 || left || right).
    An odd node is duplicated, matching the VCP v1.1 pseudocode and the
    published evidence root.

    This is not the strict RFC 6962 Merkle Tree Hash, which splits at the
    largest power of two less than the node count. See
    ``compute_rfc6962_strict_root``.
    """
    if not event_hashes:
        return None
    level = []
    for event_hash in event_hashes:
        if not _HEX64.match(event_hash or ""):
            return None
        level.append(rfc6962_leaf_hash(bytes.fromhex(event_hash)))
    while len(level) > 1:
        nxt: List[bytes] = []
        for index in range(0, len(level), 2):
            if index + 1 < len(level):
                nxt.append(rfc6962_node_hash(level[index], level[index + 1]))
            else:
                nxt.append(rfc6962_node_hash(level[index], level[index]))
        level = nxt
    return level[0].hex()


def compute_rfc6962_strict_root(event_hashes: Sequence[str]) -> Optional[str]:
    """Strict RFC 6962 §2.1 Merkle Tree Hash, for comparison only.

    Not used for the verdict. The published v1.1 evidence root does not
    match this construction when the leaf count is not a power of two.
    """
    if not event_hashes:
        return None
    leaves: List[bytes] = []
    for event_hash in event_hashes:
        if not _HEX64.match(event_hash or ""):
            return None
        leaves.append(rfc6962_leaf_hash(bytes.fromhex(event_hash)))

    def mth(nodes: Sequence[bytes]) -> bytes:
        count = len(nodes)
        if count == 1:
            return nodes[0]
        split = 1
        while split * 2 < count:
            split *= 2
        return rfc6962_node_hash(mth(nodes[:split]), mth(nodes[split:]))

    return mth(leaves).hex()


def event_content_hash(event: Dict[str, Any]) -> str:
    """Hash stored in this evidence pack's EventHash field.

    SHA-256 of ``json.dumps(Header, sort_keys=True)`` concatenated with
    ``json.dumps(Payload, sort_keys=True)`` (default separators). This
    matches the 40 published events. It is not a full RFC 8785 JSON
    Canonicalization Scheme implementation.
    """
    header = event.get("Header", {})
    payload = event.get("Payload", {})
    hash_input = json.dumps(header, sort_keys=True) + json.dumps(payload, sort_keys=True)
    return sha256_hex(hash_input)


def _event_id(event: Dict[str, Any], index: int) -> str:
    header = event.get("Header") or {}
    return str(header.get("EventID") or f"index-{index}")


def _sequence(event: Dict[str, Any]) -> Any:
    header = event.get("Header") or {}
    if "Sequence" in header:
        return header.get("Sequence")
    return header.get("SequenceNumber")


def _timestamp(event: Dict[str, Any]) -> Optional[str]:
    header = event.get("Header") or {}
    value = header.get("TimestampISO")
    return str(value) if value else None


def load_events(filepath: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    with open(filepath, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{filepath}:{line_number}: {exc}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"{filepath}:{line_number}: event is not a JSON object")
            events.append(item)
    return events


def load_json_object(filepath: str) -> Dict[str, Any]:
    with open(filepath, "r", encoding="utf-8") as handle:
        item = json.load(handle)
    if not isinstance(item, dict):
        raise ValueError(f"{filepath}: expected a JSON object")
    return item


def _b64decode(text: str) -> Optional[bytes]:
    compact = "".join(text.split())
    pad = "=" * ((4 - len(compact) % 4) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decoder(compact + pad)
        except Exception:
            continue
    return None


def parse_public_key_bytes(data: Any) -> bytes:
    """Accept a raw key, hex, base64, or a JSON object with PublicKey."""
    if isinstance(data, dict):
        material = data.get("PublicKey", data.get("public_key", data.get("x")))
        if not isinstance(material, str) or not material.strip():
            raise ValueError("public key JSON has no PublicKey field")
        text = material.strip()
    elif isinstance(data, str):
        text = data.strip()
    elif isinstance(data, (bytes, bytearray)):
        raw = bytes(data)
        if raw.startswith(b"{") or raw.startswith(b"-----"):
            return parse_public_key_bytes(raw.decode("utf-8"))
        if len(raw) == 32:
            return raw
        return parse_public_key_bytes(raw.decode("utf-8"))
    else:
        raise ValueError("unsupported public key type")

    if text.startswith("{"):
        return parse_public_key_bytes(json.loads(text))
    if _HEX64.match(text):
        return bytes.fromhex(text)
    decoded = _b64decode(text)
    if decoded is None or len(decoded) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes (hex or base64)")
    return decoded


def load_public_key(filepath: str) -> bytes:
    with open(filepath, "rb") as handle:
        raw = handle.read()
    return parse_public_key_bytes(raw)


def decode_signature(signature: str) -> Optional[bytes]:
    """Return a 64-byte Ed25519 signature, or None if the encoding is unusable.

    The evidence pack stores hex. The v1.0 signature example and the sample
    logger store standard base64. Only a detached 64-byte signature is accepted.
    """
    text = signature.strip()
    if _HEX_ANY.match(text) and len(text) % 2 == 0:
        raw = bytes.fromhex(text)
        if len(raw) == 64:
            return raw
    decoded = _b64decode(text)
    if decoded is not None and len(decoded) == 64:
        return decoded
    return None


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    if not ED25519_AVAILABLE:
        raise RuntimeError("cryptography is not installed")
    key = Ed25519PublicKey.from_public_bytes(public_key)
    try:
        key.verify(signature, message)
    except InvalidSignature:
        return False
    return True


def signature_message_candidates(digest_hex: str) -> List[Tuple[str, bytes]]:
    """Messages this verifier will accept for an event or root signature.

    The evidence pack signs the raw 32-byte digest. The v1.0 ``sign_event``
    example and ``examples/ai-trading-integration/vcp_logger.py`` sign the
    ASCII hex digest. Both are checked. A signature must match one of them
    under the trusted key; there is no third message.
    """
    candidates = [("raw_digest", bytes.fromhex(digest_hex))]
    candidates.append(("ascii_hex", digest_hex.lower().encode("ascii")))
    if digest_hex != digest_hex.lower():
        candidates.append(("ascii_hex_original_case", digest_hex.encode("ascii")))
    return candidates


def verify_digest_signature(
    public_key: bytes, signature_text: str, digest_hex: str
) -> Tuple[str, str]:
    """Return (VALID|INVALID|UNVERIFIABLE, encoding-or-reason)."""
    if not ED25519_AVAILABLE:
        return (
            UNVERIFIABLE,
            "Ed25519 verification is unimplemented in this environment "
            f"(cryptography import failed: {_ED25519_IMPORT_ERROR})",
        )
    if not _HEX64.match(digest_hex or ""):
        return INVALID, "digest is not a 32-byte hex value"
    signature = decode_signature(signature_text or "")
    if signature is None:
        return INVALID, "signature is missing or not a 64-byte Ed25519 signature"
    try:
        for name, message in signature_message_candidates(digest_hex):
            if ed25519_verify(public_key, signature, message):
                return VALID, name
    except Exception as exc:
        return UNVERIFIABLE, f"Ed25519 verification could not be completed: {exc}"
    return INVALID, "signature does not match the trusted key"


def expected_root_from_security_object(security_object: Dict[str, Any]) -> Optional[str]:
    direct = security_object.get("MerkleRoot")
    nested = (security_object.get("MerkleTree") or {}).get("Root")
    value = direct or nested
    if isinstance(value, str) and _HEX64.match(value):
        return value.lower()
    return None


def _declared_version(events: Sequence[Dict[str, Any]], security_object: Optional[Dict[str, Any]]) -> List[str]:
    found = []
    for event in events:
        security = event.get("Security") or {}
        header = event.get("Header") or {}
        for value in (security.get("Version"), header.get("VCPVersion")):
            if isinstance(value, str) and value not in found:
                found.append(value)
    if security_object:
        value = security_object.get("VCPVersion")
        if isinstance(value, str) and value not in found:
            found.append(value)
    return found


def check_spec_version(
    events: Sequence[Dict[str, Any]], security_object: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    versions = _declared_version(events, security_object)
    others = [version for version in versions if version != SPEC_VERSION]
    if others:
        return _check(
            UNVERIFIABLE,
            "This verifier implements VCP v1.1 only and does not claim support "
            f"for declared version(s): {', '.join(others)}. "
            "The checks below are v1.1 checks and are not a v1.2 verdict.",
            declared_versions=versions,
        )
    if not versions:
        return _check(
            UNVERIFIABLE,
            "No VCP version field was found on the events or security object. "
            "Checks below use v1.1 rules only.",
            declared_versions=[],
        )
    return _check(
        VALID,
        "Declared version is 1.1. This verifier does not claim v1.2 support.",
        declared_versions=versions,
    )


def check_event_hashes(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not events:
        return _check(UNVERIFIABLE, "No events were loaded, so event hashes were not checked.")
    invalid = 0
    unverifiable = 0
    examples: List[str] = []
    for index, event in enumerate(events):
        security = event.get("Security") or {}
        algo = str(security.get("HashAlgo") or security.get("HashAlgorithm") or "SHA256")
        normalized = algo.upper().replace("-", "").replace("_", "")
        event_id = _event_id(event, index)
        if normalized not in ("SHA256",):
            unverifiable += 1
            if len(examples) < 8:
                examples.append(f"{event_id}: hash algorithm {algo} is not implemented")
            continue
        stored = security.get("EventHash")
        if not isinstance(stored, str) or not stored:
            invalid += 1
            if len(examples) < 8:
                examples.append(f"{event_id}: EventHash is missing")
            continue
        computed = event_content_hash(event)
        if computed != stored:
            invalid += 1
            if len(examples) < 8:
                examples.append(
                    f"{event_id}: recomputed {computed[:16]}…, stored {stored[:16]}…"
                )
    if invalid:
        return _check(
            INVALID,
            f"{invalid} event hash(es) did not match Header+Payload; "
            f"{unverifiable} used an unimplemented hash algorithm.",
            invalid_count=invalid,
            unverifiable_count=unverifiable,
            valid_count=len(events) - invalid - unverifiable,
            examples=examples,
        )
    if unverifiable:
        return _check(
            UNVERIFIABLE,
            f"{unverifiable} event(s) use a hash algorithm other than SHA-256, "
            "which this verifier does not implement.",
            invalid_count=0,
            unverifiable_count=unverifiable,
            valid_count=len(events) - unverifiable,
            examples=examples,
        )
    return _check(
        VALID,
        f"All {len(events)} EventHash values match SHA-256 of sorted-key JSON "
        "Header concatenated with sorted-key JSON Payload. "
        "This is not a full RFC 8785 canonicalization.",
        invalid_count=0,
        unverifiable_count=0,
        valid_count=len(events),
        examples=[],
    )


def check_sequence(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not events:
        return _check(UNVERIFIABLE, "No events were loaded, so sequence was not checked.")
    examples: List[str] = []
    previous: Optional[int] = None
    for index, event in enumerate(events):
        event_id = _event_id(event, index)
        sequence = _sequence(event)
        if isinstance(sequence, bool) or not isinstance(sequence, int):
            examples.append(f"{event_id}: Sequence is missing or not an integer")
            continue
        if previous is not None and sequence != previous + 1:
            examples.append(
                f"{event_id}: sequence {sequence} at file position {index + 1}, "
                f"expected {previous + 1}"
            )
        previous = sequence
    if examples:
        return _check(
            INVALID,
            "Sequence numbers in this file are not contiguous. "
            + examples[0],
            examples=examples[:8],
            gap_count=len(examples),
        )
    first = _sequence(events[0])
    last = _sequence(events[-1])
    return _check(
        VALID,
        f"Sequence numbers in this file are contiguous from {first} to {last}. "
        "Contiguity inside the file does not by itself prove the batch is complete.",
        first_sequence=first,
        last_sequence=last,
        examples=[],
    )


def check_prev_hash(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not events:
        return _check(UNVERIFIABLE, "No events were loaded, so PrevHash was not checked.")
    mismatches: List[str] = []
    missing: List[str] = []
    previous_hash: Optional[str] = None
    for index, event in enumerate(events):
        security = event.get("Security") or {}
        event_id = _event_id(event, index)
        prev = security.get("PrevHash")
        if index == 0:
            if isinstance(prev, str) and prev and prev != "0" * 64 and previous_hash is None:
                missing.append(
                    f"{event_id}: first event PrevHash does not refer to an event in this file"
                )
        else:
            if not isinstance(prev, str) or not prev:
                missing.append(f"{event_id}: PrevHash not present")
            elif prev != previous_hash:
                mismatches.append(
                    f"{event_id}: PrevHash does not match the previous event's EventHash"
                )
        stored = security.get("EventHash")
        previous_hash = stored if isinstance(stored, str) else None
    if mismatches:
        return _check(
            INVALID,
            f"{len(mismatches)} PrevHash link(s) do not match the previous EventHash. "
            + mismatches[0],
            examples=(mismatches + missing)[:8],
            mismatch_count=len(mismatches),
            missing_count=len(missing),
        )
    if missing:
        return _check(
            UNVERIFIABLE,
            "PrevHash is optional in v1.1. "
            f"{len(missing)} link(s) were not present, so the hash chain was not confirmed. "
            + missing[0],
            examples=missing[:8],
            mismatch_count=0,
            missing_count=len(missing),
        )
    if len(events) == 1:
        detail = "Single event. No PrevHash link was required."
    else:
        detail = (
            f"PrevHash on events 2..{len(events)} matches the previous EventHash. "
            "The first event has no predecessor in this file."
        )
    return _check(VALID, detail, examples=[], mismatch_count=0, missing_count=0)


def check_security_schema(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not events:
        return _check(UNVERIFIABLE, "No events were loaded, so the Security schema was not checked.")
    required = [
        ("Version", str),
        ("EventHash", str),
        ("HashAlgo", str),
        ("Signature", str),
        ("SignAlgo", str),
        ("MerkleRoot", str),
        ("MerkleIndex", int),
        ("AnchorReference", str),
    ]
    examples: List[str] = []
    invalid = 0
    for index, event in enumerate(events):
        security = event.get("Security")
        event_id = _event_id(event, index)
        if not isinstance(security, dict):
            invalid += 1
            if len(examples) < 8:
                examples.append(f"{event_id}: Security object is missing")
            continue
        event_bad = False
        for field, field_type in required:
            if field not in security:
                event_bad = True
                if len(examples) < 8:
                    examples.append(f"{event_id}: missing Security.{field}")
            elif field_type is int:
                if isinstance(security[field], bool) or not isinstance(security[field], int):
                    event_bad = True
                    if len(examples) < 8:
                        examples.append(f"{event_id}: Security.{field} has the wrong type")
            elif not isinstance(security[field], field_type):
                event_bad = True
                if len(examples) < 8:
                    examples.append(f"{event_id}: Security.{field} has the wrong type")
        if event_bad:
            invalid += 1
    if invalid:
        return _check(
            INVALID,
            f"{invalid} event(s) do not match the v1.1 Security fields this verifier requires.",
            invalid_count=invalid,
            examples=examples,
        )
    return _check(
        VALID,
        f"All {len(events)} events include the v1.1 Security fields this verifier checks "
        "(Version, EventHash, HashAlgo, Signature, SignAlgo, MerkleRoot, MerkleIndex, "
        "AnchorReference). Field presence is not a signature or anchor confirmation.",
        invalid_count=0,
        examples=[],
    )


def check_policy(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not events:
        return _check(UNVERIFIABLE, "No events were loaded, so policy fields were not checked.")
    examples: List[str] = []
    invalid = 0
    for index, event in enumerate(events):
        event_id = _event_id(event, index)
        policy = event.get("PolicyIdentification")
        event_errors: List[str] = []
        if not isinstance(policy, dict) or not policy:
            event_errors.append("Missing PolicyIdentification")
        else:
            if "PolicyID" not in policy:
                event_errors.append("Missing PolicyIdentification.PolicyID")
            tier = policy.get("ConformanceTier")
            if "ConformanceTier" not in policy:
                event_errors.append("Missing PolicyIdentification.ConformanceTier")
            elif tier not in ("SILVER", "GOLD", "PLATINUM"):
                event_errors.append(f"Invalid ConformanceTier: {tier}")
            registration = policy.get("RegistrationPolicy") or {}
            if not isinstance(registration, dict) or "Issuer" not in registration:
                event_errors.append("Missing PolicyIdentification.RegistrationPolicy.Issuer")
            depth = policy.get("VerificationDepth")
            if not isinstance(depth, dict) or not depth:
                event_errors.append("Missing PolicyIdentification.VerificationDepth")
            else:
                for field in (
                    "HashChainValidation",
                    "MerkleProofRequired",
                    "ExternalAnchorRequired",
                ):
                    if field not in depth:
                        event_errors.append(
                            f"Missing PolicyIdentification.VerificationDepth.{field}"
                        )
        if event_errors:
            invalid += 1
            for err in event_errors:
                if len(examples) < 8:
                    examples.append(f"{event_id}: {err}")
    if invalid:
        return _check(
            INVALID,
            f"{invalid} event(s) failed the v1.1 policy field checks.",
            invalid_count=invalid,
            examples=examples,
        )
    return _check(
        VALID,
        f"All {len(events)} events include PolicyID, a known ConformanceTier, "
        "RegistrationPolicy.Issuer, and VerificationDepth flags. "
        "This does not confirm that those policies were followed.",
        invalid_count=0,
        examples=[],
    )


def check_signatures(
    events: Sequence[Dict[str, Any]],
    public_key: Optional[bytes],
    key_error: Optional[str],
) -> Dict[str, Any]:
    if not events:
        return _check(UNVERIFIABLE, "No events were loaded, so signatures were not checked.")
    if key_error:
        return _check(
            UNVERIFIABLE,
            "Trusted public key could not be loaded, so signatures were not checked: "
            + key_error,
            valid_count=0,
            invalid_count=0,
            unverifiable_count=len(events),
            examples=[],
        )
    if public_key is None:
        return _check(
            UNVERIFIABLE,
            "No trusted public key was supplied (--public-key). "
            "Event signatures were not checked and are not treated as valid.",
            valid_count=0,
            invalid_count=0,
            unverifiable_count=len(events),
            examples=[],
        )
    if len(public_key) != 32:
        return _check(
            UNVERIFIABLE,
            f"Trusted public key is {len(public_key)} bytes, not 32. Signatures were not checked.",
            valid_count=0,
            invalid_count=0,
            unverifiable_count=len(events),
            examples=[],
        )
    if not ED25519_AVAILABLE:
        return _check(
            UNVERIFIABLE,
            "Ed25519 verification is unimplemented because the cryptography package "
            f"is not available ({_ED25519_IMPORT_ERROR}). Signatures were not checked.",
            valid_count=0,
            invalid_count=0,
            unverifiable_count=len(events),
            examples=[],
        )

    valid = 0
    invalid = 0
    unverifiable = 0
    encodings: Dict[str, int] = {}
    examples: List[str] = []
    fingerprint = public_key_fingerprint(public_key)
    for index, event in enumerate(events):
        security = event.get("Security") or {}
        event_id = _event_id(event, index)
        algo = str(security.get("SignAlgo") or security.get("SignatureAlgorithm") or "ED25519")
        normalized = algo.upper().replace("-", "").replace("_", "")
        if normalized != "ED25519":
            unverifiable += 1
            if len(examples) < 8:
                examples.append(f"{event_id}: signature algorithm {algo} is not implemented")
            continue
        result, info = verify_digest_signature(
            public_key, str(security.get("Signature") or ""), str(security.get("EventHash") or "")
        )
        if result == VALID:
            valid += 1
            encodings[info] = encodings.get(info, 0) + 1
        elif result == UNVERIFIABLE:
            unverifiable += 1
            if len(examples) < 8:
                examples.append(f"{event_id}: {info}")
        else:
            invalid += 1
            if len(examples) < 8:
                examples.append(f"{event_id}: {info}")
    detail_counts = (
        f"{valid} verified, {invalid} invalid, {unverifiable} unverifiable, "
        f"using trusted key {fingerprint}."
    )
    if encodings:
        detail_counts += " Message encoding: " + ", ".join(
            f"{name}={count}" for name, count in sorted(encodings.items())
        ) + "."
    if invalid:
        result = INVALID
        detail = "One or more event signatures failed against the trusted key. " + detail_counts
    elif unverifiable:
        result = UNVERIFIABLE
        detail = "One or more event signatures could not be checked. " + detail_counts
    else:
        result = VALID
        detail = (
            "Every event signature verified as Ed25519 over that event's EventHash "
            "with the trusted key. " + detail_counts
        )
    return _check(
        result,
        detail,
        valid_count=valid,
        invalid_count=invalid,
        unverifiable_count=unverifiable,
        message_encodings=encodings,
        examples=examples,
        key_fingerprint=fingerprint,
    )


def check_merkle_root(
    events: Sequence[Dict[str, Any]],
    expected_root: Optional[str],
    root_conflict: Optional[str],
) -> Dict[str, Any]:
    hashes = [
        str((event.get("Security") or {}).get("EventHash") or "")
        for event in events
    ]
    computed = compute_vcp11_merkle_root(hashes) if events else None
    strict = compute_rfc6962_strict_root(hashes) if events else None
    extra = {
        "computed_root": computed,
        "rfc6962_strict_root": strict,
        "expected_root": expected_root,
        "algorithm": "vcp-1.1-duplicate-odd-node",
    }
    note = (
        "Computed with the VCP v1.1 tree (0x00 leaf prefix, 0x01 node prefix, "
        "odd node duplicated). Strict RFC 6962 §2.1 (power-of-two split) is "
        "reported separately and is not the verdict."
    )
    if root_conflict:
        return _check(INVALID, root_conflict + " " + note, **extra)
    if not expected_root:
        return _check(
            UNVERIFIABLE,
            "No expected Merkle root was supplied (no --expected-root and no root "
            "in --security-object). The root was computed but not compared, and "
            "is not a pass. " + note,
            **extra,
        )
    if computed is None:
        return _check(
            UNVERIFIABLE,
            "Merkle root could not be computed from the event hashes. " + note,
            **extra,
        )
    if computed == expected_root.lower():
        return _check(
            VALID,
            "Recomputed VCP v1.1 Merkle root matches the supplied expected root. " + note,
            **extra,
        )
    return _check(
        INVALID,
        "Recomputed VCP v1.1 Merkle root does not match the supplied expected root "
        f"(computed {computed}, expected {expected_root.lower()}). " + note,
        **extra,
    )


def _audit_path_reaches(event_hash: str, audit_path: Sequence[Dict[str, Any]], expected_root: str) -> bool:
    current = rfc6962_leaf_hash(bytes.fromhex(event_hash))
    for step in audit_path:
        if not isinstance(step, dict):
            return False
        sibling_hex = step.get("hash")
        position = step.get("position")
        if not isinstance(sibling_hex, str) or not _HEX64.match(sibling_hex):
            return False
        sibling = bytes.fromhex(sibling_hex)
        if position == "left":
            current = rfc6962_node_hash(sibling, current)
        elif position == "right":
            current = rfc6962_node_hash(current, sibling)
        else:
            return False
    return current.hex() == expected_root.lower()


def check_audit_paths(
    events: Sequence[Dict[str, Any]], expected_root: Optional[str]
) -> Dict[str, Any]:
    if not events:
        return _check(UNVERIFIABLE, "No events were loaded, so audit paths were not checked.")
    if not expected_root:
        return _check(
            UNVERIFIABLE,
            "No expected Merkle root was supplied, so audit paths were not accepted "
            "as inclusion proofs.",
            examples=[],
        )
    invalid: List[str] = []
    missing: List[str] = []
    for index, event in enumerate(events):
        security = event.get("Security") or {}
        event_id = _event_id(event, index)
        event_hash = str(security.get("EventHash") or "")
        path = security.get("AuditPath")
        merkle_index = security.get("MerkleIndex")
        if not isinstance(path, list) or not path:
            if len(events) == 1 and _HEX64.match(event_hash):
                leaf = rfc6962_leaf_hash(bytes.fromhex(event_hash)).hex()
                if leaf != expected_root.lower():
                    missing.append(f"{event_id}: no audit path for a multi-leaf root")
                continue
            missing.append(f"{event_id}: audit path not present")
            continue
        if not _HEX64.match(event_hash) or not _audit_path_reaches(event_hash, path, expected_root):
            invalid.append(f"{event_id}: audit path does not reach the expected root")
            continue
        if isinstance(merkle_index, bool) or not isinstance(merkle_index, int) or merkle_index != index:
            invalid.append(
                f"{event_id}: MerkleIndex {merkle_index} is not file position {index}"
            )
    if invalid:
        return _check(
            INVALID,
            f"{len(invalid)} audit path or MerkleIndex check(s) failed. " + invalid[0],
            examples=(invalid + missing)[:8],
            invalid_count=len(invalid),
            missing_count=len(missing),
        )
    if missing:
        return _check(
            UNVERIFIABLE,
            f"{len(missing)} event(s) have no audit path, so inclusion was not confirmed.",
            examples=missing[:8],
            invalid_count=0,
            missing_count=len(missing),
        )
    return _check(
        VALID,
        f"All {len(events)} stored audit paths reach the expected root, and each "
        "MerkleIndex matches the event's position in this file.",
        examples=[],
        invalid_count=0,
        missing_count=0,
    )


def check_batch_bounds(
    events: Sequence[Dict[str, Any]],
    security_object: Optional[Dict[str, Any]],
    security_error: Optional[str],
) -> Dict[str, Any]:
    if security_error:
        return _check(
            UNVERIFIABLE,
            "Security object could not be loaded, so published batch bounds were not checked: "
            + security_error,
        )
    if security_object is None:
        return _check(
            UNVERIFIABLE,
            "No security object was supplied, so EventCount and sequence bounds "
            "were not compared to a published batch. The file's own sequence "
            "contiguity is a separate check.",
        )
    problems: List[str] = []
    compared: List[str] = []
    if "EventCount" in security_object:
        published = security_object.get("EventCount")
        compared.append(f"EventCount={published}")
        if published != len(events):
            problems.append(
                f"security object EventCount is {published} but the file has {len(events)} events"
            )
    if events and "FirstSequence" in security_object:
        published = security_object.get("FirstSequence")
        actual = _sequence(events[0])
        compared.append(f"FirstSequence={published}")
        if published != actual:
            problems.append(
                f"security object FirstSequence is {published} but the first event sequence is {actual}"
            )
    if events and "LastSequence" in security_object:
        published = security_object.get("LastSequence")
        actual = _sequence(events[-1])
        compared.append(f"LastSequence={published}")
        if published != actual:
            problems.append(
                f"security object LastSequence is {published} but the last event sequence is {actual}"
            )
    if not compared:
        return _check(
            UNVERIFIABLE,
            "Security object has no EventCount, FirstSequence, or LastSequence to compare.",
        )
    if problems:
        return _check(
            INVALID,
            "Published batch bounds do not match this file. " + problems[0],
            examples=problems,
        )
    return _check(
        VALID,
        "Published batch bounds match this file (" + ", ".join(compared) + ").",
    )


def check_security_object_signature(
    security_object: Optional[Dict[str, Any]],
    public_key: Optional[bytes],
    security_error: Optional[str],
    key_error: Optional[str],
) -> Dict[str, Any]:
    if security_error:
        return _check(
            UNVERIFIABLE,
            "Security object could not be loaded, so its signature was not checked: "
            + security_error,
        )
    if security_object is None:
        return _check(
            UNVERIFIABLE,
            "No security object was supplied, so its signature was not checked.",
        )
    signature = security_object.get("Signature") or security_object.get("ObjectSignature")
    root = expected_root_from_security_object(security_object)
    if not isinstance(signature, str) or not signature.strip():
        return _check(
            UNVERIFIABLE,
            "Security object has no Signature, so the object was not authenticated.",
        )
    if root is None:
        return _check(
            UNVERIFIABLE,
            "Security object has no Merkle root, so its signature was not checked.",
        )
    if key_error or public_key is None:
        return _check(
            UNVERIFIABLE,
            "No usable trusted public key was supplied, so the security object "
            "signature was not checked.",
        )
    algo = str(security_object.get("SignAlgo") or "ED25519")
    normalized = algo.upper().replace("-", "").replace("_", "")
    if normalized != "ED25519":
        return _check(
            UNVERIFIABLE,
            f"Security object signature algorithm {algo} is not implemented.",
        )
    result, info = verify_digest_signature(public_key, signature, root)
    if result == VALID:
        return _check(
            VALID,
            "Security object signature verified as Ed25519 over the raw Merkle root "
            f"bytes ({info}) with the trusted key. "
            "This authenticates the published root. It is not an external anchor.",
            message_encoding=info,
        )
    if result == UNVERIFIABLE:
        return _check(UNVERIFIABLE, "Security object signature could not be checked: " + info)
    return _check(
        INVALID,
        "Security object signature does not verify over its Merkle root with the trusted key.",
    )


def _anchor_record(anchor: Dict[str, Any]) -> Dict[str, Any]:
    record = anchor.get("AnchorRecord")
    if isinstance(record, dict):
        return record
    return anchor


def _resolve_proof_path(
    anchor: Optional[Dict[str, Any]],
    anchor_path: Optional[str],
    ots_path: Optional[str],
) -> Tuple[Optional[str], Optional[str]]:
    """Return (path looked up, proof file name as declared)."""
    declared: Optional[str] = None
    if anchor:
        target = _anchor_record(anchor).get("AnchorTarget") or {}
        if isinstance(target, dict):
            proof = target.get("ProofFile") or target.get("Proof")
            if isinstance(proof, str) and proof and not proof.startswith("http"):
                declared = proof
    if ots_path:
        return ots_path, declared or os.path.basename(ots_path)
    candidates: List[str] = []
    if declared and anchor_path:
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(anchor_path)), declared))
    if declared:
        candidates.append(declared)
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate, declared
    if candidates:
        return candidates[0], declared
    return None, declared


def run_ots_verify(proof_path: str) -> Dict[str, Any]:
    """Run ``ots verify`` only when the caller has already found the proof file.

    Confirmation requires exit status 0 and the OpenTimestamps success text.
    Anything else is not reported as confirmed.
    """
    tool = shutil.which("ots")
    if not tool:
        return {
            "ran": False,
            "confirmed": False,
            "result": UNVERIFIABLE,
            "detail": "ots is not on PATH. The proof file was not confirmed.",
        }
    directory = os.path.dirname(os.path.abspath(proof_path)) or "."
    try:
        proc = subprocess.run(
            [tool, "verify", os.path.basename(proof_path)],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ran": True,
            "confirmed": False,
            "result": UNVERIFIABLE,
            "detail": f"ots verify could not be completed: {exc}",
        }
    output = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    if proc.returncode == 0 and "Success!" in output:
        return {
            "ran": True,
            "confirmed": True,
            "result": VALID,
            "detail": "ots verify reported success. " + output[:500],
        }
    if proc.returncode != 0 and re.search(
        r"pending|not enough|calendar|network|timed out|connection|temporary",
        output,
        re.IGNORECASE,
    ):
        return {
            "ran": True,
            "confirmed": False,
            "result": UNVERIFIABLE,
            "detail": "ots verify did not confirm the proof. " + (output[:500] or f"exit {proc.returncode}"),
        }
    if proc.returncode != 0:
        return {
            "ran": True,
            "confirmed": False,
            "result": INVALID,
            "detail": "ots verify rejected the proof. " + (output[:500] or f"exit {proc.returncode}"),
        }
    return {
        "ran": True,
        "confirmed": False,
        "result": UNVERIFIABLE,
        "detail": "ots verify exited 0 without a success attestation. Not confirmed. " + output[:500],
    }


def check_external_anchor(
    anchor: Optional[Dict[str, Any]],
    anchor_path: Optional[str],
    anchor_error: Optional[str],
    ots_path: Optional[str],
    expected_root: Optional[str],
    computed_root: Optional[str],
) -> Dict[str, Any]:
    if anchor_error:
        return _check(
            UNVERIFIABLE,
            "Anchor reference could not be loaded. External anchor was not confirmed: "
            + anchor_error,
            anchor_checked=False,
            anchor_confirmed=False,
            proof_present=False,
        )
    proof_path, declared_name = _resolve_proof_path(anchor, anchor_path, ots_path)
    proof_present = bool(proof_path and os.path.isfile(proof_path))
    claimed_root = None
    claimed_status = None
    provider = None
    if anchor:
        record = _anchor_record(anchor)
        raw_root = record.get("MerkleRoot")
        if isinstance(raw_root, str):
            claimed_root = raw_root.lower()
        target = record.get("AnchorTarget") or {}
        if isinstance(target, dict):
            claimed_status = target.get("Status")
            provider = target.get("Provider") or target.get("Identifier")
    looked_up = proof_path or declared_name
    base = {
        "anchor_checked": bool(anchor or ots_path),
        "anchor_confirmed": False,
        "proof_file": declared_name,
        "proof_path": proof_path,
        "proof_present": proof_present,
        "claimed_status": claimed_status,
        "claimed_provider": provider,
        "claimed_merkle_root": claimed_root,
    }
    if anchor is None and not ots_path:
        return _check(
            UNVERIFIABLE,
            "No anchor reference (--anchor) or OpenTimestamps proof (--ots) was supplied. "
            "External anchor confirmation was not performed.",
            **base,
        )
    compare_root = expected_root or computed_root
    if claimed_root and compare_root and claimed_root != compare_root.lower():
        return _check(
            INVALID,
            "Anchor record MerkleRoot does not match the "
            + ("expected root" if expected_root else "recomputed root")
            + ". The anchor was not confirmed.",
            **base,
        )
    if not proof_present:
        claim = ""
        if claimed_status:
            claim = (
                f" The anchor reference claims status {claimed_status}"
                + (f" via {provider}" if provider else "")
                + ". That claim was not used as confirmation."
            )
        where = declared_name or "the proof file"
        return _check(
            UNVERIFIABLE,
            f"External anchor proof {where} is not present, so the anchor was not confirmed."
            + claim,
            **base,
        )
    ots_result = run_ots_verify(proof_path or "")
    base["anchor_confirmed"] = bool(ots_result.get("confirmed"))
    base["ots_detail"] = ots_result.get("detail")
    result = ots_result["result"]
    return _check(result, ots_result["detail"], **base)


def _event_range(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if not events:
        return {
            "count": 0,
            "first_event_id": None,
            "last_event_id": None,
            "first_sequence": None,
            "last_sequence": None,
            "first_timestamp": None,
            "last_timestamp": None,
        }
    return {
        "count": len(events),
        "first_event_id": _event_id(events[0], 0),
        "last_event_id": _event_id(events[-1], len(events) - 1),
        "first_sequence": _sequence(events[0]),
        "last_sequence": _sequence(events[-1]),
        "first_timestamp": _timestamp(events[0]),
        "last_timestamp": _timestamp(events[-1]),
    }


def _unimplemented(anchor_check: Dict[str, Any]) -> List[str]:
    items = [
        "VCP v1.2 is not implemented. The spec version is fixed at v1.1.",
        "Signature algorithms other than Ed25519 are not implemented.",
        "Hash algorithms other than SHA-256 are not implemented.",
        "Full RFC 8785 JSON Canonicalization Scheme is not implemented. "
        "EventHash uses sorted-key json.dumps concatenation, which matches this evidence pack.",
        "Strict RFC 6962 §2.1 Merkle Tree Hash (largest power-of-two split) is not the "
        "tree used for the verdict. The verdict uses the VCP v1.1 duplicate-odd-node tree.",
    ]
    if not anchor_check.get("anchor_confirmed"):
        items.append(
            "External anchor confirmation (OpenTimestamps / Bitcoin) was not completed. "
            "A missing merkle_root.ots proof is not treated as confirmed, and this "
            "verifier does not synthesize an ots result."
        )
    return items


def build_report(
    events: Sequence[Dict[str, Any]],
    *,
    public_key: Optional[bytes] = None,
    public_key_path: Optional[str] = None,
    key_error: Optional[str] = None,
    expected_root: Optional[str] = None,
    root_conflict: Optional[str] = None,
    security_object: Optional[Dict[str, Any]] = None,
    security_object_path: Optional[str] = None,
    security_error: Optional[str] = None,
    anchor: Optional[Dict[str, Any]] = None,
    anchor_path: Optional[str] = None,
    anchor_error: Optional[str] = None,
    ots_path: Optional[str] = None,
    events_path: Optional[str] = None,
) -> Dict[str, Any]:
    if expected_root:
        expected_root = expected_root.lower()
    checks = {
        "spec_version": check_spec_version(events, security_object),
        "event_hash": check_event_hashes(events),
        "sequence": check_sequence(events),
        "prev_hash": check_prev_hash(events),
        "security_schema": check_security_schema(events),
        "policy": check_policy(events),
        "signature": check_signatures(events, public_key, key_error),
        "merkle_root": check_merkle_root(events, expected_root, root_conflict),
        "audit_path": check_audit_paths(events, expected_root),
        "batch_bounds": check_batch_bounds(events, security_object, security_error),
        "security_object_signature": check_security_object_signature(
            security_object, public_key, security_error, key_error
        ),
    }
    computed_root = checks["merkle_root"].get("computed_root")
    checks["external_anchor"] = check_external_anchor(
        anchor,
        anchor_path,
        anchor_error,
        ots_path,
        expected_root,
        computed_root,
    )
    overall = _combine([checks[name]["result"] for name in CHECK_ORDER])
    fingerprint = public_key_fingerprint(public_key) if public_key else None
    anchor_check = checks["external_anchor"]
    errors: List[str] = []
    for name in CHECK_ORDER:
        check = checks[name]
        if check["result"] == VALID:
            continue
        errors.append(f"{name}: {check['detail']}")
        for example in check.get("examples") or []:
            errors.append(f"{name}: {example}")
    report = {
        "spec_version": SPEC_VERSION,
        "v1_2_supported": False,
        "verifier": "vcp_verifier",
        "result": overall,
        "result_ja": "検証不能" if overall == UNVERIFIABLE else None,
        "exit_code": EXIT_CODES[overall],
        "summary": _summary(overall, checks),
        "basis": {
            "events_file": events_path,
            "security_object_file": security_object_path,
            "trusted_key_file": public_key_path,
            "trusted_key_fingerprint": fingerprint,
            "trusted_key_algorithm": "ED25519" if public_key else None,
            "trusted_public_key_hex": public_key.hex() if public_key else None,
            "expected_merkle_root": expected_root,
            "computed_merkle_root": computed_root,
            "merkle_algorithm": "vcp-1.1-duplicate-odd-node",
            "rfc6962_strict_root": checks["merkle_root"].get("rfc6962_strict_root"),
            "anchor_reference_file": anchor_path,
            "anchor_checked": bool(anchor_check.get("anchor_checked")),
            "anchor_confirmed": bool(anchor_check.get("anchor_confirmed")),
            "anchor_proof_file": anchor_check.get("proof_file"),
            "anchor_proof_present": bool(anchor_check.get("proof_present")),
            "anchor_claimed_status": anchor_check.get("claimed_status"),
            "event_range": _event_range(events),
        },
        "checks": checks,
        "unimplemented": _unimplemented(anchor_check),
        "errors": errors,
        "generated_at": _now(),
    }
    return report


def load_optional_json(path: Optional[str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    if not path:
        return None, None
    if not os.path.isfile(path):
        return None, f"file not found: {path}"
    try:
        return load_json_object(path), None
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return None, str(exc)


def load_optional_public_key(path: Optional[str]) -> Tuple[Optional[bytes], Optional[str]]:
    if not path:
        return None, None
    if not os.path.isfile(path):
        return None, f"file not found: {path}"
    try:
        return load_public_key(path), None
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return None, str(exc)


def verify_paths(
    events_path: str,
    *,
    security_object_path: Optional[str] = None,
    public_key_path: Optional[str] = None,
    anchor_path: Optional[str] = None,
    ots_path: Optional[str] = None,
    expected_root: Optional[str] = None,
) -> Dict[str, Any]:
    events = load_events(events_path)
    security_object, security_error = load_optional_json(security_object_path)
    public_key, key_error = load_optional_public_key(public_key_path)
    anchor, anchor_error = load_optional_json(anchor_path)
    object_root = (
        expected_root_from_security_object(security_object) if security_object else None
    )
    root_conflict = None
    chosen_root = expected_root.lower() if expected_root else object_root
    if expected_root and object_root and expected_root.lower() != object_root:
        root_conflict = (
            "The --expected-root value does not match Merkle root in the security object "
            f"({expected_root.lower()} vs {object_root})."
        )
        chosen_root = None
    return build_report(
        events,
        public_key=public_key,
        public_key_path=public_key_path,
        key_error=key_error,
        expected_root=chosen_root,
        root_conflict=root_conflict,
        security_object=security_object,
        security_object_path=security_object_path,
        security_error=security_error,
        anchor=anchor,
        anchor_path=anchor_path,
        anchor_error=anchor_error,
        ots_path=ots_path,
        events_path=events_path,
    )


def _error_report(message: str, events_path: Optional[str] = None) -> Dict[str, Any]:
    checks = {
        name: _check(UNVERIFIABLE, "Verification did not run: " + message)
        for name in CHECK_ORDER
    }
    return {
        "spec_version": SPEC_VERSION,
        "v1_2_supported": False,
        "verifier": "vcp_verifier",
        "result": UNVERIFIABLE,
        "result_ja": "検証不能",
        "exit_code": EXIT_CODES[UNVERIFIABLE],
        "summary": "Verification did not run: " + message,
        "basis": {
            "events_file": events_path,
            "security_object_file": None,
            "trusted_key_file": None,
            "trusted_key_fingerprint": None,
            "trusted_key_algorithm": None,
            "trusted_public_key_hex": None,
            "expected_merkle_root": None,
            "computed_merkle_root": None,
            "merkle_algorithm": "vcp-1.1-duplicate-odd-node",
            "rfc6962_strict_root": None,
            "anchor_reference_file": None,
            "anchor_checked": False,
            "anchor_confirmed": False,
            "anchor_proof_file": None,
            "anchor_proof_present": False,
            "anchor_claimed_status": None,
            "event_range": _event_range([]),
        },
        "checks": checks,
        "unimplemented": _unimplemented(checks["external_anchor"]),
        "errors": [message],
        "generated_at": _now(),
    }


def format_human(report: Dict[str, Any]) -> str:
    basis = report["basis"]
    event_range = basis["event_range"]
    lines = [
        "=" * 72,
        "VCP v1.1 verification report",
        "Spec version checked: 1.1 (fixed). v1.2 is not claimed.",
        f"Generated: {report['generated_at']}",
        "=" * 72,
        "",
        "This report describes only the checks that ran.",
        "It is not a statement of full specification compliance.",
        "",
        f"Overall: {report['result']}"
        + (" (検証不能)" if report["result"] == UNVERIFIABLE else ""),
        report["summary"],
        "",
        "Basis — what this run relied on",
        f"  Events file:              {basis.get('events_file') or '(none)'}",
        f"  Events judged:            {event_range.get('count')}",
        f"  First EventID:            {event_range.get('first_event_id')}",
        f"  Last EventID:             {event_range.get('last_event_id')}",
        f"  Sequence range:           {event_range.get('first_sequence')} .. {event_range.get('last_sequence')}",
        f"  Time range:               {event_range.get('first_timestamp')} .. {event_range.get('last_timestamp')}",
        f"  Trusted key file:         {basis.get('trusted_key_file') or '(none)'}",
        f"  Trusted key fingerprint:  {basis.get('trusted_key_fingerprint') or '(none)'}",
        f"  Expected Merkle root:     {basis.get('expected_merkle_root') or '(none)'}",
        f"  Computed Merkle root:     {basis.get('computed_merkle_root') or '(none)'}",
        f"  Merkle algorithm:         {basis.get('merkle_algorithm')}",
        f"  Strict RFC 6962 root:     {basis.get('rfc6962_strict_root') or '(not computed)'} (not the verdict)",
        f"  Security object:          {basis.get('security_object_file') or '(none)'}",
        f"  Anchor reference:         {basis.get('anchor_reference_file') or '(none)'}",
        f"  Anchor checked:           {'yes' if basis.get('anchor_checked') else 'no'}",
        f"  Anchor confirmed:         {'yes' if basis.get('anchor_confirmed') else 'no'}",
        f"  Anchor proof file:        {basis.get('anchor_proof_file') or '(none)'}"
        + (" (present)" if basis.get("anchor_proof_present") else " (not present)"),
        f"  Anchor claimed status:    {basis.get('anchor_claimed_status') or '(none)'}",
        "",
        "Checks",
    ]
    for name in CHECK_ORDER:
        check = report["checks"][name]
        label = check["result"]
        if check["result"] == UNVERIFIABLE:
            label += " (検証不能)"
        lines.append(f"  {name:<28} {label}")
        detail = check["detail"]
        lines.append(f"    {detail}")
    lines.append("")
    lines.append("Unimplemented")
    for item in report.get("unimplemented") or []:
        lines.append(f"  - {item}")
    lines.append("")
    if report.get("errors"):
        lines.append("Errors")
        shown = report["errors"][:20]
        for err in shown:
            lines.append(f"  - {err}")
        remaining = len(report["errors"]) - len(shown)
        if remaining > 0:
            lines.append(f"  - … {remaining} more")
        lines.append("")
    lines.append(
        f"Exit code: {report['exit_code']} "
        "(0 VALID, 1 INVALID, 2 UNVERIFIABLE)"
    )
    lines.append("=" * 72)
    lines.append("")
    return "\n".join(lines)


def emit_report(report: Dict[str, Any], args: argparse.Namespace) -> None:
    human = format_human(report)
    if getattr(args, "output", None):
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(human)
    if getattr(args, "json_output", None):
        with open(args.json_output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    if getattr(args, "json", False):
        json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(human)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a VCP v1.1 event chain. The spec version is fixed at v1.1. "
            "Each check is VALID, INVALID, or UNVERIFIABLE (検証不能). "
            "A missing expected root, trusted key, or anchor proof is UNVERIFIABLE, "
            "not a pass."
        )
    )
    parser.add_argument("events_file", help="JSONL file of VCP events")
    parser.add_argument(
        "-s",
        "--security-object",
        help="Security object JSON. Its Merkle root is the expected root.",
    )
    parser.add_argument(
        "-k",
        "--public-key",
        help="Trusted Ed25519 public key file (JSON with PublicKey, or raw hex/base64).",
    )
    parser.add_argument(
        "-a",
        "--anchor",
        help="Anchor reference JSON. Supplying this file does not confirm the external anchor.",
    )
    parser.add_argument(
        "--ots",
        help="OpenTimestamps proof file. Checked with `ots verify` only when the ots tool is installed.",
    )
    parser.add_argument(
        "--expected-root",
        help="Expected Merkle root (hex). If this disagrees with --security-object, the Merkle check is INVALID.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Write machine-readable JSON to stdout instead of the human report.",
    )
    parser.add_argument(
        "--json-output",
        help="Write machine-readable JSON to this file as well as the human report.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write the human-readable report to this file.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        report = verify_paths(
            args.events_file,
            security_object_path=args.security_object,
            public_key_path=args.public_key,
            anchor_path=args.anchor,
            ots_path=args.ots,
            expected_root=args.expected_root,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        report = _error_report(str(exc), args.events_file)
    emit_report(report, args)
    return int(report["exit_code"])


if __name__ == "__main__":
    sys.exit(main())
