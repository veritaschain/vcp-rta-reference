#!/usr/bin/env python3
"""Offline verifier for this repository's legacy VCP v1.1 evidence format.

Not a VCP/VAP conformance verifier. The historical JSON/hash and duplicate-odd
Merkle construction are preserved, not relabelled RFC 8785/RFC 6962 compliant.
An unavailable check never passes. Evidence files do not supply trusted keys.
See INPUT_LIMITS.md for local file and JSON resource limits.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import math
import os
import re
import stat
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # Non-cryptographic checks can still run.
    InvalidSignature = None
    Ed25519PublicKey = None

VALID = "VALID"
INVALID = "INVALID"
INDETERMINATE = "INDETERMINATE"
EXIT_CODES = {VALID: 0, INVALID: 1, INDETERMINATE: 2}
HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")
MISSING = object()
# Local resource policy, not protocol/schema limits. Never truncate input.
MAX_EVENT_FILE_BYTES = 32 * 1024 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_KEY_FILE_BYTES = 64 * 1024
MAX_EVENT_COUNT = 100000
MAX_JSON_DEPTH = 64
ExternalVerifier = Callable[[str, Dict[str, Any]], Dict[str, str]]


def check(status: str, reason: str) -> Dict[str, str]:
    if not isinstance(status, str) or status not in EXIT_CODES or not isinstance(reason, str) or not reason:
        raise ValueError("A check needs a known status and a nonempty reason")
    return {"status": status, "reason": reason}


def combine(checks: List[Dict[str, str]]) -> Dict[str, str]:
    """Empty or malformed result sets are not successful verification."""
    if not checks:
        return check(INDETERMINATE, "NO_CHECKS")
    malformed = any(not isinstance(c, dict) or not isinstance(c.get("status"), str)
                    or c.get("status") not in EXIT_CODES
                    or not isinstance(c.get("reason"), str) or not c["reason"] for c in checks)
    statuses = [c.get("status") for c in checks if isinstance(c, dict)]
    if INVALID in statuses:
        return check(INVALID, "DEMONSTRATED_MISMATCH")
    if malformed or INDETERMINATE in statuses:
        return check(INDETERMINATE, "INCOMPLETE_VERIFICATION")
    return check(VALID, "ALL_PERFORMED_CHECKS_MATCHED")


def _object(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _hex(value: Any) -> bool:
    return isinstance(value, str) and HEX64.fullmatch(value) is not None


def _integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def event_content_hash(event: Dict[str, Any]) -> str:
    """Historical pack encoding, NOT RFC 8785/JCS. Do not re-sign old data."""
    return sha256_hex(json.dumps(event["Header"], sort_keys=True, allow_nan=False)
                      + json.dumps(event["Payload"], sort_keys=True, allow_nan=False))


def rfc6962_leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def rfc6962_node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def compute_legacy_merkle_root(hashes: List[str]) -> str:
    """Duplicate-odd tree used by the published pack, NOT RFC 6962 MTH."""
    if any(not _hex(h) for h in hashes):
        raise ValueError("Event hashes must be 32-byte hexadecimal digests")
    if not hashes:
        return hashlib.sha256(b"").hexdigest()
    level = [rfc6962_leaf_hash(bytes.fromhex(h)) for h in hashes]
    while len(level) > 1:
        level = [rfc6962_node_hash(level[i], level[min(i + 1, len(level) - 1)])
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def _expected_root(record: Dict[str, Any]) -> Any:
    direct = record.get("MerkleRoot", MISSING)
    nested = _object(record.get("MerkleTree")).get("Root", MISSING)
    if direct is not MISSING:
        return direct
    return nested


def check_structure(events: List[Any]) -> Dict[str, str]:
    if not events:
        return check(INDETERMINATE, "NO_EVENTS")
    for event in events:
        if not isinstance(event, dict) or any(not isinstance(event.get(k), dict)
                                             for k in ("Header", "Payload", "Security")):
            return check(INVALID, "MALFORMED_EVENT_OBJECT")
    return check(VALID, "EVENT_CONTAINERS_ONLY; not full schema validation")


def check_hashes(events: List[Any]) -> Dict[str, str]:
    results = []
    for event in events:
        event = _object(event)
        security = _object(event.get("Security"))
        if security.get("HashAlgo") != "SHA256":
            results.append(check(INDETERMINATE, "HASH_ALGORITHM_UNSUPPORTED_OR_MISSING"))
        elif not _hex(security.get("EventHash")):
            results.append(check(INVALID, "MALFORMED_EVENT_HASH"))
        elif not all(isinstance(event.get(k), dict) for k in ("Header", "Payload")):
            results.append(check(INDETERMINATE, "HASH_INPUT_UNAVAILABLE"))
        else:
            try:
                matched = event_content_hash(event) == security["EventHash"].lower()
                results.append(check(VALID if matched else INVALID,
                                     "LEGACY_HASH_MATCH" if matched else "EVENT_HASH_MISMATCH"))
            except (TypeError, ValueError, UnicodeError, RecursionError):
                results.append(check(INVALID, "UNENCODABLE_HASH_INPUT"))
    return combine(results)


def check_sequence(events: List[Any]) -> Dict[str, str]:
    results = []
    previous = None
    for event in events:
        seq = _object(_object(event).get("Header")).get("Sequence", MISSING)
        if seq is MISSING:
            results.append(check(INDETERMINATE, "SEQUENCE_MISSING"))
        elif not _integer(seq) or seq < 1:
            results.append(check(INVALID, "MALFORMED_SEQUENCE"))
        elif previous is not None and seq != previous + 1:
            results.append(check(INVALID, "SEQUENCE_GAP"))
        else:
            results.append(check(VALID, "SUPPLIED_SEQUENCE_CONTIGUITY_ONLY"))
        previous = seq if _integer(seq) and seq >= 1 else None
    return combine(results)


def check_prevhash(events: List[Any]) -> Dict[str, str]:
    results = []
    previous = None
    for event in events:
        security = _object(_object(event).get("Security"))
        link = security.get("PrevHash", MISSING)
        if link is MISSING:
            results.append(check(INDETERMINATE, "PREVHASH_NOT_SUPPLIED"))
        elif not _hex(link):
            results.append(check(INVALID, "MALFORMED_PREVHASH"))
        elif previous is None:
            results.append(check(INDETERMINATE, "PRIOR_HASH_NOT_SUPPLIED"))
        else:
            matched = previous == link.lower()
            results.append(check(VALID if matched else INVALID,
                                 "PREVHASH_MATCH" if matched else "PREVHASH_MISMATCH"))
        stored = security.get("EventHash")
        previous = stored.lower() if _hex(stored) else None
    return combine(results)


def check_policy(events: List[Any]) -> Dict[str, str]:
    results = []
    for event in events:
        policy = _object(_object(event).get("PolicyIdentification"))
        if not policy:
            results.append(check(INDETERMINATE, "POLICY_MISSING"))
            continue
        depth = _object(policy.get("VerificationDepth"))
        ok = (isinstance(policy.get("PolicyID"), str) and bool(policy["PolicyID"])
              and policy.get("ConformanceTier") in ("SILVER", "GOLD", "PLATINUM")
              and isinstance(_object(policy.get("RegistrationPolicy")).get("Issuer"), str)
              and all(type(depth.get(k)) is bool for k in
                      ("HashChainValidation", "MerkleProofRequired", "ExternalAnchorRequired")))
        results.append(check(VALID if ok else INVALID,
                             "POLICY_FIELD_SHAPE_ONLY" if ok else "MALFORMED_POLICY"))
    return combine(results)


def ed25519_public_key_problem(public_key: Any) -> Optional[str]:
    """Validate public key material, not identity/trust. Never handles secrets.

    Require a canonical nonidentity point in the prime-order subgroup. This
    is a local key-admission policy; signature verification stays in OpenSSL.
    Only immutable 32-byte values reach the bounded cache.
    """
    if type(public_key) is not bytes or len(public_key) != 32:
        return "KEY_TYPE_OR_LENGTH"
    return _ed25519_point_problem(public_key)


@lru_cache(maxsize=128)
def _ed25519_point_problem(raw: bytes) -> Optional[str]:
    """Public-data arithmetic from RFC 8032 sections 5.1.3 and 5.1.4.

    Fixed-size input and fixed public scalar L. Not a signing implementation
    or constant-time secret-scalar primitive. Cache hits do not establish trust.
    """
    p = (1 << 255) - 19
    order = (1 << 252) + 27742317777372353535851937790883648493
    d = (-121665 * pow(121666, p - 2, p)) % p
    encoded = int.from_bytes(raw, "little")
    sign, y = encoded >> 255, encoded & ((1 << 255) - 1)
    if y >= p:
        return "NONCANONICAL_POINT"
    y2 = y * y % p
    denominator = (d * y2 + 1) % p
    if denominator == 0:
        return "POINT_NOT_ON_CURVE"
    x2 = ((y2 - 1) * pow(denominator, p - 2, p)) % p
    x = pow(x2, (p + 3) // 8, p)
    if x * x % p != x2:
        x = x * pow(2, (p - 1) // 4, p) % p
    if x * x % p != x2:
        return "POINT_NOT_ON_CURVE"
    if x == 0 and sign:
        return "NONCANONICAL_POINT"
    if (x & 1) != sign:
        x = p - x
    if x == 0 and y == 1:
        return "IDENTITY_POINT"

    def add(left, right):
        x1, y1, z1, t1 = left
        x2_, y2_, z2, t2 = right
        a = (y1 - x1) * (y2_ - x2_) % p
        b = (y1 + x1) * (y2_ + x2_) % p
        c = 2 * d * t1 * t2 % p
        dd = 2 * z1 * z2 % p
        e, f, g, h = b - a, dd - c, dd + c, b + a
        return (e * f % p, g * h % p, f * g % p, e * h % p)

    # Complete extended-coordinate addition avoids hundreds of inversions.
    total, multiple = (0, 1, 1, 0), (x, y, 1, x * y % p)
    scalar = order
    while scalar:
        if scalar & 1:
            total = add(total, multiple)
        multiple = add(multiple, multiple)
        scalar >>= 1
    xx, yy, zz, _ = total
    if zz == 0 or xx != 0 or (yy - zz) % p != 0:
        return "NON_PRIME_ORDER_POINT"
    return None


def verify_digest_signature(signature: Any, digest: Any, algorithm: Any,
                            public_key: Optional[bytes], encoding: str) -> Dict[str, str]:
    if algorithm != "ED25519":
        return check(INDETERMINATE, "SIGNATURE_ALGORITHM_UNSUPPORTED_OR_MISSING")
    # Syntax is observable without a key or message. Do not infer validity
    # from successful decoding; absent signatures retain existing handling.
    if signature is not None and signature != "":
        if not isinstance(signature, str):
            return check(INVALID, "MALFORMED_SIGNATURE")
        try:
            if re.fullmatch(r"[0-9a-fA-F]{128}", signature):
                raw = bytes.fromhex(signature)
            else:
                raw = base64.b64decode(signature, validate=True)
            if len(raw) != 64:
                return check(INVALID, "MALFORMED_SIGNATURE_LENGTH")
        except (ValueError, binascii.Error):
            return check(INVALID, "MALFORMED_SIGNATURE_ENCODING")
    if public_key is None:
        return check(INDETERMINATE, "TRUSTED_KEY_MISSING")
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        return check(INDETERMINATE, "TRUSTED_KEY_UNUSABLE")
    problem = ed25519_public_key_problem(public_key)
    if problem is not None:
        return check(INDETERMINATE, "TRUSTED_KEY_REJECTED:" + problem)
    if signature is None or signature == "":
        return check(INDETERMINATE, "SIGNATURE_MISSING")
    if not _hex(digest):
        return check(INDETERMINATE, "SIGNATURE_MESSAGE_UNAVAILABLE")
    if Ed25519PublicKey is None:
        return check(INDETERMINATE, "ED25519_DEPENDENCY_UNAVAILABLE")
    if encoding not in ("raw_digest", "ascii_hex"):
        return check(INDETERMINATE, "SIGNATURE_MESSAGE_ENCODING_UNSUPPORTED")
    message = bytes.fromhex(digest) if encoding == "raw_digest" else digest.encode("ascii")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(raw, message)
    except InvalidSignature:
        return check(INVALID, "SIGNATURE_MISMATCH")
    return check(VALID, "ED25519_MATCH; key trust supplied by caller; " + encoding)


def _guard(function: Callable[[], Dict[str, str]]) -> Dict[str, str]:
    """A failed helper cannot suppress a mismatch in another required check."""
    try:
        result = function()
        if not isinstance(result, dict):
            raise ValueError("Invalid verifier result")
        return check(result.get("status"), result.get("reason"))
    except Exception as exc:
        return check(INDETERMINATE, "VERIFIER_ERROR:" + type(exc).__name__)


def verify_chain(events: List[Any], security_object: Optional[Dict[str, Any]] = None,
                 public_key: Optional[bytes] = None, *,
                 signature_message: str = "raw_digest",
                 external_anchor_verifier: Optional[ExternalVerifier] = None) -> Dict[str, Any]:
    """Verify without early exit on missing events, proofs, records or keys.

    `external_anchor_verifier` is trusted caller code, never loaded from evidence.
    It must verify an external commitment to the EXACT supplied root and return a
    check dict. There is no built-in external-anchor provider or network access.
    """
    checks = {}
    def run(name: str, function: Callable[[], Dict[str, str]]) -> None:
        checks[name] = _guard(function)

    supplied = events if isinstance(events, list) else []
    record = _object(security_object)
    root = _expected_root(record)
    run("input", lambda: check(VALID if isinstance(events, list) else INVALID,
                               "EVENT_LIST" if isinstance(events, list) else "MALFORMED_EVENT_LIST"))
    run("structure", lambda: check_structure(supplied))
    versions = [_object(_object(e).get("Security")).get("Version") for e in supplied]
    if "VCPVersion" in record:
        versions.append(record["VCPVersion"])
    run("version", lambda: check(VALID if versions and all(v == "1.1" for v in versions)
                                 else INDETERMINATE, "LEGACY_1_1_ONLY; no v1.2 or conformance verdict"))
    run("event_hash", lambda: check_hashes(supplied))
    run("sequence", lambda: check_sequence(supplied))
    run("prev_hash", lambda: check_prevhash(supplied))
    run("policy_fields", lambda: check_policy(supplied))
    # Evaluate every signature even if another event/field cannot be processed.
    signature_results = []
    for event in supplied:
        security = _object(_object(event).get("Security"))
        signature_results.append(_guard(lambda s=security: verify_digest_signature(
            s.get("Signature"), s.get("EventHash"), s.get("SignAlgo"), public_key, signature_message)))
    run("event_signatures", lambda: combine(signature_results))

    def record_shape() -> Dict[str, str]:
        if security_object is None:
            return check(INDETERMINATE, "ANCHOR_RECORD_MISSING")
        if not isinstance(security_object, dict):
            return check(INVALID, "MALFORMED_ANCHOR_RECORD")
        if root is MISSING:
            return check(INDETERMINATE, "EXPECTED_ROOT_MISSING")
        if not _hex(root):
            return check(INVALID, "MALFORMED_EXPECTED_ROOT")
        nested = _object(record.get("MerkleTree")).get("Root", MISSING)
        if nested is not MISSING and (not _hex(nested) or root.lower() != nested.lower()):
            return check(INVALID, "CONFLICTING_EXPECTED_ROOTS")
        return check(VALID, "ROOT_FIELD_SHAPE_ONLY")
    run("anchor_record", record_shape)

    def merkle() -> Dict[str, str]:
        if not supplied or not _hex(root):
            return check(INDETERMINATE, "BATCH_OR_EXPECTED_ROOT_UNAVAILABLE")
        hashes = [_object(_object(e).get("Security")).get("EventHash") for e in supplied]
        if any(not _hex(h) for h in hashes):
            return check(INDETERMINATE, "MERKLE_INPUT_UNAVAILABLE")
        matched = compute_legacy_merkle_root(hashes) == root.lower()
        return check(VALID if matched else INVALID,
                     "LEGACY_DUPLICATE_ODD_ROOT_MATCH" if matched else "LEGACY_ROOT_MISMATCH")
    run("merkle_root", merkle)

    def bounds() -> Dict[str, str]:
        if not supplied or security_object is None:
            return check(INDETERMINATE, "BATCH_BOUNDS_INPUT_UNAVAILABLE")
        comparisons = [("EventCount", len(supplied)),
                       ("FirstSequence", _object(_object(supplied[0]).get("Header")).get("Sequence")),
                       ("LastSequence", _object(_object(supplied[-1]).get("Header")).get("Sequence"))]
        results = []
        for field, actual in comparisons:
            declared = record.get(field, MISSING)
            if declared is MISSING or actual is None:
                results.append(check(INDETERMINATE, field + "_MISSING"))
            elif not _integer(declared) or declared != actual:
                results.append(check(INVALID, field + "_MISMATCH"))
            else:
                results.append(check(VALID, field + "_MATCH"))
        # This is local consistency, NOT authenticated metadata or INT-008.
        result = combine(results)
        result["reason"] += "; local fields only; root signature does not cover metadata"
        return result
    run("batch_bounds_local", bounds)
    run("anchor_signature", lambda: verify_digest_signature(
        record.get("Signature"), root, record.get("SignAlgo"), public_key, signature_message))
    run("authenticated_batch_metadata", lambda: check(INDETERMINATE,
        "NOT_IMPLEMENTED; root-only signature does not authenticate count, range or policy"))
    def audit_paths() -> Dict[str, str]:
        if not supplied or not _hex(root):
            return check(INDETERMINATE, "INCLUSION_ROOT_OR_EVENTS_UNAVAILABLE")
        results = []
        for index, event in enumerate(supplied):
            security = _object(_object(event).get("Security"))
            path = security.get("AuditPath", MISSING)
            digest = security.get("EventHash")
            if path is MISSING or path is None:
                results.append(check(INDETERMINATE, "AUDIT_PATH_MISSING"))
                continue
            if not isinstance(path, list):
                results.append(check(INVALID, "MALFORMED_AUDIT_PATH"))
                continue
            if not _hex(digest):
                results.append(check(INDETERMINATE, "INCLUSION_LEAF_UNAVAILABLE"))
                continue
            position = security.get("MerkleIndex", MISSING)
            if position is MISSING:
                results.append(check(INDETERMINATE, "MERKLE_INDEX_MISSING"))
                continue
            if not _integer(position) or position != index:
                results.append(check(INVALID, "MERKLE_INDEX_MISMATCH"))
                continue
            node = rfc6962_leaf_hash(bytes.fromhex(digest))
            width, used = len(supplied), 0
            valid = True
            # Verify the known historical construction, not arbitrary path folds.
            for sibling in path:
                if width <= 1 or not isinstance(sibling, dict) or not _hex(sibling.get("hash")):
                    valid = False
                    break
                expected_side = "left" if position % 2 else "right"
                other = bytes.fromhex(sibling["hash"])
                if sibling.get("position") != expected_side:
                    valid = False
                    break
                if position % 2 == 0 and position + 1 == width and other != node:
                    valid = False
                    break
                node = (rfc6962_node_hash(other, node) if expected_side == "left"
                        else rfc6962_node_hash(node, other))
                width, position, used = (width + 1) // 2, position // 2, used + 1
            valid = valid and width == 1 and used == len(path) and node.hex() == root.lower()
            results.append(check(VALID if valid else INVALID,
                                 "LEGACY_INCLUSION_MATCH" if valid else "INCLUSION_MISMATCH"))
        return combine(results)
    run("audit_path", audit_paths)
    def external() -> Dict[str, str]:
        if not _hex(root):
            return check(INDETERMINATE, "EXTERNAL_ANCHOR_ROOT_UNAVAILABLE")
        if external_anchor_verifier is None:
            return check(INDETERMINATE, "EXTERNAL_ANCHOR_VERIFIER_UNAVAILABLE")
        return external_anchor_verifier(root.lower(), record)
    run("external_anchor", external)
    overall = combine(list(checks.values()))["status"]
    return {"report_version": 2, "status": overall, "events_total": len(supplied),
            "checks": checks, "conformance_claim": False,
            "verification_context": "repository legacy v1.1 evidence format only",
            "notes": ["No external-implementation, independent-reproduction or certification claim.",
                      "Historical signed bytes are never rewritten.",
                      "Full schema and authenticated batch metadata checks are not implemented."]}


def _reject_constant(value: str) -> None:
    raise ValueError("Non-finite JSON number: " + value)


def _unique_object(pairs: List[Any]) -> Dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key: " + key)
        result[key] = value
    return result


def _finite_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise ValueError("Non-finite JSON number")
    return value


def _json(text: str) -> Any:
    # Check resource limits before the recursive decoder allocates containers.
    if len(text) > MAX_JSON_BYTES or len(text.encode("utf-8")) > MAX_JSON_BYTES:
        raise ValueError("JSON document exceeds byte limit")
    depth = 0
    quoted = escaped = False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise ValueError("JSON document exceeds nesting limit")
        elif char in "]}":
            depth -= 1
    return json.loads(text, object_pairs_hook=_unique_object,
                      parse_constant=_reject_constant, parse_float=_finite_float)


@contextmanager
def _regular_input(filepath: str, limit: int):
    """Open a bounded regular file, not a pipe/device. No filesystem deadline.

    The path precheck avoids opening known special files; fstat rechecks the
    actual descriptor after open. O_NONBLOCK prevents a raced-in POSIX FIFO
    from waiting for a writer. Symlinks to regular files remain supported.
    """
    if not stat.S_ISREG(os.stat(filepath).st_mode):
        raise ValueError("Input must be a regular file")
    flags = (os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
             | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_BINARY", 0))
    fd = os.open(filepath, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Input must be a regular file")
        if info.st_size > limit:
            raise ValueError("Input exceeds byte limit")
        handle = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    with handle:
        yield handle


def _read_regular(filepath: str, limit: int) -> bytes:
    with _regular_input(filepath, limit) as handle:
        # The read limit also covers growth and misleading stat sizes.
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Input exceeds byte limit")
    return data


def load_events(filepath: str) -> List[Dict[str, Any]]:
    raw = _read_regular(filepath, MAX_EVENT_FILE_BYTES)
    events = []
    # Preserve the old text reader's LF/CRLF/CR behavior, not str.splitlines()
    # (which also splits on Unicode characters valid inside JSON strings).
    with io.StringIO(raw.decode("utf-8"), newline=None) as handle:
        number = 0
        while True:
            line = handle.readline(MAX_JSON_BYTES + 1)
            if not line:
                break
            number += 1
            if len(line) > MAX_JSON_BYTES or len(line.encode("utf-8")) > MAX_JSON_BYTES:
                raise ValueError("Event line exceeds byte limit")
            if line.strip():
                if len(events) >= MAX_EVENT_COUNT:
                    raise ValueError("Event count exceeds local limit")
                item = _json(line)
                if not isinstance(item, dict):
                    raise ValueError("Event on line %d is not an object" % number)
                events.append(item)
    return events


def load_security_object(filepath: str) -> Dict[str, Any]:
    item = _json(_read_regular(filepath, MAX_JSON_BYTES).decode("utf-8"))
    if not isinstance(item, dict):
        raise ValueError("Security object must be a JSON object")
    return item


def load_public_key(filepath: str) -> bytes:
    """Trust is an explicit caller decision, not inferred from an evidence file."""
    raw = _read_regular(filepath, MAX_KEY_FILE_BYTES)
    if len(raw) == 32:
        return raw
    text = raw.decode("utf-8").strip()
    if text.startswith("{"):
        text = _json(text).get("PublicKey")
    if not isinstance(text, str):
        raise ValueError("Expected a raw, hex, base64 or PublicKey JSON key")
    key = bytes.fromhex(text) if _hex(text) else base64.b64decode(text, validate=True)
    if len(key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return key


def render_report(report: Dict[str, Any]) -> str:
    lines = ["Legacy VCP v1.1 evidence verification (not a conformance assessment)",
             "Generated: " + datetime.now(timezone.utc).isoformat(),
             "Overall Status: " + report["status"], "Total Events: " + str(report["events_total"])]
    lines.extend("%s: %s (%s)" % (name, result["status"], result["reason"])
                 for name, result in report["checks"].items())
    return "\n".join(lines) + "\n"


def write_new_report(filepath: str, text: str, *, protected_paths=()) -> None:
    """Publish complete UTF-8 output without replacing any existing entry.

    Use a caller-controlled directory on a filesystem supporting hard links.
    Publication fails closed if that facility is unavailable. This does not
    protect against hostile directory owners or shell redirection before startup.
    """
    destination = Path(filepath)
    # Include missing optional inputs: an output must not create a substitute
    # for a requested-but-unavailable evidence, key or timestamp file.
    resolved = destination.resolve()
    if any(resolved == Path(path).resolve() for path in protected_paths if path):
        raise ValueError("Report output aliases an input path")
    if os.path.lexists(destination):
        raise FileExistsError("Report output already exists; choose a new path")
    data = text.encode("utf-8")
    staged = None
    try:
        # mkstemp-backed creation uses mode 0600 on POSIX. Nothing is published
        # at the destination until writing, flush and fsync have all succeeded.
        with tempfile.NamedTemporaryFile(mode="wb", prefix=".vcp-report-", suffix=".tmp",
                                         dir=destination.parent, delete=False) as handle:
            staged = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        # Unlike rename/replace, link cannot overwrite an existing destination,
        # including a symlink created after the preliminary existence check.
        os.link(staged, destination, follow_symlinks=False)
    finally:
        if staged is not None:
            staged.unlink()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events_file")
    parser.add_argument("--security-object", "-s")
    parser.add_argument("--public-key", help="File containing an explicitly trusted Ed25519 key")
    parser.add_argument("--signature-message", choices=("raw_digest", "ascii_hex"), default="raw_digest")
    parser.add_argument("--output", "-o", help="New report path only; never overwrites")
    parser.add_argument("--json", action="store_true", help="Emit report format version 2")
    args = parser.parse_args(argv)
    try:
        events = load_events(args.events_file)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        print("Cannot load events: " + str(exc), file=sys.stderr)
        return 3
    record = key = None
    unavailable = {}
    # Optional input errors do not suppress checks on the successfully loaded input.
    for name, path, loader in (("security_object_input", args.security_object, load_security_object),
                               ("public_key_input", args.public_key, load_public_key)):
        if path:
            try:
                value = loader(path)
                if name == "security_object_input":
                    record = value
                else:
                    key = value
            except (OSError, ValueError, UnicodeError, RecursionError) as exc:
                unavailable[name] = check(INDETERMINATE, "INPUT_UNAVAILABLE:" + type(exc).__name__)
    report = verify_chain(events, record, key, signature_message=args.signature_message)
    report["checks"].update(unavailable)
    report["status"] = combine(list(report["checks"].values()))["status"]
    text = json.dumps(report, indent=2, ensure_ascii=False) + "\n" if args.json else render_report(report)
    print(text, end="")
    if args.output:
        try:
            write_new_report(args.output, text, protected_paths=(
                args.events_file, args.security_object, args.public_key))
        except (OSError, ValueError, RuntimeError) as exc:
            print("Cannot write report: " + str(exc), file=sys.stderr)
            return 3
    return EXIT_CODES[report["status"]]


if __name__ == "__main__":
    sys.exit(main())