#!/usr/bin/env python3
"""Opt-in supplemental batch attestation and offline RFC 3161 verification.

Experimental implementation format, NOT an adopted VCP/VAP format or a
conformance verifier. Does not create signatures, contact a TSA, or rewrite
historical evidence. Trust inputs must be supplied separately by the caller.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import vcp_verifier as legacy

try:
    from asn1crypto import tsp
except ImportError:
    tsp = None

VALID, INVALID, INDETERMINATE = legacy.VALID, legacy.INVALID, legacy.INDETERMINATE
check, combine = legacy.check, legacy.combine
DOMAIN = b"VCP-RTA-SUPPLEMENTAL-STATEMENT\x00v1\x00"
ANCHOR_DOMAIN = b"VCP-RTA-SUPPLEMENTAL-ANCHOR\x00v1\x00"
FORMAT = "vcp-rta-supplemental-batch-v1"
CONSTANTS = {
    "format": FORMAT,
    "evidence_format": "vcp-rta-legacy-1.1",
    "hash_encoding": "python-json-concat-v1",
    "tree_algorithm": "sha256-duplicate-odd-v1",
    "snapshot_encoding": "python-json-sort-ascii-compact-v1",
}
FIELDS = set(CONSTANTS) | {
    "context_id", "merkle_root", "event_count", "first_event_id", "last_event_id",
    "first_sequence", "last_sequence", "policy_id", "issued_at",
    "events_snapshot_sha256", "security_object_sha256",
}
MAX_FILE_BYTES = 2 * 1024 * 1024


def bounded_read(path: str) -> bytes:
    """Read regular local files only, with a bound checked on the open handle."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Input must be a regular file")
        data = handle.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("Input exceeds 2 MiB")
    return data


def snapshot_digest(value: Any) -> str:
    """Local format contract, NOT JCS: sorted Python JSON, ASCII, compact."""
    data = json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")
    return hashlib.sha256(data).hexdigest()


def statement_bytes(statement: Any) -> bytes:
    if not isinstance(statement, dict) or set(statement) != FIELDS:
        raise ValueError("Statement fields must exactly match this implementation format")
    if any(type(v) is not str or not v or len(v) > 4096 for v in statement.values()):
        raise ValueError("Every statement value must be a bounded nonempty string")
    if any(statement[k] != v for k, v in CONSTANTS.items()):
        raise ValueError("Unsupported statement format or encoding")
    for k in ("merkle_root", "events_snapshot_sha256", "security_object_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", statement[k]):
            raise ValueError("Expected a lowercase SHA-256 digest: " + k)
    for k in ("event_count", "first_sequence", "last_sequence"):
        if not re.fullmatch(r"[1-9][0-9]{0,18}", statement[k]):
            raise ValueError("Expected a positive decimal string: " + k)
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                        statement["issued_at"]):
        raise ValueError("issued_at must be UTC YYYY-MM-DDTHH:MM:SSZ")
    datetime.strptime(statement["issued_at"], "%Y-%m-%dT%H:%M:%SZ")
    return DOMAIN + json.dumps(statement, sort_keys=True, ensure_ascii=False,
                               separators=(",", ":"), allow_nan=False).encode("utf-8")


def decode_envelope(envelope: Any) -> tuple[dict, bytes, bytes]:
    if not isinstance(envelope, dict) or set(envelope) != {"statement", "signature"}:
        raise ValueError("Envelope must contain statement and signature only")
    message = statement_bytes(envelope["statement"])
    encoded = envelope["signature"]
    if not isinstance(encoded, str) or len(encoded) != 88:
        raise ValueError("Signature must be canonical Base64 of 64 bytes")
    signature = base64.b64decode(encoded, validate=True)
    if len(signature) != 64 or base64.b64encode(signature).decode("ascii") != encoded:
        raise ValueError("Noncanonical signature encoding")
    return envelope["statement"], message, signature


def anchor_bytes(envelope: Any) -> bytes:
    """Timestamp the full domain-separated signed statement, not just its root."""
    _, message, signature = decode_envelope(envelope)
    return ANCHOR_DOMAIN + message + signature


def check_signature(envelope: Any, public_key: Optional[bytes]) -> dict:
    if envelope is None:
        return check(INDETERMINATE, "SUPPLEMENTAL_STATEMENT_MISSING")
    try:
        _, message, signature = decode_envelope(envelope)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return check(INVALID, "MALFORMED_SUPPLEMENTAL_ENVELOPE")
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        return check(INDETERMINATE, "SUPPLEMENTAL_TRUSTED_KEY_MISSING_OR_UNUSABLE")
    if legacy.Ed25519PublicKey is None:
        return check(INDETERMINATE, "ED25519_DEPENDENCY_UNAVAILABLE")
    try:
        legacy.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except legacy.InvalidSignature:
        return check(INVALID, "SUPPLEMENTAL_SIGNATURE_MISMATCH")
    return check(VALID, "SUPPLEMENTAL_ED25519_MATCH; caller-established key")


def check_bindings(envelope: Any, events: Any, record: Any,
                   expected_context: Optional[str]) -> dict:
    if envelope is None:
        return check(INDETERMINATE, "SUPPLEMENTAL_STATEMENT_MISSING")
    try:
        statement, _, _ = decode_envelope(envelope)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return check(INVALID, "MALFORMED_SUPPLEMENTAL_ENVELOPE")
    results = []
    def equal(name: str, actual: Any) -> None:
        if actual is None or actual is legacy.MISSING:
            results.append(check(INDETERMINATE, name + "_UNAVAILABLE"))
            return
        matched = statement[name] == actual
        results.append(check(VALID if matched else INVALID,
                             name + ("_MATCH" if matched else "_MISMATCH")))
    def compare_snapshot(name: str, value: Any) -> None:
        try:
            actual = snapshot_digest(value)
        except (TypeError, ValueError, UnicodeError, RecursionError):
            results.append(check(INDETERMINATE, name + "_ENCODING_UNAVAILABLE"))
        else:
            equal(name, actual)
    if not isinstance(expected_context, str) or not expected_context:
        results.append(check(INDETERMINATE, "TRUSTED_CONTEXT_MISSING"))
    else:
        equal("context_id", expected_context)
    if not isinstance(events, list) or not events:
        results.append(check(INDETERMINATE, "EVENTS_UNAVAILABLE"))
    else:
        equal("event_count", str(len(events)))
        compare_snapshot("events_snapshot_sha256", events)
        headers = [legacy._object(legacy._object(e).get("Header")) for e in events]
        equal("first_event_id", headers[0].get("EventID"))
        equal("last_event_id", headers[-1].get("EventID"))
        for name, value in (("first_sequence", headers[0].get("Sequence")),
                            ("last_sequence", headers[-1].get("Sequence"))):
            equal(name, str(value) if legacy._integer(value) else None)
        ids = [h.get("EventID") for h in headers]
        unique = (all(isinstance(v, str) and v for v in ids) and len(set(ids)) == len(ids))
        results.append(check(VALID if unique else INVALID,
                             "EVENT_IDS_UNIQUE" if unique else "DUPLICATE_OR_INVALID_EVENT_IDS"))
        hashes = [legacy._object(legacy._object(e).get("Security")).get("EventHash") for e in events]
        if all(legacy._hex(h) for h in hashes):
            equal("merkle_root", legacy.compute_legacy_merkle_root(hashes))
        else:
            results.append(check(INDETERMINATE, "ROOT_RECOMPUTATION_UNAVAILABLE"))
        for e in events:
            equal("policy_id", legacy._object(legacy._object(e).get("PolicyIdentification")).get("PolicyID"))
    if not isinstance(record, dict):
        results.append(check(INDETERMINATE, "SECURITY_OBJECT_UNAVAILABLE"))
    else:
        compare_snapshot("security_object_sha256", record)
        root = legacy._expected_root(record)
        equal("merkle_root", root.lower() if legacy._hex(root) else None)
        for target, field in (("event_count", "EventCount"), ("first_sequence", "FirstSequence"),
                              ("last_sequence", "LastSequence")):
            value = record.get(field)
            equal(target, str(value) if legacy._integer(value) else None)
        equal("policy_id", record.get("PolicyID"))
    result = combine(results)
    result["reason"] += "; " + "; ".join(c["reason"] for c in results if c["status"] != VALID)
    return result


def verify_rfc3161(data: bytes, response: Optional[bytes], ca_pem: Optional[bytes],
                   policy_oid: Optional[str], *, untrusted_pem: Optional[bytes] = None,
                   openssl: Optional[str] = None) -> dict:
    """Archived token check: SHA-256 imprint, TSP policy, signature and CA chain.

    No network, nonce/freshness, CRL/OCSP, qualified-TSA or legal-time assessment.
    Trust is only the caller's CA bundle, with an empty directory fallback.
    Unknown execution/chain failures remain INDETERMINATE, never success.
    """
    if not isinstance(response, bytes) or not response:
        return check(INDETERMINATE, "RFC3161_RESPONSE_MISSING")
    if len(response) > MAX_FILE_BYTES:
        return check(INVALID, "RFC3161_RESPONSE_TOO_LARGE")
    if tsp is None:
        return check(INDETERMINATE, "ASN1_DEPENDENCY_UNAVAILABLE")
    try:
        parsed = tsp.TimeStampResp.load(response, strict=True)
        if parsed["status"]["status"].native not in ("granted", "granted_with_mods"):
            return check(INDETERMINATE, "TSA_RESPONSE_NOT_GRANTED")
        token = parsed["time_stamp_token"]
        if token["content_type"].native != "signed_data":
            return check(INVALID, "RFC3161_CONTENT_TYPE_MISMATCH")
        content = token["content"]["encap_content_info"]
        if content["content_type"].native != "tst_info":
            return check(INVALID, "RFC3161_TSTINFO_MISSING")
        info = content["content"].parsed
        imprint = info["message_imprint"]
        if imprint["hash_algorithm"]["algorithm"].native != "sha256":
            return check(INDETERMINATE, "RFC3161_IMPRINT_ALGORITHM_UNSUPPORTED")
        if imprint["hashed_message"].native != hashlib.sha256(data).digest():
            return check(INVALID, "RFC3161_IMPRINT_MISMATCH")
        if not isinstance(policy_oid, str) or not re.fullmatch(r"[0-2](?:\.[0-9]+)+", policy_oid):
            return check(INDETERMINATE, "TRUSTED_TSA_POLICY_MISSING_OR_UNUSABLE")
        if info["policy"].dotted != policy_oid:
            return check(INVALID, "RFC3161_POLICY_MISMATCH")
    except (ValueError, TypeError, KeyError, IndexError, OverflowError, RecursionError):
        return check(INVALID, "MALFORMED_RFC3161_RESPONSE")
    if not isinstance(ca_pem, bytes) or not ca_pem:
        return check(INDETERMINATE, "TRUSTED_TSA_CA_MISSING")
    if len(ca_pem) > MAX_FILE_BYTES or (untrusted_pem is not None and
            (not isinstance(untrusted_pem, bytes) or len(untrusted_pem) > MAX_FILE_BYTES)):
        return check(INDETERMINATE, "TSA_CERTIFICATE_INPUT_UNUSABLE")
    executable = openssl if openssl is not None else shutil.which("openssl")
    if not executable:
        return check(INDETERMINATE, "OPENSSL_UNAVAILABLE")
    try:
        with tempfile.TemporaryDirectory(prefix="vcp-rta-ts-") as directory:
            d = Path(directory)
            for name, value in (("payload.bin", data), ("response.tsr", response), ("ca.pem", ca_pem)):
                (d / name).write_bytes(value)
            (d / "empty").mkdir()
            (d / "openssl.cnf").write_text("# No evidence-supplied configuration.\n", encoding="ascii")
            # OpenSSL 3.0 rejects a load-store URI with no certificate objects.
            # Use the SAME caller CA bundle in both channels, not OS defaults.
            cmd = [executable, "ts", "-verify", "-data", str(d / "payload.bin"),
                   "-in", str(d / "response.tsr"), "-CAfile", str(d / "ca.pem"),
                   "-CApath", str(d / "empty"), "-CAstore", (d / "ca.pem").as_uri()]
            if untrusted_pem:
                (d / "untrusted.pem").write_bytes(untrusted_pem)
                cmd += ["-untrusted", str(d / "untrusted.pem")]
            env = os.environ.copy()
            env.update(OPENSSL_CONF=str(d / "openssl.cnf"), SSL_CERT_FILE=str(d / "ca.pem"),
                       SSL_CERT_DIR=str(d / "empty"), LC_ALL="C")
            proc = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, timeout=15, check=False, env=env)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return check(INDETERMINATE, "RFC3161_VERIFIER_UNAVAILABLE_OR_TIMEOUT")
    if proc.returncode != 0:
        return check(INDETERMINATE, "RFC3161_SIGNATURE_OR_CHAIN_NOT_VERIFIED")
    return check(VALID, "RFC3161_SHA256_IMPRINT_POLICY_SIGNATURE_CHAIN_MATCH; "
                 "caller CA only; current-time certificate validation; no revocation/freshness check")


def verify_attested_chain(events: Any, record: Any = None, public_key: Optional[bytes] = None, *,
                          envelope: Any = None, attestor_key: Optional[bytes] = None,
                          expected_context: Optional[str] = None, response: Optional[bytes] = None,
                          ca_pem: Optional[bytes] = None, policy_oid: Optional[str] = None,
                          untrusted_pem: Optional[bytes] = None,
                          signature_message: str = "raw_digest") -> dict:
    report = legacy.verify_chain(events, record, public_key, signature_message=signature_message)
    checks = report["checks"]
    checks["supplemental_signature"] = legacy._guard(lambda: check_signature(envelope, attestor_key))
    checks["supplemental_batch_binding"] = legacy._guard(
        lambda: check_bindings(envelope, events, record, expected_context))
    checks["authenticated_batch_metadata"] = combine([
        checks["supplemental_signature"], checks["supplemental_batch_binding"]])
    def timestamp() -> dict:
        if envelope is None:
            return check(INDETERMINATE, "SUPPLEMENTAL_STATEMENT_MISSING")
        return verify_rfc3161(anchor_bytes(envelope), response, ca_pem, policy_oid,
                             untrusted_pem=untrusted_pem)
    # Runs independently even when the attestor key or historical proof is absent.
    checks["rfc3161_token"] = legacy._guard(timestamp)
    checks["external_anchor"] = combine([checks["rfc3161_token"],
                                         checks["authenticated_batch_metadata"]])
    report["status"] = combine(list(checks.values()))["status"]
    report["supplemental_format"] = FORMAT
    report["notes"][-1] = "Full schema verification is not implemented."
    report["notes"] += [
        "Opt-in implementation extension, not adopted VCP/VAP or INT-008 conformance.",
        "Supplemental signature/timestamp cannot establish original logging or anchoring time.",
        "RFC3161 check excludes revocation, live nonce/freshness and qualified-TSA assessment.",
        "Existing boundary/PrevHash checks remain: new checks do not force overall VALID.",
    ]
    return report


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events_file")
    parser.add_argument("--security-object", "-s")
    parser.add_argument("--public-key")
    parser.add_argument("--signature-message", choices=("raw_digest", "ascii_hex"), default="raw_digest")
    parser.add_argument("--attestation")
    parser.add_argument("--attestor-key")
    parser.add_argument("--expected-context")
    parser.add_argument("--tsa-response")
    parser.add_argument("--tsa-ca-file")
    parser.add_argument("--tsa-untrusted")
    parser.add_argument("--tsa-policy-oid")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", "-o", help="New report path only; never overwrites")
    args = parser.parse_args(argv)
    try:
        events = legacy.load_events(args.events_file)
    except (OSError, ValueError, UnicodeError, RecursionError) as exc:
        print("Cannot load events: " + str(exc), file=sys.stderr)
        return 3
    values, unavailable = {}, {}
    for name, path, loader in (
        ("record", args.security_object, legacy.load_security_object),
        ("public_key", args.public_key, legacy.load_public_key),
        ("envelope", args.attestation, lambda p: legacy._json(bounded_read(p).decode("utf-8"))),
        ("attestor_key", args.attestor_key, legacy.load_public_key),
        ("response", args.tsa_response, bounded_read),
        ("ca_pem", args.tsa_ca_file, bounded_read),
        ("untrusted_pem", args.tsa_untrusted, bounded_read),
    ):
        values[name] = None
        if path:
            try:
                values[name] = loader(path)
            except (OSError, ValueError, UnicodeError, RecursionError) as exc:
                unavailable[name + "_input"] = check(INDETERMINATE, "INPUT_UNAVAILABLE:" + type(exc).__name__)
    report = verify_attested_chain(events, **values, expected_context=args.expected_context,
                                   policy_oid=args.tsa_policy_oid, signature_message=args.signature_message)
    report["checks"].update(unavailable)
    report["status"] = combine(list(report["checks"].values()))["status"]
    text = json.dumps(report, indent=2, ensure_ascii=True) + "\n" if args.json else legacy.render_report(report)
    print(text, end="")
    if args.output:
        try:
            legacy.write_new_report(args.output, text, protected_paths=(
                args.events_file, args.security_object, args.public_key, args.attestation,
                args.attestor_key, args.tsa_response, args.tsa_ca_file, args.tsa_untrusted))
        except (OSError, ValueError, RuntimeError) as exc:
            print("Cannot write report: " + str(exc), file=sys.stderr)
            return 3
    return legacy.EXIT_CODES[report["status"]]


if __name__ == "__main__":
    sys.exit(main())