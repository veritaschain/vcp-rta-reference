#!/usr/bin/env python3
"""Read-only replay of the fixed historical pack, not a conformance verdict.

The optional reference-key comparison tests mathematics only. It does not
establish the key owner's identity, independent trust, or original anchoring.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
from importlib import metadata
import json
from pathlib import Path
import platform
import subprocess
import sys

import vcp_verifier as legacy

ROOT = Path(__file__).resolve().parents[2]
BASELINE = "6818bf3d08f8c24b31798d8ab0f0a60af8c22b4b"
EVENTS = "evidence/01_trade_logs/vcp_rta_events.jsonl"
RECORD = "evidence/04_anchor/security_object.json"
KEY = "evidence/04_anchor/public_key.json"
ANCHOR = "evidence/04_anchor/anchor_reference.json"
PINNED_BLOBS = {
    EVENTS: "b27d1c0d6449ff6d492fb2609c4681e44f6865ad",
    RECORD: "cd00fd6422e8a680b01cf0daef2e625dc039bec1",
    KEY: "696fabc9b8a19f50fb7904131efef3fc229a7671",
    ANCHOR: "4bb8d6b32bea69b811a6fa7a8f7b8172997755e7",
}


def blob_hash(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def evidence_manifest(root: Path) -> dict:
    result = {}
    for path in sorted((root / "evidence").rglob("*")):
        if path.is_symlink():
            raise ValueError("Historical evidence must not contain symbolic links")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            data = path.read_bytes()
            result[path.relative_to(root).as_posix()] = {
                "sha256": hashlib.sha256(data).hexdigest(), "git_blob": blob_hash(data),
                "bytes": len(data),
            }
    return result


def load_fixed_pack(root: Path):
    data = {name: (root / name).read_bytes() for name in PINNED_BLOBS}
    if any(blob_hash(data[name]) != digest for name, digest in PINNED_BLOBS.items()):
        raise ValueError("Historical bytes differ from the pinned baseline; do not silently rebaseline")
    events = [legacy._json(line) for line in data[EVENTS].decode("utf-8").splitlines() if line.strip()]
    if not events or any(not isinstance(e, dict) for e in events):
        raise ValueError("Expected a nonempty historical event array")
    record = legacy._json(data[RECORD].decode("utf-8"))
    key_record = legacy._json(data[KEY].decode("utf-8"))
    key_hex = key_record.get("PublicKey")
    if not legacy._hex(key_hex):
        raise ValueError("Malformed published reference key")
    return events, record, bytes.fromhex(key_hex)


def strict_root(hashes: list[str]) -> str:
    """Separate RFC 6962 split construction; never changes the legacy verdict."""
    leaves = [hashlib.sha256(b"\x00" + bytes.fromhex(h)).digest() for h in hashes]
    def mth(nodes):
        if not nodes:
            return hashlib.sha256(b"").digest()
        if len(nodes) == 1:
            return nodes[0]
        split = 1 << ((len(nodes) - 1).bit_length() - 1)
        return hashlib.sha256(b"\x01" + mth(nodes[:split]) + mth(nodes[split:])).digest()
    return mth(leaves).hex()


def inspect_pack(root: Path = ROOT, *, compare_reference_key: bool = False) -> dict:
    before = evidence_manifest(root)
    events, record, reference_key = load_fixed_pack(root)
    no_key = legacy.verify_chain(events, record)
    comparison = None
    per_event = []
    if compare_reference_key:
        comparison = legacy.verify_chain(events, record, reference_key)
        for index, event in enumerate(events):
            security = event["Security"]
            per_event.append({"index": index, "event_id": event["Header"].get("EventID"),
                "hash": legacy.check_hashes([event]),
                "signature": legacy._guard(lambda s=security: legacy.verify_digest_signature(
                    s.get("Signature"), s.get("EventHash"), s.get("SignAlgo"),
                    reference_key, "raw_digest"))})
    after = evidence_manifest(root)
    if before != after:
        raise ValueError("Historical evidence changed during replay")
    hashes = [e["Security"]["EventHash"] for e in events]
    commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, text=True, timeout=10, check=False)
    return {
        "inspection_version": 1, "execution_status": "completed",
        "evidence_verdict": (comparison or no_key)["status"],
        "baseline_commit": BASELINE, "executed_commit": commit.stdout.strip() if commit.returncode == 0 else None,
        "environment": {"python": platform.python_version(), "cryptography": metadata.version("cryptography")},
        "conformance_claim": False, "independent_reproduction": False,
        "key_identity_established": False, "original_anchor_confirmed": False,
        "reference_key_comparison_requested": compare_reference_key,
        "reference_key_fingerprint_sha256": hashlib.sha256(reference_key).hexdigest() if compare_reference_key else None,
        "event_count": len(events),
        "event_types": dict(sorted(Counter(e["Header"].get("EventType") for e in events).items())),
        "legacy_merkle_root": legacy.compute_legacy_merkle_root(hashes),
        "strict_rfc6962_root_comparison_only": strict_root(hashes),
        "ots_files_present_not_verified": sorted(p.relative_to(root).as_posix() for p in (root / "evidence").rglob("*.ots")),
        "without_key": no_key, "with_reference_key_comparison_only": comparison,
        "per_event_comparison_only": per_event,
        "inputs_before": before, "inputs_after": after,
        "notes": ["Reference key is explicitly selected for mathematical comparison, not established identity or trust.",
                  "No proof, signature or historical evidence is created, edited or backdated.",
                  "Original external anchoring, authenticated metadata, chain boundary and full-schema limitations remain.",
                  "A successful regression reproducing INDETERMINATE is not successful full evidence verification."],
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compare-reference-key", action="store_true",
                        help="Explicit mathematical comparison with the published key; does not establish identity")
    args = parser.parse_args(argv)
    try:
        report = inspect_pack(compare_reference_key=args.compare_reference_key)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, metadata.PackageNotFoundError) as exc:
        print("Cannot inspect historical pack: " + str(exc), file=sys.stderr)
        return 3
    print(json.dumps(report, indent=2, ensure_ascii=True))
    return legacy.EXIT_CODES[report["evidence_verdict"]]


if __name__ == "__main__":
    sys.exit(main())
