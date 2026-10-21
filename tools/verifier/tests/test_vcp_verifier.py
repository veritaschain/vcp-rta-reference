"""Tests for the VCP v1.1 verifier.

The sample evidence is the published pack in this repository.
External anchor confirmation stays UNVERIFIABLE: merkle_root.ots is not
in the repository, and these tests do not invent an OpenTimestamps result.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[3]
VERIFIER_PATH = ROOT / "tools" / "verifier" / "vcp_verifier.py"
EVENTS = ROOT / "evidence" / "01_trade_logs" / "vcp_rta_events.jsonl"
TAMPERED = ROOT / "evidence" / "03_tamper_detection" / "tampered_chain.jsonl"
SECURITY = ROOT / "evidence" / "04_anchor" / "security_object.json"
PUBLIC_KEY = ROOT / "evidence" / "04_anchor" / "public_key.json"
ANCHOR = ROOT / "evidence" / "04_anchor" / "anchor_reference.json"

BANNED = ("Fully Compliant", "VCP v1.1 Compliant")


def load_verifier():
    spec = importlib.util.spec_from_file_location("vcp_verifier", VERIFIER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_cli(args):
    return subprocess.run(
        [sys.executable, str(VERIFIER_PATH), *args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        check=False,
    )


def genuine_args():
    return [
        str(EVENTS),
        "-s",
        str(SECURITY),
        "-k",
        str(PUBLIC_KEY),
        "-a",
        str(ANCHOR),
    ]


def test_verifier_source_does_not_overclaim():
    source = VERIFIER_PATH.read_text(encoding="utf-8")
    for phrase in BANNED:
        assert phrase not in source


def test_genuine_chain_signatures_and_merkle_anchor_unverifiable():
    mod = load_verifier()
    report = mod.verify_paths(
        str(EVENTS),
        security_object_path=str(SECURITY),
        public_key_path=str(PUBLIC_KEY),
        anchor_path=str(ANCHOR),
    )
    security = json.loads(SECURITY.read_text(encoding="utf-8"))
    expected_root = security["MerkleTree"]["Root"]
    published_key = json.loads(PUBLIC_KEY.read_text(encoding="utf-8"))["PublicKey"]

    assert report["spec_version"] == "1.1"
    assert report["v1_2_supported"] is False
    assert report["result"] == "UNVERIFIABLE"
    assert report["result_ja"] == "検証不能"
    assert report["exit_code"] == 2

    assert report["checks"]["signature"]["result"] == "VALID"
    assert report["checks"]["signature"]["valid_count"] == 40
    assert report["checks"]["signature"]["invalid_count"] == 0
    assert report["checks"]["signature"]["message_encodings"] == {"raw_digest": 40}
    assert report["checks"]["merkle_root"]["result"] == "VALID"
    assert report["checks"]["event_hash"]["result"] == "VALID"
    assert report["checks"]["external_anchor"]["result"] == "UNVERIFIABLE"
    assert report["checks"]["external_anchor"]["anchor_confirmed"] is False
    assert report["checks"]["security_object_signature"]["result"] == "VALID"

    basis = report["basis"]
    assert basis["trusted_key_fingerprint"] == "sha256:" + __import__("hashlib").sha256(
        bytes.fromhex(published_key)
    ).hexdigest()
    assert basis["trusted_public_key_hex"] == published_key
    assert basis["anchor_checked"] is True
    assert basis["anchor_confirmed"] is False
    assert basis["anchor_proof_present"] is False
    assert basis["expected_merkle_root"] == expected_root
    assert basis["computed_merkle_root"] == expected_root
    assert basis["rfc6962_strict_root"] != expected_root
    assert basis["merkle_algorithm"] == "vcp-1.1-duplicate-odd-node"

    event_range = basis["event_range"]
    assert event_range["count"] == 40
    assert event_range["first_sequence"] == 1
    assert event_range["last_sequence"] == 40
    assert event_range["first_event_id"] == "28e6d6d7-91de-453e-8956-04575b911f14"
    assert event_range["last_event_id"] == "662366b1-e3bd-4963-ae5a-ca2492462244"
    assert event_range["first_timestamp"] == "2025-11-20T20:38:25.482205+09:00"
    assert event_range["last_timestamp"] == "2025-11-21T03:36:48.774980+09:00"

    for phrase in BANNED:
        assert phrase not in json.dumps(report)
        assert phrase not in mod.format_human(report)
    human = mod.format_human(report)
    assert basis["trusted_key_fingerprint"] in human
    assert "Anchor confirmed:         no" in human
    assert "検証不能" in human
    assert "UNVERIFIABLE" in human


def test_genuine_cli_json_exit_code():
    proc = run_cli(genuine_args() + ["--json"])
    assert proc.returncode == 2, proc.stderr
    report = json.loads(proc.stdout)
    assert report["result"] == "UNVERIFIABLE"
    assert report["checks"]["signature"]["result"] == "VALID"
    assert report["checks"]["merkle_root"]["result"] == "VALID"
    assert report["checks"]["external_anchor"]["result"] == "UNVERIFIABLE"
    assert report["basis"]["anchor_confirmed"] is False
    for phrase in BANNED:
        assert phrase not in proc.stdout


def test_tampered_chain_is_invalid():
    mod = load_verifier()
    report = mod.verify_paths(
        str(TAMPERED),
        security_object_path=str(SECURITY),
        public_key_path=str(PUBLIC_KEY),
        anchor_path=str(ANCHOR),
    )
    assert report["result"] == "INVALID"
    assert report["exit_code"] == 1
    assert report["checks"]["sequence"]["result"] == "INVALID"
    assert report["checks"]["prev_hash"]["result"] == "INVALID"
    assert report["checks"]["merkle_root"]["result"] == "INVALID"
    assert report["checks"]["batch_bounds"]["result"] == "INVALID"
    # Omission does not forge the remaining signatures.
    assert report["checks"]["signature"]["result"] == "VALID"
    assert report["checks"]["signature"]["valid_count"] == 39
    assert report["basis"]["event_range"]["count"] == 39
    assert report["basis"]["anchor_confirmed"] is False

    proc = run_cli(
        [
            str(TAMPERED),
            "-s",
            str(SECURITY),
            "-k",
            str(PUBLIC_KEY),
            "-a",
            str(ANCHOR),
            "--json",
        ]
    )
    assert proc.returncode == 1
    assert json.loads(proc.stdout)["result"] == "INVALID"


def test_tampered_chain_without_expected_root_does_not_pass_merkle():
    mod = load_verifier()
    report = mod.verify_paths(str(TAMPERED), public_key_path=str(PUBLIC_KEY))
    assert report["checks"]["merkle_root"]["result"] == "UNVERIFIABLE"
    assert report["checks"]["merkle_root"]["result"] != "VALID"
    assert report["result"] == "INVALID"
    assert report["exit_code"] == 1
    assert "not a pass" in report["checks"]["merkle_root"]["detail"]


def test_missing_expected_root_is_unverifiable():
    mod = load_verifier()
    report = mod.verify_paths(str(EVENTS), public_key_path=str(PUBLIC_KEY))
    assert report["checks"]["signature"]["result"] == "VALID"
    assert report["checks"]["merkle_root"]["result"] == "UNVERIFIABLE"
    assert report["checks"]["merkle_root"]["computed_root"]
    assert report["checks"]["audit_path"]["result"] == "UNVERIFIABLE"
    assert report["checks"]["external_anchor"]["result"] == "UNVERIFIABLE"
    assert report["basis"]["expected_merkle_root"] is None
    assert report["basis"]["anchor_confirmed"] is False
    assert report["result"] == "UNVERIFIABLE"
    assert report["exit_code"] == 2
    assert report["checks"]["merkle_root"]["computed_root"] != report["basis"]["rfc6962_strict_root"]

    proc = run_cli([str(EVENTS), "-k", str(PUBLIC_KEY), "--json"])
    assert proc.returncode == 2
    body = json.loads(proc.stdout)
    assert body["checks"]["merkle_root"]["result"] == "UNVERIFIABLE"
    assert body["result"] == "UNVERIFIABLE"


def test_wrong_key_invalidates_signatures(tmp_path: Path):
    private = Ed25519PrivateKey.generate()
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_path = tmp_path / "wrong_public_key.json"
    key_path.write_text(
        json.dumps({"Algorithm": "ED25519", "PublicKey": raw.hex()}),
        encoding="utf-8",
    )
    mod = load_verifier()
    report = mod.verify_paths(
        str(EVENTS),
        security_object_path=str(SECURITY),
        public_key_path=str(key_path),
        anchor_path=str(ANCHOR),
    )
    assert report["checks"]["signature"]["result"] == "INVALID"
    assert report["checks"]["signature"]["valid_count"] == 0
    assert report["checks"]["signature"]["invalid_count"] == 40
    assert report["checks"]["security_object_signature"]["result"] == "INVALID"
    assert report["result"] == "INVALID"
    assert report["exit_code"] == 1
    assert report["basis"]["trusted_key_fingerprint"] != load_verifier().verify_paths(
        str(EVENTS), public_key_path=str(PUBLIC_KEY)
    )["basis"]["trusted_key_fingerprint"]

    proc = run_cli(
        [str(EVENTS), "-s", str(SECURITY), "-k", str(key_path), "--json"]
    )
    assert proc.returncode == 1
    body = json.loads(proc.stdout)
    assert body["checks"]["signature"]["result"] == "INVALID"
    assert body["result"] == "INVALID"


def test_missing_trusted_key_does_not_pass_signatures():
    mod = load_verifier()
    report = mod.verify_paths(
        str(EVENTS),
        security_object_path=str(SECURITY),
        anchor_path=str(ANCHOR),
    )
    assert report["checks"]["signature"]["result"] == "UNVERIFIABLE"
    assert report["basis"]["trusted_key_fingerprint"] is None
    assert report["result"] == "UNVERIFIABLE"


def test_missing_ots_file_is_not_confirmed_and_ots_is_not_called(monkeypatch: pytest.MonkeyPatch):
    mod = load_verifier()

    def forbid_ots(*_args, **_kwargs):
        raise AssertionError("ots verify must not run when the proof file is absent")

    monkeypatch.setattr(mod, "run_ots_verify", forbid_ots)
    report = mod.verify_paths(
        str(EVENTS),
        security_object_path=str(SECURITY),
        public_key_path=str(PUBLIC_KEY),
        anchor_path=str(ANCHOR),
    )
    assert report["checks"]["external_anchor"]["result"] == "UNVERIFIABLE"
    assert report["basis"]["anchor_confirmed"] is False
    assert report["basis"]["anchor_proof_present"] is False


def test_ots_confirm_requires_tool_success_text(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    mod = load_verifier()
    proof = tmp_path / "merkle_root.ots"
    proof.write_bytes(b"placeholder")

    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    missing_tool = mod.run_ots_verify(str(proof))
    assert missing_tool["confirmed"] is False
    assert missing_tool["result"] == "UNVERIFIABLE"

    class Success:
        returncode = 0
        stdout = "Success! Bitcoin block 1 attests data existed as of 2026-01-04"
        stderr = ""

    monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/ots")
    monkeypatch.setattr(mod.subprocess, "run", lambda *args, **kwargs: Success())
    confirmed = mod.run_ots_verify(str(proof))
    assert confirmed["confirmed"] is True
    assert confirmed["result"] == "VALID"

    class Ambiguous:
        returncode = 0
        stdout = "finished"
        stderr = ""

    monkeypatch.setattr(mod.subprocess, "run", lambda *args, **kwargs: Ambiguous())
    ambiguous = mod.run_ots_verify(str(proof))
    assert ambiguous["confirmed"] is False
    assert ambiguous["result"] == "UNVERIFIABLE"


def test_event_hashes_match_the_stored_digests():
    mod = load_verifier()
    events = mod.load_events(str(EVENTS))
    assert len(events) == 40
    for event in events:
        assert mod.event_content_hash(event) == event["Security"]["EventHash"]
