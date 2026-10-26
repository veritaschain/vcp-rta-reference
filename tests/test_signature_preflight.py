"""Signature syntax is independent of key availability. Synthetic fixtures only."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DIRECTORY = Path(__file__).resolve().parents[1] / "tools/verifier"
sys.path.insert(0, str(DIRECTORY))
import vcp_verifier as v

PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))  # TEST ONLY
PUBLIC = PRIVATE.public_key().public_bytes_raw()
IDENTITY = bytes([1]) + bytes(31)
DIGEST = hashlib.sha256(b"synthetic signature-preflight message").hexdigest()
BAD_SIGNATURES = [
    pytest.param(7, "MALFORMED_SIGNATURE", id="number"),
    pytest.param(False, "MALFORMED_SIGNATURE", id="boolean"),
    pytest.param([], "MALFORMED_SIGNATURE", id="array"),
    pytest.param({}, "MALFORMED_SIGNATURE", id="object"),
    pytest.param("not*base64", "MALFORMED_SIGNATURE_ENCODING", id="bad-base64"),
    pytest.param("署名", "MALFORMED_SIGNATURE_ENCODING", id="non-ascii"),
    pytest.param(base64.b64encode(bytes(63)).decode(), "MALFORMED_SIGNATURE_LENGTH", id="63-bytes"),
    pytest.param(base64.b64encode(bytes(65)).decode(), "MALFORMED_SIGNATURE_LENGTH", id="65-bytes"),
]


@pytest.mark.parametrize("signature,reason", BAD_SIGNATURES)
@pytest.mark.parametrize("missing", ["key", "digest", "rejected-key"])
def test_observable_signature_syntax_is_not_hidden(signature, reason, missing):
    key = None if missing == "key" else IDENTITY if missing == "rejected-key" else PUBLIC
    digest = None if missing == "digest" else DIGEST
    result = v.verify_digest_signature(signature, digest, "ED25519", key, "raw_digest")
    assert result == v.check(v.INVALID, reason)


def test_malformed_signature_does_not_require_backend_or_key_admission(monkeypatch):
    def forbidden(_):
        raise AssertionError("syntactic failure attempted key admission")
    monkeypatch.setattr(v, "ed25519_public_key_problem", forbidden)
    monkeypatch.setattr(v, "Ed25519PublicKey", None)
    assert v.verify_digest_signature("***", None, "ED25519", PUBLIC, "raw_digest") == v.check(
        v.INVALID, "MALFORMED_SIGNATURE_ENCODING")


@pytest.mark.parametrize("algorithm", [None, "FUTURE", [], {}])
def test_unknown_algorithms_do_not_inherit_ed25519_syntax(algorithm):
    assert v.verify_digest_signature([], DIGEST, algorithm, None, "raw_digest") == v.check(
        v.INDETERMINATE, "SIGNATURE_ALGORITHM_UNSUPPORTED_OR_MISSING")


@pytest.mark.parametrize("signature", [None, ""])
@pytest.mark.parametrize("key,reason", [(None, "TRUSTED_KEY_MISSING"),
    (PUBLIC, "SIGNATURE_MISSING"), (IDENTITY, "TRUSTED_KEY_REJECTED:IDENTITY_POINT")])
def test_absent_signatures_preserve_existing_missing_input_priority(signature, key, reason):
    assert v.verify_digest_signature(signature, DIGEST, "ED25519", key, "raw_digest") == v.check(
        v.INDETERMINATE, reason)


@pytest.mark.parametrize("message_encoding", ["raw_digest", "ascii_hex"])
@pytest.mark.parametrize("wire_encoding", ["hex", "base64"])
def test_syntax_success_is_not_cryptographic_success(message_encoding, wire_encoding):
    message = bytes.fromhex(DIGEST) if message_encoding == "raw_digest" else DIGEST.encode("ascii")
    signature = PRIVATE.sign(message)
    encode = (lambda s: s.hex()) if wire_encoding == "hex" else (lambda s: base64.b64encode(s).decode())
    value = encode(signature)
    call = lambda sig, key, digest=DIGEST: v.verify_digest_signature(sig, digest, "ED25519", key, message_encoding)
    assert call(value, None) == v.check(v.INDETERMINATE, "TRUSTED_KEY_MISSING")
    assert call(value, PUBLIC, None) == v.check(v.INDETERMINATE, "SIGNATURE_MESSAGE_UNAVAILABLE")
    assert call(value, IDENTITY) == v.check(v.INDETERMINATE, "TRUSTED_KEY_REJECTED:IDENTITY_POINT")
    assert call(value, PUBLIC)["status"] == v.VALID
    altered = bytes([signature[0] ^ 1]) + signature[1:]
    assert call(encode(altered), PUBLIC) == v.check(v.INVALID, "SIGNATURE_MISMATCH")
    assert call(encode(altered), None)["status"] == v.INDETERMINATE


def fixture():
    event = {"Header": {"Sequence": 1, "EventID": "syntax-test"}, "Payload": {"value": 3},
        "PolicyIdentification": {"PolicyID": "test", "ConformanceTier": "SILVER",
            "RegistrationPolicy": {"Issuer": "synthetic"}, "VerificationDepth": {
                "HashChainValidation": True, "MerkleProofRequired": True, "ExternalAnchorRequired": True}},
        "Security": {"Version": "1.1", "HashAlgo": "SHA256", "SignAlgo": "ED25519"}}
    digest = hashlib.sha256((json.dumps(event["Header"], sort_keys=True) +
                            json.dumps(event["Payload"], sort_keys=True)).encode()).hexdigest()
    root = hashlib.sha256(b"\x00" + bytes.fromhex(digest)).hexdigest()
    event["Security"].update(EventHash=digest, Signature=PRIVATE.sign(bytes.fromhex(digest)).hex(),
                             MerkleRoot=root, MerkleIndex=0, AuditPath=[])
    record = {"VCPVersion": "1.1", "MerkleRoot": root, "SignAlgo": "ED25519",
        "Signature": PRIVATE.sign(bytes.fromhex(root)).hex(), "EventCount": 1,
        "FirstSequence": 1, "LastSequence": 1}
    return [event], record


@pytest.mark.parametrize("target", ["event", "root"])
def test_missing_proof_and_key_do_not_hide_signature_shape_failure(target):
    events, record = fixture()
    events[0]["Security"].pop("AuditPath")
    (events[0]["Security"] if target == "event" else record)["Signature"] = []
    before = copy.deepcopy((events, record))
    report = v.verify_chain(events, record)
    name = "event_signatures" if target == "event" else "anchor_signature"
    assert report["checks"][name]["status"] == v.INVALID
    assert report["checks"]["audit_path"]["status"] == v.INDETERMINATE
    assert report["status"] == v.INVALID and report["conformance_claim"] is False
    assert (events, record) == before


@pytest.mark.parametrize("script", ["vcp_verifier.py", "verify_attested_batch.py"])
@pytest.mark.parametrize("target", ["event", "root"])
@pytest.mark.parametrize("key_state", ["missing", "unreadable", "rejected"])
def test_cli_keeps_syntax_failure_despite_optional_key_problems(tmp_path, script, target, key_state):
    events, record = fixture()
    (events[0]["Security"] if target == "event" else record)["Signature"] = "***"
    event_path, record_path = tmp_path / "events", tmp_path / "record"
    event_path.write_text(json.dumps(events[0]) + "\n")
    record_path.write_text(json.dumps(record))
    command = [sys.executable, str(DIRECTORY / script), str(event_path), "-s", str(record_path), "--json"]
    if key_state != "missing":
        key_path = tmp_path / "key"
        if key_state == "rejected":
            key_path.write_bytes(IDENTITY)
        command += ["--public-key", str(key_path)]
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    proc = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert proc.returncode == 1 and "Traceback" not in proc.stderr
    report = json.loads(proc.stdout)
    name = "event_signatures" if target == "event" else "anchor_signature"
    assert report["checks"][name]["status"] == v.INVALID
    assert report["status"] == v.INVALID and report["conformance_claim"] is False
    if key_state == "unreadable":
        assert any(c["reason"].startswith("INPUT_UNAVAILABLE:") for c in report["checks"].values())
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before
