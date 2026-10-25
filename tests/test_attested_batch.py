"""Synthetic local cryptographic tests, not independent production evidence."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DIRECTORY = Path(__file__).resolve().parents[1] / "tools" / "verifier"
sys.path.insert(0, str(DIRECTORY))
import verify_attested_batch as extension
import vcp_verifier as legacy

VALID, INVALID, INDETERMINATE = "VALID", "INVALID", "INDETERMINATE"
POLICY_OID = "1.2.3.4.1"  # Test-only policy, not a registered VSO identifier.


def independent_root_and_paths(hashes_):
    leaf = [hashlib.sha256(b"\0" + bytes.fromhex(h)).digest() for h in hashes_]
    levels = [leaf]
    while len(levels[-1]) > 1:
        row = levels[-1]
        if len(row) % 2:
            row = row + [row[-1]]
        levels.append([hashlib.sha256(b"\1" + row[i] + row[i + 1]).digest()
                       for i in range(0, len(row), 2)])
    paths = []
    for index in range(len(hashes_)):
        path = []
        for row in levels[:-1]:
            other = index ^ 1
            if other >= len(row):
                other = index
            path.append({"position": "left" if index % 2 else "right", "hash": row[other].hex()})
            index //= 2
        paths.append(path)
    return levels[-1][0].hex(), paths


def fixture_batch(count=3):
    # Publicly reproducible test seeds only. Never use these keys operationally.
    event_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    attestor = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    events = []
    for i in range(count):
        e = {"Header": {"EventID": "test-event-%d" % i, "Sequence": i + 1},
             "Payload": {"Value": i},
             "Security": {"Version": "1.1", "HashAlgo": "SHA256", "SignAlgo": "ED25519"},
             "PolicyIdentification": {"PolicyID": "test-policy-v1", "ConformanceTier": "SILVER",
               "RegistrationPolicy": {"Issuer": "local-test"},
               "VerificationDepth": {"HashChainValidation": True, "MerkleProofRequired": True,
                                      "ExternalAnchorRequired": True}}}
        digest = hashlib.sha256((json.dumps(e["Header"], sort_keys=True) +
                                 json.dumps(e["Payload"], sort_keys=True)).encode()).hexdigest()
        e["Security"].update(EventHash=digest, Signature=event_key.sign(bytes.fromhex(digest)).hex())
        if events:
            e["Security"]["PrevHash"] = events[-1]["Security"]["EventHash"]
        events.append(e)
    root, paths = independent_root_and_paths([e["Security"]["EventHash"] for e in events])
    for i, e in enumerate(events):
        e["Security"].update(MerkleRoot=root, MerkleIndex=i, AuditPath=paths[i])
    record = {"VCPVersion": "1.1", "MerkleRoot": root, "EventCount": count,
              "FirstSequence": 1, "LastSequence": count, "PolicyID": "test-policy-v1",
              "SignAlgo": "ED25519", "Signature": event_key.sign(bytes.fromhex(root)).hex()}
    statement = {**extension.CONSTANTS, "context_id": "local-test-reassessment",
                 "merkle_root": root, "event_count": str(count), "first_event_id": "test-event-0",
                 "last_event_id": "test-event-%d" % (count - 1), "first_sequence": "1",
                 "last_sequence": str(count), "policy_id": "test-policy-v1",
                 "issued_at": "2026-10-26T00:00:00Z",
                 "events_snapshot_sha256": snapshot(events), "security_object_sha256": snapshot(record)}
    envelope = sign(statement, attestor)
    return SimpleNamespace(events=events, record=record, envelope=envelope, attestor=attestor,
                           public_key=event_key.public_key().public_bytes_raw(),
                           attestor_key=attestor.public_key().public_bytes_raw(),
                           expected_context="local-test-reassessment")


def snapshot(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                         separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()


def sign(statement, key):
    msg = (b"VCP-RTA-SUPPLEMENTAL-STATEMENT\x00v1\x00" +
           json.dumps(statement, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode())
    return {"statement": statement, "signature": base64.b64encode(key.sign(msg)).decode()}


@pytest.fixture
def batch():
    return fixture_batch()


def args(batch):
    return dict(envelope=batch.envelope, attestor_key=batch.attestor_key,
                expected_context=batch.expected_context)


def invoke(batch, **overrides):
    kwargs = args(batch)
    kwargs.update(overrides)
    return extension.verify_attested_chain(batch.events, batch.record, batch.public_key, **kwargs)


@pytest.mark.parametrize("count", [1, 2, 3, 5, 8, 17, 40])
def test_metadata_real_signature_and_independent_trees(count):
    batch = fixture_batch(count)
    r = invoke(batch)
    assert r["checks"]["authenticated_batch_metadata"]["status"] == VALID
    assert r["checks"]["event_signatures"]["status"] == VALID
    assert r["checks"]["merkle_root"]["status"] == VALID
    assert r["checks"]["audit_path"]["status"] == VALID
    assert r["checks"]["external_anchor"]["status"] == INDETERMINATE
    assert r["status"] == INDETERMINATE  # Missing token and original chain boundary.
    assert not r["conformance_claim"]


@pytest.mark.parametrize("field", sorted(extension.FIELDS))
def test_each_signed_field_tampering_rejected(batch, field):
    env = copy.deepcopy(batch.envelope)
    env["statement"][field] += "tampered"
    assert extension.check_signature(env, batch.attestor_key)["status"] == INVALID


@pytest.mark.parametrize("field,value", [
    ("event_count", "4"), ("first_sequence", "2"), ("last_sequence", "4"),
    ("first_event_id", "other"), ("last_event_id", "other"), ("policy_id", "other"),
    ("merkle_root", "f" * 64), ("events_snapshot_sha256", "f" * 64),
    ("security_object_sha256", "f" * 64), ("context_id", "another-context"),
])
def test_even_valid_signature_must_bind_supplied_batch(batch, field, value):
    statement = dict(batch.envelope["statement"], **{field: value})
    env = sign(statement, batch.attestor)
    assert extension.check_signature(env, batch.attestor_key)["status"] == VALID
    r = invoke(batch, envelope=env)
    assert r["checks"]["supplemental_batch_binding"]["status"] == INVALID
    assert r["status"] == INVALID


def test_policy_entire_object_protected_not_only_identifier(batch):
    old_hash = batch.events[0]["Security"]["EventHash"]
    batch.events[0]["PolicyIdentification"]["VerificationDepth"]["ExternalAnchorRequired"] = False
    assert legacy.event_content_hash(batch.events[0]) == old_hash
    assert invoke(batch)["checks"]["authenticated_batch_metadata"]["status"] == INVALID


def test_security_object_snapshot_protected(batch):
    batch.record["AgentID"] = "another-party"
    assert invoke(batch)["status"] == INVALID


def test_duplicate_odd_root_alias_does_not_pass_metadata(batch):
    batch.events.append(copy.deepcopy(batch.events[-1]))
    root, _ = independent_root_and_paths([e["Security"]["EventHash"] for e in batch.events])
    assert root == batch.record["MerkleRoot"]
    assert invoke(batch)["checks"]["authenticated_batch_metadata"]["status"] == INVALID


@pytest.mark.parametrize("key", [None, b"", b"x", "not bytes"])
def test_missing_or_unusable_attestor_key_does_not_pass(batch, key):
    assert invoke(batch, attestor_key=key)["checks"]["authenticated_batch_metadata"]["status"] == INDETERMINATE


def test_wrong_trusted_key_is_signature_mismatch(batch):
    assert extension.check_signature(batch.envelope, batch.public_key)["status"] == INVALID


def test_bad_signature_survives_missing_events_and_proof(batch):
    env = copy.deepcopy(batch.envelope)
    env["signature"] = base64.b64encode(b"\0" * 64).decode()
    r = extension.verify_attested_chain([], envelope=env, attestor_key=batch.attestor_key)
    assert r["checks"]["supplemental_signature"]["status"] == INVALID
    assert r["status"] == INVALID


def test_existing_failure_survives_missing_new_inputs(batch):
    batch.events[0]["Security"]["Signature"] = "00" * 64
    assert invoke(batch, envelope=None, attestor_key=None)["status"] == INVALID


@pytest.mark.parametrize("context", [None, ""])
def test_context_is_not_inferred_from_statement(batch, context):
    assert invoke(batch, expected_context=context)["checks"]["authenticated_batch_metadata"]["status"] == INDETERMINATE


@pytest.mark.parametrize("value", [None, {}, [], "bad", {"statement": {}},
                                    {"statement": {}, "signature": ""}])
def test_malformed_envelope_not_accepted(batch, value):
    assert invoke(batch, envelope=value)["checks"]["authenticated_batch_metadata"]["status"] != VALID


def test_unknown_field_not_silently_unsigned(batch):
    batch.envelope["PublicKey"] = base64.b64encode(batch.attestor_key).decode()
    assert invoke(batch)["status"] == INVALID


def test_statement_serialization_and_anchor_byte_contract(batch):
    statement = batch.envelope["statement"]
    statement["context_id"] = "日本語\u0000context"
    env = sign(statement, batch.attestor)
    canonical = json.dumps(statement, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    message = b"VCP-RTA-SUPPLEMENTAL-STATEMENT\x00v1\x00" + canonical
    assert extension.statement_bytes(statement) == message
    assert extension.anchor_bytes(env) == b"VCP-RTA-SUPPLEMENTAL-ANCHOR\x00v1\x00" + message + base64.b64decode(env["signature"])
    assert extension.check_signature(env, batch.attestor_key)["status"] == VALID


def run(command, **kwargs):
    result = subprocess.run(command, capture_output=True, check=False, **kwargs)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result


@pytest.fixture(scope="module")
def tsa(tmp_path_factory):
    if not shutil.which("openssl"):
        pytest.skip("OpenSSL executable required for actual RFC3161 integration tests")
    directory = tmp_path_factory.mktemp("local-test-tsa")
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LOCAL TEST CA ONLY")])
    tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LOCAL TEST TSA ONLY")])
    def base(subject, issuer, key, serial):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key()).serial_number(serial)
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=3)))
    ca = (base(ca_name, ca_name, ca_key, 1)
          .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf = (base(tsa_name, ca_name, tsa_key, 2)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .sign(ca_key, hashes.SHA256()))
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (directory / "tsa.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (directory / "tsa.key").write_bytes(tsa_key.private_bytes(serialization.Encoding.PEM,
             serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (directory / "tsa.key").chmod(0o600)
    (directory / "serial").write_text("01")
    config = f"""[tsa]
default_tsa = test_tsa
[test_tsa]
serial = {directory}/serial
signer_cert = {directory}/tsa.pem
certs = {directory}/ca.pem
signer_key = {directory}/tsa.key
signer_digest = sha256
default_policy = {POLICY_OID}
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = yes
ess_cert_id_alg = sha256
"""
    (directory / "tsa.cnf").write_text(config)
    def issue(data):
        (directory / "data.bin").write_bytes(data)
        run(["openssl", "ts", "-query", "-data", str(directory / "data.bin"), "-sha256",
             "-cert", "-no_nonce", "-tspolicy", POLICY_OID, "-out", str(directory / "request.tsq")])
        run(["openssl", "ts", "-reply", "-config", str(directory / "tsa.cnf"),
             "-queryfile", str(directory / "request.tsq"), "-out", str(directory / "response.tsr")])
        return (directory / "response.tsr").read_bytes()
    return SimpleNamespace(issue=issue, ca=ca.public_bytes(serialization.Encoding.PEM),
                           cert=leaf.public_bytes(serialization.Encoding.PEM), directory=directory)


def test_real_rfc3161_response_signature_chain_and_imprint(tsa, batch):
    data = extension.anchor_bytes(batch.envelope)
    response = tsa.issue(data)
    assert extension.verify_rfc3161(data, response, tsa.ca, POLICY_OID)["status"] == VALID
    r = invoke(batch, response=response, ca_pem=tsa.ca, policy_oid=POLICY_OID)
    assert r["checks"]["authenticated_batch_metadata"]["status"] == VALID
    assert r["checks"]["external_anchor"]["status"] == VALID
    assert r["status"] == INDETERMINATE  # Preserves unresolved historical chain boundary.


def test_other_data_timestamp_rejected(tsa, batch):
    response = tsa.issue(b"unrelated file, not a batch")
    r = invoke(batch, response=response, ca_pem=tsa.ca, policy_oid=POLICY_OID)
    assert r["checks"]["rfc3161_token"]["reason"] == "RFC3161_IMPRINT_MISMATCH"
    assert r["status"] == INVALID


def test_policy_oid_must_match(tsa, batch):
    data = extension.anchor_bytes(batch.envelope)
    assert extension.verify_rfc3161(data, tsa.issue(data), tsa.ca, "1.2.3.4.2")["status"] == INVALID


def test_no_ca_is_not_trust(tsa, batch):
    data = extension.anchor_bytes(batch.envelope)
    assert extension.verify_rfc3161(data, tsa.issue(data), None, POLICY_OID)["status"] == INDETERMINATE


def test_wrong_ca_cannot_fall_back_to_environment(tsa, batch, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WRONG TEST CA")])
    now = datetime.now(timezone.utc)
    wrong = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
             .serial_number(30).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1))
             .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
             .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("SSL_CERT_FILE", str(tsa.directory / "ca.pem"))
    data = extension.anchor_bytes(batch.envelope)
    assert extension.verify_rfc3161(data, tsa.issue(data), wrong, POLICY_OID)["status"] == INDETERMINATE


def test_tampered_cms_signature_never_passes(tsa, batch):
    data = extension.anchor_bytes(batch.envelope)
    parsed = extension.tsp.TimeStampResp.load(tsa.issue(data))
    signer = parsed["time_stamp_token"]["content"]["signer_infos"][0]
    sig = signer["signature"].native
    signer["signature"] = bytes([sig[0] ^ 1]) + sig[1:]
    result = extension.verify_rfc3161(data, parsed.dump(), tsa.ca, POLICY_OID)
    assert result["status"] == INDETERMINATE
    assert "NOT_VERIFIED" in result["reason"]


@pytest.mark.parametrize("data", [b"", b"nonsense", b"\x30\x80", b"\0"*10])
def test_malformed_timestamp_never_passes(data):
    assert extension.verify_rfc3161(b"data", data, b"bad CA", POLICY_OID)["status"] != VALID


def test_trailing_timestamp_bytes_rejected(tsa, batch):
    data = extension.anchor_bytes(batch.envelope)
    assert extension.verify_rfc3161(data, tsa.issue(data) + b"trailing", tsa.ca, POLICY_OID)["status"] == INVALID


def test_missing_executable_is_indeterminate(tsa, batch):
    data = extension.anchor_bytes(batch.envelope)
    assert extension.verify_rfc3161(data, tsa.issue(data), tsa.ca, POLICY_OID,
                                   openssl="/no-such-openssl")["status"] == INDETERMINATE


def test_timeout_not_pass(tsa, batch, monkeypatch):
    data = extension.anchor_bytes(batch.envelope)
    response = tsa.issue(data)
    def timeout(*a, **kw):
        raise subprocess.TimeoutExpired("openssl", 15)
    monkeypatch.setattr(extension.subprocess, "run", timeout)
    assert extension.verify_rfc3161(data, response, tsa.ca, POLICY_OID)["status"] == INDETERMINATE


def test_success_text_with_failed_exit_not_pass(tsa, batch, monkeypatch):
    data = extension.anchor_bytes(batch.envelope)
    response = tsa.issue(data)
    monkeypatch.setattr(extension.subprocess, "run", lambda *a, **kw:
                        SimpleNamespace(returncode=1, stdout=b"Verification: OK", stderr=b""))
    assert extension.verify_rfc3161(data, response, tsa.ca, POLICY_OID)["status"] == INDETERMINATE


def test_bad_signature_remains_invalid_when_real_timestamp_valid(tsa, batch):
    batch.envelope["signature"] = base64.b64encode(b"\0" * 64).decode()
    response = tsa.issue(extension.anchor_bytes(batch.envelope))
    r = invoke(batch, response=response, ca_pem=tsa.ca, policy_oid=POLICY_OID)
    assert r["checks"]["rfc3161_token"]["status"] == VALID
    assert r["status"] == INVALID


def test_timestamp_runs_without_attestor_key(tsa, batch):
    response = tsa.issue(extension.anchor_bytes(batch.envelope))
    r = invoke(batch, response=response, ca_pem=tsa.ca, policy_oid=POLICY_OID, attestor_key=None)
    assert r["checks"]["rfc3161_token"]["status"] == VALID
    assert r["checks"]["external_anchor"]["status"] == INDETERMINATE


def write_cli_inputs(tmp_path, batch):
    (tmp_path / "events.jsonl").write_text("".join(json.dumps(e)+"\n" for e in batch.events))
    (tmp_path / "record.json").write_text(json.dumps(batch.record))
    (tmp_path / "attestation.json").write_text(json.dumps(batch.envelope))
    (tmp_path / "event.pub").write_bytes(batch.public_key)
    (tmp_path / "attestor.pub").write_bytes(batch.attestor_key)
    return [sys.executable, str(DIRECTORY / "verify_attested_batch.py"), str(tmp_path / "events.jsonl"),
            "-s", str(tmp_path / "record.json"), "--public-key", str(tmp_path / "event.pub"),
            "--attestation", str(tmp_path / "attestation.json"), "--attestor-key", str(tmp_path / "attestor.pub"),
            "--expected-context", batch.expected_context, "--json"]


def test_cli_real_timestamp_integration(tsa, batch, tmp_path):
    cmd = write_cli_inputs(tmp_path, batch)
    (tmp_path / "proof.tsr").write_bytes(tsa.issue(extension.anchor_bytes(batch.envelope)))
    (tmp_path / "ca.pem").write_bytes(tsa.ca)
    cmd += ["--tsa-response", str(tmp_path / "proof.tsr"), "--tsa-ca-file", str(tmp_path / "ca.pem"),
            "--tsa-policy-oid", POLICY_OID]
    p = subprocess.run(cmd, capture_output=True, timeout=25)
    assert p.returncode == 2, p.stderr
    r = json.loads(p.stdout)
    assert r["checks"]["external_anchor"]["status"] == VALID
    assert not r["conformance_claim"]


def test_cli_missing_optional_input_does_not_hide_bad_signature(batch, tmp_path):
    batch.events[0]["Security"]["Signature"] = "00" * 64
    cmd = write_cli_inputs(tmp_path, batch) + ["--tsa-response", str(tmp_path / "missing.tsr")]
    p = subprocess.run(cmd, capture_output=True, timeout=25)
    assert p.returncode == 1
    assert json.loads(p.stdout)["checks"]["response_input"]["status"] == INDETERMINATE


def test_input_bytes_unchanged(batch, tmp_path):
    cmd = write_cli_inputs(tmp_path, batch)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    subprocess.run(cmd, capture_output=True, timeout=25)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_duplicate_json_keys_rejected_cli(batch, tmp_path):
    cmd = write_cli_inputs(tmp_path, batch)
    (tmp_path / "attestation.json").write_text('{"statement":{},"statement":{}}')
    p = subprocess.run(cmd, capture_output=True, timeout=25)
    assert p.returncode == 2
    assert json.loads(p.stdout)["checks"]["envelope_input"]["status"] == INDETERMINATE


def test_regular_file_bound(tmp_path):
    p = tmp_path / "too-big"
    p.write_bytes(b"0" * (extension.MAX_FILE_BYTES + 1))
    with pytest.raises(ValueError):
        extension.bounded_read(str(p))


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX FIFO test")
def test_fifo_is_rejected_without_blocking(tmp_path):
    p = tmp_path / "fifo"
    os.mkfifo(p)
    with pytest.raises(ValueError):
        extension.bounded_read(str(p))


def test_missing_asn1_dependency_keeps_other_mismatches(batch, monkeypatch):
    monkeypatch.setattr(extension, "tsp", None)
    batch.events[0]["Security"]["Signature"] = "00" * 64
    r = invoke(batch, response=b"not parsed without dependency", ca_pem=b"ca", policy_oid=POLICY_OID)
    assert r["checks"]["rfc3161_token"]["status"] == INDETERMINATE
    assert r["status"] == INVALID


def test_missing_crypto_dependency_never_passes_metadata(batch, monkeypatch):
    monkeypatch.setattr(legacy, "Ed25519PublicKey", None)
    assert invoke(batch)["checks"]["authenticated_batch_metadata"]["status"] == INDETERMINATE


def test_unencodable_snapshot_cannot_hide_context_mismatch(batch):
    batch.events[0]["Payload"]["invalid_float"] = float("nan")
    result = extension.check_bindings(batch.envelope, batch.events, batch.record, "wrong-context")
    assert result["status"] == INVALID
    assert "context_id_MISMATCH" in result["reason"]


def test_unencodable_record_cannot_hide_count_mismatch(batch):
    batch.record["invalid"] = float("nan")
    batch.record["EventCount"] = 999
    result = extension.check_bindings(batch.envelope, batch.events, batch.record, batch.expected_context)
    assert result["status"] == INVALID


def test_both_inputs_and_return_values_not_modified(batch):
    before = copy.deepcopy((batch.events, batch.record, batch.envelope))
    invoke(batch)
    assert (batch.events, batch.record, batch.envelope) == before
