"""Timestamp-policy isolation using an ephemeral local CA/TSA, not a live service."""
from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DIRECTORY = Path(__file__).resolve().parents[1] / "tools" / "verifier"
sys.path.insert(0, str(DIRECTORY))
import verify_attested_batch as v

POLICY = "1.2.3.4.1"
OTHER_POLICY = "1.2.3.4.2"
DATA = b"synthetic timestamp-policy regression, not historical evidence"
BAD_POLICIES = [None, "", [], {}, True, 1, "1", "3.1", "0.40", "1.40", "1.99",
                "1.02.3", "2.000.3", "01.2.3", "1.2.", "1..2", " 1.2", "1.2 ",
                "1.\u0662.3", "2." + "9" * 4095]


def run(command):
    result = subprocess.run(command, capture_output=True, timeout=15, check=False)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return result


@pytest.fixture(scope="module")
def stamps(tmp_path_factory):
    """Generate real RSA-signed RFC3161 responses with two imprint algorithms."""
    directory = tmp_path_factory.mktemp("test-timestamp-policy")
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SYNTHETIC POLICY TEST CA")])
    tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SYNTHETIC POLICY TEST TSA")])
    def builder(subject, issuer, key, serial):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                .public_key(key.public_key()).serial_number(serial)
                .not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=2)))
    ca = (builder(ca_name, ca_name, ca_key, 1)
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf = (builder(tsa_name, ca_name, tsa_key, 2)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .sign(ca_key, hashes.SHA256()))
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    (directory / "ca.pem").write_bytes(ca_pem)
    (directory / "tsa.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (directory / "tsa.key").write_bytes(tsa_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (directory / "tsa.key").chmod(0o600)
    (directory / "serial").write_text("01\n")
    config = f"""[tsa]
default_tsa = test_tsa
[test_tsa]
serial = {directory}/serial
signer_cert = {directory}/tsa.pem
certs = {directory}/ca.pem
signer_key = {directory}/tsa.key
signer_digest = sha256
default_policy = {POLICY}
digests = sha256, sha384
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = yes
ess_cert_id_alg = sha256
"""
    (directory / "tsa.cnf").write_text(config)
    (directory / "data.bin").write_bytes(DATA)
    responses = {}
    for algorithm in ("sha256", "sha384"):
        query, response = directory / (algorithm + ".tsq"), directory / (algorithm + ".tsr")
        run(["openssl", "ts", "-query", "-data", str(directory / "data.bin"), "-" + algorithm,
             "-cert", "-no_nonce", "-tspolicy", POLICY, "-out", str(query)])
        run(["openssl", "ts", "-reply", "-config", str(directory / "tsa.cnf"),
             "-queryfile", str(query), "-out", str(response)])
        # Verify the issued fixture with OpenSSL independently of our helper.
        run(["openssl", "ts", "-verify", "-queryfile", str(query), "-in", str(response),
             "-CAfile", str(directory / "ca.pem")])
        responses[algorithm] = response.read_bytes()
    return SimpleNamespace(ca=ca_pem, responses=responses)


@pytest.mark.parametrize("ca_kind", ["present", "missing", "unusable"])
@pytest.mark.parametrize("backend_missing", [False, True])
def test_unsupported_imprint_does_not_hide_policy_mismatch(stamps, ca_kind, backend_missing):
    ca = {"present": stamps.ca, "missing": None, "unusable": b"not a CA"}[ca_kind]
    result = v.verify_rfc3161(DATA, stamps.responses["sha384"], ca, OTHER_POLICY,
                             openssl="/nonexistent-timestamp-verifier" if backend_missing else None)
    assert result == v.check(v.INVALID, "RFC3161_POLICY_MISMATCH")


@pytest.mark.parametrize("policy", [POLICY, None, "1.99"])
def test_unsupported_imprint_with_no_demonstrated_mismatch_stays_unknown(stamps, policy):
    assert v.verify_rfc3161(DATA, stamps.responses["sha384"], stamps.ca, policy) == v.check(
        v.INDETERMINATE, "RFC3161_IMPRINT_ALGORITHM_UNSUPPORTED")


@pytest.mark.parametrize("policy", BAD_POLICIES, ids=["bad-%02d" % i for i in range(len(BAD_POLICIES))])
def test_unusable_expected_policy_is_not_an_evidence_mismatch(stamps, policy):
    result = v.verify_rfc3161(DATA, stamps.responses["sha256"], stamps.ca, policy)
    assert result == v.check(v.INDETERMINATE, "TRUSTED_TSA_POLICY_MISSING_OR_UNUSABLE")


@pytest.mark.parametrize("policy", [None, "0.40", "1.02.3", POLICY])
def test_bad_policy_or_missing_ca_does_not_hide_supported_imprint_mismatch(stamps, policy):
    result = v.verify_rfc3161(DATA + b"changed", stamps.responses["sha256"], None, policy)
    assert result == v.check(v.INVALID, "RFC3161_IMPRINT_MISMATCH")


@pytest.mark.parametrize("policy", ["0.0", "0.39", "1.39", "2.0", "2.999.3", "2." + "9" * 4094],
                         ids=["zero", "arc0-39", "arc1-39", "arc2-0", "arc2-large", "4096-char-limit"])
def test_admissible_but_different_oid_still_is_a_policy_mismatch(stamps, policy):
    assert v.verify_rfc3161(DATA, stamps.responses["sha256"], stamps.ca, policy) == v.check(
        v.INVALID, "RFC3161_POLICY_MISMATCH")


def test_matching_sha256_token_still_requires_real_crypto_verification(stamps):
    result = v.verify_rfc3161(DATA, stamps.responses["sha256"], stamps.ca, POLICY)
    assert result["status"] == v.VALID
    assert "SIGNATURE_CHAIN_MATCH" in result["reason"]


def test_missing_ca_still_cannot_pass(stamps):
    assert v.verify_rfc3161(DATA, stamps.responses["sha256"], None, POLICY) == v.check(
        v.INDETERMINATE, "TRUSTED_TSA_CA_MISSING")


def test_altered_signature_is_not_made_valid_by_matching_policy(stamps):
    parsed = v.tsp.TimeStampResp.load(stamps.responses["sha256"])
    signer = parsed["time_stamp_token"]["content"]["signer_infos"][0]
    raw = signer["signature"].native
    signer["signature"] = bytes([raw[0] ^ 1]) + raw[1:]
    result = v.verify_rfc3161(DATA, parsed.dump(), stamps.ca, POLICY)
    assert result == v.check(v.INDETERMINATE, "RFC3161_SIGNATURE_OR_CHAIN_NOT_VERIFIED")


@pytest.mark.parametrize("algorithm,policy", [("sha384", OTHER_POLICY), ("sha384", POLICY),
                                               ("sha256", "1.99")])
def test_incomplete_or_mismatching_fields_never_reach_backend(stamps, monkeypatch, algorithm, policy):
    response = stamps.responses[algorithm]
    def forbidden(*args, **kwargs):
        raise AssertionError("incomplete timestamp verification reached backend")
    monkeypatch.setattr(v.subprocess, "run", forbidden)
    result = v.verify_rfc3161(DATA, response, stamps.ca, policy)
    assert result["status"] != v.VALID


@pytest.mark.parametrize("response", [b"nonsense", b"\x30\x80", b"\0" * 10])
def test_malformed_responses_are_still_invalid(response):
    assert v.verify_rfc3161(DATA, response, None, POLICY)["status"] == v.INVALID


def test_missing_asn1_dependency_is_still_indeterminate(stamps, monkeypatch):
    monkeypatch.setattr(v, "tsp", None)
    assert v.verify_rfc3161(DATA, stamps.responses["sha384"], stamps.ca, OTHER_POLICY) == v.check(
        v.INDETERMINATE, "ASN1_DEPENDENCY_UNAVAILABLE")


def test_token_and_trust_inputs_are_not_mutated(stamps):
    before = {name: hashlib.sha256(value).digest() for name, value in stamps.responses.items()}
    ca_before = hashlib.sha256(stamps.ca).digest()
    for algorithm in stamps.responses:
        for policy in (POLICY, OTHER_POLICY, None, "1.99"):
            v.verify_rfc3161(DATA, stamps.responses[algorithm], stamps.ca, policy)
    assert {name: hashlib.sha256(value).digest() for name, value in stamps.responses.items()} == before
    assert hashlib.sha256(stamps.ca).digest() == ca_before
