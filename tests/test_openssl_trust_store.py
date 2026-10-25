"""Actual synthetic RFC 3161 checks; no external TSA or production trust claim."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Reuse the local, short-lived CA/TSA and batch fixtures, never production keys.
from test_attested_batch import tsa, batch, POLICY_OID, extension


def test_ca_file_and_store_use_exact_same_caller_bundle(tsa, batch, monkeypatch):
    data = extension.anchor_bytes(batch.envelope)
    response = tsa.issue(data)
    real_run = extension.subprocess.run
    calls = []

    def inspect(command, **kwargs):
        if command[1:3] == ["ts", "-verify"]:
            cafile = Path(command[command.index("-CAfile") + 1])
            capath = Path(command[command.index("-CApath") + 1])
            uri = urlparse(command[command.index("-CAstore") + 1])
            assert uri.scheme == "file" and not uri.netloc
            assert Path(unquote(uri.path)) == cafile
            assert cafile.read_bytes() == tsa.ca
            assert capath.is_dir() and not list(capath.iterdir())
            assert kwargs["env"]["SSL_CERT_FILE"] == str(cafile)
            assert kwargs["env"]["SSL_CERT_DIR"] == str(capath)
            calls.append(command)
        return real_run(command, **kwargs)

    monkeypatch.setattr(extension.subprocess, "run", inspect)
    result = extension.verify_rfc3161(data, response, tsa.ca, POLICY_OID)
    assert result["status"] == "VALID", result
    assert len(calls) == 1


def test_untrusted_chain_and_environment_cannot_replace_caller_ca(tsa, batch, monkeypatch):
    data = extension.anchor_bytes(batch.envelope)
    response = tsa.issue(data)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "UNRELATED TEST ROOT")])
    now = datetime.now(timezone.utc)
    wrong_ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(41)
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("SSL_CERT_FILE", str(tsa.directory / "ca.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(tsa.directory))
    result = extension.verify_rfc3161(data, response, wrong_ca, POLICY_OID,
                                     untrusted_pem=tsa.cert + tsa.ca)
    assert result["status"] == "INDETERMINATE", result
    assert result["reason"] == "RFC3161_SIGNATURE_OR_CHAIN_NOT_VERIFIED"
