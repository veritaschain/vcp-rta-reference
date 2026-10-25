"""Public-key admission tests. Local synthetic fixtures, not identity evidence."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DIRECTORY = Path(__file__).resolve().parents[1] / "tools" / "verifier"
sys.path.insert(0, str(DIRECTORY))
import vcp_verifier as v
import verify_attested_batch as supplemental

IDENTITY = bytes([1]) + bytes(31)
# Not produced by signing or by using any private key.
IDENTITY_SIGNATURE = IDENTITY + bytes(32)
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
# All eight torsion points and B plus each nonidentity torsion point. These
# fixed vectors were constructed using a separate affine group-law oracle.
TORSION_HEX = [
    "0100000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "0000000000000000000000000000000000000000000000000000000000000080",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "0000000000000000000000000000000000000000000000000000000000000000",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
]
MIXED_HEX = [
    "98519eadf35b995233b51b5cd23e9cc5a28b639b5a4af0ec903cb960d81b7819",
    "9bad33f580df7ecc49df5342bac8145d5bedc40f573d1b067f3c4ce449689a15",
    "da99e28ba529cdde35a25fba9059e78ecaee239f99755b9b1aa4f65df00803e2",
    "9599999999999999999999999999999999999999999999999999999999999999",
    "55ae61520ca466adcc4ae4a32dc1633a5d749c64a5b50f136fc3469f27e487e6",
    "5252cc0a7f208133b620acbd4537eba2a4123bf0a8c2e4f980c3b31bb69765ea",
    "13661d745ad63221ca5da0456fa618713511dc60668aa464e55b09a20ff7fc1d",
]
NONCANONICAL = [P.to_bytes(32, "little"), (P+1).to_bytes(32, "little"),
                (2**255-1).to_bytes(32, "little"),
                (1 + 2**255).to_bytes(32, "little"),
                (P-1 + 2**255).to_bytes(32, "little")]
OFF_CURVE = [n.to_bytes(32, "little") for n in (2, 7, 8, 11)]
BAD_POINTS = [bytes.fromhex(x) for x in TORSION_HEX + MIXED_HEX] + NONCANONICAL + OFF_CURVE


def fixture():
    # TEST ONLY. Private keys are used only to create positive synthetic cases.
    signer = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    attestor = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    event = {"Header": {"Sequence": 1, "EventID": "test-event"},
             "Payload": {"Value": 7},
             "Security": {"Version": "1.1", "HashAlgo": "SHA256", "SignAlgo": "ED25519"},
             "PolicyIdentification": {"PolicyID": "test-policy", "ConformanceTier": "SILVER",
                "RegistrationPolicy": {"Issuer": "synthetic-test"},
                "VerificationDepth": {"HashChainValidation": True, "MerkleProofRequired": True,
                                       "ExternalAnchorRequired": True}}}
    digest = hashlib.sha256((json.dumps(event["Header"], sort_keys=True) +
                            json.dumps(event["Payload"], sort_keys=True)).encode()).hexdigest()
    root = hashlib.sha256(b"\x00" + bytes.fromhex(digest)).hexdigest()
    event["Security"].update(EventHash=digest, Signature=signer.sign(bytes.fromhex(digest)).hex(),
                             MerkleRoot=root, MerkleIndex=0, AuditPath=[])
    record = {"VCPVersion": "1.1", "MerkleRoot": root, "EventCount": 1,
              "FirstSequence": 1, "LastSequence": 1, "PolicyID": "test-policy", "SignAlgo": "ED25519",
              "Signature": signer.sign(bytes.fromhex(root)).hex()}
    events = [event]
    def snapshot(value):
        return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
            separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()
    statement = dict(supplemental.CONSTANTS, context_id="synthetic-test-context",
        merkle_root=root, event_count="1", first_event_id="test-event", last_event_id="test-event",
        first_sequence="1", last_sequence="1", policy_id="test-policy", issued_at="2026-10-26T00:00:00Z",
        events_snapshot_sha256=snapshot(events), security_object_sha256=snapshot(record))
    message = b"VCP-RTA-SUPPLEMENTAL-STATEMENT\x00v1\x00" + json.dumps(
        statement, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    env = {"statement": statement, "signature": base64.b64encode(attestor.sign(message)).decode()}
    return events, record, signer, attestor, env


@pytest.mark.parametrize("digest", ["00"*32, "ab"*32, "ff"*32, hashlib.sha256(b"different").hexdigest()])
@pytest.mark.parametrize("encoding", ["raw_digest", "ascii_hex"])
def test_identity_cannot_make_arbitrary_digest_a_verified_signature(digest, encoding):
    result = v.verify_digest_signature(IDENTITY_SIGNATURE.hex(), digest, "ED25519", IDENTITY, encoding)
    assert result["status"] == v.INDETERMINATE
    assert result["reason"] == "TRUSTED_KEY_REJECTED:IDENTITY_POINT"


@pytest.mark.parametrize("context", ["synthetic-test-context", "another-context"])
def test_supplemental_identity_signature_is_rejected(context):
    _, _, _, _, env = fixture()
    env["statement"]["context_id"] = context
    env["signature"] = base64.b64encode(IDENTITY_SIGNATURE).decode()
    assert supplemental.check_signature(env, IDENTITY) == v.check(
        v.INDETERMINATE, "SUPPLEMENTAL_TRUSTED_KEY_REJECTED:IDENTITY_POINT")


@pytest.mark.parametrize("raw", BAD_POINTS, ids=lambda b: b.hex()[:12] + b.hex()[-4:])
def test_rejected_points_do_not_reach_backend(raw, monkeypatch):
    class ForbiddenBackend:
        @staticmethod
        def from_public_bytes(_):
            raise AssertionError("unusable key reached signature backend")
    monkeypatch.setattr(v, "Ed25519PublicKey", ForbiddenBackend)
    assert v.ed25519_public_key_problem(raw) is not None
    result = v.verify_digest_signature(IDENTITY_SIGNATURE.hex(), "ab"*32, "ED25519", raw, "raw_digest")
    assert result["status"] == v.INDETERMINATE and result["reason"].startswith("TRUSTED_KEY_REJECTED:")
    _, _, _, _, env = fixture()
    result = supplemental.check_signature(env, raw)
    assert result["status"] == v.INDETERMINATE and result["reason"].startswith("SUPPLEMENTAL_TRUSTED_KEY_REJECTED:")


@pytest.mark.parametrize("raw", [None, [], {}, True, "01"*32, bytes(31), bytes(33), bytearray(32)])
def test_key_admission_type_and_length_are_checked_before_cache(raw):
    assert v.ed25519_public_key_problem(raw) == "KEY_TYPE_OR_LENGTH"


# RFC 8032 section 7.1 test-vector public keys plus the published reference key.
@pytest.mark.parametrize("raw", [
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    "8f55a71ef23962e173bbb7262b088f1a620e2ff49f27fd0a76dfdaaf774e3e66",
    "5866666666666666666666666666666666666666666666666666666666666666",
])
def test_known_prime_order_keys_are_admitted(raw):
    assert v.ed25519_public_key_problem(bytes.fromhex(raw)) is None


@pytest.mark.parametrize("seed", range(8))
@pytest.mark.parametrize("encoding", ["raw_digest", "ascii_hex"])
def test_generated_key_signatures_and_tampering_keep_existing_verdicts(seed, encoding):
    private = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(bytes([seed])).digest())
    public = private.public_key().public_bytes_raw()
    digest = hashlib.sha256(b"synthetic digest" + bytes([seed])).hexdigest()
    message = bytes.fromhex(digest) if encoding == "raw_digest" else digest.encode()
    sig = private.sign(message)
    assert v.ed25519_public_key_problem(public) is None
    assert v.verify_digest_signature(sig.hex(), digest, "ED25519", public, encoding)["status"] == v.VALID
    bad = bytes([sig[0] ^ 1]) + sig[1:]
    assert v.verify_digest_signature(bad.hex(), digest, "ED25519", public, encoding)["status"] == v.INVALID


def test_rejected_event_key_does_not_hide_payload_mismatch():
    events, record, _, _, _ = fixture()
    events[0]["Security"]["Signature"] = IDENTITY_SIGNATURE.hex()
    record["Signature"] = IDENTITY_SIGNATURE.hex()
    events[0]["Payload"]["Value"] += 1
    r = v.verify_chain(events, record, IDENTITY)
    assert r["checks"]["event_signatures"]["status"] == v.INDETERMINATE
    assert r["checks"]["anchor_signature"]["status"] == v.INDETERMINATE
    assert r["checks"]["event_hash"]["status"] == v.INVALID
    assert r["status"] == v.INVALID


def test_supplemental_good_bindings_cannot_authenticate_identity_signature():
    events, record, signer, _, env = fixture()
    env["signature"] = base64.b64encode(IDENTITY_SIGNATURE).decode()
    before = copy.deepcopy((events, record, env))
    r = supplemental.verify_attested_chain(events, record, signer.public_key().public_bytes_raw(),
        envelope=env, attestor_key=IDENTITY, expected_context="synthetic-test-context")
    assert r["checks"]["supplemental_batch_binding"]["status"] == v.VALID
    assert r["checks"]["event_signatures"]["status"] == v.VALID
    assert r["checks"]["authenticated_batch_metadata"]["status"] == v.INDETERMINATE
    assert r["status"] == v.INDETERMINATE
    assert (events, record, env) == before


def test_valid_supplemental_key_still_requires_real_signature():
    _, _, _, attestor, env = fixture()
    public = attestor.public_key().public_bytes_raw()
    assert supplemental.check_signature(env, public)["status"] == v.VALID
    env["statement"]["context_id"] += "tampered"
    assert supplemental.check_signature(env, public)["status"] == v.INVALID


@pytest.mark.parametrize("script", ["vcp_verifier.py", "verify_attested_batch.py"])
@pytest.mark.parametrize("key_format", ["raw", "hex", "base64", "json"])
def test_both_cli_key_encodings_cannot_bypass_admission(tmp_path, script, key_format):
    events, record, _, _, _ = fixture()
    events[0]["Security"]["Signature"] = record["Signature"] = IDENTITY_SIGNATURE.hex()
    paths = [tmp_path / x for x in ("events.jsonl", "record.json", "key")]
    paths[0].write_text(json.dumps(events[0]) + "\n")
    paths[1].write_text(json.dumps(record))
    paths[2].write_bytes({"raw": IDENTITY, "hex": IDENTITY.hex().encode(),
        "base64": base64.b64encode(IDENTITY), "json": json.dumps({"PublicKey": IDENTITY.hex()}).encode()}[key_format])
    before = [p.read_bytes() for p in paths]
    proc = subprocess.run([sys.executable, str(DIRECTORY / script), str(paths[0]), "-s", str(paths[1]),
        "--public-key", str(paths[2]), "--json"], capture_output=True, text=True, timeout=10)
    assert proc.returncode == 2 and "Traceback" not in proc.stderr
    report = json.loads(proc.stdout)
    assert report["checks"]["event_signatures"]["status"] == v.INDETERMINATE
    assert report["checks"]["anchor_signature"]["reason"] == "TRUSTED_KEY_REJECTED:IDENTITY_POINT"
    assert [p.read_bytes() for p in paths] == before


def test_supplemental_cli_attestor_key_cannot_bypass_admission(tmp_path):
    events, record, signer, _, env = fixture()
    env["signature"] = base64.b64encode(IDENTITY_SIGNATURE).decode()
    for name, value in (("events", events[0]), ("record", record), ("envelope", env)):
        (tmp_path / name).write_text(json.dumps(value) + "\n")
    (tmp_path / "public").write_bytes(signer.public_key().public_bytes_raw())
    (tmp_path / "attestor").write_bytes(IDENTITY)
    proc = subprocess.run([sys.executable, str(DIRECTORY / "verify_attested_batch.py"),
        str(tmp_path / "events"), "-s", str(tmp_path / "record"), "--public-key", str(tmp_path / "public"),
        "--attestation", str(tmp_path / "envelope"), "--attestor-key", str(tmp_path / "attestor"),
        "--expected-context", "synthetic-test-context", "--json"], capture_output=True, text=True, timeout=10)
    assert proc.returncode == 2
    r = json.loads(proc.stdout)
    assert r["checks"]["supplemental_signature"]["reason"] == "SUPPLEMENTAL_TRUSTED_KEY_REJECTED:IDENTITY_POINT"
    assert r["checks"]["authenticated_batch_metadata"]["status"] == v.INDETERMINATE


def test_missing_backend_does_not_become_success(monkeypatch):
    public = Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key().public_bytes_raw()
    monkeypatch.setattr(v, "Ed25519PublicKey", None)
    assert v.verify_digest_signature(IDENTITY_SIGNATURE.hex(), "ab"*32, "ED25519", public, "raw_digest") == v.check(
        v.INDETERMINATE, "ED25519_DEPENDENCY_UNAVAILABLE")


def test_cache_is_bounded_and_never_skips_signature_verification():
    v._ed25519_point_problem.cache_clear()
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public = private.public_key().public_bytes_raw()
    assert v.ed25519_public_key_problem(public) is None
    assert v.ed25519_public_key_problem(public) is None
    assert v._ed25519_point_problem.cache_info().hits == 1
    assert v.verify_digest_signature(IDENTITY_SIGNATURE.hex(), "ab"*32, "ED25519", public, "raw_digest")["status"] == v.INVALID
    for i in range(160):
        v.ed25519_public_key_problem(hashlib.sha256(str(i).encode()).digest())
    assert v._ed25519_point_problem.cache_info().maxsize == 128
    assert v._ed25519_point_problem.cache_info().currsize <= 128


def test_vector_classes_with_separate_affine_oracle():
    # Distinct from the production extended-coordinate multiplier. This checks
    # the fixtures' group membership; it is not an independent-party audit.
    d = -121665 * pow(121666, P-2, P) % P
    def decode(raw):
        encoded = int.from_bytes(raw, "little")
        sign, y = encoded >> 255, encoded % (1 << 255)
        if y >= P:
            return None
        x2 = (y*y-1) * pow(d*y*y+1, P-2, P) % P
        x = pow(x2, (P+3)//8, P)
        if x*x % P != x2:
            x = x * pow(2, (P-1)//4, P) % P
        if x*x % P != x2 or (x == 0 and sign):
            return None
        return (x if x % 2 == sign else P-x, y)
    def add(a, b):
        x, y = a
        u, w = b
        t = d*x*u*y*w % P
        return ((x*w+y*u)*pow(1+t, P-2, P) % P, (y*w+x*u)*pow(1-t, P-2, P) % P)
    def mul(k, point):
        result = (0, 1)
        for bit in bin(k)[2:]:
            result = add(result, result)
            if bit == "1":
                result = add(result, point)
        return result
    assert len(set(TORSION_HEX)) == 8
    for raw in map(bytes.fromhex, TORSION_HEX):
        assert mul(8, decode(raw)) == (0, 1)
    for raw in map(bytes.fromhex, MIXED_HEX):
        assert mul(8, decode(raw)) != (0, 1)
        assert mul(L, decode(raw)) != (0, 1)
    for raw in NONCANONICAL + OFF_CURVE:
        assert decode(raw) is None
