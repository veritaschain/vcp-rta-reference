"""Legacy full-batch proof syntax is observable without a trusted key or root."""
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


def fixture(count=3):
    """Build the historical duplicate-odd tree independently of verifier helpers."""
    events = []
    for index in range(count):
        event = {"Header": {"Sequence": index + 1, "EventID": "merkle-test-%d" % index},
                 "Payload": {"value": index},
                 "Security": {"Version": "1.1", "HashAlgo": "SHA256", "SignAlgo": "ED25519"},
                 "PolicyIdentification": {"PolicyID": "synthetic", "ConformanceTier": "SILVER",
                    "RegistrationPolicy": {"Issuer": "synthetic-test"},
                    "VerificationDepth": {"HashChainValidation": True,
                        "MerkleProofRequired": True, "ExternalAnchorRequired": True}}}
        digest = hashlib.sha256((json.dumps(event["Header"], sort_keys=True) +
                                 json.dumps(event["Payload"], sort_keys=True)).encode()).hexdigest()
        event["Security"].update(EventHash=digest, MerkleIndex=index,
                                 Signature=PRIVATE.sign(bytes.fromhex(digest)).hex())
        if events:
            event["Security"]["PrevHash"] = events[-1]["Security"]["EventHash"]
        events.append(event)
    levels = [[hashlib.sha256(b"\0" + bytes.fromhex(e["Security"]["EventHash"])).digest()
               for e in events]]
    while len(levels[-1]) > 1:
        row = levels[-1]
        padded = row + [row[-1]] if len(row) % 2 else row
        levels.append([hashlib.sha256(b"\1" + a + b).digest()
                       for a, b in zip(padded[::2], padded[1::2])])
    root = levels[-1][0].hex()
    for index, event in enumerate(events):
        position, path = index, []
        for row in levels[:-1]:
            sibling = min(position ^ 1, len(row) - 1)
            path.append({"position": "left" if position % 2 else "right", "hash": row[sibling].hex()})
            position //= 2
        event["Security"].update(MerkleRoot=root, AuditPath=path)
    record = {"VCPVersion": "1.1", "MerkleRoot": root, "EventCount": count,
              "FirstSequence": 1, "LastSequence": count, "SignAlgo": "ED25519",
              "Signature": PRIVATE.sign(bytes.fromhex(root)).hex()}
    return events, record


def make_unavailable(events, record, kind):
    if kind in ("root", "both"):
        record.pop("MerkleRoot")
    if kind in ("leaf", "both"):
        events[0]["Security"].pop("EventHash")


BAD_PATHS = [
    pytest.param({}, id="object"),
    pytest.param(False, id="boolean"),
    pytest.param("path", id="string"),
    pytest.param([None], id="nonobject-sibling"),
    pytest.param([{"hash": "x" * 64, "position": "right"}], id="nonhex-sibling"),
    pytest.param([{"hash": "00" * 32, "position": "up"}], id="unknown-side"),
    pytest.param([], id="too-short-for-three-leaves"),
]


@pytest.mark.parametrize("path", BAD_PATHS)
@pytest.mark.parametrize("unavailable", ["root", "leaf", "both"])
def test_path_shape_errors_survive_missing_root_or_leaf(path, unavailable):
    events, record = fixture()
    events[0]["Security"]["AuditPath"] = path
    make_unavailable(events, record, unavailable)
    before = copy.deepcopy((events, record))
    report = v.verify_chain(events, record)  # No key either.
    assert report["checks"]["audit_path"]["status"] == v.INVALID
    assert report["status"] == v.INVALID
    assert report["conformance_claim"] is False
    assert (events, record) == before


@pytest.mark.parametrize("position", [True, None, -1, 3, [], {}])
@pytest.mark.parametrize("unavailable", ["path", "root", "leaf"])
def test_declared_position_errors_are_not_hidden(position, unavailable):
    events, record = fixture()
    events[0]["Security"]["MerkleIndex"] = position
    if unavailable == "path":
        events[0]["Security"].pop("AuditPath")
    else:
        make_unavailable(events, record, unavailable)
    report = v.verify_chain(events, record)
    assert report["checks"]["audit_path"]["status"] == v.INVALID
    assert report["status"] == v.INVALID


@pytest.mark.parametrize("change", ["opposite-side", "too-long", "missing-sibling-hash"])
@pytest.mark.parametrize("unavailable", ["root", "leaf", "index"])
def test_full_batch_path_topology_can_be_checked_without_crypto_inputs(change, unavailable):
    events, record = fixture()
    path = events[0]["Security"]["AuditPath"]
    if change == "opposite-side":
        path[0]["position"] = "left"
    elif change == "too-long":
        path.append(copy.deepcopy(path[-1]))
    else:
        path[0].pop("hash")
    if unavailable == "index":
        events[0]["Security"].pop("MerkleIndex")
    else:
        make_unavailable(events, record, unavailable)
    report = v.verify_chain(events, record)
    assert report["checks"]["audit_path"]["status"] == v.INVALID


@pytest.mark.parametrize("missing", ["path", "null-path", "index", "root", "leaf", "everything"])
def test_missing_material_without_syntax_mismatch_is_not_invented_invalid(missing):
    events, record = fixture()
    security = events[0]["Security"]
    if missing in ("path", "everything"):
        security.pop("AuditPath")
    if missing == "null-path":
        security["AuditPath"] = None
    if missing in ("index", "everything"):
        security.pop("MerkleIndex")
    if missing in ("root", "everything"):
        record.pop("MerkleRoot")
    if missing in ("leaf", "everything"):
        security.pop("EventHash")
    assert v.verify_chain(events, record)["checks"]["audit_path"]["status"] == v.INDETERMINATE


@pytest.mark.parametrize("count", [1, 2, 3, 5, 8, 17, 40])
def test_real_legacy_paths_still_require_and_match_root(count):
    events, record = fixture(count)
    before = copy.deepcopy((events, record))
    report = v.verify_chain(events, record, PUBLIC)
    for name in ("audit_path", "merkle_root", "event_signatures", "anchor_signature"):
        assert report["checks"][name]["status"] == v.VALID
    assert report["status"] == v.INDETERMINATE  # Remaining historical boundaries.
    assert (events, record) == before
    record["MerkleRoot"] = "00" * 32
    assert v.verify_chain(events, record, PUBLIC)["checks"]["audit_path"]["status"] == v.INVALID


def test_single_leaf_empty_path_is_not_confused_with_missing_path():
    events, record = fixture(1)
    assert events[0]["Security"]["AuditPath"] == []
    assert v.verify_chain(events, record)["checks"]["audit_path"]["status"] == v.VALID
    record.pop("MerkleRoot")
    assert v.verify_chain(events, record)["checks"]["audit_path"]["status"] == v.INDETERMINATE


def test_missing_first_path_does_not_hide_later_path_error():
    events, record = fixture()
    events[0]["Security"].pop("AuditPath")
    events[-1]["Security"]["AuditPath"] = {}
    record.pop("MerkleRoot")
    assert v.verify_chain(events, record)["checks"]["audit_path"]["status"] == v.INVALID


def test_valid_shape_does_not_replace_odd_duplicate_or_root_calculation():
    events, record = fixture()
    # Syntactically valid hash and side, but wrong duplicate for the odd leaf.
    events[-1]["Security"]["AuditPath"][0]["hash"] = "00" * 32
    assert v.verify_chain(events, record)["checks"]["audit_path"]["status"] == v.INVALID


def test_empty_input_cannot_produce_path_success():
    assert v.verify_chain([], {"MerkleRoot": "00" * 32})["checks"]["audit_path"]["status"] == v.INDETERMINATE


def test_missing_path_does_not_hide_real_signature_mismatch():
    events, record = fixture()
    events[0]["Security"].pop("AuditPath")
    record["Signature"] = "00" * 64
    report = v.verify_chain(events, record, PUBLIC)
    assert report["checks"]["audit_path"]["status"] == v.INDETERMINATE
    assert report["checks"]["anchor_signature"]["status"] == v.INVALID
    assert report["status"] == v.INVALID


@pytest.mark.parametrize("script", ["vcp_verifier.py", "verify_attested_batch.py"])
@pytest.mark.parametrize("mutation", ["path-object", "wrong-index", "too-long"])
def test_both_clis_preserve_malformed_proof_despite_absent_root_and_key(tmp_path, script, mutation):
    events, record = fixture()
    security = events[0]["Security"]
    if mutation == "path-object":
        security["AuditPath"] = {}
    elif mutation == "wrong-index":
        security["MerkleIndex"] = -1
        security.pop("AuditPath")
    else:
        security["AuditPath"].append(copy.deepcopy(security["AuditPath"][-1]))
    record.pop("MerkleRoot")
    event_path, record_path = tmp_path / "events", tmp_path / "record"
    event_path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    record_path.write_text(json.dumps(record), encoding="utf-8")
    before = [event_path.read_bytes(), record_path.read_bytes()]
    process = subprocess.run([sys.executable, str(DIRECTORY / script), str(event_path),
        "-s", str(record_path), "--json"], capture_output=True, text=True, timeout=10)
    assert process.returncode == 1 and "Traceback" not in process.stderr
    report = json.loads(process.stdout)
    assert report["checks"]["audit_path"]["status"] == v.INVALID
    assert report["status"] == v.INVALID and report["conformance_claim"] is False
    assert [event_path.read_bytes(), record_path.read_bytes()] == before
