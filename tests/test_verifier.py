"""Local regression tests. Synthetic fixtures, not independent reproduction."""
import base64
import copy
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MODULE = Path(__file__).resolve().parents[1] / "tools/verifier/vcp_verifier.py"
spec = importlib.util.spec_from_file_location("vcp_verifier", MODULE)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


def fixture(n=1):
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))  # TEST ONLY
    public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    events = []
    for i in range(n):
        event = {"Header": {"Sequence": i + 1, "EventID": "test-%d" % i},
                 "Payload": {"value": i},
                 "Security": {"Version": "1.1", "HashAlgo": "SHA256", "SignAlgo": "ED25519"},
                 "PolicyIdentification": {"PolicyID": "test", "ConformanceTier": "SILVER",
                     "RegistrationPolicy": {"Issuer": "test"},
                     "VerificationDepth": {"HashChainValidation": True, "MerkleProofRequired": True,
                                           "ExternalAnchorRequired": True}}}
        digest = v.event_content_hash(event)
        event["Security"].update(EventHash=digest, Signature=key.sign(bytes.fromhex(digest)).hex(),
                                  MerkleIndex=i)
        if events:
            event["Security"]["PrevHash"] = events[-1]["Security"]["EventHash"]
        events.append(event)
    # Independent fixture builder for the historical duplicate-odd construction.
    levels = [[hashlib.sha256(b"\x00" + bytes.fromhex(e["Security"]["EventHash"])).digest()
               for e in events]]
    while len(levels[-1]) > 1:
        level = levels[-1]
        expanded = level + [level[-1]] if len(level) % 2 else level
        levels.append([hashlib.sha256(b"\x01" + a + b).digest()
                       for a, b in zip(expanded[::2], expanded[1::2])])
    root = levels[-1][0].hex()
    for i, event in enumerate(events):
        position, path = i, []
        for level in levels[:-1]:
            sibling = position ^ 1
            sibling = min(sibling, len(level) - 1)
            path.append({"position": "left" if position % 2 else "right", "hash": level[sibling].hex()})
            position //= 2
        event["Security"].update(AuditPath=path, MerkleRoot=root)
    record = {"VCPVersion": "1.1", "MerkleRoot": root, "SignAlgo": "ED25519",
              "Signature": key.sign(bytes.fromhex(root)).hex(), "EventCount": n,
              "FirstSequence": 1, "LastSequence": n}
    return events, record, public, key


def status(report, name):
    return report["checks"][name]["status"]


@pytest.mark.parametrize("states", itertools.product([v.VALID, v.INVALID, v.INDETERMINATE], repeat=4))
def test_all_81_aggregations(states):
    expected = v.INVALID if v.INVALID in states else (v.INDETERMINATE if v.INDETERMINATE in states else v.VALID)
    assert v.combine([v.check(s, "test") for s in states])["status"] == expected


@pytest.mark.parametrize("states", [[], [{"status": "SUCCESS"}], [True], [{"status": v.VALID}]])
def test_no_vacuous_or_unknown_pass(states):
    assert v.combine(states)["status"] == v.INDETERMINATE


def test_bad_adapter_result_cannot_hide_invalid():
    assert v.combine([v.check(v.INVALID, "mismatch"), True])["status"] == v.INVALID


def test_no_key_never_passes_signatures():
    events, record, _, _ = fixture()
    result = v.verify_chain(events, record)
    assert status(result, "event_signatures") == v.INDETERMINATE
    assert status(result, "anchor_signature") == v.INDETERMINATE
    assert status(result, "external_anchor") == v.INDETERMINATE
    assert result["status"] == v.INDETERMINATE
    assert result["conformance_claim"] is False


def test_record_embedded_key_is_not_automatically_trusted():
    events, record, public, _ = fixture()
    record["PublicKey"] = public.hex()
    assert status(v.verify_chain(events, record), "anchor_signature") == v.INDETERMINATE


def test_missing_path_does_not_hide_real_bad_signature():
    events, record, public, _ = fixture()
    del events[0]["Security"]["AuditPath"]
    record["Signature"] = "00" * 64
    result = v.verify_chain(events, record, public)
    assert status(result, "audit_path") == v.INDETERMINATE
    assert status(result, "anchor_signature") == v.INVALID
    assert result["status"] == v.INVALID


def test_missing_path_does_not_hide_real_bad_event_signature():
    events, record, public, _ = fixture()
    del events[0]["Security"]["AuditPath"]
    events[0]["Security"]["Signature"] = "00" * 64
    result = v.verify_chain(events, record, public)
    assert status(result, "event_signatures") == v.INVALID
    assert result["status"] == v.INVALID


def test_absent_record_does_not_hide_event_tampering():
    events, _, public, _ = fixture()
    events[0]["Payload"]["value"] += 1
    result = v.verify_chain(events, public_key=public)
    assert status(result, "anchor_record") == v.INDETERMINATE
    assert status(result, "event_hash") == v.INVALID
    assert result["status"] == v.INVALID


def test_absent_events_do_not_hide_bad_anchor_signature():
    _, record, public, _ = fixture()
    record["Signature"] = "00" * 64
    result = v.verify_chain([], record, public)
    assert status(result, "anchor_signature") == v.INVALID
    assert status(result, "event_hash") == v.INDETERMINATE
    assert result["status"] == v.INVALID


def test_empty_path_is_present_and_checked():
    events, record, public, _ = fixture()
    assert events[0]["Security"]["AuditPath"] == []
    result = v.verify_chain(events, record, public)
    assert status(result, "audit_path") == v.VALID
    assert status(result, "anchor_signature") == v.VALID


def test_empty_path_is_not_automatic_pass():
    events, record, public, _ = fixture(2)
    events[0]["Security"]["AuditPath"] = []
    assert status(v.verify_chain(events, record, public), "audit_path") == v.INVALID


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 17, 40])
def test_legacy_tree_and_paths(n):
    events, record, public, _ = fixture(n)
    result = v.verify_chain(events, record, public)
    for name in ("event_hash", "sequence", "policy_fields", "event_signatures", "merkle_root",
                 "audit_path", "batch_bounds_local", "anchor_signature"):
        assert status(result, name) == v.VALID, (n, name, result["checks"][name])
    assert result["status"] == v.INDETERMINATE


@pytest.mark.parametrize("change", ["side", "digest", "length", "index", "odd_duplicate"])
def test_path_mutations_rejected(change):
    events, record, public, _ = fixture(3)
    security = events[2]["Security"]
    if change == "side":
        security["AuditPath"][0]["position"] = "left"
    elif change == "digest":
        security["AuditPath"][0]["hash"] = "00" * 32
    elif change == "length":
        security["AuditPath"].append(security["AuditPath"][0])
    elif change == "index":
        security["MerkleIndex"] = True
    else:
        security["AuditPath"][0]["hash"] = events[0]["Security"]["AuditPath"][0]["hash"]
    assert status(v.verify_chain(events, record, public), "audit_path") == v.INVALID


def test_missing_root_is_not_computed_then_passed():
    events, _, public, _ = fixture()
    result = v.verify_chain(events, public_key=public)
    assert status(result, "merkle_root") == v.INDETERMINATE
    assert result["status"] == v.INDETERMINATE


def test_wrong_root_is_invalid_even_without_key_or_anchor():
    events, record, _, _ = fixture()
    record["MerkleRoot"] = "00" * 32
    result = v.verify_chain(events, record)
    assert status(result, "merkle_root") == v.INVALID
    assert status(result, "event_signatures") == v.INDETERMINATE
    assert result["status"] == v.INVALID


def test_unknown_algorithm_does_not_hide_later_bad_signature():
    events, record, public, _ = fixture(2)
    events[0]["Security"]["SignAlgo"] = "FUTURE"
    events[1]["Security"]["Signature"] = "00" * 64
    assert status(v.verify_chain(events, record, public), "event_signatures") == v.INVALID


def test_missing_crypto_dependency_is_indeterminate(monkeypatch):
    events, record, public, _ = fixture()
    monkeypatch.setattr(v, "Ed25519PublicKey", None)
    result = v.verify_chain(events, record, public)
    assert status(result, "event_signatures") == v.INDETERMINATE
    assert result["status"] == v.INDETERMINATE


def test_signature_encoding_is_explicit_not_guessed():
    events, record, public, key = fixture()
    s = events[0]["Security"]
    s["Signature"] = base64.b64encode(key.sign(s["EventHash"].encode("ascii"))).decode("ascii")
    record["Signature"] = key.sign(record["MerkleRoot"].encode("ascii")).hex()
    assert status(v.verify_chain(events, record, public), "event_signatures") == v.INVALID
    assert status(v.verify_chain(events, record, public, signature_message="ascii_hex"), "event_signatures") == v.VALID


@pytest.mark.parametrize("bad", [None, {}, [], True, "oops"])
def test_bad_event_containers_do_not_suppress_anchor_signature(bad):
    _, record, public, _ = fixture()
    record["Signature"] = "00" * 64
    result = v.verify_chain([bad], record, public)
    assert status(result, "structure") == v.INVALID
    assert status(result, "anchor_signature") == v.INVALID
    assert result["status"] == v.INVALID


def test_bad_record_does_not_suppress_event_signature():
    events, _, public, _ = fixture()
    events[0]["Security"]["Signature"] = "00" * 64
    result = v.verify_chain(events, ["bad"], public)
    assert status(result, "event_signatures") == v.INVALID
    assert result["status"] == v.INVALID


def test_external_adapter_receives_exact_root_despite_missing_path():
    events, record, public, _ = fixture()
    del events[0]["Security"]["AuditPath"]
    calls = []
    def adapter(root, received):
        calls.append((root, received))
        return v.check(v.INVALID, "SYNTHETIC_EXTERNAL_MISMATCH")
    result = v.verify_chain(events, record, public, external_anchor_verifier=adapter)
    assert calls == [(record["MerkleRoot"], record)]
    assert status(result, "external_anchor") == v.INVALID
    assert result["status"] == v.INVALID


@pytest.mark.parametrize("outcome", [True, {"status": "VALID"}, {"status": "SUCCESS", "reason": "oops"}, "exception"])
def test_bad_external_adapter_cannot_hide_bad_signature(outcome):
    events, record, public, _ = fixture()
    record["Signature"] = "00" * 64
    def adapter(root, received):
        if outcome == "exception":
            raise RuntimeError("test")
        return outcome
    result = v.verify_chain(events, record, public, external_anchor_verifier=adapter)
    assert status(result, "external_anchor") == v.INDETERMINATE
    assert status(result, "anchor_signature") == v.INVALID
    assert result["status"] == v.INVALID


def test_root_signature_is_not_metadata_authentication():
    events, record, public, _ = fixture()
    record["EventCount"] = 999
    result = v.verify_chain(events, record, public)
    assert status(result, "anchor_signature") == v.VALID
    assert status(result, "batch_bounds_local") == v.INVALID
    assert status(result, "authenticated_batch_metadata") == v.INDETERMINATE


@pytest.mark.parametrize("field", ["EventCount", "FirstSequence", "LastSequence"])
def test_boolean_bounds_are_not_integers(field):
    events, record, public, _ = fixture()
    record[field] = True
    assert status(v.verify_chain(events, record, public), "batch_bounds_local") == v.INVALID


def test_inputs_are_not_modified():
    events, record, public, _ = fixture(3)
    before = copy.deepcopy((events, record))
    v.verify_chain(events, record, public)
    assert (events, record) == before


def cli(tmp_path, events, record=None, public=None, extra=()):
    event_file = tmp_path / "events.jsonl"
    event_file.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
    args = [sys.executable, str(MODULE), str(event_file), "--json"]
    if record is not None:
        path = tmp_path / "record.json"
        path.write_text(json.dumps(record), encoding="utf-8")
        args += ["-s", str(path)]
    if public is not None:
        path = tmp_path / "key.txt"
        path.write_text(public.hex())
        args += ["--public-key", str(path)]
    return subprocess.run(args + list(extra), text=True, capture_output=True, timeout=10)


def test_cli_missing_key_and_anchor_exit_2(tmp_path):
    events, record, _, _ = fixture()
    result = cli(tmp_path, events, record)
    assert result.returncode == 2
    assert json.loads(result.stdout)["status"] == v.INDETERMINATE
    assert "Fully Compliant" not in result.stdout


def test_cli_bad_signature_exit_1(tmp_path):
    events, record, public, _ = fixture()
    record["Signature"] = "00" * 64
    result = cli(tmp_path, events, record, public)
    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == v.INVALID


def test_cli_optional_input_failure_does_not_hide_event_mismatch(tmp_path):
    events, _, public, _ = fixture()
    events[0]["Payload"]["value"] += 1
    result = cli(tmp_path, events, public=public, extra=("-s", str(tmp_path / "missing.json")))
    assert result.returncode == 1
    report = json.loads(result.stdout)
    assert status(report, "security_object_input") == v.INDETERMINATE
    assert status(report, "event_hash") == v.INVALID


@pytest.mark.parametrize("text", ['{"Header":{},"Header":{}}', '{"x": NaN}', '[1,2]', '{bad'])
def test_cli_malformed_json_exit_3(tmp_path, text):
    path = tmp_path / "bad.jsonl"
    path.write_text(text)
    result = subprocess.run([sys.executable, str(MODULE), str(path)], text=True, capture_output=True)
    assert result.returncode == 3


def test_cli_report_saved_identically(tmp_path):
    events, record, public, _ = fixture()
    output = tmp_path / "report.json"
    result = cli(tmp_path, events, record, public, extra=("-o", str(output)))
    assert result.returncode == 2
    assert output.read_text() == result.stdout
