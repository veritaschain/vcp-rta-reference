"""Fixed published-pack regressions; reference-key agreement is not identity trust."""
import copy
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools/verifier"))
import inspect_historical_pack as history
import vcp_verifier as legacy


@pytest.fixture(scope="module")
def replay():
    return history.inspect_pack(compare_reference_key=True)


def test_fixed_bytes_and_whole_evidence_preserved(replay):
    assert replay["inputs_before"] == replay["inputs_after"]
    for name, digest in history.PINNED_BLOBS.items():
        assert replay["inputs_before"][name]["git_blob"] == digest
    assert replay["execution_status"] == "completed"
    assert replay["conformance_claim"] is False
    assert replay["key_identity_established"] is False
    assert replay["independent_reproduction"] is False


def test_no_key_is_not_trust(replay):
    report = replay["without_key"]
    assert report["status"] == legacy.INDETERMINATE
    for name in ("event_signatures", "anchor_signature", "external_anchor"):
        assert report["checks"][name]["status"] == legacy.INDETERMINATE


def test_all_40_hashes_and_signatures_match_reference(replay):
    assert replay["event_count"] == 40
    rows = replay["per_event_comparison_only"]
    assert len(rows) == 40
    assert len({r["event_id"] for r in rows}) == 40
    assert all(r["hash"]["status"] == legacy.VALID for r in rows)
    assert all(r["signature"]["status"] == legacy.VALID for r in rows)


def test_root_signature_and_all_paths_match(replay):
    checks = replay["with_reference_key_comparison_only"]["checks"]
    for name in ("anchor_signature", "audit_path", "merkle_root", "sequence", "batch_bounds_local"):
        assert checks[name]["status"] == legacy.VALID, (name, checks[name])
    assert replay["legacy_merkle_root"] == "86c05dbad79ffe6fdb5c3063128df0af0bcb5a3e95f4586348f13ca49778a47e"


def test_three_unresolved_checks_are_not_hidden(replay):
    report = replay["with_reference_key_comparison_only"]
    assert report["status"] == legacy.INDETERMINATE
    assert {n for n, c in report["checks"].items() if c["status"] != legacy.VALID} == {
        "prev_hash", "authenticated_batch_metadata", "external_anchor"}
    assert replay["original_anchor_confirmed"] is False
    assert replay["ots_files_present_not_verified"] == []


def test_tree_difference_not_relabelled(replay):
    assert replay["strict_rfc6962_root_comparison_only"] != replay["legacy_merkle_root"]


def test_event_labels_are_signal_and_execution(replay):
    assert replay["event_types"] == {"EXE": 20, "SIG": 20}


@pytest.mark.parametrize("index", [0, 19, 39])
def test_payload_changes_in_first_middle_last_events_are_detected(index):
    events, record, key = history.load_fixed_pack(ROOT)
    events = copy.deepcopy(events)
    events[index]["Payload"]["historical_regression_tamper"] = True
    report = legacy.verify_chain(events, record, key)
    assert report["checks"]["event_hash"]["status"] == legacy.INVALID
    assert report["status"] == legacy.INVALID


def test_missing_path_still_detects_bad_root_signature():
    events, record, key = history.load_fixed_pack(ROOT)
    events[0]["Security"].pop("AuditPath")
    record["Signature"] = "00" * 64
    report = legacy.verify_chain(events, record, key)
    assert report["checks"]["audit_path"]["status"] == legacy.INDETERMINATE
    assert report["checks"]["anchor_signature"]["status"] == legacy.INVALID
    assert report["status"] == legacy.INVALID


def test_whole_pack_wrong_key_rejected():
    events, record, _ = history.load_fixed_pack(ROOT)
    report = legacy.verify_chain(events, record, b"\x00" * 32)
    assert report["checks"]["event_signatures"]["status"] == legacy.INVALID
    assert report["status"] == legacy.INVALID


def test_changed_fixed_bytes_rejected(tmp_path):
    for name in history.PINNED_BLOBS:
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes((ROOT / name).read_bytes())
    with (tmp_path / history.EVENTS).open("ab") as handle:
        handle.write(b"\n")
    with pytest.raises(ValueError, match="pinned baseline"):
        history.load_fixed_pack(tmp_path)


@pytest.mark.parametrize("compare", [False, True])
def test_cli_keeps_incomplete_verdict_and_requires_key_opt_in(compare):
    before = history.evidence_manifest(ROOT)
    command = [sys.executable, str(ROOT / "tools/verifier/inspect_historical_pack.py")]
    if compare:
        command.append("--compare-reference-key")
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert result.returncode == 2, result.stderr
    report = json.loads(result.stdout)
    assert report["evidence_verdict"] == legacy.INDETERMINATE
    assert report["reference_key_comparison_requested"] is compare
    assert (report["with_reference_key_comparison_only"] is not None) is compare
    assert len(report["per_event_comparison_only"]) == (40 if compare else 0)
    assert history.evidence_manifest(ROOT) == before
