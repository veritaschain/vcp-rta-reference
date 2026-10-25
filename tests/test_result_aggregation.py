"""Malformed result isolation; local synthetic inputs, not external evidence."""
import copy
import importlib.util
import itertools
import json
from pathlib import Path
import random

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MODULE = Path(__file__).resolve().parents[1] / "tools/verifier/vcp_verifier.py"
spec = importlib.util.spec_from_file_location("aggregation_verifier", MODULE)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)

BAD_STATUSES = [
    pytest.param([], id="empty-list"),
    pytest.param({}, id="empty-object"),
    pytest.param(["INVALID"], id="nested-list"),
    pytest.param({"status": "INVALID"}, id="nested-object"),
    pytest.param(None, id="null"),
    pytest.param(True, id="boolean"),
    pytest.param(0, id="number"),
    pytest.param("SUCCESS", id="unknown-string"),
    pytest.param("", id="empty-string"),
]


def malformed(value):
    return {"status": value, "reason": "synthetic malformed helper result"}


@pytest.mark.parametrize("bad", BAD_STATUSES)
@pytest.mark.parametrize("invalid_first", [False, True])
def test_malformed_status_never_hides_explicit_invalid(bad, invalid_first):
    results = [v.check(v.INVALID, "KNOWN_MISMATCH"), malformed(bad)]
    if not invalid_first:
        results.reverse()
    before = copy.deepcopy(results)
    expected = {"status": v.INVALID, "reason": "DEMONSTRATED_MISMATCH"}
    assert v.combine(results) == expected
    assert v._guard(lambda: v.combine(results)) == expected
    assert results == before


@pytest.mark.parametrize("bad", BAD_STATUSES)
@pytest.mark.parametrize("other", ["VALID", "INDETERMINATE"])
def test_malformed_status_alone_cannot_be_pass_or_invented_mismatch(bad, other):
    expected = {"status": v.INDETERMINATE, "reason": "INCOMPLETE_VERIFICATION"}
    assert v.combine([malformed(bad)]) == expected
    for results in ([malformed(bad), v.check(other, "synthetic")],
                    [v.check(other, "synthetic"), malformed(bad)]):
        assert v.combine(results) == expected


@pytest.mark.parametrize("bad", BAD_STATUSES)
def test_check_constructor_rejects_wrong_status_with_value_error(bad):
    with pytest.raises(ValueError):
        v.check(bad, "synthetic")


@pytest.mark.parametrize("reason", [None, "", [], {}, True, 1])
def test_reason_validation_remains_fail_closed(reason):
    with pytest.raises(ValueError):
        v.check(v.VALID, reason)
    assert v.combine([{"status": v.VALID, "reason": reason}])["status"] == v.INDETERMINATE
    # Preserve the existing conservative treatment of an explicit INVALID tag.
    assert v.combine([{"status": v.INVALID, "reason": reason}])["status"] == v.INVALID


@pytest.mark.parametrize("entry", [None, True, 1, "INVALID", ["INVALID"]])
def test_nonobject_entry_is_not_a_success_or_a_claim_of_invalid(entry):
    assert v.combine([entry])["status"] == v.INDETERMINATE
    assert v.combine([entry, v.check(v.INVALID, "KNOWN_MISMATCH")])["status"] == v.INVALID


@pytest.mark.parametrize("bad", BAD_STATUSES[:4])
@pytest.mark.parametrize("invalid_first", [False, True])
def test_real_signature_mismatch_survives_nested_callback_aggregation(bad, invalid_first):
    # Actual local Ed25519 mismatch. The callback is a synthetic integration
    # fixture, not an external-anchor implementation or proof of anchoring.
    private = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))  # TEST ONLY
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    digest = "ab" * 32
    signature = private.sign(bytes.fromhex(digest))
    tampered = bytes([signature[0] ^ 1]) + signature[1:]
    mismatch = v.verify_digest_signature(tampered.hex(), digest, "ED25519", public, "raw_digest")
    assert mismatch == {"status": v.INVALID, "reason": "SIGNATURE_MISMATCH"}
    results = [mismatch, malformed(bad)]
    if not invalid_first:
        results.reverse()
    calls = []
    def callback(root, record):
        calls.append(root)
        return v.combine(results)
    report = v.verify_chain([], {"MerkleRoot": digest}, external_anchor_verifier=callback)
    assert calls == [digest]
    assert report["checks"]["external_anchor"]["status"] == v.INVALID
    assert report["status"] == v.INVALID
    assert report["conformance_claim"] is False


def test_well_formed_aggregation_contract_is_unchanged():
    states = [v.VALID, v.INVALID, v.INDETERMINATE]
    assert v.combine([]) == {"status": v.INDETERMINATE, "reason": "NO_CHECKS"}
    for count in range(1, 5):
        for case in itertools.product(states, repeat=count):
            expected = (v.INVALID if v.INVALID in case else
                        v.INDETERMINATE if v.INDETERMINATE in case else v.VALID)
            assert v.combine([v.check(s, "synthetic") for s in case])["status"] == expected


def test_two_thousand_deterministic_json_result_arrays():
    # JSON values only. Not a sandbox for executable Python object subclasses.
    rng = random.Random(26102608)
    values = [None, True, False, 0, 2.5, "", "SUCCESS", "VALID", "INVALID",
              "INDETERMINATE", [], {}, ["INVALID"], {"status": "INVALID"}]
    for _ in range(2000):
        results = []
        for _ in range(rng.randrange(1, 8)):
            entry = rng.choice(values)
            if rng.choice([True, False]):
                entry = {"status": rng.choice(values), "reason": rng.choice(values)}
            results.append(entry)
        results = json.loads(json.dumps(results))
        explicit_invalid = any(isinstance(c, dict) and isinstance(c.get("status"), str)
                               and c["status"] == v.INVALID for c in results)
        all_valid = all(isinstance(c, dict) and isinstance(c.get("status"), str)
                        and c["status"] == v.VALID and isinstance(c.get("reason"), str)
                        and bool(c["reason"]) for c in results)
        expected = v.INVALID if explicit_invalid else (v.VALID if all_valid else v.INDETERMINATE)
        before = copy.deepcopy(results)
        assert v.combine(results)["status"] == expected
        assert results == before
