"""Harness tests. Synthetic XML/process fixtures are not cryptographic proof."""
import importlib.util
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

import pytest

MODULE = Path(__file__).resolve().parents[1] / "tools/verifier/run_regression.py"
spec = importlib.util.spec_from_file_location("regression_runner", MODULE)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def xml(tmp_path, cases=1, child=None, **attrs):
    root = ET.Element("testsuites")
    suite = ET.SubElement(root, "testsuite", tests=str(cases), errors="0", failures="0", skipped="0")
    suite.attrib.update(attrs)
    for i in range(cases):
        case = ET.SubElement(suite, "testcase", classname="tests.demo", name="test_%d" % i)
        if child:
            ET.SubElement(case, child)
    path = tmp_path / "junit.xml"
    ET.ElementTree(root).write(path, encoding="utf-8")
    return path


def test_success(tmp_path):
    assert r.assess_junit(xml(tmp_path), 0, {"demo": 1})["passed"]


@pytest.mark.parametrize("child", ["failure", "error", "skipped"])
def test_bad_cases_never_pass(tmp_path, child):
    assert not r.assess_junit(xml(tmp_path, child=child), 0, {"demo": 1})["passed"]


@pytest.mark.parametrize("attribute", ["failures", "errors", "skipped"])
def test_suite_counters_cannot_be_hidden(tmp_path, attribute):
    assert not r.assess_junit(xml(tmp_path, **{attribute: "1"}), 0, {"demo": 1})["passed"]


@pytest.mark.parametrize("code", [-9, 1, 2, 3, 4, 5])
def test_nonzero_exit_even_with_success_xml(tmp_path, code):
    assert not r.assess_junit(xml(tmp_path), code, {"demo": 1})["passed"]


def test_empty_suite_never_passes(tmp_path):
    assert not r.assess_junit(xml(tmp_path, cases=0), 0, {})["passed"]


def test_missing_suite(tmp_path):
    assert not r.assess_junit(xml(tmp_path), 0, {"other": 1})["passed"]


def test_too_few_cases(tmp_path):
    assert not r.assess_junit(xml(tmp_path), 0, {"demo": 2})["passed"]


def test_declared_count_mismatch(tmp_path):
    assert not r.assess_junit(xml(tmp_path, tests="9"), 0, {"demo": 1})["passed"]


def test_duplicate_test_ids(tmp_path):
    path = xml(tmp_path, cases=2)
    tree = ET.parse(path)
    for item in tree.iter("testcase"):
        item.set("name", "same")
    tree.write(path)
    assert not r.assess_junit(path, 0, {"demo": 2})["passed"]


def test_real_timestamp_test_must_be_present(tmp_path):
    result = r.assess_junit(xml(tmp_path), 0, {"test_attested_batch": 1})
    assert "REAL_RFC3161_TEST_MISSING" in result["problems"]


@pytest.mark.parametrize("content", [b"", b"not xml", b"<wrong/>",
    b'<!DOCTYPE x [<!ENTITY e "unsafe">]><testsuites/>'])
def test_malformed_xml(tmp_path, content):
    path = tmp_path / "bad.xml"
    path.write_bytes(content)
    assert not r.assess_junit(path, 0, {})["passed"]


def test_missing_xml(tmp_path):
    assert not r.assess_junit(tmp_path / "missing.xml", 0, {})["passed"]


def test_oversized_xml(tmp_path, monkeypatch):
    path = xml(tmp_path)
    monkeypatch.setattr(r, "LIMIT", 8)
    assert not r.assess_junit(path, 0, {})["passed"]


@pytest.mark.parametrize("name", ["evidence", "tools", "tests", ".git"])
def test_no_reports_in_protected_directory(tmp_path, name):
    with pytest.raises(ValueError):
        r.prepare_output(tmp_path, tmp_path / name / "report")


def test_output_is_never_overwritten(tmp_path):
    path = r.prepare_output(tmp_path, tmp_path / "reports")
    with pytest.raises(FileExistsError):
        r.prepare_output(tmp_path, path)


def test_manifest_detects_modified_evidence_and_ignores_cache(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    original = evidence / "sample.bin"
    original.write_bytes(b"original")
    before = r.input_manifest(tmp_path)
    cache = evidence / "__pycache__"
    cache.mkdir()
    (cache / "cached.pyc").write_bytes(b"cache")
    assert r.input_manifest(tmp_path) == before
    original.write_bytes(b"changed")
    assert r.input_manifest(tmp_path) != before


def test_dependency_or_openssl_failure_is_preflight_failure(tmp_path):
    info = {"openssl": "LibreSSL 3.5.5", "dependencies": {}}
    problems = r.preflight(tmp_path, info)
    assert "OPENSSL_3_OR_NEWER_REQUIRED" in problems
    assert "DEPENDENCY_MANIFEST_UNUSABLE" in problems


def test_main_preflight_failure_writes_report(tmp_path, monkeypatch):
    monkeypatch.setattr(r, "ROOT", tmp_path)
    output = tmp_path / "out"
    assert r.main(["--output-dir", str(output)]) == 1
    import json
    assert json.loads((output / "run.json").read_text())["run_status"] == "preflight_failed"
    assert (output / "artifacts.sha256.json").is_file()
