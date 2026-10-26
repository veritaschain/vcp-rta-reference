"""Fail-closed pytest report assessment; synthetic XML, not evidence verdicts."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

import pytest

MODULE = Path(__file__).resolve().parents[1] / "tools/verifier/run_regression.py"
spec = importlib.util.spec_from_file_location("junit_integrity_runner", MODULE)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)

CASE = '<testcase classname="tests.demo" name="test_ok"/>'
SUITE = '<testsuite tests="1" errors="0" failures="0" skipped="0">' + CASE + '</testsuite>'
EMPTY = '<testsuite tests="0" errors="0" failures="0" skipped="0"/>'
GOOD = '<testsuites>' + SUITE + '</testsuites>'


def assess(tmp_path, content, code=0):
    path = tmp_path / "report.xml"
    data = content.encode("utf-8") if isinstance(content, str) else content
    path.write_bytes(data)
    result = r.assess_junit(path, code, {"demo": 1})
    assert path.read_bytes() == data
    return result


@pytest.mark.parametrize("content", [
    '<testsuites>' + SUITE.replace(CASE, '') + CASE + '</testsuites>',
    '<testsuites><wrapper>' + SUITE + '</wrapper></testsuites>',
    GOOD.replace(CASE, '<wrapper>' + CASE + '</wrapper>'),
    GOOD.replace('<testsuites>', '<testsuites><failure message="reported failure"/>'),
    GOOD.replace(CASE, CASE.replace('/>', '><wrapper><skipped/></wrapper></testcase>')),
    GOOD.replace(CASE, CASE.replace('/>', '><system-out><failure/></system-out></testcase>')),
    GOOD.replace(CASE, CASE.replace('/>', '><properties><skipped/></properties></testcase>')),
    GOOD.replace(CASE, CASE.replace('/>', '><properties><property name="x"><error/></property></properties></testcase>')),
    GOOD.replace('</testsuite>', EMPTY + '</testsuite>'),
    GOOD.replace(CASE, CASE.replace('/>', '>' + CASE.replace('test_ok', 'nested') + '</testcase>')),
    GOOD.replace(CASE, CASE.replace('/>', '><unknown/></testcase>')),
    GOOD.replace('<testsuites>', '<testsuites>unclassified error'),
    GOOD.replace('</testsuite>', '</testsuite>unclassified error'),
    GOOD.replace('<testsuites>', '<testsuites xmlns="urn:other-format">'),
], ids=["orphan-case", "suite-wrapper", "case-wrapper", "root-failure", "nested-skip",
        "failure-in-log", "skip-in-properties", "error-in-property", "nested-suite",
        "nested-case", "unknown-child", "root-text", "trailing-text", "namespace"])
def test_misplaced_outcomes_and_cases_cannot_pass(tmp_path, content):
    result = assess(tmp_path, content)
    assert not result["passed"] and result["problems"]


@pytest.mark.parametrize("counts", [(2, -1), (0, 1)])
def test_wrong_suite_counts_cannot_cancel_each_other(tmp_path, counts):
    first = SUITE.replace('tests="1"', 'tests="%s"' % counts[0])
    second = EMPTY.replace('tests="0"', 'tests="%s"' % counts[1])
    assert not assess(tmp_path, '<testsuites>' + first + second + '</testsuites>')["passed"]


@pytest.mark.parametrize("field", ["tests", "failures", "errors", "skipped"])
@pytest.mark.parametrize("bad", [None, "-1", "+0", "00", " 0", "0.0", "\u0660", "9" * 21])
def test_counters_must_be_present_canonical_bounded_ascii_integers(tmp_path, field, bad):
    root = ET.fromstring(GOOD)
    suite = root[0]
    if bad is None:
        del suite.attrib[field]
    else:
        suite.set(field, bad)
    assert not assess(tmp_path, ET.tostring(root, encoding="utf-8"))["passed"]


@pytest.mark.parametrize("field,value", [("tests", "0"), ("failures", "1"), ("errors", "1"),
                                        ("skipped", "1"), ("tests", "-1")])
def test_present_root_counts_must_match_children(tmp_path, field, value):
    root = ET.fromstring(GOOD)
    root.set(field, value)
    assert not assess(tmp_path, ET.tostring(root, encoding="utf-8"))["passed"]


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16", "utf-16-le", "utf-16-be", "utf-32"])
def test_dtd_in_alternate_encoding_never_reaches_xml_parser(tmp_path, monkeypatch, encoding):
    # One tiny harmless entity, not an expansion bomb and no network entity.
    content = ('<!DOCTYPE testsuites [<!ENTITY label "test_ok">]>' +
               GOOD.replace('name="test_ok"', 'name="&label;"')).encode(encoding)
    def forbidden(*args, **kwargs):
        raise AssertionError("forbidden declaration reached XML parser")
    monkeypatch.setattr(r.ET, "fromstring", forbidden)
    assert not assess(tmp_path, content)["passed"]


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be", "utf-32"])
def test_non_utf8_reports_are_outside_local_profile(tmp_path, encoding):
    assert not assess(tmp_path, GOOD.encode(encoding))["passed"]


@pytest.mark.parametrize("declaration", ['encoding="iso-8859-1"', "encoding='utf-16'"])
def test_incompatible_encoding_declaration_is_not_ignored(tmp_path, declaration):
    assert not assess(tmp_path, '<?xml version="1.0" ' + declaration + '?>' + GOOD)["passed"]


@pytest.mark.parametrize("content", [GOOD, SUITE, '\ufeff' + GOOD,
    '<?xml version="1.0" encoding="UTF-8"?>' + GOOD,
    GOOD.replace('<testsuites>', '<testsuites tests="1" errors="0" failures="0" skipped="0">'),
    '<testsuites>' + SUITE + EMPTY + '</testsuites>',
    GOOD.replace(CASE, CASE.replace('test_ok', '日本語')),
    GOOD.replace(CASE, CASE.replace('/>', '><system-out><![CDATA[<failure/> is logged text]]></system-out></testcase>')),
    GOOD.replace(CASE, '<properties><property name="language" value="日本語"/></properties>' + CASE),
    GOOD.replace(CASE, CASE.replace('/>', '><properties><property name="value" value="1"/></properties></testcase>')),
], ids=["flat", "single-suite", "bom", "declaration", "root-counts", "empty-sibling",
        "unicode", "escaped-log", "suite-properties", "case-properties"])
def test_supported_normal_reports_are_accepted(tmp_path, content):
    result = assess(tmp_path, content)
    assert result == {"passed": True, "cases": 1, "by_suite": {"demo": 1}, "problems": []}


@pytest.mark.parametrize("code", [1, 2, 5, -9])
def test_exit_failure_still_wins_over_good_report(tmp_path, code):
    result = assess(tmp_path, GOOD, code)
    assert not result["passed"]
    assert "PYTEST_EXIT_" + str(code) in result["problems"]


@pytest.mark.parametrize("tag,counter", [("failure", "failures"), ("error", "errors"), ("skipped", "skipped")])
def test_real_outcome_elements_still_fail_with_consistent_counters(tmp_path, tag, counter):
    content = GOOD.replace(CASE, CASE.replace('/>', '><' + tag + '/></testcase>'))
    content = content.replace(counter + '="0"', counter + '="1"')
    result = assess(tmp_path, content)
    assert not result["passed"]
    assert "FAILED_ERROR_OR_SKIPPED_CASE" in result["problems"]
    assert "FAILED_ERROR_OR_SKIPPED_SUITE" in result["problems"]


@pytest.mark.parametrize("duplicate", [False, True])
def test_missing_or_duplicate_id_checks_are_preserved(tmp_path, duplicate):
    content = (GOOD.replace('tests="1"', 'tests="2"').replace(CASE, CASE + CASE) if duplicate
               else GOOD.replace(' name="test_ok"', ''))
    result = assess(tmp_path, content)
    assert not result["passed"]
    assert "MISSING_OR_DUPLICATE_TEST_ID" in result["problems"]


@pytest.mark.parametrize("mode", ["pass", "fail", "skip", "error"])
def test_actual_pytest_output_is_assessed_not_a_mock(tmp_path, mode):
    body = {
        "pass": 'def test_case(record_testsuite_property):\n    record_testsuite_property("kind", "日本語")\n    print("<failure/> is only text")\n    assert True\n',
        "fail": 'def test_case():\n    assert False, "synthetic failure"\n',
        "skip": 'import pytest\ndef test_case():\n    pytest.skip("synthetic skip")\n',
        "error": 'import pytest\n@pytest.fixture\ndef broken():\n    raise RuntimeError("synthetic setup error")\ndef test_case(broken):\n    pass\n',
    }[mode]
    (tmp_path / 'test_demo.py').write_text(body, encoding='utf-8')
    xml_path = tmp_path / 'actual.xml'
    env = os.environ.copy()
    env.pop('PYTEST_ADDOPTS', None)
    env.pop('PYTEST_PLUGINS', None)
    env.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD='1', PYTHONHASHSEED='0')
    process = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-o', 'addopts=',
        '-o', 'junit_logging=all', '--junitxml=' + str(xml_path), 'test_demo.py'],
        cwd=tmp_path, env=env, capture_output=True, timeout=30, check=False)
    result = r.assess_junit(xml_path, process.returncode, {'test_demo': 1})
    assert result['cases'] == 1
    assert result['passed'] is (mode == 'pass')
    # An accidentally zeroed exit status must not hide the reported outcome.
    assert r.assess_junit(xml_path, 0, {'test_demo': 1})['passed'] is (mode == 'pass')
    assert process.returncode == (1 if mode in ('fail', 'error') else 0)
