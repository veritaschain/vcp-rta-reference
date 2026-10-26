"""Runner inventory guard. Temporary repositories; not evidence verification."""
import importlib.util
from importlib import metadata
import json
import os
from pathlib import Path

import pytest

MODULE = Path(__file__).resolve().parents[1] / "tools/verifier/run_regression.py"
spec = importlib.util.spec_from_file_location("inventory_runner", MODULE)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


@pytest.fixture
def tree(tmp_path, monkeypatch):
    root = tmp_path / "synthetic-repository"
    (root / "tests").mkdir(parents=True)
    (root / "requirements-verifier-test.txt").write_text("\n".join(
        name + "==" + metadata.version(name) for name in r.DEPENDENCIES) + "\n")
    (root / "tests/test_registered.py").write_text("def test_ok():\n    assert True\n")
    (root / "tests/test_historical_evidence.py").write_text(
        "def test_history_placeholder():\n    assert True\n")
    monkeypatch.setattr(r, "ROOT", root)
    monkeypatch.setattr(r, "SUITES", {"test_registered": 1})
    return root


def put(root, relative, content="def test_new():\n    assert False\n"):
    path = root / "tests" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return path


def test_complete_inventory_names_both_execution_scopes(tree):
    result = r.assess_test_inventory(tree)
    assert result == {"passed": True, "regression_files": ["test_registered.py"],
        "separate_files": ["test_historical_evidence.py"],
        "discovered_files": ["test_historical_evidence.py", "test_registered.py"], "problems": []}


@pytest.mark.parametrize("name", ["test_new.py", "new_test.py", "nested/test_new.py",
                                 "nested/test_registered.py", ".hidden/test_new.py"])
def test_unregistered_candidate_files_are_never_ignored(tree, name):
    put(tree, name)
    result = r.assess_test_inventory(tree)
    assert not result["passed"]
    assert "UNREGISTERED_TEST_MODULE:" + name in result["problems"]


@pytest.mark.parametrize("name", ["test_registered.py", "test_historical_evidence.py"])
def test_missing_regression_or_separate_suite_is_refused(tree, name):
    (tree / "tests" / name).unlink()
    result = r.assess_test_inventory(tree)
    assert not result["passed"]
    assert "EXPECTED_TEST_MODULE_MISSING:" + name in result["problems"]


def test_helpers_and_caches_are_not_test_modules_and_are_not_imported(tree):
    for name in ("conftest.py", "helpers.py", "__init__.py", "__pycache__/test_old.pyc",
                 "test_notes.txt", "attestation.json"):
        put(tree, name, "raise AssertionError('inventory must not import this file')\n")
    assert r.assess_test_inventory(tree)["passed"]


@pytest.mark.parametrize("dangling", [False, True])
def test_candidate_symlink_cannot_satisfy_inventory(tree, dangling):
    path = tree / "tests/test_registered.py"
    path.unlink()
    target = tree / "outside.py"
    if not dangling:
        target.write_text("def test_outside():\n    assert True\n")
    path.symlink_to(target)
    result = r.assess_test_inventory(tree)
    assert not result["passed"]
    assert "TEST_MODULE_NOT_REGULAR:test_registered.py" in result["problems"]


def test_directory_symlink_is_refused_without_traversal(tree):
    outside = tree / "outside"
    outside.mkdir()
    (outside / "test_hidden.py").write_text("raise AssertionError('not imported')\n")
    (tree / "tests/linked").symlink_to(outside, target_is_directory=True)
    result = r.assess_test_inventory(tree)
    assert "TEST_DIRECTORY_SYMLINK:linked" in result["problems"]
    assert "linked/test_hidden.py" not in result["discovered_files"]


def test_symlinked_tests_root_is_refused(tree):
    (tree / "tests").rename(tree / "outside")
    (tree / "tests").symlink_to(tree / "outside", target_is_directory=True)
    result = r.assess_test_inventory(tree)
    assert not result["passed"] and result["discovered_files"] == []


def test_fifo_test_module_is_not_opened_or_imported(tree):
    path = tree / "tests/test_pipe.py"
    os.mkfifo(path)
    result = r.assess_test_inventory(tree)
    assert not result["passed"]
    assert "TEST_MODULE_NOT_REGULAR:test_pipe.py" in result["problems"]


def test_walk_error_is_not_an_empty_success(tree, monkeypatch):
    def broken(*args, **kwargs):
        kwargs["onerror"](PermissionError("synthetic inaccessible directory"))
        return iter(())
    monkeypatch.setattr(r.os, "walk", broken)
    result = r.assess_test_inventory(tree)
    assert not result["passed"]
    assert "TEST_INVENTORY_UNUSABLE:PermissionError" in result["problems"]


def test_missing_tests_directory_is_refused(tmp_path):
    result = r.assess_test_inventory(tmp_path)
    assert not result["passed"] and result["discovered_files"] == []


def test_inventory_is_read_only_and_deterministically_sorted(tree):
    for name in ("test_z.py", "test_a.py"):
        put(tree, name)
    before = {p.relative_to(tree).as_posix(): p.read_bytes() for p in tree.rglob("*") if p.is_file()}
    first = r.assess_test_inventory(tree)
    assert first == r.assess_test_inventory(tree)
    assert first["discovered_files"] == sorted(first["discovered_files"])
    assert before == {p.relative_to(tree).as_posix(): p.read_bytes() for p in tree.rglob("*") if p.is_file()}


@pytest.mark.parametrize("name", ["test_new.py", "new_test.py", "nested/test_new.py"])
def test_main_blocks_unregistered_failure_before_running_pytest(tree, tmp_path, name):
    put(tree, name)
    output = tmp_path / "reports"
    code = r.main(["--output-dir", str(output)])
    report = json.loads((output / "run.json").read_text())
    assert code == 1
    assert report["run_status"] == "preflight_failed"
    assert "UNREGISTERED_TEST_MODULE:" + name in report["problems"]
    assert not report["test_inventory"]["passed"]
    assert "pytest_exit" not in report and "command" not in report
    assert not (output / "junit.xml").exists() and not (output / "pytest.log").exists()
    assert (output / "artifacts.sha256.json").is_file()


def test_main_complete_registration_executes_real_pytest(tree, tmp_path):
    output = tmp_path / "reports"
    assert r.main(["--output-dir", str(output)]) == 0
    report = json.loads((output / "run.json").read_text())
    assert report["run_status"] == "passed"
    assert report["test_inventory"]["passed"]
    assert report["junit"]["cases"] == 1
    assert report["inputs_before_sha256"] == report["inputs_after_sha256"]
    assert report["test_inventory"]["separate_files"] == ["test_historical_evidence.py"]
    assert "tests/test_historical_evidence.py" not in report["command"]


def test_registration_does_not_turn_a_failing_test_into_success(tree, tmp_path, monkeypatch):
    put(tree, "test_new.py")
    monkeypatch.setattr(r, "SUITES", {"test_registered": 1, "test_new": 1})
    output = tmp_path / "reports"
    assert r.main(["--output-dir", str(output)]) == 1
    report = json.loads((output / "run.json").read_text())
    assert report["test_inventory"]["passed"]
    assert report["run_status"] == "failed" and report["pytest_exit"] == 1
    assert report["junit"]["cases"] == 2
    assert "FAILED_ERROR_OR_SKIPPED_CASE" in report["problems"]


def test_guard_precedes_input_manifest_and_test_execution(tree, tmp_path, monkeypatch):
    put(tree, "test_unregistered.py")
    def forbidden(*args, **kwargs):
        raise AssertionError("unaccounted sources reached hashing or execution")
    monkeypatch.setattr(r, "input_manifest", forbidden)
    monkeypatch.setattr(r, "git_head", lambda _: None)
    info = r.environment()
    monkeypatch.setattr(r, "environment", lambda: info)
    monkeypatch.setattr(r.subprocess, "run", forbidden)
    assert r.main(["--output-dir", str(tmp_path / "reports")]) == 1


def test_inventory_failure_does_not_overwrite_prior_output(tree, tmp_path):
    put(tree, "test_new.py")
    output = tmp_path / "reports"
    output.mkdir()
    (output / "keep").write_bytes(b"previous report")
    assert r.main(["--output-dir", str(output)]) == 2
    assert (output / "keep").read_bytes() == b"previous report"
    assert sorted(p.name for p in output.iterdir()) == ["keep"]


def test_explicit_historical_exception_does_not_cover_another_history_file(tree):
    put(tree, "test_historical_other.py")
    assert "UNREGISTERED_TEST_MODULE:test_historical_other.py" in r.assess_test_inventory(tree)["problems"]


def test_hidden_cache_named_python_test_is_not_silently_exempt(tree):
    put(tree, "__pycache__/test_unexpected.py")
    assert "UNREGISTERED_TEST_MODULE:__pycache__/test_unexpected.py" in r.assess_test_inventory(tree)["problems"]


def test_empty_unknown_test_file_still_requires_registration(tree):
    put(tree, "test_empty.py", "")
    assert "UNREGISTERED_TEST_MODULE:test_empty.py" in r.assess_test_inventory(tree)["problems"]
