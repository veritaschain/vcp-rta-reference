#!/usr/bin/env python3
"""Record a fail-closed local regression run; never a conformance verdict."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[2]
SUITES = {"test_verifier": 135, "test_attested_batch": 80, "test_regression_runner": 33,
          "test_openssl_trust_store": 2, "test_report_output": 51, "test_input_limits": 75,
          "test_result_aggregation": 66}
REQUIRED_TEST = ("test_attested_batch", "test_real_rfc3161_response_signature_chain_and_imprint")
DEPENDENCIES = ("pytest", "cryptography", "asn1crypto")
LIMIT = 16 * 1024 * 1024


def assess_junit(path: Path, returncode: int, minimums=None) -> dict:
    """Reject empty, skipped, partial, malformed, failed or stale-looking results."""
    minimums = SUITES if minimums is None else minimums
    result = {"passed": False, "cases": 0, "by_suite": {}, "problems": []}
    problems = result["problems"]
    if returncode != 0:
        problems.append("PYTEST_EXIT_" + str(returncode))
    try:
        with path.open("rb") as handle:
            data = handle.read(LIMIT + 1)
        if len(data) > LIMIT or b"<!DOCTYPE" in data or b"<!ENTITY" in data:
            raise ValueError("Unsafe or oversized JUnit XML")
        root = ET.fromstring(data)
        if root.tag not in ("testsuites", "testsuite"):
            raise ValueError("Unexpected JUnit root")
        cases = list(root.iter("testcase"))
        result["cases"] = len(cases)
        counts = Counter()
        identities = set()
        for case in cases:
            suite = case.get("classname", "").rsplit(".", 1)[-1]
            identity = (suite, case.get("name", ""))
            if not all(identity) or identity in identities:
                problems.append("MISSING_OR_DUPLICATE_TEST_ID")
            identities.add(identity)
            counts[suite] += 1
            if any(case.find(tag) is not None for tag in ("failure", "error", "skipped")):
                problems.append("FAILED_ERROR_OR_SKIPPED_CASE")
        declared = list(root.iter("testsuite"))
        if not declared or sum(int(s.get("tests", "0")) for s in declared) != len(cases):
            problems.append("INCONSISTENT_JUNIT_COUNTS")
        for suite in declared:
            if any(int(suite.get(k, "0")) != 0 for k in ("failures", "errors", "skipped")):
                problems.append("FAILED_ERROR_OR_SKIPPED_SUITE")
        result["by_suite"] = dict(sorted(counts.items()))
        if not cases:
            problems.append("NO_TESTS")
        for suite, minimum in minimums.items():
            if counts[suite] < minimum:
                problems.append("MISSING_CASES:" + suite)
        if "test_attested_batch" in minimums and REQUIRED_TEST not in identities:
            problems.append("REAL_RFC3161_TEST_MISSING")
    except (OSError, ValueError, ET.ParseError) as exc:
        problems.append("JUNIT_UNUSABLE:" + type(exc).__name__)
    result["problems"] = sorted(set(problems))
    result["passed"] = not result["problems"]
    return result


def input_manifest(root: Path) -> dict:
    """Hash code/tests and archival bytes, excluding generated Python caches."""
    paths = {root / "requirements-verifier-test.txt"}
    for name in ("tools/verifier", "tests"):
        paths.update((root / name).rglob("*.py"))
    paths.update(p for p in (root / "evidence").rglob("*") if p.is_file()
                 and "__pycache__" not in p.parts and p.suffix != ".pyc")
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths) if p.is_file()}


def prepare_output(root: Path, path: Path) -> Path:
    path = path.resolve()
    if path == root.resolve() or any(path.is_relative_to((root / name).resolve())
                                    for name in ("evidence", "tools", "tests", ".git")):
        raise ValueError("Output must be outside source and evidence directories")
    path.mkdir(parents=True, exist_ok=False)
    return path


def environment() -> dict:
    versions = {}
    for name in DEPENDENCIES:
        try:
            versions[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            versions[name] = None
    executable = shutil.which("openssl")
    info = {"python": platform.python_version(), "platform": platform.platform(),
            "dependencies": versions, "openssl_executable": executable, "openssl": None}
    if executable:
        try:
            process = subprocess.run([executable, "version"], capture_output=True, text=True,
                                     timeout=10, check=False)
            if process.returncode == 0:
                info["openssl"] = process.stdout.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass
    return info


def preflight(root: Path, info: dict) -> list:
    problems = []
    if sys.version_info < (3, 10):
        problems.append("PYTHON_3_10_OR_NEWER_REQUIRED")
    if not re.match(r"OpenSSL (?:[3-9]|[1-9][0-9]+)\.", info.get("openssl") or ""):
        problems.append("OPENSSL_3_OR_NEWER_REQUIRED")
    try:
        lines = (root / "requirements-verifier-test.txt").read_text(encoding="utf-8").splitlines()
        pins = dict(line.split("==") for line in lines if line and not line.startswith("#"))
        if set(pins) != set(DEPENDENCIES):
            raise ValueError("Unexpected dependency manifest")
        for name, version in pins.items():
            if info["dependencies"].get(name) != version:
                problems.append("DEPENDENCY_VERSION_MISMATCH:" + name)
    except (OSError, ValueError):
        problems.append("DEPENDENCY_MANIFEST_UNUSABLE")
    for suite in SUITES:
        if not (root / "tests" / (suite + ".py")).is_file():
            problems.append("TEST_FILE_MISSING:" + suite)
    return problems


def git_head(root: Path):
    try:
        p = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                           capture_output=True, text=True, timeout=10, check=False)
        return p.stdout.strip() if p.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        help="New directory; an existing directory is never overwritten")
    args = parser.parse_args(argv)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = args.output_dir or ROOT / ".verification-results" / (stamp + "-" + uuid.uuid4().hex[:8])
    try:
        output = prepare_output(ROOT, output)
    except (OSError, ValueError) as exc:
        print("Cannot create output directory: " + str(exc), file=sys.stderr)
        return 2
    report = {"report_version": 1, "run_status": "incomplete", "started_utc": stamp,
              "scope": "first-party synthetic regression; not conformance or independent reproduction",
              "git_head": git_head(ROOT), "environment": environment(), "problems": []}
    try:
        before = input_manifest(ROOT)
        report["inputs_before_sha256"] = before
        report["problems"] = preflight(ROOT, report["environment"])
        if report["problems"]:
            report["run_status"] = "preflight_failed"
        else:
            command = [sys.executable, "-m", "pytest", "-q", "--strict-config", "--strict-markers",
                       "-o", "addopts=", "--junitxml=" + str(output / "junit.xml")]
            command += ["tests/" + name + ".py" for name in SUITES]
            report["command"] = command
            env = os.environ.copy()
            env.pop("PYTEST_ADDOPTS", None)
            env.pop("PYTEST_PLUGINS", None)
            env.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONHASHSEED="0")
            with (output / "pytest.log").open("wb") as log:
                process = subprocess.run(command, cwd=ROOT, env=env, stdout=log,
                                         stderr=subprocess.STDOUT, timeout=300, check=False)
            report["pytest_exit"] = process.returncode
            report["junit"] = assess_junit(output / "junit.xml", process.returncode)
            report["problems"].extend(report["junit"]["problems"])
            after = input_manifest(ROOT)
            report["inputs_after_sha256"] = after
            if before != after:
                report["problems"].append("SOURCE_OR_EVIDENCE_CHANGED_DURING_RUN")
            if git_head(ROOT) != report["git_head"]:
                report["problems"].append("GIT_HEAD_CHANGED_DURING_RUN")
            report["run_status"] = "passed" if not report["problems"] else "failed"
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        report["problems"].append("RUNNER_ERROR:" + type(exc).__name__)
        report["run_status"] = "incomplete"
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (output / "run.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.iterdir())
                if p.is_file()}
    (output / "artifacts.sha256.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Regression run: " + report["run_status"] + "; reports: " + str(output))
    return 0 if report["run_status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
