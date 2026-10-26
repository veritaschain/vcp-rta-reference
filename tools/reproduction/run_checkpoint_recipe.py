#!/usr/bin/env python3
"""Execute the published, pinned shell recipe; first-party self-check only.

Runs reviewed repository code and network setup in a disposable directory.
Not a sandbox, independent reproduction, or a verifier of arbitrary reports.
Only the explicit report allowlist is retained; no checkout/venv/TSA directory.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
GUIDE_COMMIT = "a839d7a918c9a23ce170937f536e6c13b3a69b93"
TARGET = "cc695fe1698250878fbbc5f0c5461591ac8e0954"
TARGET_TREE = "52bcbe53daaaecf0ad45f1e65f251d945854eee1"
DOCUMENTS = {
    "docs/REPRODUCTION_CHECKPOINT_2026-10-26.md": "f408c887a468bd33492658f91d107f98618f93a2",
    "docs/REPRODUCTION_CHECKPOINT_2026-10-26.json": "462744e63a372df2554a3ec5cc538e7d18659aec",
    "docs/REVIEWER_REPORT_TEMPLATE.md": "6dfdc8a31dba6afd991b7e833d2a1ca0ae76f7f1",
}
REPORT_FILES = (
    "guide-commit.txt", "checkpoint.json", "reviewer-report-template.md", "pip-freeze.txt",
    "openssl-version.txt", "input-check.json", "historical.xml", "historical.log",
    "historical.exit", "historical-pack.json", "replay.exit", "review-assessment.json",
    "review-files.sha256.json", "regression/run.json", "regression/pytest.log",
    "regression/junit.xml", "regression/artifacts.sha256.json",
)
MAX_REPORT_BYTES = 32 * 1024 * 1024


def git(root: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          capture_output=True, timeout=30).stdout


def blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def extract_recipe(markdown: bytes) -> bytes:
    blocks = re.findall(rb"(?ms)^```sh\r?\n(.*?)^```[ \t]*\r?$", markdown)
    if len(blocks) != 1 or not blocks[0].startswith(b"set -eu\n"):
        raise ValueError("Expected exactly one reviewed POSIX-shell recipe")
    return blocks[0]


def copy_reports(source: Path, destination: Path) -> list[str]:
    """Copy named regular report files only, never recurse over test scratch data."""
    copied = []
    for name in REPORT_FILES:
        path = source / name
        if not path.exists() and not path.is_symlink():
            continue  # A failed setup may have generated only partial reports.
        if (path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode)
                or not path.resolve().is_relative_to(source.resolve())
                or any(parent.is_symlink() for parent in path.parents if parent != source.parent)):
            raise ValueError("Report must be an ordinary in-directory file: " + name)
        with path.open("rb") as handle:
            data = handle.read(MAX_REPORT_BYTES + 1)
        if len(data) > MAX_REPORT_BYTES:
            raise ValueError("Report exceeds local retention limit: " + name)
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(data)
        copied.append(name)
    return copied


def assess_completion(directory: Path, reference: dict) -> dict:
    """Check recipe completion; the pinned recipe does the actual test assessment."""
    assessment = json.loads((directory / "review-assessment.json").read_text())
    run = json.loads((directory / "regression/run.json").read_text())
    replay = json.loads((directory / "historical-pack.json").read_text())
    problems = []
    if assessment.get("reproduction_matches_reference") is not True or assessment.get("problems") != []:
        problems.append("RECIPE_ASSESSMENT_NOT_PASSED")
    if assessment.get("executed_commit") != TARGET or assessment.get("conformance_claim") is not False:
        problems.append("RECIPE_SCOPE_DIFFERS")
    for name, count in (("main", 809), ("historical", 15)):
        result = assessment.get(name, {})
        if result.get("passed") is not True or result.get("cases") != count or result.get("problems") != []:
            problems.append("RECIPE_CASE_RESULTS_DIFFER:" + name)
    if (run.get("run_status") != "passed" or run.get("pytest_exit") != 0
            or run.get("git_head") != TARGET):
        problems.append("MAIN_RUN_NOT_CONFIRMED")
    if int((directory / "historical.exit").read_text()) != 0:
        problems.append("HISTORICAL_TEST_EXIT_DIFFERS")
    if int((directory / "replay.exit").read_text()) != 2:
        problems.append("REPLAY_EXIT_DIFFERS")
    if replay.get("executed_commit") != TARGET:
        problems.append("REPLAY_COMMIT_DIFFERS")
    for name, expected in reference["replay_expectations"].items():
        if replay.get(name) != expected:
            problems.append("REPLAY_DIFFERS:" + name)
    expected = reference["input_sha256"]
    if run.get("inputs_before_sha256") != expected or run.get("inputs_after_sha256") != expected:
        problems.append("PINNED_INPUTS_DIFFER")
    return {"passed": not problems, "problems": problems, "main_cases": 809,
            "historical_cases": 15, "evidence_verdict": replay.get("evidence_verdict"),
            "environment": run.get("environment")}


def execute_shell(recipe: Path, work: Path, log: Path, temporary: Path) -> int:
    env = os.environ.copy()
    env.update(TMPDIR=str(temporary), GIT_TERMINAL_PROMPT="0")
    # No credentials are needed to clone this public repository.
    env.pop("GITHUB_TOKEN", None)
    env.pop("GH_TOKEN", None)
    with log.open("xb") as handle:
        process = subprocess.Popen(["sh", str(recipe)], cwd=work, env=env,
                                   stdin=subprocess.DEVNULL, stdout=handle,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return process.wait(timeout=900)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path,
                        help="New directory outside the source checkout")
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if output == ROOT.resolve() or output.is_relative_to(ROOT.resolve()):
        parser.error("Keep output outside the source checkout")
    try:
        output.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        print("Cannot create new output directory: " + type(exc).__name__)
        return 2
    report = {"format": "vcp-rta-checkpoint-recipe-run-v1", "run_status": "incomplete",
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "guide_source_commit": GUIDE_COMMIT, "checkpoint_commit": TARGET,
              "checkpoint_tree": TARGET_TREE, "launcher_python": platform.python_version(),
              "scope": "first-party execution of the published recipe; not independent reproduction",
              "independent_reproduction": False, "conformance_claim": False, "problems": []}
    try:
        report["automation_commit"] = git(ROOT, "rev-parse", "HEAD").decode().strip()
        documents = {name: git(ROOT, "show", GUIDE_COMMIT + ":" + name) for name in DOCUMENTS}
        for name, value in documents.items():
            if blob_id(value) != DOCUMENTS[name]:
                raise ValueError("Pinned guide document changed: " + name)
        markdown, reference_bytes, template_bytes = documents.values()
        reference = json.loads(reference_bytes)
        if reference["checkout_commit"] != TARGET or reference["git_tree"] != TARGET_TREE:
            raise ValueError("Checkpoint target differs")
        recipe = extract_recipe(markdown)
        report["guide_document_blobs"] = DOCUMENTS
        report["recipe_sha256"] = hashlib.sha256(recipe).hexdigest()
        recipe_path = output / "executed-recipe.sh"
        recipe_path.write_bytes(recipe)
        subprocess.run(["sh", "-n", str(recipe_path)], check=True, timeout=15)
        with tempfile.TemporaryDirectory(prefix="vcp-recipe-selfcheck-") as scratch:
            work = Path(scratch)
            temporary = work / "tmp"
            temporary.mkdir()
            try:
                report["recipe_exit"] = execute_shell(recipe_path, work, output / "recipe.log", temporary)
            finally:
                matches = list(temporary.glob("vcp-rta-review.*"))
                if len(matches) == 1 and matches[0].is_dir() and not matches[0].is_symlink():
                    report["retained_report_files"] = copy_reports(matches[0], output / "review")
            if report.get("recipe_exit") != 0:
                report["problems"].append("RECIPE_EXIT_NOT_ZERO")
            elif len(matches) != 1:
                report["problems"].append("RECIPE_OUTPUT_DIRECTORY_NOT_UNIQUE")
            else:
                retained = output / "review"
                if sorted(report["retained_report_files"]) != sorted(REPORT_FILES):
                    raise ValueError("Successful recipe did not produce every expected report")
                if (retained / "checkpoint.json").read_bytes() != reference_bytes:
                    raise ValueError("Cloned checkpoint metadata differs from pinned guide")
                if (retained / "reviewer-report-template.md").read_bytes() != template_bytes:
                    raise ValueError("Cloned reviewer template differs from pinned guide")
                checkout = work / "vcp-rta-checkpoint-20261026"
                if git(checkout, "rev-parse", "HEAD").decode().strip() != TARGET:
                    raise ValueError("Actual checkout commit differs")
                if git(checkout, "rev-parse", "HEAD^{tree}").decode().strip() != TARGET_TREE:
                    raise ValueError("Actual checkout tree differs")
                guide_head = (retained / "guide-commit.txt").read_text().strip()
                if not re.fullmatch(r"[0-9a-f]{40}", guide_head):
                    raise ValueError("Missing actual cloned-guide commit")
                report["cloned_guide_commit"] = guide_head
                report["assessment"] = assess_completion(retained, reference)
                report["problems"].extend(report["assessment"]["problems"])
            report["run_status"] = "passed" if not report["problems"] else "failed"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        report["problems"].append("RECIPE_SELFCHECK_ERROR:" + type(exc).__name__)
        report["run_status"] = "incomplete"
    report["finished_utc"] = datetime.now(timezone.utc).isoformat()
    (output / "recipe-run.json").write_text(json.dumps(report, indent=2) + "\n")
    manifest = {p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(output.rglob("*")) if p.is_file()}
    (output / "files.sha256.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["run_status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
