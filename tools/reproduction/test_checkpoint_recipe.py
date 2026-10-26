"""Self-check launcher tests. Synthetic reports; not a checkpoint execution."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("recipe_launcher", Path(__file__).with_name("run_checkpoint_recipe.py"))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class RecipeLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_extract_preserves_exact_bytes(self):
        body = b"set -eu\nprintf '%s\\n' test\n"
        self.assertEqual(r.extract_recipe(b"# Guide\n\n```sh\n" + body + b"```\n"), body)

    def test_missing_multiple_or_unguarded_recipe_rejected(self):
        for content in (b"no shell", b"```sh\necho x\n```\n",
                        b"```sh\nset -eu\n```\n```sh\nset -eu\n```\n"):
            with self.subTest(content=content), self.assertRaises(ValueError):
                r.extract_recipe(content)

    def test_git_blob_hash_known_empty(self):
        self.assertEqual(r.blob_id(b""), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391")

    def test_allowlist_does_not_copy_private_keys_or_checkout(self):
        source, output = self.root / "source", self.root / "out"
        (source / "regression").mkdir(parents=True)
        (source / "regression/run.json").write_text("{}")
        (source / "historical.exit").write_text("0\n")
        (source / "tsa.key").write_text("SYNTHETIC SECRET NOT TO RETAIN")
        (source / ".venv").mkdir()
        (source / ".venv/token").write_text("SYNTHETIC SECRET")
        self.assertEqual(set(r.copy_reports(source, output)), {"historical.exit", "regression/run.json"})
        self.assertFalse((output / "tsa.key").exists())
        self.assertFalse((output / ".venv").exists())

    def test_symlinked_report_refused(self):
        source = self.root / "source"
        source.mkdir()
        target = self.root / "outside"
        target.write_text("not a report")
        (source / "historical.exit").symlink_to(target)
        with self.assertRaises(ValueError):
            r.copy_reports(source, self.root / "out")

    def test_symlinked_parent_refused(self):
        source = self.root / "source"
        source.mkdir()
        actual = source / "actual"
        actual.mkdir()
        (actual / "run.json").write_text("{}")
        (source / "regression").symlink_to(actual, target_is_directory=True)
        with self.assertRaises(ValueError):
            r.copy_reports(source, self.root / "out")

    def test_report_copy_does_not_overwrite(self):
        source, output = self.root / "source", self.root / "out"
        source.mkdir()
        output.mkdir()
        (source / "historical.exit").write_text("0")
        (output / "historical.exit").write_text("old")
        with self.assertRaises(FileExistsError):
            r.copy_reports(source, output)
        self.assertEqual((output / "historical.exit").read_text(), "old")

    def test_report_size_limit_refused(self):
        source = self.root / "source"
        source.mkdir()
        (source / "historical.log").write_bytes(b"123456789")
        with mock.patch.object(r, "MAX_REPORT_BYTES", 8), self.assertRaises(ValueError):
            r.copy_reports(source, self.root / "out")

    def fixture_reports(self):
        expected = {"file": "synthetic-hash"}
        reference = {"input_sha256": expected, "replay_expectations": {
            "evidence_verdict": "INDETERMINATE", "execution_status": "completed"}}
        contents = {
            "review-assessment.json": {"reproduction_matches_reference": True, "problems": [],
                "executed_commit": r.TARGET, "conformance_claim": False,
                "main": {"passed": True, "cases": 809, "problems": []},
                "historical": {"passed": True, "cases": 15, "problems": []}},
            "regression/run.json": {"run_status": "passed", "pytest_exit": 0, "git_head": r.TARGET,
                "inputs_before_sha256": expected, "inputs_after_sha256": expected},
            "historical-pack.json": dict(reference["replay_expectations"], executed_commit=r.TARGET),
        }
        for name, data in contents.items():
            p = self.root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(json.dumps(data))
        (self.root / "historical.exit").write_text("0")
        (self.root / "replay.exit").write_text("2")
        return reference, contents

    def test_completion_requires_matching_reports(self):
        reference, _ = self.fixture_reports()
        self.assertTrue(r.assess_completion(self.root, reference)["passed"])

    def test_zero_shell_exit_does_not_replace_reports(self):
        reference, contents = self.fixture_reports()
        mutations = [
            ("review-assessment.json", "reproduction_matches_reference", False),
            ("review-assessment.json", "problems", ["failed"]),
            ("review-assessment.json", "executed_commit", "wrong"),
            ("review-assessment.json", "conformance_claim", True),
            ("regression/run.json", "run_status", "failed"),
            ("regression/run.json", "pytest_exit", 1),
            ("regression/run.json", "inputs_after_sha256", {}),
            ("historical-pack.json", "evidence_verdict", "VALID"),
        ]
        for name, field, value in mutations:
            with self.subTest(name=name, field=field):
                changed = copy.deepcopy(contents[name])
                changed[field] = value
                p = self.root / name
                p.write_text(json.dumps(changed))
                self.assertFalse(r.assess_completion(self.root, reference)["passed"])
                p.write_text(json.dumps(contents[name]))

    def test_wrong_exit_codes_refused(self):
        reference, _ = self.fixture_reports()
        for name, good, bad in (("historical.exit", "0", "1"), ("replay.exit", "2", "0")):
            with self.subTest(name=name):
                p = self.root / name
                p.write_text(bad)
                self.assertFalse(r.assess_completion(self.root, reference)["passed"])
                p.write_text(good)

    def test_actual_shell_exit_and_log_are_preserved(self):
        recipe = self.root / "recipe.sh"
        recipe.write_text("set -eu\nprintf 'synthetic-only\\n'\nexit 7\n")
        log = self.root / "recipe.log"
        self.assertEqual(r.execute_shell(recipe, self.root, log, self.root), 7)
        self.assertEqual(log.read_text(), "synthetic-only\n")

    def test_existing_output_never_runs_recipe(self):
        output = self.root / "out"
        output.mkdir()
        (output / "keep").write_text("old")
        with mock.patch.object(r, "git", side_effect=AssertionError("must not execute")):
            self.assertEqual(r.main(["--output-dir", str(output)]), 2)
        self.assertEqual((output / "keep").read_text(), "old")


if __name__ == "__main__":
    unittest.main()
