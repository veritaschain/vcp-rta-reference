# Reproducing the verifier regression tests

Updated 2026-10-26. This is a first-party test/reproduction entry point, not
VCP/VAP conformance, normative adoption, certification, independent validation,
or a claim that the historical Evidence Pack is fully authenticated.

## Run from a reviewed checkout

Use Python 3.10 or newer and an OpenSSL 3.x command-line executable. The tests
create a temporary local CA/TSA and verify actual synthetic RFC 3161 responses.
They do not contact a commercial TSA, modify historical evidence or supply a
missing original OpenTimestamps proof.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-verifier-test.txt
python tools/verifier/run_regression.py
```

The default destination is a new `.verification-results/<time>-<random>/`
directory. To choose a location, use `--output-dir /path/to/new-directory`.
Existing output directories are rejected, as are destinations inside `evidence/`,
`tools/`, `tests/` or `.git/`. Run only code you have reviewed, preferably in a
fresh disposable environment. Installing dependencies and GitHub Actions setup
require network access; the verifier tests use local fixtures, not online TSA
services. The runner itself is not a network sandbox.

Direct dependencies are pinned to the versions used for the original verifier
regressions. This is **not a complete transitive dependency or OS lockfile** and
is not a claim that pinned versions will always be the most secure versions.
Review updates separately. The report records the actual Python, platform,
OpenSSL executable/version and direct dependency versions. CI tests Python 3.11
(latest available patch in that line) and the original 3.13.5 baseline on
`ubuntu-24.04`; runner images and transitive dependencies can change.

## What counts as a successful run

The runner currently requires all three suites:

| Suite | Minimum collected/executed cases |
|---|---:|
| `tests/test_verifier.py` | 135 |
| `tests/test_attested_batch.py` | 80 |
| `tests/test_regression_runner.py` | 33 |

The expected baseline is **248 cases**. Each minimum is checked separately to
avoid silently dropping one suite. The named real RFC 3161 integration test
must be present. Pytest must exit zero; any failure, error, skip (including
expected failures reported as skips), malformed/missing XML, duplicate test ID,
count inconsistency or insufficient coverage makes the run unsuccessful.

A missing OpenSSL executable or dependency-version mismatch fails preflight
instead of turning the cryptographic suite into a successful skipped run.
Pytest plugin autoload and environment-provided extra options/plugins are
disabled. Tests and verifier source files, the direct-dependency manifest, and
all non-cache archival files under `evidence/` are SHA-256 hashed before and
after execution. Changed inputs or a changed Git HEAD fail the run.

These guards catch accidental incomplete execution. They do not defend against
a malicious test harness rewriting its own results. The runner's self-tests
use synthetic XML/process fixtures, not cryptographic proofs.

## Reports

A run writes:

- `run.json`: run status, exact Git HEAD where available, command, environment,
  per-suite counts, failure reasons, before/after input hashes.
- `pytest.log` and `junit.xml`: test execution output and machine-readable cases.
- `artifacts.sha256.json`: hashes of the files written in that output directory
  before the hash manifest itself is written.

Preflight failure may produce only `run.json` and the hash manifest. The output
status is `passed`, `failed`, `preflight_failed` or `incomplete`, not the
verifier's `VALID`/`INVALID`/`INDETERMINATE` verdicts. Exit zero means the
regression run passed, **not that any Evidence Pack passed verification**.
Checksums detect changed report bytes; they do not authenticate their author.
No private key or certificate file from the temporary test TSA is intentionally
included in the uploaded artifact set. Logs may contain failing test details.

## Continuous integration and outside reproduction

`.github/workflows/verifier-regression.yml` runs on main pushes, pull requests
and manual dispatch. Actions are pinned to reviewed commit IDs; the job has
read-only repository permissions, does not persist checkout credentials, does
not consume production secrets and does not use `pull_request_target`. Only the
four named report files are uploaded for 30 days. CI success is first-party
regression evidence, not independent third-party validation.

An outside reviewer should record their own checked-out commit, input hashes,
environment, command, output and discrepancies. A report must be attributed to
its actual executor. Running this harness does not by itself establish that the
executor is independent or that VCP/VAP conformance has been assessed. Existing
K3 and fixed reproduction-kit baselines are unchanged.

## 日本語

実行入口は `python tools/verifier/run_regression.py`。既存215件とランナー33件を
まとめて実行し、実行環境・コミット・コードと証拠ファイルのハッシュ・結果を残す。
スキップ、件数不足、失敗、実行中の入力変更は成功扱いにしない。
「回帰テスト成功」と「Evidence Packの検証成功」は別であり、独立再現・適合性・
認証の成立を自動宣言しない。過去の署名済み証拠や規範仕様は変更しない。
