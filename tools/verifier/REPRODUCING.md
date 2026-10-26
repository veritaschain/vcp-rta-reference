# Reproducing the verifier regression tests

Updated 2026-10-26. This is a test/reproduction entry point, not VCP/VAP
conformance, normative adoption, certification, independent validation, or a
claim that the historical Evidence Pack is fully authenticated.

For an outside review of a specific version, use the
[fixed checkpoint and complete procedure](../../docs/REPRODUCTION_CHECKPOINT_2026-10-26.md),
[reference JSON](../../docs/REPRODUCTION_CHECKPOINT_2026-10-26.json), and
[reviewer report template](../../docs/REVIEWER_REPORT_TEMPLATE.md).
That checkpoint pins a commit; the general commands below use your checkout.

## Run from a reviewed checkout

Use Python 3.10 or newer and an OpenSSL 3.x command-line executable. The recorded
CI environments are Linux; platform-specific tests include POSIX FIFOs and
symlinks. Windows portability is not established by these results. Review the
code before execution, preferably in a fresh disposable environment.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-verifier-test.txt
python tools/verifier/run_regression.py
```

The default destination is a new `.verification-results/<time>-<random>/`
directory. Use `--output-dir /path/to/new-directory` to choose one. Existing
directories and destinations inside `evidence/`, `tools/`, `tests/` or `.git/`
are refused. Do not send a report to an input filename using shell redirection.

Installing dependencies and setting up CI require network access. Timestamp
tests create temporary local CA/TSA fixtures and verify actual signed RFC 3161
responses; they do not contact a commercial TSA or supply a missing historical
OpenTimestamps proof. The runner is not a network or malicious-code sandbox.

Direct dependencies are pinned, not a complete transitive dependency or OS
lockfile, and not a claim that the pins are always the most secure versions.
Review dependency updates separately. Reports record actual Python, platform,
OpenSSL and direct dependency versions. CI uses Python 3.11 (the available patch
in that line) and 3.13.5 on `ubuntu-24.04`; runner images can change.

## Discover the counts for your checkout

`SUITES` in `run_regression.py` is the main-suite registry. Print its minimums
rather than assuming the obsolete four-suite/250-case baseline:

```sh
python - <<'PY'
import sys
sys.path.insert(0, 'tools/verifier')
import run_regression as runner
for name, count in runner.SUITES.items():
    print(f'{name}: {count}')
print('main minimum:', sum(runner.SUITES.values()))
print('separate modules:', ', '.join(sorted(runner.SEPARATE_TEST_FILES)))
PY
```

At the fixed PR #14 checkpoint, the main run has **13 modules / 809 cases**;
`test_historical_evidence.py` adds **15 separately executed cases**. These dated
counts describe that checkpoint, not every future main. A main-run success does
not imply that the historical suite ran. Run it separately:

```sh
python -m pytest -q tests/test_historical_evidence.py
```

The fixed-checkpoint procedure retains both sets of results and the full replay
JSON. Existing K3 and other pinned reproduction kits are not replaced.

## What counts as a successful run

The runner accounts for every test module before execution: both `test_*.py`
and `*_test.py`, including nested candidates, must belong to its registry or the
one explicitly separate historical suite. Unknown or missing modules, candidate
symlinks/special files and traversal errors fail preflight. Inventory does not
establish exact case coverage or execution of the separate suite.

Every registered suite must meet its own minimum. The named real RFC 3161 test
must be present. Pytest must exit zero, with no failed, erroneous, skipped or
duplicate cases. JUnit results must satisfy the local UTF-8 flat-pytest profile,
including per-suite counters. A valid-looking total alone does not pass.
See [inventory rules](TEST_INVENTORY.md) and [report integrity](JUNIT_INTEGRITY.md).

Unavailable OpenSSL or mismatched dependencies fail preflight rather than
silently skipping crypto tests. Plugin autoload and environment-provided pytest
extra options/plugins are disabled. Code, tests, direct dependency pins and
non-cache archival files under `evidence/` are SHA-256 hashed before and after
execution. Changed listed inputs or Git HEAD fail the run. These are accidental
execution guards, not defenses against a malicious test rewriting its own report.

## Reports and exit codes

`run_regression.py` writes `run.json`, `pytest.log`, `junit.xml` and
`artifacts.sha256.json`. The run report records environment, command, Git HEAD
where available, inventory, per-suite results, problems and before/after hashes.
Preflight failure may have only the run report and hash manifest, with no input
hashes because inventory and dependency checks precede hashing.

| Command | Successful execution means |
| --- | --- |
| `run_regression.py` | Exit 0 and `run_status: passed`; only registered main tests |
| `pytest tests/test_historical_evidence.py` | Exit 0; expected fixed-corpus behavior reproduced |
| `inspect_historical_pack.py --compare-reference-key` | At this checkpoint, exit **2** and evidence verdict **INDETERMINATE** |

The runner's other exits are 1 for failed/incomplete/preflight-failed runs and 2
when the output directory cannot be prepared. Its exit 2 is not an evidence
verdict. Evidence-verifier CLIs have their own exit meanings. Never interpret
an exit code without the command and its report. Do not hide unexpected failures
with an unconditional `|| true`.

Checksums detect changed bytes, not their author. Test success is not overall
Evidence Pack validity. The temporary TSA private keys are not intentionally
included in uploaded reports. Review logs before sharing; they may contain
local paths or failing test details.

## Continuous integration and outside reports

`verifier-regression.yml` and `historical-pack.yml` run separately on main pushes,
PRs and manual dispatch. Their checkout/setup/upload actions are pinned; jobs
have read-only repository permissions, do not persist checkout credentials or
consume production secrets, and do not use `pull_request_target`. Artifacts have
a 30-day retention policy, not permanent archival availability.

Outside reviewers should retain their own exact commit/tree, commands, exit
codes, environment, hashes and discrepancies. Record the actual executor and
any relationship to VSO separately. Permission to publish results, a personal
name and an affiliation are separate decisions. A short agreement to run a test
is not blanket attribution consent. Use the report template; no mailing or
publication is performed by these instructions.

## 日本語

古い「4テスト群・250件」の案内を、使用するコミットの登録一覧から確認する方式に
訂正しました。PR #14の固定版では通常809件と、別実行の公開証拠15件です。
通常テストの成功だけで公開証拠のテストも実行済みとは扱いません。

固定版の手順では、コミット・対象29ファイルのハッシュ・実行結果を照合します。
証拠再検証の終了コード2は期待どおりですが、テストランナーの終了コード2とは意味が
違います。レポートの種別と内容を必ず確認してください。独立再現、適合性、認証や
元の外部アンカーの成立は自動宣言しません。

## Historical OpenSSL portability correction

The original PR #4 CI exposed OpenSSL 3.0.13 rejecting an empty `-CAstore`
directory. The verifier uses the same explicitly selected CA bundle in both
`-CAfile` and `-CAstore`, an empty `-CApath`, and overridden certificate-path
variables. No extra trust root was added. The two original portability tests
remain in the registry. A failure-only diagnostic uses disposable synthetic
material without changing the test verdict or uploading its generated key.
