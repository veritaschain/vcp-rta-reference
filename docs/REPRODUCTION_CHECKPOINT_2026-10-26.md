# VCP RTA fixed-checkpoint reproduction: 26 October 2026

This is a review handoff for **VeritasChain Protocol (VCP)** reference code
maintained by **VeritasChain Standards Organization (VSO)**, operated by
VeritasChain Co., Ltd. It is not a new software release, adopted specification,
certification, external implementation, or completed independent reproduction.
Earlier K3 and fixed reproduction kits, tags and releases are not replaced.

## Fixed target and recorded first-party result

| Item | Reference |
| --- | --- |
| Checkout commit | `cc695fe1698250878fbbc5f0c5461591ac8e0954` |
| Git tree | `52bcbe53daaaecf0ad45f1e65f251d945854eee1` |
| PR #14 CI executed merge | `0314e019d6741fb9b44ca08fd7e6ad85f6373323` |
| Main regression | 809 cases, 13 registered modules |
| Separate historical tests | 15 cases, one module |
| Each recorded environment | 824 cases; zero failure/error/skip |
| Environments observed | Python 3.11.17 and 3.13.5; OpenSSL 3.0.13; Ubuntu 24.04 CI |
| Published evidence | 40 events: SIG 20, EXE 20; overall INDETERMINATE |
| Independent reproduction | **Not established by this handoff** |

The CI merge commit and checkout commit have the same Git tree; their commit
IDs differ. Do not relabel the CI logs as executions of the final merge commit.
The [reference JSON](REPRODUCTION_CHECKPOINT_2026-10-26.json) records both IDs,
the 29 input-file SHA-256 values, expected per-suite counts, workflow/artifact
IDs and four artifact ZIP digests. Counts are fixed to this target, not future main.

These documents were introduced **after** the target commit. Save them outside
the checkout before detaching at the target, as below. Review the document and
code versions you actually use. A hash stored beside content is not independent
authentication; trust in the selected repository/reference must be established
separately. Dependencies/runner images are not completely locked.

## Reproduce in a fresh disposable Linux environment

Prerequisites: Git, a selected Python 3.11 or 3.13 interpreter with `venv`, and
OpenSSL 3.x on PATH. The recorded patch versions above are reference observations,
not automatically installed by this recipe. Record any environment differences.
Use `python3` below only after confirming it is the interpreter you intend to
review. Setup uses the network; tests use local fixtures. This is not a sandbox.

Run the following in one POSIX shell. The clone directory must not already exist.
Do not run unknown code against production credentials or evidence.

```sh
set -eu

git clone https://github.com/veritaschain/vcp-rta-reference.git vcp-rta-checkpoint-20261026
cd vcp-rta-checkpoint-20261026
out=$(mktemp -d "${TMPDIR:-/tmp}/vcp-rta-review.XXXXXXXX")
export out
git rev-parse HEAD > "$out/guide-commit.txt"
cp docs/REPRODUCTION_CHECKPOINT_2026-10-26.json "$out/checkpoint.json"
cp docs/REVIEWER_REPORT_TEMPLATE.md "$out/reviewer-report-template.md"

git checkout --detach cc695fe1698250878fbbc5f0c5461591ac8e0954
test "$(git rev-parse HEAD)" = cc695fe1698250878fbbc5f0c5461591ac8e0954
test "$(git rev-parse 'HEAD^{tree}')" = 52bcbe53daaaecf0ad45f1e65f251d945854eee1
git diff --quiet HEAD --

python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-verifier-test.txt
python -m pip freeze > "$out/pip-freeze.txt"
openssl version -a > "$out/openssl-version.txt"

# Compare the pinned input inventory before running any tests.
python - "$out" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
output = Path(sys.argv[1])
reference = json.loads((output / 'checkpoint.json').read_text())
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
if head != reference['checkout_commit']:
    raise SystemExit('Checkout does not match the reference')
sys.path.insert(0, 'tools/verifier')
import run_regression as runner
actual = runner.input_manifest(runner.ROOT)
if actual != reference['input_sha256']:
    raise SystemExit('Code, test, dependency or evidence input hashes differ')
with (output / 'input-check.json').open('x') as handle:
    json.dump({'commit': head, 'input_sha256': actual,
               'checkpoint_json_sha256': hashlib.sha256((output / 'checkpoint.json').read_bytes()).hexdigest()},
              handle, indent=2)
PY

# Main tests and historical tests are distinct executions.
python tools/verifier/run_regression.py --output-dir "$out/regression"
export PYTEST_ADDOPTS= PYTEST_PLUGINS= PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONHASHSEED=0
if python -m pytest -q --strict-config --strict-markers -o addopts= \
    --junitxml="$out/historical.xml" tests/test_historical_evidence.py \
    > "$out/historical.log" 2>&1; then
    history_rc=0
else
    history_rc=$?
fi
printf '%s\n' "$history_rc" > "$out/historical.exit"

# Explicit reference-key comparison, not identity or trust establishment.
if python tools/verifier/inspect_historical_pack.py --compare-reference-key \
    > "$out/historical-pack.json"; then
    replay_rc=0
else
    replay_rc=$?
fi
printf '%s\n' "$replay_rc" > "$out/replay.exit"

# Validate both executions and the expected incomplete evidence verdict.
python - "$out" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
sys.path.insert(0, 'tools/verifier')
import run_regression as runner
output = Path(sys.argv[1])
reference = json.loads((output / 'checkpoint.json').read_text())
run = json.loads((output / 'regression/run.json').read_text())
problems = []
if run.get('run_status') != 'passed' or run.get('pytest_exit') != 0:
    problems.append('MAIN_REGRESSION_NOT_PASSED')
main = runner.assess_junit(output / 'regression/junit.xml', run.get('pytest_exit'),
                          reference['test_expectations']['regression_by_suite'])
history = runner.assess_junit(output / 'historical.xml',
    int((output / 'historical.exit').read_text()), {'test_historical_evidence': 15})
for name, result, expected in [('main', main, 809), ('historical', history, 15)]:
    if not result['passed'] or result['cases'] != expected:
        problems.append(name.upper() + '_TEST_RESULTS_DIFFER')
replay = json.loads((output / 'historical-pack.json').read_text())
if int((output / 'replay.exit').read_text()) != reference['replay_expected_exit']:
    problems.append('UNEXPECTED_REPLAY_EXIT')
for key, expected in reference['replay_expectations'].items():
    if replay.get(key) != expected:
        problems.append('REPLAY_DIFFERS:' + key)
checks = replay.get('with_reference_key_comparison_only', {}).get('checks', {})
unresolved = sorted(name for name, result in checks.items() if result['status'] != 'VALID')
if unresolved != reference['reference_key_unresolved_checks']:
    problems.append('UNRESOLVED_CHECKS_DIFFER')
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
if any(commit != reference['checkout_commit'] for commit in
       (head, run.get('git_head'), replay.get('executed_commit'))):
    problems.append('EXECUTION_COMMIT_DIFFERS')
expected_inputs = reference['input_sha256']
if any(actual != expected_inputs for actual in
       (run.get('inputs_before_sha256'), run.get('inputs_after_sha256'),
        runner.input_manifest(runner.ROOT))):
    problems.append('INPUT_HASHES_DIFFER')
if replay.get('inputs_before') != replay.get('inputs_after'):
    problems.append('REPLAY_INPUTS_CHANGED')
assessment = {'checkpoint': reference['checkpoint_id'], 'executed_commit': head,
    'reproduction_matches_reference': not problems, 'problems': problems,
    'main': main, 'historical': history, 'evidence_verdict': replay.get('evidence_verdict'),
    'independence_assessment': 'not assessed by this script', 'conformance_claim': False}
with (output / 'review-assessment.json').open('x') as handle:
    json.dump(assessment, handle, indent=2)
files = {p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
         for p in sorted(output.rglob('*')) if p.is_file()}
with (output / 'review-files.sha256.json').open('x') as handle:
    json.dump(files, handle, indent=2)
print(json.dumps(assessment, indent=2))
print('Reports:', output)
raise SystemExit(1 if problems else 0)
PY
```

The last step succeeds only when both test runs and the expected incomplete
replay agree. An unexpected replay exit is **not** ignored. A setup/main-test
failure stops early; retain the partial directory and terminal output. Malformed
or missing report files can also stop the assessment rather than create success.
Do not reuse an old report directory or amend a failing reference to match output.
This documented recipe is not an independently executed result merely because
it is published. CI runs the existing suites, not this entire clone/setup recipe.

## Interpret and return the result

For a match, main tests and historical tests exit 0; the published-pack replay
exits **2**, with `execution_status: completed` and `evidence_verdict: INDETERMINATE`.
`baseline_commit` inside the replay refers to the historical corpus baseline;
it is not the new checkout commit. Use `executed_commit` for the actual run.

All 40 event hashes/signatures and the legacy root/path comparisons are expected
to match the selected reference material. The unresolved checks remain the prior
chain boundary, authenticated batch metadata and original external anchor. Full
schema conformance, key-owner identity, original logging time and regulatory or
legal acceptance are not established. Synthetic TSA tests are not a live TSA
interoperability exercise.

Complete the [reviewer template](REVIEWER_REPORT_TEMPLATE.md) with the actual
executor, relationship, environment, commands, results and discrepancies. Keep
execution evidence separate from permission to publish results, name or affiliation.
No person has been attributed or contacted by adding this handoff. Do not publish
credentials, private keys or unreviewed local paths from logs.

## Source records and retention

The recorded first-party results are [PR #14](https://github.com/veritaschain/vcp-rta-reference/pull/14),
[regression run](https://github.com/veritaschain/vcp-rta-reference/actions/runs/40258239286)
and [historical run](https://github.com/veritaschain/vcp-rta-reference/actions/runs/40258239228).
Artifact IDs and digests are in the JSON. GitHub artifacts are configured for
30-day retention; access may require authentication and availability is not
permanent. The manifest preserves identifiers and digests, **not artifact bytes**.
Save reports separately when retention matters; a checksum alone cannot recover
a deleted artifact. No long-term retention or independent timestamp is claimed.

## 日本語

今回は実装の追加変更ではなく、第三者に渡す再現対象と手順を固定したものです。
対象コミットは `cc695fe`、参考の自社CIは通常809件と公開証拠15件。実行済みCIの
一時マージコミットと最終コミットは別ですが、Gitツリーは一致しています。

手順書は固定版より後に追加したため、チェックアウト前にJSONと報告様式を作業木の
外に保存します。証拠再検証の期待結果は終了コード2・INDETERMINATEです。
テスト成功と証拠全体の完全検証を混同せず、失敗や環境差もそのまま報告してください。
結果・氏名・所属の公開許可は別々に確認します。この資料の公開だけで独立再現が成立した
ことにはならず、既存の研究キット、K3、正式仕様や署名済み証拠も変更しません。
