# Account for every test module before regression execution

Updated 2026-10-26. Regression-harness correction only. Evidence verification,
cryptographic algorithms and VCP/VAP specifications are not changed.

## Reproduced gap

The runner at baseline `ed3444f4a1a6cd2be1608437b18f0fa2be22d94f` executes an
explicit list of test modules. Its minimum-case checks protect the registered
suites, but did not detect a new test module omitted from that registry.

A temporary synthetic repository with one registered passing test and one
unregistered failing test produced runner exit 0 and `run_status: passed`.
Running the omitted file explicitly with pytest failed. All three variants
(`test_new.py`, `new_test.py`, and `nested/test_new.py`) reproduced the gap.
This demonstrates a harness limitation, not that previously reported project
CI runs actually omitted a test or that historical evidence was falsely valid.

## Inventory rule

Before input hashing and pytest execution, the runner inspects `tests/` without
importing modules. Every regular file named `test_*.py` or `*_test.py`, recursively,
must be accounted for by the main `SUITES` registry or the explicit separate
suite list. Unknown modules, missing expected modules, candidate symlinks or
special files, symlinked directories and unreadable traversal fail preflight.
Hidden directories are not silently excluded. Python cache files ending in
`.pyc` are not source test modules. Helpers such as `conftest.py`, `helpers.py`
and `__init__.py` do not become test modules solely by having a `.py` suffix.

Only `test_historical_evidence.py` is explicitly deferred to the existing
`historical-pack.yml` workflow. Listing it as separate does not claim that the
historical workflow executed or passed. That workflow and its 15 test cases
remain independently necessary. No broad filename prefix is exempted.

The current main suite registry addresses top-level file stems. A nested
candidate is therefore rejected instead of being guessed into a suite; moving
or adding suites requires an explicit registry/layout change and review.
Do not rename a failing test into a helper to bypass the inventory.

## Reports and failure behavior

`run.json` adds `test_inventory`, containing the expected regression files,
explicit separate files, discovered files, sorted problems and an inventory
pass flag. This additive field does not change the evidence-verifier report
schema or verdicts. The regression report remains version 1.

An inventory error produces `run_status: preflight_failed`, exit 1, and the
usual report/hash-manifest files. It does not run pytest or generate a success
JUnit report. Because preflight now precedes hashing, preflight-failure reports
need not have before/after input-hash fields; successful runs retain both.
Existing output directories are still refused instead of overwritten.

Registration alone is not success: after registration, an actually failing test
still fails the unchanged pytest/JUnit assessment. Existing minimum-case,
real-timestamp-test, duplicate-ID, skip, changed-input and changed-HEAD checks
remain in place. Both CI workflows and their dependency configuration are unchanged.

## Validation scope

The exact baseline runner was reconstructed from the retained PR #12 source
and matched to live Git blob `d7eb3ecf4a5c3f69369a6df1db0db52ec808e092`.
A network checkout was attempted but unavailable. The actual runner and real
pytest subprocesses were exercised on temporary synthetic repositories.

The three targeted omission cases failed against the baseline and pass after
the guard. All 27 added tests pass locally on Python 3.13.5 / pytest 9.0.2.
The new suite covers normal/missing/extra modules, both filename conventions,
nested and hidden files, special files, symlinks, traversal errors, read-only
inventory, failure reporting, real pytest success/failure and output preservation.
This is not a full local repository run. Actual complete CI results and artifact
checks are recorded in the pull request after execution. Expected counts are
722 regression cases (695 existing + 27 new) and 15 separate historical cases.

This is a file-inventory policy, not an independent implementation, a coverage
proof, an exact test-case identity ledger, or a sandbox. Custom pytest collection
rules, conftest hooks/plugins, deliberate changes to the registry or tests,
concurrent hostile directory changes and tests outside `tests/` are not solved
by this guard. It does not add automatic execution of arbitrary discovered code.
No existing test is removed or weakened; both evidence verifiers, historical
bytes, fixed reproduction kits, releases and normative documents are unchanged.

## 日本語

新しいテストファイルを追加しても実行対象への登録を忘れると、以前のランナーは
そのファイルを実行せずに成功と表示し得ました。今後は実行前にファイル一覧と
登録を照合し、漏れがあれば停止します。公開済み証拠のテストは別ワークフローの
対象として明示し、この照合だけで実行済みとは扱いません。暗号検証・正式仕様・
過去の証拠には変更がなく、独立第三者による検証の成立でもありません。

## Reference

pytest's standard filename discovery and explicit file selection:
https://docs.pytest.org/en/stable/explanation/goodpractices.html#conventions-for-python-test-discovery
