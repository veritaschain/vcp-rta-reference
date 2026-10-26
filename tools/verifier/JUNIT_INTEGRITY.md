# Validate the test report before declaring regression success

Updated 2026-10-26. Regression-harness correction only, not a change to the
VCP/VAP evidence verifier, signature rules, or normative specifications.

## Reproduced gap

At baseline `f38836d267e33be74417aae1688676c7aa096511`, the JUnit assessor
counted every descendant testcase, checked only direct testcase outcomes,
and compared the total declared case count with the total observed count.
Synthetic reports with orphan cases, misplaced failure/skip elements or
contradictory per-suite counts could therefore be classified as passed.
One suite's incorrect count could cancel another's, including negative counts.

The byte-string check for forbidden DTD/entity declarations also missed a
UTF-16-encoded document containing one harmless internal entity. No expansion
bomb, external entity, network request or production artifact was used.
This is a harness input-validation gap, not a demonstrated compromise of
pytest/Python, proof that previous project CI reports were corrupt, or a
false VALID evidence verdict.

## Local report profile

The assessor now accepts the flat pytest XML profile used by this repository:

- UTF-8, with an optional UTF-8 BOM or UTF-8/utf8 declaration. Other encodings,
  NUL characters, DTDs and entity declarations are rejected before XML parsing.
- A testsuites root with direct testsuite children, or a single testsuite root.
  Cases must be direct suite children. Nested suites, orphan cases, wrappers,
  unexpected namespaces and misplaced elements are rejected rather than ignored.
- Standard properties/property and system-out/system-err metadata are allowed
  at their supported positions. Log text and escaped XML-like strings are data,
  not outcome elements. Container text must be whitespace only.
- Each suite must supply tests, failures, errors and skipped counters as
  canonical nonnegative ASCII integers of at most 20 digits. Each count must
  agree with that suite's direct cases and outcomes. Optional root counters
  must also agree. These are local reader limits, not universal JUnit rules.

The existing 16 MiB raw-file limit, nonzero-pytest-exit rejection, unique case
IDs, minimum suite counts, mandatory real-timestamp test, failure/error/skip
rejection, source-hash preservation and test-file inventory remain in place.
A normal all-success report has the same assessment object as before.
Malformed input returns a failed assessment, not an uncaught parser error or
an evidence verdict. Both workflows reuse this assessor; neither workflow
file is changed. No new dependency or XML resolver is introduced.

## Reproduction and compatibility

The new `tests/test_junit_integrity.py` has 87 cases. The exact baseline runner
blob was checked as `8ff38558861e381b43fa9824f1c5daaaae85b1c9` before editing.
The suite gave 42 failures / 45 passes before correction and 87 passes after.
Together with the unchanged runner and inventory suites, 147 local cases pass
under Python 3.13.5 / pytest 9.0.2, without skips. Four tests run actual pytest
subprocesses to obtain passing, failing, skipped and setup-error reports;
these are not mocked successful subprocess results.

All four retained PR #13 JUnit artifacts (722 regression and 15 historical
cases for each of the two Python versions) were reassessed with the old and
new readers using the previous minimums. Their complete assessments match.
This is compatibility checking of those bytes, not a rerun of the old tests.

A network clone was attempted but unavailable. Local source was reconstructed
from retained artifacts and live file contents and matched to Git blob IDs.
The complete repository is exercised by GitHub CI, not claimed as a full local
checkout run. Expected current counts: 809 regression (722 + 87) plus the
separate 15 historical cases per environment. Actual CI and downloaded-artifact
checks are recorded in the PR after execution.

## Boundaries

Only the runner assessor, two parsing/count helpers, suite registration, added
tests and this guide change. Both evidence verifiers, existing tests, signing
bytes, keys, timestamp logic, original evidence, fixed kits/releases and formal
specifications are unchanged. The historical pack remains incomplete.

This is deliberately not a general JUnit importer, report authentication,
coverage proof, exact-case identity ledger or sandbox against malicious tests,
plugins, a compromised runner or concurrently modified files. A well-formed
fabricated report is not made trustworthy by structural checks. Memory/CPU
quotas beyond the existing raw-file limit are not promised. These are first-party
regressions, not independent third-party reproduction or certification.

## 日本語

テスト結果の件数やXML構造が矛盾していても成功になる場合を修正しました。
結果を正しい位置から数え、テスト群ごとの件数と照合します。文字コードを変えて
禁止された宣言をすり抜ける入力も拒否します。実際のpytest出力との互換性は確認
していますが、過去のCI結果に不正があったと示すものではありません。暗号検証、
正式仕様、署名済み証拠、Evidence Packの判定は変更しません。

## References

- pytest report generation and suite properties: https://docs.pytest.org/en/stable/how-to/output.html
- Python XML processing: https://docs.python.org/3/library/xml.html
