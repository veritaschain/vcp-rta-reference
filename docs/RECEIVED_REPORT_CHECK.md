# Read-only triage of received RTA checkpoint reports

Added 2026-10-26 by VeritasChain Standards Organization (VSO), operated by
VeritasChain Co., Ltd. This is an optional maintainer aid for the
[external-review intake](EXTERNAL_REVIEW_INTAKE.md), not a new verifier,
certification rule, independence decision or change to the frozen checkpoint.

## Use the reviewed local checker, never submitted code

On a reviewed Linux checkout containing this tool:

```sh
python tools/reproduction/check_received_report.py /path/to/received-recipe-output
```

Supply the unpacked output directory produced by the
[fixed recipe](REPRODUCTION_CHECKPOINT_2026-10-26.md), containing
`checkpoint.json`, `historical.xml`, `regression/run.json` and the other named
reports. For the first-party recipe CI ZIP, that directory is
`checkpoint-recipe/review/` after operator-controlled safe extraction.
The checker does not download or extract archives, follow manifest-supplied paths,
execute supplied Python or shell files, rerun tests or contact a network. Run it
from the reviewed repository, not by copying a contributor's Python module.
Do not put a virtual environment or reviewer narrative inside the original
checksummed report set. Keep the separate human report/permissions separately.

The checker writes JSON to stdout only. It does not modify inputs or save a
report file. To retain stdout, choose a new destination outside the submission;
shell redirection can overwrite a file before Python starts. It provides no
shell-redirection protection or automatic publication.

## What is compared

The local checkpoint JSON is pinned by SHA-256
`296d6f468cf0a4b67d297e2208bdb820a1fbd7cba46fae0164c9cb30b1e5ca24`.
The local JUnit assessor's source must match the checkpoint's own input manifest
before it is loaded. A future assessor/reference change requires a separate
review; this tool does not silently switch to a different checkpoint.

The reader snapshots exactly 17 fixed report paths, then checks:

- Both report manifests against the actual received bytes and exact member sets.
  Manifest keys are compared as strings and never opened as filesystem paths.
- Declared execution commits and all 29 declared input hashes against the pinned
  `cc695fe1698250878fbbc5f0c5461591ac8e0954` reference, before and after execution.
- Main and historical JUnit XML using the unchanged local assessor, including
  exact per-suite counts, 809 + 15 cases, failure/error/skip and duplicate-ID checks.
  It compares these computed assessments to the reported summary, rather than
  trusting a claimed success flag. Command/execution and environment records are
  required; direct dependency versions must match the pinned setup.
- Historical-test exit 0, replay exit 2, and the complete stable replay report:
  event-level comparisons, root/check results, original evidence manifests and
  INDETERMINATE limitations. Only execution commit and environment are excluded
  from the stable projection; those are checked separately for consistency.

The stable replay fingerprint is
`077a9ab39911bbec06cb122e73e6ba67104f3c8a1d93bfa37aba762ca5fc12bf`.
It comes from the actual PR #16 outputs in workflow `40263948191`, artifacts
`12625955091` (Python 3.11.17) and `12625227494` (Python 3.13.5). Both projections
match. The source ZIP SHA-256 values are, respectively,
`ead068a3295ff647596972c79de16583989500f65826ff26fd7e620c428ee4ee` and
`bcea5dc8ba7c552f41613a6a6d90f671bcbf8d6b6fcf66b6ced7ed8c9d53f36d`.
Projection comparison uses Python's sorted compact JSON with ASCII escaping and
nonfinite numbers disallowed. It is a local report comparison, NOT JCS or a change
to VCP signing bytes. JSON duplicate keys/nonfinite values are refused, and
comparison distinguishes booleans from integers. Missing files do not suppress
checks possible from other available files.

## Interpret the result without overclaiming

| Exit | Status | Meaning |
| --- | --- | --- |
| 0 | `REPORTS_MATCH_REFERENCE` | Required saved-report bytes and checked fields are internally consistent with this reference |
| 1 | `REVIEW_REQUIRED` | Missing, unusable, changed or inconsistent material; inspect the listed reasons |
| 2 | `CHECKER_ERROR`, or command usage error | The local checker/reference/platform could not be used; not a submission verdict |

None of these is an evidence-verifier VALID/INVALID verdict. A difference may be
an honest failure, different environment or redaction, not misconduct. Original
report bytes should be retained and public redactions separately identified.
Python/OpenSSL versions differing from the recorded observations are flagged as
warnings, not silently treated as identical environments. The checker is not a
complete environment comparison. An optional extra file is not read or endorsed.

**A consistently fabricated report, or a copied first-party report, can pass.**
A hash comparison does not prove that the submitter executed anything, controlled
a separate machine, had no financial relationship or authorized publication.
The tool always records `tests_rerun: false`, `independence: NOT_ASSESSED`,
`publication_permission: NOT_ASSESSED` and `conformance_claim: false`.
Use the human report and [intake guidance](EXTERNAL_REVIEW_INTAKE.md) to assess
those separate questions. No real external report is asserted by adding a tool.

## Input and trust limits

This implementation targets POSIX/Linux and requires O_NOFOLLOW. Input files
and parent directories may not be symlinks; special files such as FIFOs are
refused without waiting. Files are read with bounded lengths: JSON 2 MiB, other
named reports 16 MiB, total retained input 64 MiB. These are local tool limits,
not protocol requirements. Duplicate or unsupported/oversized material needs
manual review; never split or rewrite an original signed batch to force success.

Use a stationary copy in a disposable environment. This is not protection against
a hostile process replacing parent directories concurrently, a compromised local
Python/runtime/reference, arbitrary hostile plugins, full memory/CPU exhaustion
or forged execution records. It never traverses arbitrary extra files. No
private key or production credential is needed. The output includes only fixed
check identifiers, report-file hashes and status flags, not report log contents,
executor names or local paths.

## Tests and first-party checks

`python -m unittest discover -s tools/reproduction -p 'test_*.py' -v` includes the
50 added reader tests and 13 unchanged launcher tests. New fixtures are synthetic
saved reports; the replay fingerprint alone is substituted for those fixtures.
They are not 50 cryptographic tests, external executions or additions to the
fixed 824-case checkpoint. Local preparation also checked both unmodified saved
PR #16 report sets using the actual, unmodified reference and replay fingerprint.

The existing recipe workflow additionally runs the reader on its real newly
generated fixed-checkpoint output and retains `checkpoint-intake.json` separately.
Actual CI outcomes belong in the PR after execution. This does not alter the
frozen recipe, reference JSON, evidence verifiers, test registry, old records,
formal specifications, tags or K3. No email is sent or publication permission
inferred by these checks.

## 日本語

受け取ったRTA固定版のレポート17ファイルを読み取り専用で照合します。提出物に
含まれるコードは実行せず、成功の自己申告だけでなくXML、件数、終了コード、
入力ハッシュ、40件の詳細な再検証結果まで参考結果と比較します。資料不足や
対象違いは要確認として残し、未検証を完全合格に変えません。

結果が一致しても、実行者本人が実行した証明や独立性・公開許可の確認にはなりません。
コピーされた自社CI結果でも一致し得ることを明示し、人による判断を置き換えません。
VAPのOS隔離キットは対象外です。固定版・規範仕様・署名済み証拠は変更しません。
