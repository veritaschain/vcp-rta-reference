# VCP RTA: recorded first-party checkpoint execution

Recorded 26 October 2026 by **VeritasChain Standards Organization (VSO)**,
operated by VeritasChain Co., Ltd. These are selected original records from
PR #16's already completed CI, not a new run or an outside review.

## What was actually executed

[PR #16](https://github.com/veritaschain/vcp-rta-reference/pull/16) and
[workflow run 40263948191](https://github.com/veritaschain/vcp-rta-reference/actions/runs/40263948191)
record execution of the published procedure from a fresh public clone and
virtual environment through dependency installation, input-hash checks, both
test suites, historical replay and final assessment.

| Observed environment | Existing checkpoint tests | Recipe result | Historical evidence |
| --- | --- | --- | --- |
| Python 3.11.17 | 809 regression + 15 historical | Passed, shell exit 0 | INDETERMINATE, replay exit 2 |
| Python 3.13.5 | 809 regression + 15 historical | Passed, shell exit 0 | INDETERMINATE, replay exit 2 |

Both source artifacts contain 824 unique test cases per environment, with no
failure/error/skip elements. The separate 13 launcher tests are not added to
that frozen count. Two Python jobs repeat the same tests; they are not two
independent reviewers or additional unique coverage.

The executed checkpoint was `cc695fe1698250878fbbc5f0c5461591ac8e0954`, not the
automation's synthetic merge `d0f9ba51c181c72b064c6fb877f211fcf51f2d02` or final
merge `4a40ee40f44ca8efe1e4d4f0f07df9050d5f3b21`. The published guide came from
`a839d7a918c9a23ce170937f536e6c13b3a69b93`. [provenance.json](provenance.json)
keeps those identities and original artifact IDs/digests separate.

## Selected original records stored in Git

| Environment | Completion record | Final assessment | Original artifact manifest |
| --- | --- | --- | --- |
| 3.11.17 | [recipe-run.json](python-3.11.17/recipe-run.json) | [review-assessment.json](python-3.11.17/review-assessment.json) | [original-files.sha256.json](python-3.11.17/original-files.sha256.json) |
| 3.13.5 | [recipe-run.json](python-3.13.5/recipe-run.json) | [review-assessment.json](python-3.13.5/review-assessment.json) | [original-files.sha256.json](python-3.13.5/original-files.sha256.json) |

These six files are byte-for-byte copies, not regenerated or redacted summaries.
Only their repository paths differ. Both assessments happen to have identical
bytes; their separate source archives and environment records are retained.
The copied files were reviewed for publication: versions, public commit IDs,
hashes, case totals and scope flags, with no production credentials or reviewer
personal details. No external reviewer's name or permission is inferred.

**This is a selected-record archive, not a full backup of the CI artifacts.**
Each original ZIP has 22 members; only three from each are copied here. Full
JUnit XML, the 40-event replay, input manifests, shell log and environment
inventories are not in this directory. The original `retained_report_files`
field describes the original CI artifact, not files available in this folder.
The unchanged original manifest also lists absent files; their hashes cannot
recover their bytes. The two ZIP digests and member-to-local-path mapping are
recorded in `provenance.json`.

The six selected records no longer depend on the Actions artifact's 30-day
retention window, but still depend on repository availability and history.
This is not immutable storage or a guarantee of permanent availability. Retain
the complete original ZIPs separately for per-test and terminal-log inspection;
GitHub artifact access may require authentication and later expire. No future
archival or monitoring task is implied by publishing this directory.

## Check copied bytes without executing the verifier

From the repository root, with Python 3, this checks only the six selected
files against the local provenance record. Establish trust in that reference
separately; a digest stored beside a file does not authenticate its publisher.

```sh
python - <<'PY'
import hashlib, json
from pathlib import Path
root = Path('docs/reproduction-results/2026-10-26-pr16')
reference = json.loads((root / 'provenance.json').read_text(encoding='utf-8'))
files = [item for record in reference['records'] for item in record['files']]
if len(files) != 6 or len({item['path'] for item in files}) != 6:
    raise SystemExit('Expected six distinct selected records')
for item in files:
    data = (root / item['path']).read_bytes()
    if len(data) != item['bytes'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise SystemExit('Selected record differs: ' + item['path'])
print('Six selected records match; no test execution or independent trust claimed.')
PY
```

The original ZIP SHA-256 values are:

- Python 3.11.17, artifact `12625955091`: `ead068a3295ff647596972c79de16583989500f65826ff26fd7e620c428ee4ee`
- Python 3.13.5, artifact `12625227494`: `bcea5dc8ba7c552f41613a6a6d90f671bcbf8d6b6fcf66b6ced7ed8c9d53f36d`

At archival preparation, both original archives were checked against live
GitHub metadata. All internal manifest entries, original JUnit counts and IDs,
29 before/after input hashes, original evidence-file hashes and replay
expectations were checked too. That source inspection is stronger than the
six-file checksum command above; do not describe this command as rerunning it.

## What still requires outside evidence

**Independent reproduction remains NOT_ESTABLISHED.** The historical pack's
original external anchor, preceding-chain boundary and authenticated batch
metadata remain unresolved. Reference-key signature agreement does not
establish the key owner's identity. These results are not full VCP/VAP
conformance, certification, legal acceptance or production-readiness evidence.

An outside reviewer can use the [fixed-checkpoint procedure](../../REPRODUCTION_CHECKPOINT_2026-10-26.md)
and [unfilled report template](../../REVIEWER_REPORT_TEMPLATE.md). Record their
actual execution, relationship, deviations and separate permissions to publish
results, name and affiliation. No outside person is contacted by this update.
Do not move the fixed checkpoint or alter historical evidence to obtain a pass.

## 日本語

PR #16で完走した自社CIの主要結果原本を、各環境3ファイル、計6ファイル保存しました。
元ZIPと内部ハッシュを照合し、JSONの内容や日時は書き換えていません。入口から
実行結果と出典を確認できますが、新たなテスト実行や独立第三者の評価ではありません。

この場所に保存したのは主要結果の一部です。全テストのXML、実行ログ、40件の詳細な
再検証結果などは元ZIPにあり、ここにはありません。コピーしたマニフェストの記載は
全ファイルの保存を意味しません。元ZIPの30日保存期限と、Gitでの選択保存を区別します。

証拠全体はINDETERMINATE、独立再現は未成立のままです。次の外部評価は、固定版と
報告様式を使って実行者自身の結果を得ることです。仕様・コード・署名済み証拠・
既存研究キットは変更していません。
