# VCP RTA checkpoint reproduction report

Template only. No result, independence assessment or publication consent is
pre-filled. Use the [fixed-checkpoint procedure](REPRODUCTION_CHECKPOINT_2026-10-26.md).
Record failures and partial execution as well as matches. Do not edit evidence,
keys, expected results or tests merely to obtain a passing result.

## Executor and scope

- Report date/time and timezone:
- Executor name or chosen identifier (may be withheld publicly):
- Organization, if any:
- Relationship to VSO / VeritasChain Co., Ltd., authors or funders:
- Who controlled the machine and executed the commands:
- Assistance, compensation or changes supplied by others:
- Checkpoint requested: `2026-10-26-pr14`
- Guide source commit, checkpoint JSON SHA-256, checkout commit and Git tree:
- Clean checkout / modifications / missing files:

## Environment and actual execution

- OS/image and architecture:
- Python / OpenSSL / direct and transitive dependency versions:
- Network access during setup and during execution:
- Exact commands, including any deviations:
- Main regression: executed / not executed; exit; case counts; problems:
- Historical tests: executed / not executed; exit; case counts; problems:
- Published-pack replay: executed / not executed; exit; execution status; evidence verdict:
- Input manifests before and after; comparison to checkpoint reference:
- Report filenames, SHA-256 values and storage location:

Attach `regression/` reports, `historical.xml`, `historical.log`,
`historical.exit`, `historical-pack.json`, `replay.exit`, `review-assessment.json`
and `review-files.sha256.json` when generated. Also retain failures from setup
or commands that stopped early. Review paths, logs and personal information
before making attachments public. Do not include credentials or private keys.

## Observations

- Results reproduced exactly:
- Differences, failures and minimal reproduction:
- Items not executed or not evaluated:
- Any unmodified-code requirement that could not be met:
- Conclusions within the executed scope:

Expected reference behavior is 809 main plus 15 historical tests with no
failure/error/skip, and a replay that exits 2 with INDETERMINATE. Matching that
behavior is not overall VALID evidence, certification, producer identity,
original anchoring, an independent implementation or automatic proof of the
executor's independence. Do not infer unavailable evidence from test success.

## Publication permission (complete separately)

- Results/attachments: undecided / private only / public, with conditions:
- Personal name: undecided / do not publish / may publish as:
- Organization/affiliation: undecided / do not publish / may publish as:
- Approved quotation or summary wording, if any:
- Approval date and approver:

No selection or an ambiguous reply means permission is unresolved, not granted.
Permission to publish a name does not imply that an organization endorses VCP/VAP.

## 日本語

実際に実行した項目と未実行の項目を分け、失敗や環境差も記録してください。
結果の公開、氏名の掲載、所属の掲載はそれぞれ別に意思確認します。空欄は承諾では
ありません。自社CIとの一致は再現結果であり、独立性や正式規格への適合は別評価です。
