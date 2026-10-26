---
name: VCP RTA checkpoint reproduction report
about: Report a fresh run, mismatch, partial run or setup failure for the fixed VCP RTA checkpoint.
title: '[Reproduction] VCP RTA cc695fe: '
labels: ''
assignees: ''
---

## Before posting

**This is a public issue.** Your account, text and uploaded files will be public.
Do not post credentials, private keys, third-party personal data or sensitive logs.
For a private technical report, first contact standards@veritaschain.org to agree
how to transfer it; do not assume this form provides confidential submission.
A chosen identifier is sufficient here. Do not name another person or organization
without their permission. Public posting does not authorize a new endorsement,
marketing attribution or publication of materials supplied privately.

This form is for **veritaschain/vcp-rta-reference**, checkpoint
`cc695fe1698250878fbbc5f0c5461591ac8e0954` (`2026-10-26-pr14`).
It is **not** the VAP OS-isolation kit `b1af0dc` / subject `c8ccf97`.
Do not replace an existing review target without agreeing the new scope.

[Fixed instructions](https://github.com/veritaschain/vcp-rta-reference/blob/a839d7a918c9a23ce170937f536e6c13b3a69b93/docs/REPRODUCTION_CHECKPOINT_2026-10-26.md)
| [Detailed report template](https://github.com/veritaschain/vcp-rta-reference/blob/a839d7a918c9a23ce170937f536e6c13b3a69b93/docs/REVIEWER_REPORT_TEMPLATE.md)
| [Scope and intake notes](https://github.com/veritaschain/vcp-rta-reference/blob/main/docs/EXTERNAL_REVIEW_INTAKE.md)

## Actual executor and target

- Report date/time and timezone:
- Executor's chosen identifier; who controlled the environment and ran commands:
- Relationship to VSO / VeritasChain Co., Ltd., evaluated code, authors or funders;
  assistance or compensation (state unknown or share privately when necessary):
- Actual repository, checked-out full commit and Git tree:
- Guide source commit and checkpoint JSON SHA-256:
- Clean checkout, modifications, missing files or substituted dependencies:

## Environment and commands

- OS/image, architecture, Python and OpenSSL:
- Dependency versions; include retained pip-freeze when safe:
- Exact commands and any deviations from the published procedure:
- Execution kind: fresh execution / inspection of existing reports / not executed:

## Observed results, including failures

Fill in what happened, not what the reference says should happen.
Use "not executed" for any step not reached. Do not pre-fill a successful result.

| Operation | Executed? | Exit code | Cases / failures / errors / skips | Report or problem |
| --- | --- | --- | --- | --- |
| Main regression | | | | |
| Historical tests | | | | |
| Published-pack replay | | | Not a pytest count | |
| Final procedure assessment | | | Not a pytest count | |

- Actual replay execution_status and evidence_verdict:
- Input hashes before/after and comparison with the pinned 29-file manifest:
- Setup failures, incomplete steps, mismatches or unexpected behavior:
- Report/attachment filenames and SHA-256; inaccessible or missing artifacts:
- Redactions made to public copies (retain originals separately; record new hashes):

Reference only: 809 main + 15 historical tests, each command exit 0; the
**evidence replay exits 2 with INDETERMINATE**, not overall VALID. The complete
procedure's final assessment exits 0 on a match. Exit meanings depend on the
command. A failed or incomplete reproduction is useful; do not change tests,
keys, evidence or expected results to make it match.

## Publication and interpretation

- Permission for additional publication/quotation of results or private attachments:
- Permission to use a personal name outside this issue:
- Permission to use an organization/affiliation; exact approved wording:
- Items to keep private or clarify before any additional publication:

Blank or ambiguous permission remains unresolved. A report or closed issue does
not establish independence, an independent implementation, certification, legal
acceptance or VCP/VAP conformance. Matching the reference does not recover the
historical external anchor or establish the original producer's identity.

## 日本語

VCP RTA固定版の実行報告用です。VAPのOS隔離実験とは別の対象です。
成功だけでなく、準備失敗・途中停止・相違点・未実行項目も記入してください。
このIssueは公開されるため、機密情報や未承諾の氏名・所属は投稿しないでください。
追加の公開・引用・氏名や所属の利用許可は別途確認し、空欄を同意と扱いません。
