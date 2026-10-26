# VCP / VAP reproduction: keep review targets and claims separate

26 October 2026. A non-normative intake aid for VeritasChain Standards
Organization (VSO), operated by VeritasChain Co., Ltd. This is not a new
certification scheme, adoption decision, release, or external reproduction result.
It does not change existing reviewer agreements, fixed kits or expected outputs.
No individual, organization, invitation or consent is recorded by this document.

## Choose the requested track before running or accepting a report

| Track | Fixed code and instructions | Requested observation |
| --- | --- | --- |
| VCP RTA historical-evidence checkpoint | Repository `veritaschain/vcp-rta-reference`; code `cc695fe1698250878fbbc5f0c5461591ac8e0954`; guide at `a839d7a918c9a23ce170937f536e6c13b3a69b93` | 809 main tests and 15 historical tests; 40-event replay; report actual environment, exits, hashes and deviations |
| VAP experimental OS-isolated mock gate | Repository `veritaschain/vap-spec`; kit `b1af0dc9d368b466bf74e7c1b2a6808fb41949ae`; subject `c8ccf972196a16d11429a478f4918a08fe27bb73` | The kit's own regression/scenario runs and saved-evidence rechecks; report using that kit's own expectations and evaluator template |

The RTA checkpoint checks archived trading records and verifier behavior. The
VAP research kit exercises an experimental mock gate and Linux isolation setup.
They are different repositories, programs, dependencies and claims. Success in
one is not evidence that the other was reproduced. An agreement to run one is
not acceptance of an added or substituted assignment. Confirm scope separately
before asking an evaluator to switch targets; preserve their original target.

The VAP kit specifies a disposable native Linux host/VM, Python 3.12+, rootful
Docker Engine and Compose v2. Its recorded expectations are 28 + 46 + 64
regression tests, 16 OS cases, 15 gate scenarios with 11 evidence bundles, and
14 verifier cases in both modes. Do not add those scenario counts to the RTA
824-test count or interpret negative controls as security successes.
Its extension remains experimental and unadopted.

The RTA recipe uses a disposable Linux setup with Git, Python/venv and OpenSSL
3.x, plus network access for setup. Reference CI used Python 3.11.17 and 3.13.5;
these are observations, not a complete environment lock. Follow each track's
pinned instructions rather than combining their installation commands.

## Entry points

For **RTA**, use the [fixed procedure](https://github.com/veritaschain/vcp-rta-reference/blob/a839d7a918c9a23ce170937f536e6c13b3a69b93/docs/REPRODUCTION_CHECKPOINT_2026-10-26.md),
[reference JSON](https://github.com/veritaschain/vcp-rta-reference/blob/a839d7a918c9a23ce170937f536e6c13b3a69b93/docs/REPRODUCTION_CHECKPOINT_2026-10-26.json)
and [existing report template](https://github.com/veritaschain/vcp-rta-reference/blob/a839d7a918c9a23ce170937f536e6c13b3a69b93/docs/REVIEWER_REPORT_TEMPLATE.md).
The new [public issue template](../.github/ISSUE_TEMPLATE/checkpoint-reproduction.md)
is only a submission convenience, not an alternative execution procedure.
[Selected original first-party results](reproduction-results/2026-10-26-pr16/README.md)
are a reference, not an evaluator's own run or a full archive of all logs.

For **VAP OS isolation**, use that kit's
[English instructions](https://github.com/veritaschain/vap-spec/blob/b1af0dc9d368b466bf74e7c1b2a6808fb41949ae/reproduction/os-isolation/README.md),
[expected observations](https://github.com/veritaschain/vap-spec/blob/b1af0dc9d368b466bf74e7c1b2a6808fb41949ae/reproduction/os-isolation/EXPECTED-RESULTS.md)
and [reporting guidance](https://github.com/veritaschain/vap-spec/blob/b1af0dc9d368b466bf74e7c1b2a6808fb41949ae/reproduction/os-isolation/REPORTING.md).
Return its own evaluator report separately from the checksummed result directory.
Do not relabel a VAP result as an RTA submission or vice versa.

## Suggested handling of an incoming RTA report

1. **Confirm identity of the target and completeness of the submission.** Record
   the actual full commit/tree, guide revision, commands, exits and environment.
   Note which steps were not run. Preserve failed and partial submissions rather
   than silently excluding them. A response expressing willingness is not an
   execution report. Do not rewrite old records as a new execution.
2. **Check the submitted evidence before summarizing its outcome.** Compare the
   29-file inventory, before/after hashes, per-suite counts, original JUnit
   outcomes, replay and assessment. Request missing logs or discrepancies instead
   of inferring success. A hash match confirms bytes against a reference, not
   who ran the command, the trustworthiness of the machine or test coverage.
3. **Keep technical outcome and independence as different questions.** Record
   who controlled the environment, who executed commands, involvement in the
   implementation, assistance, funding and contractual relationships. Missing
   information remains unknown. An external email domain or two Python versions
   is not an independence assessment. Running VSO code is not an independently
   developed implementation. Record any later assessment and rationale separately;
   this checklist does not itself decide or award independence.
4. **Separate submission from further publication.** Before reusing privately
   received results or creating new public attribution, obtain separate decisions
   about results/attachments, personal name, affiliation and exact quotation.
   Keep the original submitted bytes; make clearly marked redacted public copies
   when needed, with their own hashes. Do not expose private consent correspondence.

For RTA, main tests and historical tests each have expected exit 0. Its
historical replay has expected exit **2**, execution_status **completed** and
evidence_verdict **INDETERMINATE**; the matching final procedure assessment
exits 0. The runner's own exit 2 denotes an output-directory error, not the same
thing. Always retain the command alongside its exit and report.

The unresolved RTA checks are `prev_hash`, `authenticated_batch_metadata` and
`external_anchor`. Matching those expected incomplete results is not overall
VALID evidence, original anchoring, producer identity, full schema conformance,
regulatory/legal acceptance or production-readiness certification. A completed
or closed issue does not resolve these limits. Keep discrepant reports visible
within their approved disclosure scope.

## Public and private submission boundaries

A GitHub issue is public in this repository; submitting it exposes the account,
body and uploaded material. A blank publication field cannot make a public post
private. Use a chosen identifier and redact personal paths before posting. Do
not post credentials, private keys or another person's unpublished details.
For a private technical report, first contact standards@veritaschain.org to agree
a transfer method, without attaching secrets. No confidential upload service,
retention guarantee or new security-disclosure process is created here.

Public submission does not imply organizational endorsement or blanket consent
for later marketing attribution or release of additional private attachments.
No result is automatically promoted to "independently reproduced" by a template,
checksum, successful CI, issue label, reviewer assignment or merge.

## 日本語

VCP RTA固定版とVAPのOS隔離キットは別案件です。相手が同意した対象を勝手に
差し替えず、リポジトリ・コミット・手順書・実行内容を確認してください。
今回のIssue様式はRTA用で、既存の再現手順や固定研究キットは変更しません。

返事が来たこと、実行報告が届いたこと、結果が一致したこと、独立性を確認したこと、
公開の許可を得たことを区別します。失敗や未実行もそのまま記録します。
Issueは公開されるため、非公開資料は掲載せず、別途提出方法を相談してください。
結果・氏名・所属・引用の追加利用はそれぞれ確認し、自動的な認証や独立再現の
宣言は行いません。個人名、私信、連絡先一覧、同意の有無はこの公開文書に記録しません。
