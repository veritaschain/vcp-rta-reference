# Execute the published checkpoint recipe end to end

Added 2026-10-26. First-party automation maintained by VeritasChain Standards
Organization (VSO), operated by VeritasChain Co., Ltd. This does not establish
independent reproduction, certification or VCP/VAP conformance.

## What this job exercises

The existing main and historical workflows test the checked-out source. This
additional workflow, **Published checkpoint recipe**, instead executes the exact
POSIX-shell block published in `docs/REPRODUCTION_CHECKPOINT_2026-10-26.md` at
commit `a839d7a918c9a23ce170937f536e6c13b3a69b93`.

The launcher checks the three published guide/JSON/template Git blob IDs,
extracts the shell block without substitution, records its SHA-256, and executes
it in a new temporary directory. The shell itself performs a real public GitHub
clone, saves the guide metadata outside its checkout, detaches at the fixed
`cc695fe1698250878fbbc5f0c5461591ac8e0954` checkpoint, creates a new virtual
environment, installs pinned direct dependencies, compares the 29 input hashes,
runs 809 regression and 15 historical cases, replays the 40-event corpus, and
assesses the reports. No mock checkout or injected input-manifest provider is
used by this workflow.

The entire recipe must exit zero. Historical tests must exit zero; the actual
evidence replay must exit **2** with **INDETERMINATE**. The launcher also checks
the real checkout commit/tree, saved report counts, input manifests and the
recipe's own assessment. A zero shell exit alone is insufficient. Errors,
timeouts, missing reports and changed checkpoint metadata do not become passes.

The clone initially retrieves the repository's current public default branch,
just as the published recipe says. That actual initial commit is recorded as
`cloned_guide_commit`. The saved checkpoint JSON and reviewer template must still
match the pinned published bytes; a later incompatible guide update stops this
self-check instead of silently changing the review target. The automation's
own tested commit, pinned guide commit and executed checkpoint commit are kept
separate. These are intentionally different revisions.

## Run and inspect

On a reviewed Linux checkout with the guide commit in its Git history:

```sh
python -m unittest discover -s tools/reproduction -p 'test_*.py' -v
python tools/reproduction/run_checkpoint_recipe.py --output-dir /path/to/new-report-directory
```

The output must be new and outside the source checkout. Git, OpenSSL 3.x,
`python3` with venv support and network access to GitHub/the package index are
required. The wrapper has a 15-minute shell timeout; CI jobs have a 20-minute
limit. On timeout it terminates the launched shell process group. The runner is
not a general malicious-code, network or resource sandbox.

CI uses Ubuntu 24.04 and the selected Python 3.11 / 3.13.5 interpreters. It does
not preinstall the recipe dependencies into the fresh virtual environment.
The existing read-only workflow permission and pinned checkout/setup/upload
action versions are reused. Checkout credentials are not persisted, no production
secrets are supplied, and no `pull_request_target` workflow is introduced.

The 13 launcher unit tests are separate standard-library tests under
`tools/reproduction/`, executed explicitly by this new workflow. They are not
added to or counted among the checkpoint's frozen 809 + 15 cases. Their fixtures
are synthetic; only the subsequent recipe job performs the complete setup.

## Retained evidence and limitations

`recipe-run.json` records the automation, guide, cloned-guide and checkpoint
revisions, the exact shell hash, shell exit, completion assessment and actual
regression environment. `executed-recipe.sh` and `recipe.log` retain the executed
instructions and terminal output. `review/` contains only the explicitly named
recipe reports, including both JUnit files, the input check, dependency inventory,
replay exit/result and the reviewer assessment. `files.sha256.json` hashes the
retained files; the original recipe hash manifests are preserved too.

The entire temporary working directory, cloned repository, virtual environment
and synthetic TSA scratch directories are **not** uploaded. Report copies must
be regular bounded files; symlinks, existing destinations and oversized files
are refused. A failed setup can retain partial reports and the failed shell log.
Review logs before wider sharing; allowlisting filenames is not automatic secret
redaction of arbitrary malicious test output. No production key is required.

Artifacts are retained for 30 days, not permanently archived. Checksums are not
proof of authorship. Running both Python jobs is first-party reproduction of a
published procedure, not two independent organizations or an independent
implementation. The historical evidence verdict remains incomplete. Existing
K3, fixed kits, releases, normative specifications, original evidence and the
checkpoint JSON are not modified by this automation.

Observed run IDs, environment details, success/failure and artifact hashes belong
in the pull request after execution. Adding this workflow does not itself claim
a successful run or close the independent-review requirement.

## 日本語

前回は手順の構文と一部の結果照合を確認しただけでした。この追加CIは、公開済みの
手順本文を改変せず、新規クローン・仮想環境・依存導入から最後まで実行します。
再現対象はcc695feのままです。自社管理のCIによる手順確認であり、独立第三者に
よる再現ではありません。実行失敗や不足したレポートを成功にせず、証拠全体の
期待結果もINDETERMINATEのまま維持します。
