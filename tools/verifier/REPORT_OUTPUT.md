# Report output: no-clobber publication

Updated 2026-10-26. Implementation safety correction for `vcp_verifier.py`
and `verify_attested_batch.py`, not a normative VCP/VAP change.

## Defect and correction

At baseline `6fec8343b84e31c0162bc2085ba503df46c21d2e`, both CLI commands
used `Path.write_text` for `--output`. Selecting an input file as the output
could replace the input with a report after verification. Existing reports
and symbolic/hard-link aliases could also be overwritten. This was reproduced
on temporary synthetic inputs only, not on the archived Evidence Pack.

Both CLIs now call the same `write_new_report` helper. The output must be a
new directory entry and must not resolve to any supplied input path, including
an optional input that was missing or could not be loaded. Existing regular
files, empty files, directories, hard links and symbolic links, including
broken links, are not overwritten. There is no force/overwrite option.

The helper encodes the complete report as UTF-8, stages it in a private file
in the destination directory, flushes and fsyncs it, closes it, and publishes
it with an exclusive hard-link creation. The destination is not published
before the complete staged write succeeds. A competing writer creating the
destination after the preliminary check causes publication to fail instead
of replacing the competing file. Temporary staging files are cleaned up on
normal success and handled exceptions.

The report format, cryptographic checks, trust inputs and evidence verdicts
are unchanged. A refused save returns the existing output-error exit code
**3**, with a diagnostic on stderr. The already printed stdout report still
contains its independently computed evidence verdict; do not mistake that
verdict for confirmation that the report file was saved.

## Migration

Use a fresh filename for each run, in a directory you control. Repeating a
command with the same `--output report.json` now fails rather than replacing
the previous report. Automation that relied on overwriting must allocate a
new output name. Retain earlier reports according to the operator's own
retention policy; the verifier does not delete them.

Both text and JSON output use this policy. No file is written when `--output`
is omitted. Output parents must already exist. POSIX staging permissions are
0600; the published hard link has the same restricted file mode.

## Filesystem and process limits

A local filesystem with working hard-link support and a caller-controlled
output directory is required. Unsupported publication fails closed; there is
no overwrite fallback. Linux is exercised by the CI matrix. Windows, remote
filesystems and unusual filesystem semantics have not been validated by this
change. This is not protection against an adversary controlling the process,
its imports, or the parent directory.

Shell redirection is outside this protection. A shell can truncate an output
before Python starts, so never redirect stdout onto an evidence or key file.
The read-only historical inspector prints to stdout and has no `--output`
option; its caller must also select a safe redirection destination.

A process kill or power loss may leave a private staging file, or a complete
published report before cleanup. Directory-entry crash durability is not
claimed. An unlink/cleanup error is reported as an output failure; a completed
report may already exist in that case. Existing evidence is not a cleanup
target. Keep backups and run in a trusted working directory.

## Regression scope

`tests/test_report_output.py` contains 51 local safety cases covering both
CLIs: input aliases, all optional input paths (including missing inputs),
existing outputs, exact output bytes, restricted POSIX mode, repeated saves,
UTF-8 errors, injected fsync/link failures, late-created destinations and
symlinks, and two concurrent writers. Fault injections are explicitly synthetic.
No production keys, actual disk exhaustion, external TSA or network is used.

The existing regression runner adds these 51 cases to its 250-case baseline
(301 cases). Historical replay remains a separate 15-case workflow. Test
success does not turn the historical Evidence Pack's INDETERMINATE verdict
into VALID, recover missing evidence, or establish independent reproduction.

## 日本語

通常・追加検証器の `--output` は新規ファイル専用です。入力ログ・鍵・証明書・
追加証明や既存レポートを上書きしません。別名のリンクや、読み込めなかった入力の
パスも保護対象です。同じ出力名を繰り返す運用は、新しい名前を使う方式へ変更してください。
保存拒否は終了コード3ですが、標準出力の検証結果は別に表示されます。

シェルの `>` はPython起動前にファイルを上書きし得るため、この保護の対象外です。
管理下のローカルディレクトリを使用し、証拠・鍵をリダイレクト先にしないでください。
元の証拠、署名対象バイト列、検証基準、正式仕様の採択状態は変更していません。

## References

- Python `os.link` and `os.fsync`: https://docs.python.org/3/library/os.html
- Python temporary-file creation: https://docs.python.org/3/library/tempfile.html
