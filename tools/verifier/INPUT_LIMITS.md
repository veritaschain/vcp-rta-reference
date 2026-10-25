# Bounded verifier input

Updated 2026-10-26. Local input-safety policy for the legacy verifier and the
supplemental CLI that reuses its loaders. This is not a VCP/VAP schema rule,
a wire-format change, or a conformance claim.

## Reproduced defects

At baseline `0a5f7d03205ebfc52391b3c4d72fe13a983ea7b1`, a POSIX named pipe
used as the events, security-object or public-key path made the default CLI
wait for a writer. Each case was reproduced in a temporary directory with a
0.7-second subprocess timeout; the test terminated the waiting child. No
historical evidence was altered. These loaders also had no byte limits.

The shared JSON reader rejected literal NaN/Infinity but decoded `1e9999` and
`-1e9999` as non-finite floating-point values, including in otherwise unused
fields. The finite-float hook now rejects those values during parsing.
Finite floating-point conversion and exact integer decoding are unchanged.

## Input policy

| Input | Maximum |
| --- | --- |
| Complete event file, raw bytes | 32 MiB |
| Each event line after universal-newline normalization, UTF-8 bytes | 2 MiB |
| Security Object, raw bytes | 2 MiB |
| Public/attestor key file, raw bytes | 64 KiB |
| Nonblank event records | 100,000 |
| JSON object/array nesting, outer container counted as 1 | 64 |
| Any document passed through the shared JSON reader, UTF-8 bytes | 2 MiB |

MiB and KiB are binary units. Limits include whitespace. Input is never
truncated or silently split into a different batch. If any required event
input fails loading, the CLI exits 3 without a partial verification report.
A rejected optional input remains an INDETERMINATE input check; available
checks still run and an independently established mismatch still wins.

The supplemental envelope uses the shared JSON reader and therefore has the
same finite-number and depth checks. Existing 2 MiB supplemental-envelope,
TSA-response and certificate bounds remain in that executable. Its key and
Security Object inputs inherit the shared loaders. No certificate or
cryptographic validation is relaxed.

Files must be regular files. Known pipes, devices and directories are rejected
before open; the opened descriptor is checked again with fstat. POSIX opens
use O_NONBLOCK so a FIFO substituted after the path check cannot wait for a
writer. Size is checked on the descriptor, and reads are also bounded even
if the file grows or its reported size is misleading. Descriptor handles are
closed on successful reads and handled errors. Symlinks to regular files
remain accepted; this is not a path-confinement feature.

The JSON depth scan precedes decoding and ignores brackets inside quoted
strings, including escaped quotes/backslashes. Duplicate keys remain errors.
LF, CRLF and CR event-file line endings retain the old text reader behavior;
Unicode line separators inside JSON strings are not split into extra events.
All four prior public-key encodings remain available.

## Compatibility and limits

This intentionally rejects streams and files beyond the stated local budget,
including /dev/stdin when it is a pipe. Use a completed regular local file
within the budget. Do not blindly split a signed batch: doing so changes the
batch against which roots, ranges and signatures are checked. Larger-volume
processing needs an explicitly designed and tested ingestion profile, not
an unbounded bypass flag.

These bounds are not a hard process RAM, CPU or wall-clock quota. Decoded
Python objects can occupy more memory than the source bytes. Regular files
on a stalled/network filesystem may still block; no universal I/O deadline,
filesystem snapshot, or defense against hostile parent-directory/process
owners is claimed. Windows and nonlocal filesystems were not validated by
this change. Deployment isolation and operating-system limits remain the
operator's responsibility.

The in-memory Python verification API does not call these file loaders and
is not newly resource-bounded by this change. The fixed historical inspector
retains its pinned-corpus reader. No new remote-access or upload capability
is introduced. Normal-input hash/signature/Merkle checks, report schemas,
no-clobber report writes and historical evidence remain unchanged.

## Tests

`tests/test_input_limits.py` adds 75 cases covering finite/non-finite numbers,
large exact integers, depth and byte boundaries, string escaping, event count,
line endings, key encodings, regular/special files, descriptor cleanup,
misleading stat size, both CLIs and optional-input failures that must not hide
an event-hash mismatch. All fixtures are temporary and synthetic.

The main runner now requires 376 cases (301 existing + 75 new); the historical
workflow remains a separate 15 cases. CI success does not establish overall
VALID for the historical pack, independent reproduction or certification.

## 日本語

ログ・鍵・Security Objectは容量制限付きの通常ファイルだけを読み込みます。
パイプ等で待ち続ける入力、深すぎるJSON、無限大に変換される指数表記を拒否します。
入力を切り詰めて検証したことにはしません。任意入力が読めなくても、読み込み済みの
ログから検出できる不一致はそのまま報告します。上限はこの実装の資源方針であり、
VCP/VAPの規範上の上限ではありません。署名済みバッチを単純分割しないでください。

## References

- Python JSON decoding hooks and untrusted-input warning: https://docs.python.org/3/library/json.html
- Python file descriptors and nonblocking flags: https://docs.python.org/3/library/os.html
