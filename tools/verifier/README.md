# Legacy evidence verifier: runtime correction

Updated 2026-10-26. This is executable first-party code, not adoption of a VAP
specification revision, VCP/VAP conformance, certification, or independent reproduction.
It replaces the old default CLI's silent signature/anchor skips and false all-pass result.
The separate `cursor/vcp-verifier-three-valued-faf6` branch is not merged by this change.

## Run

Python 3.8+ is required. `cryptography` enables Ed25519 checks. Without it,
signature checks are INDETERMINATE; hashes, paths and other checks still run.

```sh
python -m pip install cryptography
python tools/verifier/vcp_verifier.py evidence/01_trade_logs/vcp_rta_events.jsonl \
  --security-object evidence/04_anchor/security_object.json --json
```

Supply `--public-key /path/to/trusted-key.json` only after establishing key trust
outside the evidence. Raw 32-byte keys, 64-character hex, standard base64, and
JSON with a `PublicKey` string are accepted. A key embedded in a supplied security
object is never automatically trusted. `--signature-message raw_digest` (default)
verifies raw-digest signatures; `ascii_hex` must be explicitly selected for the
other historical encoding. The verifier does not try encodings until one passes.

`--output report.json --json` saves the same JSON report that is printed.
Without `--json`, output is text. Existing event-file, `-s` and `-o` CLI options
remain available, but **report format and Python return shape change to version 2**.
The old boolean result fields and falsely named `compute_rfc6962_merkle_root`
helper are not compatibility APIs. Update scripts that consume old output.

## Verdicts and exit codes

- VALID / 0: every required, actually executed check matches.
- INVALID / 1: a demonstrated mismatch or malformed checked field exists.
- INDETERMINATE / 2: no mismatch was established, but verification is incomplete.
- 3: input events cannot be read/parsed, or the output report cannot be written.
  Argparse usage errors retain Python's standard exit code 2.

INVALID takes priority over INDETERMINATE and VALID. A missing event, path, record
or key affects only its dependent checks. Available signatures and other checks
still run. A malformed optional file is an additional INDETERMINATE check and
cannot hide a mismatch in loaded event data. Duplicate JSON keys and NaN/Infinity
are rejected at the CLI boundary rather than silently normalized.

**This revision cannot return an overall VALID result.** Authenticated count/range/
policy metadata is not implemented and remains an explicit INDETERMINATE check.
The CLI also has no external-anchor provider. This deliberately prevents a local
consistency result from being promoted to complete verification. A per-check
VALID result, such as a verified Ed25519 signature, is still useful and reported.
Absent PrevHash material also remains INDETERMINATE, not evidence of nonconformance
(the protocol permits optional chaining).

## Actual checks and boundaries

Event hashes use this repository's historical `json.dumps(Header, sort_keys=True)`
plus `json.dumps(Payload, sort_keys=True)` bytes. They are NOT RFC 8785/JCS.
Merkle roots and paths use the historical duplicate-odd tree, NOT the RFC 6962
Merkle Tree Hash. This preserves historical evidence interpretation rather than
rewriting or re-signing it. Inclusion checks require complete-batch ordering and
MerkleIndex, validate path shape, and distinguish a supplied empty path from no
path. An empty path passes only for the consistent single-leaf case.

Ed25519 event signatures and the root signature are actually verified against the
explicitly supplied key. Root signatures do not authenticate EventCount, sequence
bounds, or policy metadata. Local bounds comparison is named accordingly; it is
not VAP INT-008 verification. Basic object/policy checks are not full JSON Schema
validation. This is not a general v1.1 verifier, a v1.2 verifier, or an SDK upgrade.

The Python API accepts a trusted `external_anchor_verifier(root_hex, record)`
callback returning `{"status": ..., "reason": ...}`. The callback must check an
external commitment to the exact supplied root under the caller's trust policy.
It must not trust a producer's `Status: CONFIRMED` declaration. No callback or
provider code is loaded from evidence. Missing callbacks, exceptions or malformed
callback results are INDETERMINATE. There is no built-in OTS, TSA, blockchain or
SCITT verification and no network access in the default verifier.

## Tests

```sh
python -m pip install pytest cryptography
python -m pytest -q tests/test_verifier.py
```

Tests use synthetic keys and events, real local Ed25519 signing/verification,
independently assembled legacy tree fixtures, CLI subprocesses, and explicitly
stubbed external-adapter outcomes. They exercise all 81 four-check aggregation
combinations, missing-path/bad-signature cases, empty paths, malformed optional
inputs, signature encodings and output exit codes. External-adapter tests do NOT
validate any external timestamp or service. The archived 40-event Evidence Pack
is not an end-to-end validation claim made by these tests.

Files under `evidence/`, historical reports, keys, signed data, tags and releases
are unchanged. The VAP discussion draft remains unadopted; this code does not
change its governance status or the pinned K3/reproduction-kit baselines.
