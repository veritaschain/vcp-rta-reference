# Current verification guide for the legacy evidence pack

Updated 26 October 2026. This guide describes executable tools, not a normative
VCP/VAP conformance assessment. It replaces the obsolete all-pass checklist.
Historical logs, signatures and reports under `evidence/` remain unchanged.

## 1. Establish the revision and install test dependencies

```sh
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference
git rev-parse HEAD
python -m pip install -r requirements-verifier-test.txt
```

For reproducible work, record the exact commit. Python 3.11 and 3.13.5 are
exercised by the current CI workflows. The direct dependency pins do not freeze
the whole OS or transitive dependency set. See [REPRODUCING.md](../tools/verifier/REPRODUCING.md).

## 2. Run without assuming key trust

```sh
python tools/verifier/vcp_verifier.py evidence/01_trade_logs/vcp_rta_events.jsonl \
  -s evidence/04_anchor/security_object.json --json
```

Missing trusted keys produce `INDETERMINATE` for signature checks. The program
continues checking hashes, sequences, local bounds and inclusion paths. It does
not establish key ownership from `public_key.json` or an embedded key.

Only after establishing a key through a separate trust process should it be
supplied to the default verifier with `--public-key /trusted/key.json`.
The historical pack uses `raw_digest` signatures. `ascii_hex` is a separate,
explicit legacy encoding option; it is not guessed until something passes.

## 3. Replay the fixed public corpus

```sh
python tools/verifier/inspect_historical_pack.py
python tools/verifier/inspect_historical_pack.py --compare-reference-key
```

The second command explicitly compares signatures to the published reference
key. It tests mathematics, **not the key owner's identity or independent trust**.
It pins the original four core files by Git blob ID and records SHA-256 hashes
of the complete evidence directory before and after reading it.

For the recorded baseline, all 40 event hashes and signatures, the root signature,
and all inclusion paths match. Local sequence and bounds comparisons also match.
The overall result remains **INDETERMINATE**, with unresolved `prev_hash`,
`authenticated_batch_metadata` and `external_anchor` checks. The first record's
chain boundary is unavailable; root-only signatures do not authenticate metadata;
the original `.ots` proof is absent. Full schema verification is not implemented.
The [dated replay record](../tools/verifier/HISTORICAL.md) gives roots and CI evidence.

Exit 1 means a demonstrated mismatch; exit 2 means incomplete verification;
exit 3 means inspection/input failure. A successful CI regression reproducing
exit 2 is **not** a successful overall evidence-verification verdict.
The new inspector writes only to standard output. Do not redirect reports over
original evidence, keys or source files.

## 4. Run current regression tests

```sh
python tools/verifier/run_regression.py
python -m pytest -q tests/test_historical_evidence.py
```

The first command retains the existing 250-case regression baseline. The second
runs 15 fixed-pack cases, including first/middle/last payload tampering, wrong-key
verification, missing paths with a bad signature, CLI behavior, byte preservation
and rejection of an altered baseline. Mutations use memory copies or temporary
files, never the original evidence directory.

The scripts and results under `evidence/03_tamper_detection/` are historical
artifacts, not the current test suite and not a basis for a compliance claim.

## 5. Optional supplemental attestation

The separate [supplemental verifier](../tools/verifier/SUPPLEMENTAL.md) can
verify a new signed batch statement and its actual RFC 3161 response. Caller
keys, CA bundle, policy and context must be supplied explicitly. It does not
recover the missing original OpenTimestamps proof and cannot retroactively
establish the original creation or anchoring time.

No timestamp service is contacted by these commands. No signatures or proofs
are created. Revocation, freshness, historical certificate validity, complete
schema assessment and independent reproduction remain outside the stated results.

## Interpreting reports

Read per-check names, reasons and scope, not just the overall label. Historical
JSON concatenation is not RFC 8785 JCS. The duplicate-odd Merkle construction is
not strict RFC 6962 MTH. A local match to a producer-supplied root is not an
independent anchor; a matching root signature is not authenticated count/range/
policy metadata; an event not recorded in the first place cannot be recovered
by replaying the supplied records.

Questions: standards@veritaschain.org, VeritasChain Standards Organization (VSO).
