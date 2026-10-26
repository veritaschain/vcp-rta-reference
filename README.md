# VeritasChain Protocol (VCP) Reference Trading Agent

[English](README.md) | [日本語](README.ja.md)

![Legacy format](https://img.shields.io/badge/Evidence-legacy_v1.1-blue)
![Non-certified PoC](https://img.shields.io/badge/Status-Non--certified_PoC-orange)
![License](https://img.shields.io/badge/License-CC_BY_4.0-lightgrey)

First-party proof-of-concept code and archived trading records maintained by
**VeritasChain Standards Organization (VSO)**, operated by VeritasChain Co., Ltd.
The original design targeted VCP v1.1 Silver. **No VCP tier or VAP conformance,
certification, production readiness, or independent reproduction is established
by this repository.** The archived format declares v1.1 but has implementation
choices that differ from the specification's referenced algorithms.

## Current status: 26 October 2026

The default verifier actually checks Ed25519 signatures when the caller supplies
an explicitly trusted key. It reports `VALID`, `INVALID` or `INDETERMINATE` for
each check. Missing material does not pass or hide an independently detected
mismatch. Its default CLI has no external-anchor provider or authenticated-batch
metadata implementation. See [runtime behavior](tools/verifier/README.md).

A **separate opt-in verifier** checks a signed supplemental batch statement and
an RFC 3161 timestamp using caller-selected keys, CA certificates and policy.
This is an implementation extension, not an adopted VCP/VAP format. A later
supplemental stamp does not establish the historical log's creation or original
anchoring time. See [supplemental verification](tools/verifier/SUPPLEMENTAL.md).

The original OpenTimestamps proof named `merkle_root.ots` is not present in the
archived evidence. The producer's anchor-reference claim is not confirmation.
Existing reports, signatures and files under `evidence/` are preserved. Their
old all-pass or compliance wording is historical, not a current result.

## Published-pack replay

The [read-only replay](tools/verifier/HISTORICAL.md) checks the fixed **40-event**
corpus, not just synthetic fixtures. Initial CI replay on 26 October 2026 found:

| Check | Result and boundary |
| --- | --- |
| All 40 event hashes | Match the historical JSON-concatenation encoding, not JCS |
| All 40 event signatures | Match the explicitly selected published reference key; this does not establish its owner's identity |
| Root signature and all inclusion paths | Match the published root using the historical duplicate-odd tree, not strict RFC 6962 MTH |
| Sequence and local batch bounds | Match supplied records; root-only signing does not authenticate the bounds |
| First-link/PrevHash boundary, authenticated metadata, original external anchor | Remain `INDETERMINATE` |
| Overall evidence verdict | **INDETERMINATE**, not full verification or certification |

The records contain **20 SIG and 20 EXE events**. EXE records executions, not
order submissions; the previous "Order Events" label has been corrected.
A passing regression means the expected results were reproduced, not that the
evidence received an overall `VALID` verdict.

## Fixed-checkpoint reproduction

For a review of one fixed version, use the [26 October 2026 checkpoint](docs/REPRODUCTION_CHECKPOINT_2026-10-26.md),
its [machine-readable reference](docs/REPRODUCTION_CHECKPOINT_2026-10-26.json), and the
[reviewer report template](docs/REVIEWER_REPORT_TEMPLATE.md). The checkpoint pins
`cc695fe1698250878fbbc5f0c5461591ac8e0954`: 809 regression cases plus 15 historical
cases per environment in the recorded first-party CI. Those counts describe
that commit, not an automatically updated claim about every future main.
External reproduction remains **not established**. This is not a new release
or a replacement for earlier fixed kits.

Recorded completion results from the later full-recipe self-check are available
in the [selected PR #16 CI records](docs/reproduction-results/2026-10-26-pr16/README.md).
These are unchanged first-party records, not independent review or a complete
backup of the expiring Actions artifacts.

## Run

The current regression workflows exercise Python 3.11 and 3.13.5 on Ubuntu 24.04.
Use the [pinned direct test dependencies and reproduction guide](tools/verifier/REPRODUCING.md).
They are not a complete operating-system or transitive dependency lockfile.

```sh
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference
python -m pip install -r requirements-verifier-test.txt

# No key is automatically trusted; missing checks stay INDETERMINATE.
python tools/verifier/vcp_verifier.py evidence/01_trade_logs/vcp_rta_events.jsonl \
  -s evidence/04_anchor/security_object.json --json

# Explicit mathematical comparison only, not a key-identity assertion.
python tools/verifier/inspect_historical_pack.py --compare-reference-key
```

The replay intentionally exits **2** for the current incomplete evidence verdict.
Use `--public-key /path/to/trusted-key` with the default verifier only after
establishing trust separately. Do not infer trust from an embedded public key.

```sh
# Registered regression suites; counts are defined by this checkout's runner.
python tools/verifier/run_regression.py
# Fixed-pack regression suite: 15 cases, including in-memory tampering tests.
python -m pytest -q tests/test_historical_evidence.py
```

Both suites run in CI. The historical replay workflow separately retains its
JSON report, JUnit results, source/evidence hashes and artifact manifest. These
are first-party results, not independent third-party validation.

## Repository map

| Location | Purpose |
| --- | --- |
| `evidence/` | Unmodified historical logs, keys, root, claims and reports |
| `tools/verifier/vcp_verifier.py` | Legacy-format three-valued verifier |
| `tools/verifier/verify_attested_batch.py` | Opt-in supplemental signature and RFC 3161 checks |
| `tools/verifier/inspect_historical_pack.py` | Read-only fixed-corpus replay, with explicit reference-key opt-in |
| `tests/` | Current synthetic and fixed-pack regression tests |
| `examples/ai-trading-integration/` | Historical logger/demo examples, not upgraded by the verifier changes |
| `docs/VERIFICATION_GUIDE.md` | Current verification entry points and interpretation |
| `docs/architecture.md` | Implementation architecture and limits |

## Related implementations and historical materials

Related first-party repositories: [cTrader](https://github.com/veritaschain/vcp-ctrader-rta-reference),
[FIX](https://github.com/veritaschain/vcp-fix-rta-reference),
[IBKR](https://github.com/veritaschain/vcp-ibkr-rta-reference),
[Nasdaq](https://github.com/veritaschain/vcp-nasdaq-rta-reference), and
[Cloudflare](https://github.com/veritaschain/vcp-cloudflare-rta-reference).
This replay does not validate those repositories or promote their status.

The [historical "World's First" report](VCP_Worlds_First_Evidence_Report.pdf)
is preserved as an earlier research record, not adopted here as a verified
priority claim. Earlier README wording is available in Git history.
For the separate newer offline SDK, see [vcp-sdk](https://github.com/veritaschain/vcp-sdk).
Specification status is maintained in [vcp-spec](https://github.com/veritaschain/vcp-spec),
not determined by the version label in this archived pack.

## License and contact

[CC BY 4.0](LICENSE). See [DISCLAIMER.md](DISCLAIMER.md).
Technical contact: standards@veritaschain.org.

**VeritasChain Standards Organization (VSO): Verify, Don't Trust.**
