# VCP v1.1 Verification Guide

This guide shows how to run the VCP v1.1 verifier on the published Evidence Pack and how to read its results. The verifier is three-valued: each check is VALID, INVALID, or UNVERIFIABLE (検証不能). A missing `merkle_root.ots` makes the external anchor UNVERIFIABLE, not a pass. The Merkle verdict uses the VCP v1.1 duplicate-odd-node tree, not strict RFC 6962. There is no claim of VCP v1.2 full conformity. This is a first-party reference pack, not a certified product, and it is not Production Ready. External implementations recorded here: zero. Evidence Pack procedural acceptances recorded here: zero. Unresolved items are in [KNOWN_ISSUES.md](../KNOWN_ISSUES.md).

Third parties can reproduce these steps without access to the original trading system.

---

## Prerequisites

- Python 3.8 or higher
- Git (for cloning the repository)
- The `cryptography` package, used for Ed25519 signature verification:

```bash
python3 -m pip install cryptography
```

If `cryptography` is not installed, signature checks are **UNVERIFIABLE**. They are not reported as passed.

The verifier implements **VCP v1.1 only**. It does not claim v1.2 full conformity.

---

## Verification Steps

### Step 1: Obtain the Repository

```bash
git clone https://github.com/veritaschain/vcp-rta-reference.git
cd vcp-rta-reference
```

### Step 2: Review the Evidence Index

```bash
cat evidence/evidence_index.json
```

This displays:
- VCP version: 1.1
- Tier: Silver
- Event count and date range
- Merkle Root

### Step 3: Verify Chain Integrity

Pass the trusted public key explicitly. The Merkle root is read from the security object. The anchor reference is an input, not a confirmation.

**Linux / macOS:**
```bash
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_rta_events.jsonl \
    -s evidence/04_anchor/security_object.json \
    -k evidence/04_anchor/public_key.json \
    -a evidence/04_anchor/anchor_reference.json
```

**Windows:**
```cmd
python tools\verifier\vcp_verifier.py evidence\01_trade_logs\vcp_rta_events.jsonl -s evidence\04_anchor\security_object.json -k evidence\04_anchor\public_key.json -a evidence\04_anchor\anchor_reference.json
```

Machine-readable JSON (stdout is JSON only; exit status is still the overall result):

```bash
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_rta_events.jsonl \
    -s evidence/04_anchor/security_object.json \
    -k evidence/04_anchor/public_key.json \
    -a evidence/04_anchor/anchor_reference.json \
    --json
```

Write both reports:

```bash
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_rta_events.jsonl \
    -s evidence/04_anchor/security_object.json \
    -k evidence/04_anchor/public_key.json \
    --json-output /tmp/vcp-report.json \
    -o /tmp/vcp-report.txt
```

**CLI options:**

| Option | Meaning |
|--------|---------|
| `events_file` | JSONL event chain (positional) |
| `-s`, `--security-object` | Security object. Its Merkle root is the expected root. Also checks the object's Ed25519 signature and published batch bounds. |
| `-k`, `--public-key` | Trusted Ed25519 public key (JSON `PublicKey` as hex or base64, or a raw key file). Required for signature verification. |
| `-a`, `--anchor` | Anchor reference JSON. Supplying it does not confirm the external anchor. |
| `--ots` | OpenTimestamps proof file. `ots verify` runs only when this file exists and the `ots` tool is on `PATH`. |
| `--expected-root` | Expected Merkle root hex. If it disagrees with `--security-object`, the Merkle check is INVALID. |
| `--json` | JSON result on stdout. |
| `--json-output` | Write JSON to a file. The human report stays on stdout unless `--json` is also set. |
| `-o`, `--output` | Write the human report to a file. |

**Exit codes:** `0` VALID, `1` INVALID, `2` UNVERIFIABLE (検証不能).

**What is checked:**

| Check | How | If the input needed for the check is missing |
|-------|-----|-----------------------------------------------|
| Event hash | SHA-256 of sorted-key JSON Header concatenated with sorted-key JSON Payload | — |
| Sequence | Contiguity inside the supplied file | — |
| PrevHash | Each stored PrevHash against the previous EventHash | Absent links are UNVERIFIABLE, not a pass |
| Ed25519 signature | Signature over the raw 32-byte EventHash, using `--public-key`. The signature field may be hex (this evidence pack) or base64 | UNVERIFIABLE |
| Merkle root | VCP v1.1 tree (0x00 / 0x01 prefixes, odd node duplicated) compared with the supplied expected root | UNVERIFIABLE. The computed root is shown and is not a pass |
| Audit path | Stored path reaches the expected root, and MerkleIndex matches file position | UNVERIFIABLE without an expected root |
| External anchor | `ots verify` on the proof file | UNVERIFIABLE. `anchor_reference.json` claiming `ANCHORED` is not confirmation |

The report prints the basis it relied on: trusted key fingerprint, whether an anchor was checked and whether it was confirmed, and the event range (first and last EventID, sequence endpoints, time range, count). Sequence endpoints are the first and last numbers in the file; the sequence check says whether the numbers in between are contiguous.

On this evidence pack the published root matches the duplicate-odd-node tree. A strict RFC 6962 §2.1 Merkle Tree Hash (largest power-of-two split) is different for this 40-leaf batch and is not the verdict. The report shows that root for comparison only.

### Step 4: Run Tamper Detection Test

**Linux / macOS:**
```bash
python evidence/03_tamper_detection/tamper_detection_test.py
```

**Windows:**
```cmd
python evidence\03_tamper_detection\tamper_detection_test.py
```

This test simulates the following attack scenarios:
1. **Omission Attack** - Event deletion
2. **Modification Attack** - Event content alteration
3. **Insertion Attack** - Fake event injection

Verify that all cases report **[DETECTED]**.

The script is an older demo. Its banner still says "Fully Compliant" and "RFC 6962 compliant". Those lines were not rewritten. They are not the three-valued verifier result. The tree in that script duplicates the odd node; that is the VCP v1.1 construction, not strict RFC 6962 §2.1.

### Step 5: Manually Verify Tampered Sample

**Linux / macOS:**
```bash
python tools/verifier/vcp_verifier.py \
    evidence/03_tamper_detection/tampered_chain.jsonl \
    -s evidence/04_anchor/security_object.json \
    -k evidence/04_anchor/public_key.json \
    -a evidence/04_anchor/anchor_reference.json
```

**Windows:**
```cmd
python tools\verifier\vcp_verifier.py evidence\03_tamper_detection\tampered_chain.jsonl -s evidence\04_anchor\security_object.json -k evidence\04_anchor\public_key.json -a evidence\04_anchor\anchor_reference.json
```

The tampered file is an omission of one event. The overall result is **INVALID** (exit code 1): sequence, PrevHash, published batch bounds, and the Merkle root do not match. Signatures on the events that remain can still verify; that does not make the file valid.

Without `-s` / `--expected-root`, the Merkle check is **UNVERIFIABLE**. Computing a root and having nothing to compare it with is not a pass.

---

## Verification Checklist

Command: genuine JSONL, `-s` security object, `-k` public key, `-a` anchor reference.

| Item | Expected result |
|------|-----------------|
| Overall | UNVERIFIABLE (検証不能), exit code 2 |
| Event count | 40 |
| Event hash | VALID |
| Sequence inside the file | VALID (1 .. 40) |
| PrevHash | VALID |
| Ed25519 signatures | VALID against `public_key.json` (fingerprint is printed) |
| Merkle root | VALID against the security object's root |
| External anchor | UNVERIFIABLE. `merkle_root.ots` is not in this repository. Claimed status `ANCHORED` is not confirmation. |
| Anchor confirmed | no |
| Tampered sample, with `-s` and `-k` | INVALID, exit code 1 |
| Genuine sample without an expected root | Merkle UNVERIFIABLE, overall UNVERIFIABLE, exit code 2 |
| Genuine sample with a different public key | Signature INVALID, overall INVALID, exit code 1 |

---

## External Anchor Verification

`evidence/04_anchor/anchor_reference.json` names OpenTimestamps and `merkle_root.ots`. That proof file is not in this repository. The verifier therefore reports the external anchor as **UNVERIFIABLE** and sets anchor confirmed to **no**.

Optional confirmation, only when both the proof file and the `ots` tool exist:

```bash
python tools/verifier/vcp_verifier.py \
    evidence/01_trade_logs/vcp_rta_events.jsonl \
    -s evidence/04_anchor/security_object.json \
    -k evidence/04_anchor/public_key.json \
    -a evidence/04_anchor/anchor_reference.json \
    --ots path/to/merkle_root.ots
```

`ots verify` is executed only in that case. Exit 0 together with OpenTimestamps success text is required before the anchor is reported as confirmed. A pending or unreachable calendar stays UNVERIFIABLE. The verifier does not invent a timestamp proof.

The Ed25519 signature on the security object authenticates the published Merkle root under the trusted key. It is not an external anchor.

### Public search for `merkle_root.ots` (2026-10-21)

The proof file was not found, so `ots verify` was not run and no new timestamp was created. The external anchor cannot be verified from the public materials. The search is recorded in [evidence/VERIFICATION_STATUS.md](../evidence/VERIFICATION_STATUS.md). It covered:

- every blob reachable from this repository's branches (`main`, `cursor/vcp-verifier-three-valued-faf6`) and tags (`v1.0.0`, `v1.1.0`) after `git fetch --all --tags`
- GitHub releases `v1.0.0` and `v1.1.0` of `veritaschain/vcp-rta-reference` (both have empty asset lists)
- default-branch trees and shallow clones of the other public `veritaschain` repositories

Historical `merkle_root.txt` files on the tags record different roots (`e0a1a56c…` and `13112218…`), not `86c05dba…a47e`. The v1.1.0 anchor record says its OpenTimestamps proof was simulated.

---

## Understanding Verification Results

Each check, and the overall result, is one of:

- **VALID** — the check finished and matched. Exit code 0 only when every check is VALID.
- **INVALID** — the check finished and did not match. Any INVALID check makes the overall result INVALID (exit code 1).
- **UNVERIFIABLE (検証不能)** — the check could not be finished. A missing expected root, trusted key, or anchor proof is this result, not a pass. If nothing is INVALID but something is UNVERIFIABLE, the overall result is UNVERIFIABLE (exit code 2).

### On the genuine evidence pack
With the key and the security object supplied: event hashes, signatures, sequence, PrevHash, and the Merkle root are VALID. The external anchor is UNVERIFIABLE because `merkle_root.ots` is absent, so the overall result is UNVERIFIABLE.

### On `tampered_chain.jsonl`
With the same key and security object: sequence, PrevHash, batch bounds, and Merkle root are INVALID. The overall result is INVALID.

### Running the verifier tests

```bash
python3 -m pip install pytest cryptography
python3 -m pytest tools/verifier/tests -q
```

---

## Troubleshooting

### Python version issues
```bash
python3 --version  # Must be 3.8 or higher
```

### Encoding issues (Windows)
```cmd
set PYTHONIOENCODING=utf-8
```

### Encoding issues (Linux/macOS)
```bash
export PYTHONIOENCODING=utf-8
```

### Hash mismatch on legitimate data
Ensure you are using the unmodified evidence files from the repository.

---

## Contact

For verification questions, contact the VeritasChain Standards Organization.
