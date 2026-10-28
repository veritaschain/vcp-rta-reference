# Known issues

This note is documentation. It does not change signed events, git tags, or `evidence/02_verification/verification_report.txt`.

This repository is a first-party reference pack for a VCP v1.1 evidence set. It is not a certified product. It is not Production Ready. It does not claim VCP v1.2 full conformity.

## Under review for VCP v1.2

These items are known and unresolved. They are not closed by the checks in this pack.

- **Schema and norm gaps.** Field names, required-versus-optional rules, and the difference between a file label (`Silver`) and a check the verifier can finish are not fully aligned with a single norm. The v1.1 text treats an external anchor as required for Silver. This pack names an anchor and does not contain `merkle_root.ots`.
- **Signature issues.** Event signatures and the security-object signature are Ed25519 over raw hashes in this pack. Other algorithms, encodings, and canonicalization choices are not settled for v1.2. A passing Ed25519 check is not a claim that every signature rule is closed.
- **Merkle issues.** The published root matches the VCP v1.1 duplicate-odd-node tree (`0x00` / `0x01`, odd node duplicated). That is not a strict RFC 6962 §2.1 Merkle Tree Hash. Which construction a later norm will require is under review.
- **Numeric precision.** Timestamps and numeric payload fields are carried as published. Precision, rounding, and canonical number formatting are under review for v1.2. This pack does not claim those questions are settled.

## What this pack does not do

- The verifier is three-valued and fixed at v1.1. VCP v1.2 is not implemented.
- A missing `.ots` file makes the external anchor UNVERIFIABLE. The verifier does not treat that as a pass and does not create a replacement proof.
- External implementations recorded here: zero.
- Evidence Pack procedural acceptances recorded here: zero.

Older generated text still says "Fully Compliant" or "RFC 6962 compliant": `evidence/02_verification/verification_report.txt` and the banner in `evidence/03_tamper_detection/tamper_detection_test.py`. Those files were left unchanged. The current result is `evidence/02_verification/verification_report_2026-10-22.txt`. The PDF filename `VCP_Worlds_First_Evidence_Report.pdf` is not a verification result.

Details of the 2026-10-21 search for the anchor proof are in [evidence/VERIFICATION_STATUS.md](evidence/VERIFICATION_STATUS.md).
