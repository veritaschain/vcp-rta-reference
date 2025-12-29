# Tamper Detection Demo Procedures

**Document ID:** TAMPER-2025-001  
**Version:** 1.0  
**Date:** 2025-12-29  

---

## Purpose

Visually demonstrate the tamper detection capability of VCP hash chains.
Show that deleting just one line causes the entire chain verification to fail.

---

## Demo Execution Steps

### Step 1: Verify Original Chain

```bash
cd 02_verification/verifier
python vcp_verifier.py ../../01_sample_logs/vcp_rta_demo_events.jsonl
```

**Expected Result:** `VERIFICATION: PASS`

-> **Screenshot: screenshot_pass.png**

---

### Step 2: Run Tamper Demo

```bash
cd 03_tamper_demo
python tamper_demo.py
```

---

### Step 3: Verify Tampered Chain

```bash
cd 02_verification/verifier
python vcp_verifier.py ../../03_tamper_demo/vcp_rta_demo_events_tampered.jsonl
```

**Expected Result:** `VERIFICATION: FAIL`

-> **Screenshot: screenshot_fail.png**

---

## Tampering Details

| Item | Value |
|------|-------|
| Deleted Line Number | 5 |
| Deleted Event Type | SIG (AI Signal) |
| Original Event Count | 150 |
| Tampered Event Count | 149 |

---

## Detected Errors

```
Line 5: PrevHash mismatch 
  expected: a1b2c3d4e5f6...
  got:      f6e5d4c3b2a1...
```

---

## Conclusion

- **Delete 1 line** -> Chain broken -> Immediately detected
- **Change 1 byte** -> Hash mismatch -> Immediately detected
- **Reorder events** -> PrevHash mismatch -> Immediately detected

**VCP cryptographically guarantees tamper resistance.**

---

## File List

| File | Description |
|------|-------------|
| `tamper_demo.py` | Automated demo script |
| `tamper_step.md` | This document |
| `diff.txt` | Details of deleted event |
| `screenshot_pass.png` | Screenshot of successful verification |
| `screenshot_fail.png` | Screenshot of tamper detection |
| `vcp_rta_demo_events_tampered.jsonl` | Tampered chain |

---

**VCP - Verify, Don't Trust**
