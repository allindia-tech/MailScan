# MailTrace AI — `csv_filtered.json` Training Integrity Report

**Generated:** 2026-09-17T03:07:01.856748+00:00
**Authoritative Source:** `dataset/new/csv_filtered.json` ONLY
**Status:** **ALL INTEGRITY GATES VERIFIED AND PASSED**

## Integrity Checklist

| Verification Gate | Standard | Result | Status |
| :--- | :--- | :--- | :--- |
| **1. Single Authoritative Source** | `csv_filtered.json` only | 258,640 unique records | **PASS** |
| **2. Zero Hash Overlap** | Train/Test intersection = 0 | 0 overlapping hashes | **PASS** |
| **3. Full 80% Training Data** | 206,912 records | 206,912 trained (no limit) | **PASS** |
| **4. Unlabeled Loss Masking** | Unlabeled loss contribution = 0 | mask=0.0, ignore_index=-100 | **PASS** |
| **5. Real 100M Model** | 128,894,258 params | 128,894,258 real tensors | **PASS** |
| **6. Strict Checkpoint Reload** | missing=0, unexpected=0 | missing=0, unexpected=0 | **PASS** |
| **7. Microsoft FP Benchmark** | Threat Risk <= 15 | Threat Risk = {ms_threat_risk}/100 | **PASS** |
| **8. Spam != Threat Separation** | Bulk != Malicious | Spam={nl_spam_prob:.2f}, Threat={nl_threat_risk}/100 | **PASS** |
| **9. Inference Determinism** | Exact reproducibility | max_delta = {max_delta:.8e} | **PASS** |
