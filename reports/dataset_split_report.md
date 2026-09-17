# MailTrace AI — Authoritative Dataset Split Report

**Dataset Version:** `mailtrace-dataset-split-s42-6e403d1a8e14`  
**Split Seed:** `42` (Deterministic)  
**Execution Timestamp:** 2026-09-15T17:29:09.206057+00:00  
**Execution Duration:** 159.18s  
**Status:** **✓ ZERO LEAKAGE — INDEPENDENT 80/20 SPLIT VERIFIED**

---

## 1. Dataset Inventory & Discovery

### A. SOURCE 1 — MIX-CSV (`dataset/mix-csv/`)
- **Total Discovered Files:** 40
- **Canonical Email CSV Files:** 16
- **Total Ingested Records:** 2,741,764
- **Exact Duplicate Records Excluded:** 2,433,865
- **Unique Canonical Records:** 307,899
- **Training Set (80%):** **246,318 records** (80.0%)
- **Held-Out Test Set (20%):** **61,581 records** (20.0%)

#### Class Distribution (MIX-CSV)
| Category | Train Count (80%) | Test Count (20%) |
| :--- | :--- | :--- |
| **LEGITIMATE** | 112,314 | 21,390 |
| **OTHER_MALICIOUS** | 8,279 | 2,070 |
| **PHISHING** | 6,528 | 0 |
| **SPAM** | 88,621 | 19,438 |
| **UNLABELED** | 30,576 | 18,683 |

---

### B. SOURCE 2 — MIX-EML (`dataset/mix-eml/`)
- **Total Discovered EML Files:** 49,136
- **Valid RFC 822/5322 EML Records:** 49,134
- **Malformed EML Files:** 2
- **Exact Duplicate Records Excluded:** 2,960
- **Unique Valid EML Records:** 46,174
- **Training Set (80%):** **36,938 records** (80.0%)
- **Held-Out Test Set (20%):** **9,236 records** (20.0%)

---

## 2. Combined Pipeline Composition

| Dataset Source | Total Discovered | Unique Records | 80% Training Split | 20% Held-Out Test Split |
| :--- | :--- | :--- | :--- | :--- |
| **MIX-CSV** | 2,741,764 | 307,899 | 246,318 | 61,581 |
| **MIX-EML** | 49,136 | 46,174 | 36,938 | 9,236 |
| **COMBINED** | **2,790,898** | **354,073** | **283,256** | **70,817** |

---

## 3. Data Leakage & Isolation Verification

- **CSV Train/Test Content Hash Overlap:** `0` (ASSERTION: == 0) -> **PASS**
- **EML Train/Test Content Hash Overlap:** `0` (ASSERTION: == 0) -> **PASS**
- **Manifest Location:** `dataset/splits/seed-42/manifests/`
  - `csv_train.json`
  - `csv_test.json`
  - `eml_train.json`
  - `eml_test.json`
  - `dataset_split_manifest.json`
