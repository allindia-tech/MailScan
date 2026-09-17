# MailTrace AI — `csv_filtered.json` Dataset Inventory Report

**Generated:** 2026-09-16T16:42:19.041516+00:00
**Authoritative Source:** `dataset/new/csv_filtered.json`
**File Size:** 119.47 MB (125,278,456 bytes)

## 1. Summary Metrics

| Metric | Value |
| :--- | :--- |
| **Total Raw Records** | 258,640 |
| **Unique Records (by SHA-256 contentHash)** | 258,640 |
| **Duplicate Records** | 0 |
| **Malformed Records** | 0 |
| **Unlabeled Records** | 0 (0.0%) |
| **Labeled Records** | 258,640 (100.0%) |

## 2. Schema Definition

- **Root Structure:** Top-level JSON Array of Objects (`List[Dict]`)
- **Fields:** `campaignGroup, contentHash, exclusionReason, normalizedLabel, recordId, sender, sourceFile, sourceRecordId, sourceType, split, subject`
- **Primary Identifier:** `recordId`
- **Canonical Hash Field:** `contentHash`
- **Ground Truth Label Field:** `normalizedLabel`

## 3. Label Distribution

| Label / Class | Count | Percentage |
| :--- | :--- | :--- |
| `LEGITIMATE` | 133,704 | 51.7% |
| `SPAM` | 108,059 | 41.78% |
| `OTHER_MALICIOUS` | 10,349 | 4.0% |
| `PHISHING` | 6,528 | 2.52% |
| **TOTAL** | **258,640** | **100.0%** |

## 4. Referenced Source Files

| Source CSV File | Record Count | Percentage |
| :--- | :--- | :--- |
| `TREC-05.csv` | 55,151 | 21.32% |
| `TREC-07.csv` | 53,749 | 20.78% |
| `CEAS-08.csv` | 39,149 | 15.14% |
| `Enron.csv` | 29,745 | 11.5% |
| `Phishing_Email.csv` | 17,457 | 6.75% |
| `TREC-06.csv` | 16,378 | 6.33% |
| `full_dataset.csv` | 12,476 | 4.82% |
| `fraud_email_.csv` | 10,218 | 3.95% |
| `phishing_legit_dataset_KD_10000.csv` | 9,956 | 3.85% |
| `Assassin.csv` | 5,807 | 2.25% |
| `emails copy.csv` | 5,695 | 2.2% |
| `Ling.csv` | 2,859 | 1.11% |
