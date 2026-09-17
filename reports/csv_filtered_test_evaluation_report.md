# MailTrace AI — `csv_filtered.json` Held-Out Test Evaluation Report

**Generated:** 2026-09-17T03:07:01.855371+00:00
**Model:** `mailtrace-100m-v3-csv-filtered.pt`
**Evaluation Set:** 100% of 20% Held-Out Test Split (51,728 records)

## 1. Test Dataset Summary

| Metric | Value |
| :--- | :--- |
| **Total Test Records** | 51,728 |
| **Labeled Records** | 51,728 |
| **Parse Failures / Unresolved** | 0 |

## 2. Threat Detection Performance

| Metric | Value |
| :--- | :--- |
| **Accuracy** | 94.50% |
| **Precision** | 57.95% |
| **Recall** | 56.05% |
| **F1 Score** | 0.5699 |
| **ROC-AUC** | 0.944 |
| **PR-AUC** | 0.5815 |

## 3. Spam Detection Performance

| Metric | Value |
| :--- | :--- |
| **Accuracy** | 87.87% |
| **Precision** | 88.74% |
| **Recall** | 81.69% |
| **F1 Score** | 0.8507 |
| **ROC-AUC** | 0.9426 |
| **PR-AUC** | 0.9316 |

## 4. Benchmark Verification

- **Microsoft False-Positive Benchmark:** Threat Risk = **0.1/100** (<= 15.0) -> **PASS**
- **Spam ≠ Threat Separation:** Spam Prob = **0.6633**, Threat Risk = **0.4/100** -> **PASS**
- **Inference Determinism:** Max Delta = **0.00000000e+00** -> **PASS**
- **Model Collapse Check:** **PASS** (Zero collapse, active detections)
