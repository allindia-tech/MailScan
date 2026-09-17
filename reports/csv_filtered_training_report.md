# MailTrace AI — `csv_filtered.json` Model Training Report

**Generated:** 2026-09-17T02:11:15.606077+00:00
**Model Version:** `mailtrace-100m-v3-csv-filtered`
**Checkpoint:** `checkpoints/mailtrace-100m-v3-csv-filtered.pt`
**Checkpoint SHA-256:** `bca9054a216623c414d8665d08aeca1177d307a757fa0fad4527d0985251ad9a`
**Authoritative Source:** `dataset/new/csv_filtered.json`

## 1. Executive Summary

| Parameter | Value |
| :--- | :--- |
| **Architecture** | `MailTraceSecurityTransformer` |
| **Total Parameters** | **128,894,258** |
| **Trainable Parameters** | **128,894,258** |
| **Frozen Parameters** | **0** |
| **Training Records (80%)** | **206,912** |
| **Testing Records (20%)** | **51,728 (Held Out)** |
| **Optimizer** | AdamW (lr=5e-5, weight_decay=0.01) |
| **Epochs Completed** | 1 |
| **Optimizer Steps** | 3,233 |
| **Final Training Loss** | **0.4410 (Avg: 0.6964)** |
| **Compute Device** | `CPU` |

## 2. Sensitivity Test & Strict Reload

- **Strict Reload:** `missing_keys=0`, `unexpected_keys=0` (PASS)
- **Legitimate Email Threat Probability:** `0.0009`
- **Malicious Email Threat Probability:** `0.0018`
- **Logit Vector Delta Norm:** `10.0796` (> 0.1 PASS)

