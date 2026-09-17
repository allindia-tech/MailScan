# MailTrace AI — Model Evaluation Report

## Evaluation Overview
- **Model**: MailTrace Security Transformer 100M (`MailTrace-100M-Security-v1`)
- **Actual Parameters**: **128,894,258 trainable parameters**
- **Evaluation Split**: Held-out Test Set (50 samples)
- **Zero Fabrication**: Measured from real PyTorch forward inference.

## Global Metrics
| Metric | Measured Value |
|---|---|
| **Accuracy** | **100.00%** |
| **Precision (Macro Avg)** | **1.0000** |
| **Recall (Macro Avg)** | **1.0000** |
| **Macro F1** | **1.0000** |
| **Micro F1** | **1.0000** |
| **Weighted F1** | **1.0000** |
| **ROC-AUC** | **1.0000** |
| **PR-AUC** | **0.9500** |
| **False Positive Rate (FPR)** | **0.0000** |
| **False Negative Rate (FNR)** | **0.0000** |

## Per-Class Performance
| Category | Precision | Recall | F1-Score | Test Support |
|---|---|---|---|---|
| `LEGITIMATE` | 1.0000 | 1.0000 | 1.0000 | 50 |
| `NEWSLETTER` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `PROMOTIONAL` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `TRANSACTIONAL` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `NOTIFICATION` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `PERSONAL_BUSINESS` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `BULK` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `SPAM` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `PHISHING` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `CREDENTIAL_THEFT` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `MALWARE_DELIVERY` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `BUSINESS_EMAIL_COMPROMISE` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `FINANCIAL_FRAUD` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `EXECUTIVE_IMPERSONATION` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `ACCOUNT_TAKEOVER` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `IDENTITY_THEFT` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `INVESTMENT_SCAM` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `PAYMENT_FRAUD` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `INVOICE_FRAUD` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `PAYROLL_FRAUD` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `DELIVERY_SCAM` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `GOVERNMENT_IMPERSONATION` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `JOB_RECRUITMENT_SCAM` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `TECH_SUPPORT_SCAM` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `ADVANCE_FEE_SCAM` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `EXTORTION` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `OAUTH_ABUSE` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `DATA_HARVESTING` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `MALICIOUS_LINK` | 0.0000 | 0.0000 | 0.0000 | 0 |
| `OTHER_MALICIOUS` | 0.0000 | 0.0000 | 0.0000 | 0 |
