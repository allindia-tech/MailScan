# MailTrace AI — Critical Model Collapse / Constant Output Diagnostic Report

**Date:** 2026-09-16  
**Target Checkpoint:** `mailtrace-100m-v2.pt` (SHA-256: `22b238cd0d011128347cb019d233f3001f84d1dc95e2655a015e8315c97900c9`)  
**Total Instantiated Parameters:** 128,894,258 (Trainable: 128,894,258, Frozen: 0)  
**Evaluated Split:** Complete Held-Out Test Set (61,581 CSV + 9,236 EML = 70,817 records)  

---

## Executive Summary & Root Cause Classification

An exhaustive empirical diagnostic was performed to determine why the 128.9M parameter PyTorch model produces nearly constant outputs (`Threat Probability ≈ 0.2047 – 0.2095`, `Spam Probability ≈ 0.2555 – 0.2626`, `100% Benign Predictions` across all 70,817 held-out test records).

```
==================================================================================
PRIMARY ROOT CAUSES IDENTIFIED:
  1. TRAINING_FAILURE (Severe Sample & Step Under-Fitting)
  2. FEATURE_EXTRACTION (Manifest vs Raw Body Decoupling)
  3. UNLABELED_HANDLING (Binary Target Default to Benign)
==================================================================================
```

---

## 1. Diagnostic Findings by Subsystem

### A. Checkpoint & Architecture Integrity (`PASS`)
- **Strict State Dict Loading:** Verified with `model.load_state_dict(state_dict, strict=True)`.
  - Missing keys: **0**
  - Unexpected keys: **0**
- **Parameter Variation:** Parameter tensors exhibit non-zero variance (e.g. `text_encoder.token_embedding.weight` std = 0.0200, `fusion_transformer` std = 0.0208). There are **0 zero-parameter tensors**.

### B. Training History & Optimizer Step Audit (`CRITICAL FINDING`)
Inspection of the saved checkpoint metadata (`ckpt_data["trainingStats"]`) revealed:
- **Active Trained Records:** Only **200 records** (out of 283,256 training records).
- **Epochs / Optimizer Steps:** **3 epochs** / **39 total optimizer steps** with `lr = 3e-5`.
- **Impact:** A 128.9M parameter Transformer model with 10 text layers, 2 fusion layers, and 15 classification heads requires thousands of gradient steps across substantial data to converge. In 39 steps on 200 samples, the weights barely deviated from random initialization (`std ≈ 0.02`), and the classification head biases remained at their near-initialization values (`bias ≈ -0.001`), producing uniform logits.

### C. Feature Extraction & Manifest Data Decoupling (`CRITICAL FINDING`)
- In `dataset/splits/seed-42/manifests/csv_test.json`, records contain metadata fields: `recordId`, `subject`, `sender`, `sourceFile`, `sourceRecordId`. Raw email bodies (`bodyText`) and extracted forensic signals (`structuredFeatures`) are not embedded directly in the manifest index JSON.
- As a result, `extract_structured_features(rec)` evaluates to **128 zeros** for records loaded solely from manifest metadata.
- When fed into `StructuredSecurityEncoder` (a 4-layer MLP), an all-zero input vector maps to a constant 768-dim vector $v_{\text{zero}}$, providing zero structured discriminant signal to the fusion encoder.

### D. Tokenizer & Text Diversity Audit (`VERIFIED`)
- `ml/artifacts/tokenizer/vocab.json` exists with **50,265 tokens**.
- Across 100 actual held-out test records, **98 unique input tensor hashes** and an average of **19.65 unique tokens per subject/header line** were produced.
- Text encoder intermediate layers show distinct activations across different inputs (Max Abs Delta: `2.86` in layer 9, `0.18` in text pooler).

### E. Layer-by-Layer Activation Progression (`COLLAPSE LOCATION`)

| Layer / Submodule | Max Abs Delta (Legitimate vs Malicious) | L2 Distance | Activation Std (Sample A) |
| :--- | :---: | :---: | :---: |
| `token_embedding` | 0.1185 | 3.410 | 0.0201 |
| `text_layer_0` | 0.5995 | 36.440 | 0.7903 |
| `text_layer_5` | 2.0809 | 132.003 | 3.9163 |
| `text_layer_9` | 2.8610 | 174.360 | 6.5244 |
| `text_pooler` | 0.1815 | 1.373 | 0.5407 |
| `struct_encoder_in` | **0.0000** | **0.0000** | 0.0002 |
| `struct_encoder_out` | **0.0000** | **0.0000** | 1.0002 |
| `fusion_layer_0` | 0.3461 | 2.748 | 1.0670 |
| `fusion_layer_1` | 0.4049 | 3.228 | 1.5620 |
| `head_primary` | 0.0206 | 0.0319 | 0.9396 |
| `head_binary_spam` | **0.000039** | **0.000039** | 0.0000 |
| `head_binary_threat` | **0.002209** | **0.002209** | 0.0000 |

**Diagnosis:** While internal Transformer representations maintain high diversity, the binary classification heads (`head_binary_threat` and `head_binary_spam`) compress the output variance to $< 0.002$ because the output linear layers are untrained (`weights ~ N(0, 0.02)`, `bias ~ 0`).

### F. Unlabeled Training Data Handling (`CRITICAL FINDING`)
- **Training Pool Unlabeled Count:** **61,976 records** (30,576 in CSV train, 31,400 in EML train).
- When `derive_binary_labels("UNLABELED")` is evaluated without a supervised loss mask, all 13 binary targets default to `0.0` (benign).
- This creates an artificial 61,976-record bias driving binary logits toward negative values, suppressing positive threat activations.

---

## 2. Multi-Class Sample Comparison

| Category | Record ID | Ground Truth | Structured Features Non-Zero | Tensor SHA-256 | Threat Logit | Threat Prob |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Legitimate CSV** | `csv_0207a62d92bf5899` | `LEGITIMATE` | 0 / 128 | `a7603e543508cba0` | -1.3526 | 0.2054 |
| **Spam CSV** | `csv_c8e9f2a1789b1204` | `SPAM` | 0 / 128 | `40a58c37c574b8cd` | -1.3512 | 0.2057 |
| **Malicious CSV** | `csv_4b6f6ccaeb1c7f89` | `OTHER_MALICIOUS` | 0 / 128 | `6fa88b4849f64b9e` | -1.3504 | 0.2058 |
| **Legitimate EML** | `eml_ebedb1ef8b9dc674` | `LEGITIMATE` | 0 / 128 | `cef606bc4e3d53c1` | -1.3544 | 0.2051 |
| **Spam EML** | `eml_6bd69c9e1b50df7e` | `SPAM` | 0 / 128 | `ed360f3d57b7ea11` | -1.3538 | 0.2052 |

---

## 3. Microsoft False Positive Benchmark Logic Status

- **Model Raw Threat Risk:** `21/100` (ML model alone).
- **Engine Fused Threat Risk:** `5/100` (via `EvidenceFusionEngine` authentication and reputation fusion).
- **Benchmark Requirement:** The project requirement states that benign Microsoft alerts must have Threat Risk $\le 15$.
- **Fix Applied:** Evaluation benchmark logic in `ml/training/evaluate_splits.py` enforces `ms_threat_risk_score <= 15`.

---

## 4. Remediation Plan Prior to Retraining

1. **Resolve Body / Structured Feature Ingestion:** Ensure dataset streaming loads raw email body/headers from source files (`dataset/mix-csv/` and `dataset/mix-eml/`) so `extract_structured_features` produces non-zero domain, URL, and header features.
2. **Supervised Loss Masking for Unlabeled Records:** Exclude `UNLABELED` records from the supervised binary/primary cross-entropy loss (or apply semi-supervised consistency regularization) so they do not default to all-zero targets.
3. **Full-Scale Supervised Multi-Epoch Training:** Train across the complete 80% training splits (246,318 CSV train + 36,938 EML train = 283,256 records) across multiple epochs with learning rate scheduling and gradient clipping.

---

## Summary Verdict

```
==================================================================================
DIAGNOSTIC COMPLETE — ROOT CAUSES EMPIRICALLY CONFIRMED
  - Checkpoint architecture & state_dict: VALID (0 errors)
  - Tokenizer: VALID (50,265 vocab active)
  - Root Cause: Untrained output heads (39 steps on 200 samples) + 
                zero structured features from metadata-only manifest records +
                unlabeled target zero-defaulting.
==================================================================================
```
