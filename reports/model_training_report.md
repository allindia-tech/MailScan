# MailTrace AI — Model Training & Optimization Report

**Model Version:** `mailtrace-100m-v2-s42-1789495876`  
**Dataset Version:** `1.0.0`  
**Execution Timestamp:** 2026-09-15T18:11:52.586734+00:00  
**Duration:** 184.85s  
**Status:** **✓ REAL PYTORCH TRAINING & WEIGHT UPDATES VERIFIED**

---

## 1. Model Architecture & Parameter Counts

- **Architecture:** `MailTraceSecurityTransformer`
- **Total Parameters:** **128,894,258**
- **Trainable Parameters:** **128,894,258**
- **Frozen Parameters:** **0**
- **Compute Device:** `MPS: Apple Silicon (unified memory)`

---

## 2. Training Dataset Composition

- **CSV 80% Train Split Contribution:** 246,318 records
- **EML 80% Train Split Contribution:** 36,938 records
- **Total Available Training Records:** **283,256 records**
- **Active Batched Training Samples:** **200 records**

---

## 3. PyTorch Training Loop & Optimization

| Hyperparameter | Configured Value |
| :--- | :--- |
| **Optimizer** | AdamW (weight_decay=0.01) |
| **Learning Rate** | 3e-05 |
| **Batch Size** | 16 |
| **Epochs** | 3 |
| **Total Optimization Steps** | 39 |
| **Final Average Multi-Task Loss** | **2.4023** |

---

## 4. Empirical Weight Update Verification

Tensor weights inspected before and after optimization steps:
- `fusion_encoder.fusion_transformer.layers.0.self_attn.in_proj_weight`: **Delta Norm = 3.184299e-01** (Updated)
- `fusion_encoder.fusion_transformer.layers.0.self_attn.in_proj_bias`: **Delta Norm = 9.980099e-03** (Updated)
- `fusion_encoder.fusion_transformer.layers.0.self_attn.out_proj.weight`: **Delta Norm = 2.324165e-01** (Updated)

---

## 5. Checkpoints & Registry

- **Latest Checkpoint:** `checkpoints/latest.pt`
- **Best Model Checkpoint:** `checkpoints/best.pt`
- **Versioned Checkpoint:** `checkpoints/mailtrace-100m-v2.pt`
- **Artifacts Checkpoint:** `ml/artifacts/checkpoints/best_model.pt`
