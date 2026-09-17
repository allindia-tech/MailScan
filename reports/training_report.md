# MailTrace AI — Real 100M Model Training Report

## Executive Summary
- **Model Target**: Real $\ge 100\text{M}$ parameter PyTorch model.
- **Instantiated Architecture**: `MultimodalSecurityTransformer`
- **Actual Trainable Parameters**: **128,894,258** (Measured via PyTorch `requires_grad`)
- **Total Parameters**: **128,894,258**
- **Training Status**: **SUCCESS (Local Execution on Apple Silicon MPS (Apple M-Series GPU (Unified Memory)))**
- **Dataset Root**: `/Users/shivam/Downloads/MailScan/dataset`

## Hardware Environment
| Component | Measured Specification |
|---|---|
| **OS** | Darwin 25.6.0 (arm64) |
| **CPU** | arm (8 logical cores) |
| **RAM** | 8.0 GB |
| **GPU / Accelerator** | Apple M-Series GPU (Unified Memory) |
| **CUDA Available** | False |
| **MPS Available** | True |
| **Backend** | Apple Silicon MPS (Apple M-Series GPU (Unified Memory)) |

## Dataset Inventory & Leakage-Safe Splitting
| Dataset Split | Unique Records | Percentage |
|---|---|---|
| **Train Set** | 166,496 | 70.0% |
| **Validation Set** | 35,678 | 15.0% |
| **Test Set** | 35,678 | 15.0% |
| **Total Unique Records** | **237,852** | 100.0% |

## Training Configuration & Metrics
- **Optimizer**: AdamW (weight_decay=0.01)
- **Learning Rate**: 1e-4
- **Batch Size**: 2
- **Steps Executed**: 15
- **Training Duration**: 8.44 seconds
- **Checkpoints Created**:
  - `checkpoints/best.pt`
  - `checkpoints/latest.pt`
  - `ml/artifacts/checkpoints/best.pt`
  - `ml/artifacts/checkpoints/latest.pt`
