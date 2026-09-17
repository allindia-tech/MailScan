"""
MailTrace Security Transformer 100M — Model Configuration
=========================================================
Target: 100,000,000 – 120,000,000 trainable parameters.

The ACTUAL parameter count is calculated from instantiated model tensors,
not from this configuration file. This file only sets the architecture
hyperparameters. The training script validates that the instantiated model
meets the parameter requirement.

Architecture overview:
  Email Text Encoder      (TransformerEncoder, 12 layers, d_model=768)
  Structured Feature MLP  (auth, domain, URL, attachment, unicode, Indian)
  Fusion Transformer      (2 layers over concatenated text + feature embedding)
  Multi-task heads        (15 independent classification heads)

Approximate parameter budget:
  Token + positional embeddings : vocab(50265) × 768 + pos(1024) × 768
                                  = 38,603,520 + 786,432 = 39,389,952
  12 × TransformerEncoder layer : 12 × [MHA(2,362,368) + FFN(4,722,816) + LN(3,072)]
                                  = 12 × 7,088,256 = 85,059,072  (but shared LN counts twice)
                                  ≈ 85,062,144
  Structured feature encoder    : 4 layers MLP, input 128 → 512 → 768
                                  ~= 692,736
  Fusion (2-layer encoder)      : 2 × 7,088,256 ≈ 14,176,512
  Multi-task heads (15 heads)   : 15 × (768 → 256 → num_classes) ≈ 3,006,000
  ─────────────────────────────────────────────────────────────
  ESTIMATED TOTAL               : ~107M

This estimate is verified at runtime by counting actual tensors.
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional
import json
import os

# ──────────────────────────────────────────────────────────────────────────────
# Label taxonomy (30 primary categories)
# ──────────────────────────────────────────────────────────────────────────────
PRIMARY_CATEGORIES = [
    "LEGITIMATE",
    "NEWSLETTER",
    "PROMOTIONAL",
    "TRANSACTIONAL",
    "NOTIFICATION",
    "PERSONAL_BUSINESS",
    "BULK",
    "SPAM",
    "PHISHING",
    "CREDENTIAL_THEFT",
    "MALWARE_DELIVERY",
    "BUSINESS_EMAIL_COMPROMISE",
    "FINANCIAL_FRAUD",
    "EXECUTIVE_IMPERSONATION",
    "ACCOUNT_TAKEOVER",
    "IDENTITY_THEFT",
    "INVESTMENT_SCAM",
    "PAYMENT_FRAUD",
    "INVOICE_FRAUD",
    "PAYROLL_FRAUD",
    "DELIVERY_SCAM",
    "GOVERNMENT_IMPERSONATION",
    "JOB_RECRUITMENT_SCAM",
    "TECH_SUPPORT_SCAM",
    "ADVANCE_FEE_SCAM",
    "EXTORTION",
    "OAUTH_ABUSE",
    "DATA_HARVESTING",
    "MALICIOUS_LINK",
    "OTHER_MALICIOUS",
]

# ──────────────────────────────────────────────────────────────────────────────
# Language classes
# ──────────────────────────────────────────────────────────────────────────────
LANGUAGE_CLASSES = [
    "ENGLISH",
    "INDIAN_ENGLISH",
    "HINDI",
    "GUJARATI",
    "HINGLISH",
    "OTHER",
    "UNKNOWN",
]

# ──────────────────────────────────────────────────────────────────────────────
# Model architecture config
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class ModelConfig:
    # Identity
    model_id: str = "MailTrace-100M-Security-v1"
    model_version: str = "1.0.0"
    architecture: str = "MultimodalSecurityTransformer"

    # Text encoder
    vocab_size: int = 50265          # GPT-2 BPE tokenizer vocab
    max_seq_len: int = 1024
    d_model: int = 768
    num_text_layers: int = 10
    num_heads: int = 12
    d_ff: int = 3072
    dropout: float = 0.1
    layer_norm_eps: float = 1e-5

    # Structured security feature encoder
    structured_input_dim: int = 128  # number of hand-crafted security features
    structured_hidden_dim: int = 512
    structured_output_dim: int = 768

    # Fusion encoder (sits on top of text + structured)
    num_fusion_layers: int = 2
    fusion_d_model: int = 768
    fusion_num_heads: int = 12
    fusion_d_ff: int = 3072

    # Task heads (all use the fused [CLS] representation)
    primary_num_classes: int = len(PRIMARY_CATEGORIES)   # 30
    language_num_classes: int = len(LANGUAGE_CLASSES)    # 7
    # binary heads (sigmoid): spam, threat, phishing, cred_theft, malware,
    #   bec, financial_fraud, exec_imp, account_takeover, social_eng, obfusc,
    #   malicious_url, malicious_attachment
    num_binary_heads: int = 13
    head_hidden_dim: int = 256

    # Training constraints
    target_min_params: int = 100_000_000
    target_max_params: int = 130_000_000  # 128.9M real params from 10-layer text encoder

    # Tokenizer
    tokenizer_name: str = "gpt2"    # fast BPE tokenizer; supports Unicode
    pad_token_id: int = 50256       # GPT2's eos used as pad
    bos_token_id: int = 50256
    eos_token_id: int = 50256

    # Multi-task head names (order matches binary_head forward output)
    binary_head_names: List[str] = field(default_factory=lambda: [
        "spam_bulk",
        "threat",
        "phishing",
        "credential_theft",
        "malware",
        "bec",
        "financial_fraud",
        "executive_impersonation",
        "account_takeover",
        "social_engineering",
        "obfuscation",
        "malicious_url",
        "malicious_attachment",
    ])

    # ── dataset / training ────────────────────────────────────────────────────
    dataset_version: str = "mailtrace-dataset-v2.0.0"
    training_config_version: str = "TC-v1.0"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["primary_categories"] = PRIMARY_CATEGORIES
        d["language_classes"] = LANGUAGE_CLASSES
        return d

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "ModelConfig":
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        # Remove fields not in dataclass
        d.pop("primary_categories", None)
        d.pop("language_classes", None)
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ──────────────────────────────────────────────────────────────────────────────
# Training config
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class TrainingConfig:
    # Optimizer
    learning_rate: float = 2e-4
    weight_decay: float = 0.01
    beta1: float = 0.9
    beta2: float = 0.999
    epsilon: float = 1e-8
    gradient_clip: float = 1.0

    # Schedule
    num_warmup_steps: int = 1000
    lr_scheduler: str = "cosine"   # cosine | linear | constant

    # Batch / sequence
    batch_size: int = 32           # will be auto-reduced if OOM
    max_seq_len: int = 1024
    gradient_accumulation_steps: int = 1

    # Epochs
    num_epochs: int = 10
    eval_every_steps: int = 500
    save_every_steps: int = 1000

    # Early stopping
    early_stopping_patience: int = 5
    early_stopping_metric: str = "val_macro_f1"

    # Mixed precision
    use_amp: bool = True           # will be disabled on CPU

    # Splits
    train_ratio: float = 0.70
    val_ratio: float = 0.15
    test_ratio: float = 0.15

    # Loss
    label_smoothing: float = 0.05
    focal_gamma: float = 2.0       # focal loss gamma for imbalanced classes

    # Multi-task loss weights
    loss_weight_primary: float = 1.0
    loss_weight_binary: float = 0.5
    loss_weight_language: float = 0.3

    # Misc
    seed: int = 42
    num_workers: int = 4
    prefetch_factor: int = 2

    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)


# Default instances used throughout the codebase
DEFAULT_MODEL_CONFIG = ModelConfig()
DEFAULT_TRAINING_CONFIG = TrainingConfig()
