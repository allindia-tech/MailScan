"""
MailTrace — Verified Feedback Dataset & DataLoader
==================================================
PyTorch Dataset for verified analyst ground-truth training samples with controlled sample weighting.
Loads full 128-dim structured features, tokenized body/subject, and multi-task ground truth targets.
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import torch
from torch.utils.data import Dataset, DataLoader

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from data.dataset import (
    extract_structured_features,
    derive_binary_labels,
    detect_language,
    CATEGORY_INDEX,
    LANG_INDEX,
    STRUCTURED_FEATURES,
    PRIMARY_CATEGORIES,
    BINARY_HEAD_NAMES
)

logger = logging.getLogger(__name__)


class VerifiedFeedbackDataset(Dataset):
    """
    Dataset representing verified analyst feedback and ground-truth samples.
    Supports controlled sample weighting (1.0 - 2.0) and hard-negative prioritization.
    """

    def __init__(
        self,
        manifest_path_or_store: str,
        tokenizer=None,
        max_seq_len: int = 1024,
        include_unverified: bool = False
    ):
        self.max_seq_len = max_seq_len
        self.tokenizer = tokenizer
        self.samples = []

        if os.path.exists(manifest_path_or_store):
            with open(manifest_path_or_store, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "samples" in data:
                    raw_items = data["samples"]
                elif isinstance(data, list):
                    raw_items = data
                else:
                    raw_items = []
        else:
            logger.warning(f"Manifest path {manifest_path_or_store} not found, initializing empty.")
            raw_items = []

        for item in raw_items:
            # Filter out non-verified if requested
            status = item.get("status", "VERIFIED")
            if not include_unverified and status not in ("VERIFIED", "QUEUED_FOR_TRAINING", "APPLIED"):
                continue

            self.samples.append(item)

        logger.info(f"Loaded {len(self.samples)} verified training samples.")

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        item = self.samples[idx]

        # Extract text
        raw_email = item.get("rawEmailSample") or {}
        subject = item.get("emailSubject") or item.get("subject") or raw_email.get("subject", "")
        body = item.get("rawBody") or raw_email.get("bodyText", "")
        text = f"{subject} {body}".strip()

        # Tokenize
        if self.tokenizer:
            enc = self.tokenizer(
                text,
                max_length=self.max_seq_len,
                truncation=True,
                padding="max_length",
                return_tensors=None,
            )
            input_ids = enc["input_ids"]
            attention_mask = enc["attention_mask"]
        else:
            # Deterministic character/byte encoding fallback
            bts = text.encode("utf-8", errors="replace")[:self.max_seq_len]
            pad_len = self.max_seq_len - len(bts)
            input_ids = list(bts) + [0] * pad_len
            attention_mask = [1] * len(bts) + [0] * pad_len

        # Extract structured features
        rec_for_feats = {
            "subject": subject,
            "bodyText": body,
            "sender": item.get("sender") or raw_email.get("sender", ""),
            "urls": item.get("urls") or raw_email.get("urls", []),
            "structuredFeatures": item.get("structuredFeatures") or {}
        }
        feats = extract_structured_features(rec_for_feats)

        # Ground truth labels
        gt = item.get("verifiedGroundTruth") or {}
        category = gt.get("primaryCategory") or item.get("primaryCategory") or "LEGITIMATE"
        category_norm = category.upper().replace(" ", "_").replace("/", "_")
        primary_idx = CATEGORY_INDEX.get(category_norm, CATEGORY_INDEX.get("LEGITIMATE", 0))

        lang_idx = detect_language(rec_for_feats)

        # Multi-label binary heads
        binary = derive_binary_labels(category_norm, rec_for_feats)

        # Controlled sample weight (capped between 1.0 and 2.0)
        sample_weight = float(item.get("sampleWeight", 1.5))
        sample_weight = max(1.0, min(2.0, sample_weight))

        # Hard negative flag
        is_hard_negative = 1.0 if item.get("isHardNegative", False) else 0.0
        is_hard_positive = 1.0 if item.get("isHardPositive", False) else 0.0

        return {
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "attention_mask": torch.tensor(attention_mask, dtype=torch.long),
            "structured_feats": torch.tensor(feats, dtype=torch.float32),
            "primary_label": torch.tensor(primary_idx, dtype=torch.long),
            "language_label": torch.tensor(lang_idx, dtype=torch.long),
            "binary_labels": torch.tensor(binary, dtype=torch.float32),
            "sample_weight": torch.tensor(sample_weight, dtype=torch.float32),
            "is_hard_negative": torch.tensor(is_hard_negative, dtype=torch.float32),
            "is_hard_positive": torch.tensor(is_hard_positive, dtype=torch.float32),
        }


def make_feedback_dataloader(
    dataset: VerifiedFeedbackDataset,
    batch_size: int = 4,
    shuffle: bool = True
) -> DataLoader:
    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=shuffle,
        pin_memory=False,
        drop_last=False
    )
