"""
MailTrace — Real Training Pipeline
====================================
Implements REAL backpropagation, REAL optimizer updates, REAL checkpoints.

NO simulated training. NO fake loss. NO fake checksum.
If training cannot start, the error is shown and the system exits honestly.

Pipeline:
  Preprocessing → Tokenization → Shard Writing → Training Loop →
  Validation → Checkpointing → Final Test Evaluation
"""

import argparse
import json
import logging
import math
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.optim import AdamW
from torch.optim.lr_scheduler import CosineAnnealingLR, LinearLR, SequentialLR
from torch.cuda.amp import GradScaler, autocast as cuda_autocast
from contextlib import nullcontext

# ── local imports ──────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from model.config import ModelConfig, TrainingConfig
from model.mailtrace_100m import build_model, count_parameters, MailTraceSecurityTransformer
from data.parser import DatasetInventory, stream_canonical_records
from data.splitter import GroupAwareSplitter
from data.dataset import (
    ShardWriter, ShardedEmailDataset, make_dataloader,
    CATEGORY_INDEX, PRIMARY_CATEGORIES, BINARY_HEAD_NAMES,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Device detection
# ──────────────────────────────────────────────────────────────────────────────
def get_device() -> Tuple[torch.device, str]:
    """
    Returns (device, device_name_str).
    Priority: CUDA > MPS (Apple Silicon) > CPU.
    Reports the REAL device — never claims GPU if running on CPU.
    """
    if torch.cuda.is_available():
        device = torch.device("cuda")
        props = torch.cuda.get_device_properties(0)
        vram_gb = props.total_memory / 1e9
        name = f"CUDA:{props.name} ({vram_gb:.1f} GB VRAM)"
    elif torch.backends.mps.is_available():
        device = torch.device("mps")
        import platform, subprocess
        try:
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True, text=True, timeout=5
            )
            chip = next(
                (l.split(":")[-1].strip() for l in result.stdout.splitlines()
                 if "Chip" in l or "Processor" in l), "Apple Silicon"
            )
        except Exception:
            chip = "Apple Silicon"
        name = f"MPS:{chip} (shared memory)"
    else:
        device = torch.device("cpu")
        name = "CPU (no GPU available)"

    logger.info(f"Device: {name}")
    return device, name


# ──────────────────────────────────────────────────────────────────────────────
# Memory estimation
# ──────────────────────────────────────────────────────────────────────────────
def estimate_memory(
    model: MailTraceSecurityTransformer,
    batch_size: int,
    seq_len: int,
    device: torch.device,
) -> Dict[str, float]:
    """
    Estimates model + optimizer + activation memory in GB.
    Returns dict of estimates. These are estimates, not guarantees.
    """
    counts = count_parameters(model)
    trainable = counts["trainableParameters"]

    # Model weights: float32 = 4 bytes, float16 = 2 bytes
    weight_gb_fp32 = trainable * 4 / 1e9
    weight_gb_fp16 = trainable * 2 / 1e9

    # AdamW optimizer: ~3× trainable params (m, v, grad)
    optimizer_gb = trainable * 4 * 3 / 1e9

    # Activations: rough estimate for one batch
    # batch × seq × d_model × layers × 4 bytes
    d_model = model.cfg.d_model
    layers = model.cfg.num_text_layers + model.cfg.num_fusion_layers
    activation_gb = batch_size * seq_len * d_model * layers * 4 / 1e9

    return {
        "weightsFP32_GB": round(weight_gb_fp32, 2),
        "weightsFP16_GB": round(weight_gb_fp16, 2),
        "optimizerFP32_GB": round(optimizer_gb, 2),
        "estimatedActivations_GB": round(activation_gb, 3),
        "totalEstimatedFP32_GB": round(weight_gb_fp32 + optimizer_gb + activation_gb, 2),
        "totalEstimatedFP16_GB": round(weight_gb_fp16 + optimizer_gb / 2 + activation_gb, 2),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Multi-task loss
# ──────────────────────────────────────────────────────────────────────────────
class MultiTaskLoss(nn.Module):
    """
    Combines:
    - CrossEntropyLoss for primary category (30 classes)
    - CrossEntropyLoss for language (7 classes)
    - BCEWithLogitsLoss for 13 binary security heads

    Uses class weights to handle imbalance.
    """

    def __init__(self, primary_weights: Optional[torch.Tensor] = None,
                 language_weights: Optional[torch.Tensor] = None,
                 label_smoothing: float = 0.05,
                 loss_w_primary: float = 1.0,
                 loss_w_binary: float = 0.5,
                 loss_w_language: float = 0.3):
        super().__init__()
        self.loss_w_primary = loss_w_primary
        self.loss_w_binary = loss_w_binary
        self.loss_w_language = loss_w_language

        self.primary_criterion = nn.CrossEntropyLoss(
            weight=primary_weights, label_smoothing=label_smoothing
        )
        self.language_criterion = nn.CrossEntropyLoss(
            weight=language_weights
        )
        self.binary_criterion = nn.BCEWithLogitsLoss(reduction="mean")

    def forward(
        self,
        primary_logits: torch.Tensor,   # (B, 30)
        language_logits: torch.Tensor,  # (B, 7)
        binary_logits: torch.Tensor,    # (B, 13)
        primary_labels: torch.Tensor,   # (B,) long
        language_labels: torch.Tensor,  # (B,) long
        binary_labels: torch.Tensor,    # (B, 13) float
    ) -> Tuple[torch.Tensor, Dict[str, float]]:
        loss_primary = self.primary_criterion(primary_logits, primary_labels)
        loss_lang = self.language_criterion(language_logits, language_labels)
        loss_binary = self.binary_criterion(binary_logits, binary_labels)

        total = (
            self.loss_w_primary * loss_primary
            + self.loss_w_language * loss_lang
            + self.loss_w_binary * loss_binary
        )

        return total, {
            "loss_primary": loss_primary.item(),
            "loss_language": loss_lang.item(),
            "loss_binary": loss_binary.item(),
            "loss_total": total.item(),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Checkpointing
# ──────────────────────────────────────────────────────────────────────────────
def save_checkpoint(
    model: MailTraceSecurityTransformer,
    optimizer: AdamW,
    scheduler,
    epoch: int,
    step: int,
    val_loss: float,
    val_macro_f1: float,
    cfg: ModelConfig,
    training_cfg: TrainingConfig,
    checkpoint_dir: str,
    is_best: bool = False,
    tokenizer_version: str = "gpt2-v1",
    dataset_version: str = "mailtrace-dataset-v2.0.0",
):
    """Saves a REAL checkpoint containing model weights, optimizer, scheduler state."""
    epoch_dir = os.path.join(checkpoint_dir, f"epoch-{epoch:03d}-step-{step:07d}")
    os.makedirs(epoch_dir, exist_ok=True)

    ckpt = {
        "epoch": epoch,
        "step": step,
        "model_state_dict": model.state_dict(),
        "optimizer_state_dict": optimizer.state_dict(),
        "scheduler_state_dict": scheduler.state_dict() if scheduler else None,
        "val_loss": val_loss,
        "val_macro_f1": val_macro_f1,
        "model_config": cfg.to_dict(),
        "training_config": training_cfg.to_dict(),
        "parameter_counts": model.get_parameter_counts(),
        "tokenizer_version": tokenizer_version,
        "dataset_version": dataset_version,
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }

    path = os.path.join(epoch_dir, "checkpoint.pt")
    torch.save(ckpt, path)
    logger.info(f"Checkpoint saved: {path}")

    if is_best:
        best_dir = os.path.join(checkpoint_dir, "best-validation")
        os.makedirs(best_dir, exist_ok=True)
        best_path = os.path.join(best_dir, "checkpoint.pt")
        torch.save(ckpt, best_path)
        logger.info(f"Best checkpoint updated: {best_path}")

    return path


def load_checkpoint(
    model: MailTraceSecurityTransformer,
    optimizer: Optional[AdamW],
    scheduler,
    checkpoint_path: str,
    device: torch.device,
) -> Tuple[int, int, float, float]:
    """Loads checkpoint and returns (epoch, step, val_loss, val_macro_f1)."""
    logger.info(f"Resuming from checkpoint: {checkpoint_path}")
    ckpt = torch.load(checkpoint_path, map_location=device)
    model.load_state_dict(ckpt["model_state_dict"])
    if optimizer and "optimizer_state_dict" in ckpt:
        optimizer.load_state_dict(ckpt["optimizer_state_dict"])
    if scheduler and ckpt.get("scheduler_state_dict"):
        scheduler.load_state_dict(ckpt["scheduler_state_dict"])
    return (
        ckpt.get("epoch", 0),
        ckpt.get("step", 0),
        ckpt.get("val_loss", float("inf")),
        ckpt.get("val_macro_f1", 0.0),
    )


def find_latest_checkpoint(checkpoint_dir: str) -> Optional[str]:
    """Finds the most recently saved checkpoint file."""
    if not os.path.isdir(checkpoint_dir):
        return None
    candidates = []
    for d in Path(checkpoint_dir).iterdir():
        if d.is_dir() and d.name.startswith("epoch-"):
            p = d / "checkpoint.pt"
            if p.exists():
                candidates.append((d.name, str(p)))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x[0])
    return candidates[-1][1]


# ──────────────────────────────────────────────────────────────────────────────
# Evaluation
# ──────────────────────────────────────────────────────────────────────────────
def evaluate(
    model: MailTraceSecurityTransformer,
    dataloader,
    criterion: MultiTaskLoss,
    device: torch.device,
    split_name: str = "validation",
) -> Dict[str, float]:
    """
    Computes REAL evaluation metrics from actual model predictions.
    NO hardcoded values.
    """
    from sklearn.metrics import (
        accuracy_score, precision_recall_fscore_support,
        average_precision_score, roc_auc_score, confusion_matrix
    )
    import numpy as np

    model.eval()
    total_loss = 0.0
    steps = 0

    all_primary_preds = []
    all_primary_labels = []
    all_binary_probs = []
    all_binary_labels = []

    with torch.no_grad():
        for batch in dataloader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            struct_feats = batch["structured_feats"].to(device)
            primary_labels = batch["primary_label"].to(device)
            language_labels = batch["language_label"].to(device)
            binary_labels = batch["binary_labels"].to(device)

            outputs = model(input_ids, attention_mask=attention_mask,
                            structured_feats=struct_feats)

            loss, _ = criterion(
                outputs["primary_logits"],
                outputs["language_logits"],
                outputs["binary_logits"],
                primary_labels, language_labels, binary_labels,
            )
            total_loss += loss.item()
            steps += 1

            primary_preds = outputs["primary_logits"].argmax(dim=-1).cpu().numpy()
            all_primary_preds.extend(primary_preds.tolist())
            all_primary_labels.extend(primary_labels.cpu().numpy().tolist())

            binary_probs = torch.sigmoid(outputs["binary_logits"]).cpu().numpy()
            all_binary_probs.extend(binary_probs.tolist())
            all_binary_labels.extend(binary_labels.cpu().numpy().tolist())

    all_primary_preds = np.array(all_primary_preds)
    all_primary_labels = np.array(all_primary_labels)

    accuracy = accuracy_score(all_primary_labels, all_primary_preds)
    precision, recall, f1, support = precision_recall_fscore_support(
        all_primary_labels, all_primary_preds, average=None,
        labels=list(range(len(PRIMARY_CATEGORIES))), zero_division=0
    )
    macro_f1 = float(f1[support > 0].mean()) if (support > 0).any() else 0.0
    micro_prec, micro_recall, micro_f1, _ = precision_recall_fscore_support(
        all_primary_labels, all_primary_preds, average="micro", zero_division=0
    )
    weighted_prec, weighted_recall, weighted_f1, _ = precision_recall_fscore_support(
        all_primary_labels, all_primary_preds, average="weighted", zero_division=0
    )

    # Per-category metrics
    per_category = {}
    for i, cat in enumerate(PRIMARY_CATEGORIES):
        n = int(support[i])
        if n < 5:
            per_category[cat] = {"status": "INSUFFICIENT_TEST_SAMPLES", "support": n}
        else:
            per_category[cat] = {
                "precision": round(float(precision[i]), 4),
                "recall": round(float(recall[i]), 4),
                "f1": round(float(f1[i]), 4),
                "support": n,
            }

    # Binary head AUC
    binary_metrics = {}
    all_bp = np.array(all_binary_probs)
    all_bl = np.array(all_binary_labels)
    for i, head_name in enumerate(BINARY_HEAD_NAMES):
        n_pos = int(all_bl[:, i].sum())
        if n_pos < 5 or n_pos == len(all_bl):
            binary_metrics[head_name] = {"status": "INSUFFICIENT_SAMPLES"}
        else:
            try:
                auc = roc_auc_score(all_bl[:, i], all_bp[:, i])
                binary_metrics[head_name] = {"roc_auc": round(float(auc), 4)}
            except Exception:
                binary_metrics[head_name] = {"status": "COMPUTE_ERROR"}

    # Confusion matrix
    cm = confusion_matrix(all_primary_labels, all_primary_preds,
                          labels=list(range(len(PRIMARY_CATEGORIES)))).tolist()

    avg_loss = total_loss / max(steps, 1)

    return {
        f"{split_name}_loss": round(avg_loss, 6),
        "accuracy": round(float(accuracy), 4),
        "macro_f1": round(macro_f1, 4),
        "micro_f1": round(float(micro_f1), 4),
        "weighted_f1": round(float(weighted_f1), 4),
        "micro_precision": round(float(micro_prec), 4),
        "micro_recall": round(float(micro_recall), 4),
        "per_category_metrics": per_category,
        "binary_head_metrics": binary_metrics,
        "confusion_matrix": cm,
        "n_samples": len(all_primary_labels),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Training loop
# ──────────────────────────────────────────────────────────────────────────────
def train(args):
    """Main training entry point."""
    # ── Config ────────────────────────────────────────────────────────────────
    cfg = ModelConfig()
    training_cfg = TrainingConfig()

    # Override from args
    if args.epochs:
        training_cfg.num_epochs = args.epochs
    if args.batch_size:
        training_cfg.batch_size = args.batch_size
    if args.lr:
        training_cfg.learning_rate = args.lr

    project_root = Path(args.project_root).resolve()
    dataset_dir = str(project_root / "dataset")
    shard_dir = str(project_root / "dataset" / "processed" / "shards")
    checkpoint_dir = str(project_root / "ml" / "artifacts" / "checkpoints")
    reports_dir = str(project_root / "ml" / "artifacts" / "reports")

    os.makedirs(shard_dir, exist_ok=True)
    os.makedirs(checkpoint_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)

    status_path = os.path.join(reports_dir, "training_status.json")

    def update_status(status: str, **kwargs):
        s = {"status": status, "updatedAt": datetime.now(timezone.utc).isoformat(), **kwargs}
        with open(status_path, "w") as f:
            json.dump(s, f, indent=2)
        logger.info(f"Training status: {status}")

    update_status("INITIALIZING")

    # ── Device ────────────────────────────────────────────────────────────────
    device, device_name = get_device()

    # Reduce batch size for MPS/CPU
    if device.type in ("mps", "cpu") and training_cfg.batch_size > 16:
        training_cfg.batch_size = 16
        training_cfg.gradient_accumulation_steps = 4
        logger.info(f"Reduced batch_size to {training_cfg.batch_size} for {device.type}")

    # Disable AMP for MPS (not fully supported)
    use_amp = training_cfg.use_amp and device.type == "cuda"

    # ── Model ─────────────────────────────────────────────────────────────────
    logger.info("Initializing MailTrace Security Transformer 100M...")
    update_status("INITIALIZING_MODEL")
    model = build_model(cfg)
    model = model.to(device)
    param_counts = model.get_parameter_counts()

    logger.info(f"Trainable parameters: {param_counts['trainableParameters']:,}")

    # ── Memory estimate ───────────────────────────────────────────────────────
    mem_est = estimate_memory(model, training_cfg.batch_size, cfg.max_seq_len, device)
    logger.info(f"Estimated memory: {mem_est}")

    # ── Tokenizer ─────────────────────────────────────────────────────────────
    update_status("LOADING_TOKENIZER")
    try:
        from transformers import GPT2TokenizerFast
        tokenizer = GPT2TokenizerFast.from_pretrained("gpt2")
        tokenizer.pad_token = tokenizer.eos_token
        tokenizer_version = f"gpt2-{tokenizer.__class__.__name__}-v1"
    except ImportError:
        logger.warning("transformers not installed; using character tokenizer")
        tokenizer = None
        tokenizer_version = "char-fallback-v1"

    # ── Dataset preprocessing ─────────────────────────────────────────────────
    update_status("PREPROCESSING")

    # Inventory
    logger.info("Scanning dataset directory...")
    inventory = DatasetInventory(dataset_dir)
    entries = inventory.scan()
    inventory.save(str(project_root / "dataset" / "processed" / "dataset_inventory.json"))
    canonical = [e for e in entries if e.status == "CANONICAL"]
    total_raw = sum(e.rawRecords for e in canonical)
    logger.info(f"Canonical files: {len(canonical)}, raw records: {total_raw:,}")

    # Check if shards already exist
    existing_shards = list(Path(shard_dir).glob("shard_*.bin"))
    if existing_shards and not args.force_preprocess:
        logger.info(f"Found {len(existing_shards)} existing shards. Skipping preprocessing.")
        logger.info("Use --force-preprocess to rebuild shards.")
    else:
        logger.info("Building shards from canonical records (streaming)...")
        update_status("PREPROCESSING_SHARDS",
                      totalCanonicalRecords=total_raw,
                      canonicalFiles=len(canonical))

        # Buffer records for splitting (use IDs only, not all content)
        records_meta: List[Dict] = []
        writer = ShardWriter(shard_dir, shard_size=10_000,
                             max_seq_len=cfg.max_seq_len, tokenizer=tokenizer)

        # First pass: collect metadata for splitting
        logger.info("Collecting metadata for group-aware splitting...")
        for record in stream_canonical_records(entries):
            records_meta.append({
                "recordId": record.recordId,
                "sourceFile": record.sourceFile,
                "normalizedLabel": record.normalizedLabel,
                "bodyText": (record.bodyText or "")[:200],  # truncated for meta
                "subject": record.subject,
                "sender": record.sender,
            })
            if len(records_meta) % 100_000 == 0:
                logger.info(f"  Collected {len(records_meta):,} records for splitting...")

        logger.info(f"Total collected: {len(records_meta):,}. Running group-aware split...")

        splitter = GroupAwareSplitter(
            train_ratio=training_cfg.train_ratio,
            val_ratio=training_cfg.val_ratio,
            test_ratio=training_cfg.test_ratio,
            seed=training_cfg.seed,
        )
        split_records = splitter.split(records_meta)
        split_map = {sr.recordId: sr.split for sr in split_records}

        splitter.save_manifest(
            split_records,
            str(project_root / "dataset" / "processed" / "split_manifest.json")
        )

        logger.info("Second pass: tokenizing and writing shards...")
        written = excluded = 0
        for record in stream_canonical_records(entries):
            split = split_map.get(record.recordId, "excluded")
            if split == "excluded":
                excluded += 1
                continue
            rec_dict = {
                "bodyText": record.bodyText,
                "subject": record.subject,
                "sender": record.sender,
                "normalizedLabel": record.normalizedLabel,
                "urls": record.urls,
                "structuredFeatures": record.structuredFeatures,
            }
            writer.write(rec_dict, split=split)
            written += 1
            if written % 100_000 == 0:
                logger.info(f"  Written {written:,} records...")
        writer.close()
        logger.info(f"Shard writing complete: {written:,} written, {excluded:,} excluded")

    # ── DataLoaders ────────────────────────────────────────────────────────────
    update_status("LOADING_DATA")
    train_ds = ShardedEmailDataset(shard_dir, split="train", max_seq_len=cfg.max_seq_len)
    val_ds = ShardedEmailDataset(shard_dir, split="validation", max_seq_len=cfg.max_seq_len)
    test_ds = ShardedEmailDataset(shard_dir, split="test", max_seq_len=cfg.max_seq_len)

    logger.info(f"Train: {len(train_ds):,} | Val: {len(val_ds):,} | Test: {len(test_ds):,}")

    if len(train_ds) == 0:
        logger.error("Train dataset is empty — cannot start training")
        update_status("FAILED", reason="Empty training dataset")
        sys.exit(1)

    num_workers = min(training_cfg.num_workers, os.cpu_count() or 1)
    # MPS doesn't support multi-process DataLoader well
    if device.type == "mps":
        num_workers = 0

    train_loader = make_dataloader(train_ds, training_cfg.batch_size, shuffle=True,
                                   num_workers=num_workers)
    val_loader = make_dataloader(val_ds, training_cfg.batch_size, shuffle=False,
                                 num_workers=num_workers)
    test_loader = make_dataloader(test_ds, training_cfg.batch_size, shuffle=False,
                                  num_workers=num_workers)

    # ── Optimizer & Scheduler ─────────────────────────────────────────────────
    optimizer = AdamW(
        model.parameters(),
        lr=training_cfg.learning_rate,
        weight_decay=training_cfg.weight_decay,
        betas=(training_cfg.beta1, training_cfg.beta2),
        eps=training_cfg.epsilon,
    )

    total_steps = len(train_loader) * training_cfg.num_epochs
    warmup_scheduler = LinearLR(
        optimizer,
        start_factor=0.01,
        end_factor=1.0,
        total_iters=training_cfg.num_warmup_steps,
    )
    cosine_scheduler = CosineAnnealingLR(
        optimizer,
        T_max=max(total_steps - training_cfg.num_warmup_steps, 1),
        eta_min=training_cfg.learning_rate * 0.01,
    )
    scheduler = SequentialLR(
        optimizer,
        schedulers=[warmup_scheduler, cosine_scheduler],
        milestones=[training_cfg.num_warmup_steps],
    )

    criterion = MultiTaskLoss(
        label_smoothing=training_cfg.label_smoothing,
        loss_w_primary=training_cfg.loss_weight_primary,
        loss_w_binary=training_cfg.loss_weight_binary,
        loss_w_language=training_cfg.loss_weight_language,
    )

    scaler = GradScaler() if use_amp else None
    amp_ctx = cuda_autocast if use_amp else nullcontext

    # ── Resume ────────────────────────────────────────────────────────────────
    start_epoch = 0
    global_step = 0
    best_val_macro_f1 = 0.0
    best_val_loss = float("inf")
    patience_counter = 0

    if args.resume:
        ckpt_path = args.resume if isinstance(args.resume, str) else find_latest_checkpoint(checkpoint_dir)
        if ckpt_path:
            start_epoch, global_step, best_val_loss, best_val_macro_f1 = load_checkpoint(
                model, optimizer, scheduler, ckpt_path, device
            )
            start_epoch += 1
        else:
            logger.warning("--resume specified but no checkpoint found. Starting fresh.")

    # ── Training loop ─────────────────────────────────────────────────────────
    update_status("TRAINING",
                  device=device_name,
                  parameterCounts=param_counts,
                  trainSamples=len(train_ds),
                  valSamples=len(val_ds),
                  testSamples=len(test_ds),
                  totalSteps=total_steps,
                  numEpochs=training_cfg.num_epochs)

    training_start = time.time()
    training_log = []

    for epoch in range(start_epoch, training_cfg.num_epochs):
        model.train()
        epoch_loss = 0.0
        epoch_steps = 0
        epoch_start = time.time()

        optimizer.zero_grad()

        for batch_idx, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            struct_feats = batch["structured_feats"].to(device)
            primary_labels = batch["primary_label"].to(device)
            language_labels = batch["language_label"].to(device)
            binary_labels = batch["binary_labels"].to(device)

            with amp_ctx():
                outputs = model(input_ids, attention_mask=attention_mask,
                                structured_feats=struct_feats)
                loss, loss_parts = criterion(
                    outputs["primary_logits"],
                    outputs["language_logits"],
                    outputs["binary_logits"],
                    primary_labels, language_labels, binary_labels,
                )
                loss = loss / training_cfg.gradient_accumulation_steps

            if scaler:
                scaler.scale(loss).backward()
            else:
                loss.backward()

            global_step += 1
            epoch_steps += 1
            epoch_loss += loss.item() * training_cfg.gradient_accumulation_steps

            if global_step % training_cfg.gradient_accumulation_steps == 0:
                if scaler:
                    scaler.unscale_(optimizer)
                nn.utils.clip_grad_norm_(model.parameters(), training_cfg.gradient_clip)
                if scaler:
                    scaler.step(optimizer)
                    scaler.update()
                else:
                    optimizer.step()
                scheduler.step()
                optimizer.zero_grad()

            # Logging
            if global_step % 100 == 0:
                avg_loss = epoch_loss / epoch_steps
                lr = scheduler.get_last_lr()[0]
                elapsed = time.time() - epoch_start
                steps_per_sec = epoch_steps / elapsed
                logger.info(
                    f"Epoch {epoch+1}/{training_cfg.num_epochs} "
                    f"Step {global_step:,}/{total_steps:,} "
                    f"Loss: {avg_loss:.4f} LR: {lr:.2e} "
                    f"Speed: {steps_per_sec:.1f} steps/s"
                )
                training_log.append({
                    "epoch": epoch + 1,
                    "step": global_step,
                    "loss": round(avg_loss, 6),
                    "lr": round(lr, 8),
                })

            # Validation checkpoint
            if global_step % training_cfg.eval_every_steps == 0:
                update_status("VALIDATING", epoch=epoch+1, step=global_step)
                val_metrics = evaluate(model, val_loader, criterion, device, "validation")
                val_loss = val_metrics["validation_loss"]
                val_macro_f1 = val_metrics["macro_f1"]
                logger.info(
                    f"[Validation] Loss: {val_loss:.4f} "
                    f"Macro F1: {val_macro_f1:.4f} "
                    f"Accuracy: {val_metrics['accuracy']:.4f}"
                )

                is_best = val_macro_f1 > best_val_macro_f1
                if is_best:
                    best_val_macro_f1 = val_macro_f1
                    best_val_loss = val_loss
                    patience_counter = 0
                else:
                    patience_counter += 1

                save_checkpoint(
                    model, optimizer, scheduler, epoch + 1, global_step,
                    val_loss, val_macro_f1, cfg, training_cfg, checkpoint_dir,
                    is_best=is_best,
                    tokenizer_version=tokenizer_version,
                    dataset_version=cfg.dataset_version,
                )
                model.train()
                update_status("TRAINING", epoch=epoch+1, step=global_step)

                # Early stopping
                if patience_counter >= training_cfg.early_stopping_patience:
                    logger.info(
                        f"Early stopping: val macro F1 has not improved for "
                        f"{patience_counter} evaluations."
                    )
                    break

        else:
            continue
        break  # Early stopping triggered inner loop

    # ── Final test evaluation ─────────────────────────────────────────────────
    update_status("EVALUATING")
    logger.info("Running final evaluation on held-out TEST set...")

    # Load best model for final test evaluation
    best_ckpt = find_latest_checkpoint(os.path.join(checkpoint_dir, "best-validation"))
    if best_ckpt:
        load_checkpoint(model, None, None, best_ckpt, device)

    test_metrics = evaluate(model, test_loader, criterion, device, "test")
    logger.info(
        f"[TEST] Loss: {test_metrics.get('test_loss', 'N/A')} "
        f"Macro F1: {test_metrics['macro_f1']:.4f} "
        f"Accuracy: {test_metrics['accuracy']:.4f}"
    )

    training_duration = time.time() - training_start

    # ── Reports ───────────────────────────────────────────────────────────────
    training_report = {
        "modelVersion": cfg.model_id,
        "modelId": cfg.model_id,
        "architecture": cfg.architecture,
        "totalParameters": param_counts["totalParameters"],
        "trainableParameters": param_counts["trainableParameters"],
        "frozenParameters": param_counts["frozenParameters"],
        "device": device_name,
        "epochs": training_cfg.num_epochs,
        "stepsCompleted": global_step,
        "trainingSamples": len(train_ds),
        "validationSamples": len(val_ds),
        "testSamples": len(test_ds),
        "batchSize": training_cfg.batch_size,
        "gradAccumulationSteps": training_cfg.gradient_accumulation_steps,
        "effectiveBatchSize": training_cfg.batch_size * training_cfg.gradient_accumulation_steps,
        "learningRate": training_cfg.learning_rate,
        "sequenceLength": cfg.max_seq_len,
        "trainingDurationSeconds": round(training_duration, 1),
        "trainingLog": training_log[-100:],  # last 100 steps
        "checkpointDir": checkpoint_dir,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
    }

    eval_report = {
        "modelVersion": cfg.model_id,
        "evaluationSplit": "test",
        "nSamples": test_metrics["n_samples"],
        **test_metrics,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
    }

    model_card = {
        "modelName": "MailTrace Security Transformer 100M",
        "modelId": cfg.model_id,
        "version": cfg.model_version,
        "architecture": cfg.architecture,
        "totalParameters": param_counts["totalParameters"],
        "trainableParameters": param_counts["trainableParameters"],
        "tokenizerVersion": tokenizer_version,
        "datasetVersion": cfg.dataset_version,
        "languages": ["English", "Indian English", "Hindi", "Gujarati", "Hinglish"],
        "primaryCategories": PRIMARY_CATEGORIES,
        "binaryHeads": BINARY_HEAD_NAMES,
        "trainingDevice": device_name,
        "trainingDurationSeconds": round(training_duration, 1),
        "evaluationResults": {
            "testAccuracy": test_metrics["accuracy"],
            "testMacroF1": test_metrics["macro_f1"],
            "testMicroF1": test_metrics["micro_f1"],
            "testWeightedF1": test_metrics["weighted_f1"],
        },
        "knownLimitations": [
            "Training on limited labeled BEC/payroll-fraud data — low recall expected",
            "Indian-language detection uses Unicode range heuristics during preprocessing",
            "email-data.csv structured malware features may not generalize to all email types",
        ],
        "generatedAt": datetime.now(timezone.utc).isoformat(),
    }

    with open(os.path.join(reports_dir, "training_report.json"), "w") as f:
        json.dump(training_report, f, indent=2)
    with open(os.path.join(reports_dir, "evaluation_report.json"), "w") as f:
        json.dump(eval_report, f, indent=2)
    with open(os.path.join(reports_dir, "model_card.json"), "w") as f:
        json.dump(model_card, f, indent=2)

    logger.info(f"Reports saved to {reports_dir}")

    update_status(
        "COMPLETED",
        testMacroF1=test_metrics["macro_f1"],
        testAccuracy=test_metrics["accuracy"],
        checkpointDir=checkpoint_dir,
    )

    return test_metrics


# ──────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MailTrace 100M Training Pipeline")
    parser.add_argument("--project-root", default=".", help="Project root directory")
    parser.add_argument("--epochs", type=int, default=None, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=None, help="Batch size")
    parser.add_argument("--lr", type=float, default=None, help="Learning rate")
    parser.add_argument("--resume", nargs="?", const=True, default=False,
                        help="Resume from latest checkpoint (or specify path)")
    parser.add_argument("--force-preprocess", action="store_true",
                        help="Rebuild shards even if they exist")
    parser.add_argument("--preprocess-only", action="store_true",
                        help="Only run preprocessing, no training")

    args = parser.parse_args()

    try:
        train(args)
    except KeyboardInterrupt:
        logger.info("Training interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Training failed: {e}", exc_info=True)
        sys.exit(1)
