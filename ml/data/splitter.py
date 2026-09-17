"""
MailTrace — Independent Multi-Source Dataset Splitter (80/20)
=============================================================
Performs independent, deterministic 80% train / 20% test splits for:
  1. dataset/mix-csv/
  2. dataset/mix-eml/

Key Invariants:
- Source isolation: mix-csv and mix-eml are split INDEPENDENTLY.
- Complete train/test isolation: intersection(TRAIN_HASHES, TEST_HASHES) == 0.
- Reproducibility: Seed (default 42) ensures identical split allocations.
- Zero data leakage: No template or campaign cross-contamination.
- Manifest generation in dataset/splits/seed-42/manifests/ without duplicating 50,000 files.
"""

import os
import re
import json
import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SplitRecord:
    recordId: str
    sourceFile: str
    sourceType: str      # "mix-csv" | "mix-eml"
    sourceRecordId: str
    normalizedLabel: str
    split: str           # "train" | "test" | "excluded"
    exclusionReason: str
    contentHash: str
    campaignGroup: str
    subject: str = ""
    sender: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _content_hash(text: str) -> str:
    """SHA-256 of normalized text for exact duplicate detection."""
    return hashlib.sha256(str(text or "").encode("utf-8", errors="replace")).hexdigest()


def _subject_template(subject: str) -> str:
    """Strips dates and numbers to derive clean template fingerprint."""
    s = str(subject or "").lower()
    s = re.sub(r"\b\d{1,4}[-/]\d{1,2}[-/]\d{2,4}\b", "", s)
    s = re.sub(r"\b\d+\b", "", s)
    s = re.sub(r"[^a-z\s]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:60]


def _sender_domain(sender: str) -> str:
    m = re.search(r"@([\w.\-]+)", str(sender or ""))
    return m.group(1).lower() if m else "unknown"


def _campaign_group(sender: str, subject: str) -> str:
    domain = _sender_domain(sender)
    template = _subject_template(subject)
    combined = f"{domain}::{template}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


class IndependentSourceSplitter:
    """
    Splits mix-csv and mix-eml independently into 80% train / 20% test sets.
    """

    def __init__(self, train_ratio: float = 0.80, test_ratio: float = 0.20, seed: int = 42):
        assert abs(train_ratio + test_ratio - 1.0) < 1e-6, "train_ratio + test_ratio must equal 1.0"
        self.train_ratio = train_ratio
        self.test_ratio = test_ratio
        self.seed = seed

    def split_records(
        self,
        records: List[Any],
        source_name: str = "mix-csv"
    ) -> Tuple[List[SplitRecord], Dict[str, Any]]:
        """
        Deduplicates and deterministically splits records from a single source into 80% train / 20% test.
        """
        seen_hashes: Set[str] = set()
        split_records: List[SplitRecord] = []
        exact_duplicates = 0
        template_groups: Dict[str, List[int]] = defaultdict(list)

        def _get(obj, key, default=""):
            if isinstance(obj, dict):
                return obj.get(key, default)
            return getattr(obj, key, default)

        for r in records:
            rec_id = _get(r, "recordId", "")
            src_file = _get(r, "sourceFile", "")
            src_type = _get(r, "sourceType", source_name)
            src_rec_id = _get(r, "sourceRecordId", "")
            norm_label = _get(r, "normalizedLabel", "UNLABELED")
            subject = _get(r, "subject", "")
            sender = _get(r, "sender", "")
            body = _get(r, "bodyText", "")
            
            c_hash = _get(r, "contentHash", "") or _content_hash(f"{subject} {body} {sender}")
            cg = _campaign_group(sender, subject)

            if c_hash in seen_hashes:
                exact_duplicates += 1
                split_records.append(SplitRecord(
                    recordId=rec_id,
                    sourceFile=src_file,
                    sourceType=src_type,
                    sourceRecordId=str(src_rec_id),
                    normalizedLabel=norm_label,
                    split="excluded",
                    exclusionReason="EXACT_DUPLICATE_CONTENT",
                    contentHash=c_hash,
                    campaignGroup=cg,
                    subject=subject[:100],
                    sender=sender[:100],
                ))
            else:
                seen_hashes.add(c_hash)
                idx = len(split_records)
                template_groups[cg].append(idx)
                split_records.append(SplitRecord(
                    recordId=rec_id,
                    sourceFile=src_file,
                    sourceType=src_type,
                    sourceRecordId=str(src_rec_id),
                    normalizedLabel=norm_label,
                    split="pending",
                    exclusionReason="",
                    contentHash=c_hash,
                    campaignGroup=cg,
                    subject=subject[:100],
                    sender=sender[:100],
                ))

        # Stratified / Group-aware deterministic split
        # We group by (normalizedLabel, campaignGroup) to preserve class balance while preventing template leakage
        label_groups: Dict[str, List[str]] = defaultdict(list)
        for cg, idxs in template_groups.items():
            primary_label = split_records[idxs[0]].normalizedLabel
            label_groups[primary_label].append(cg)

        assigned_train = 0
        assigned_test = 0

        for lbl in sorted(label_groups.keys()):
            cgs = label_groups[lbl]
            # Deterministic sort using sha256(cg + seed)
            def _sort_key(k: str) -> str:
                return hashlib.sha256(f"{k}_{self.seed}_{lbl}".encode()).hexdigest()

            cgs.sort(key=_sort_key)

            total_records_in_label = sum(len(template_groups[cg]) for cg in cgs)
            train_target_for_label = int(total_records_in_label * self.train_ratio)
            current_train_for_label = 0

            for cg in cgs:
                idxs = template_groups[cg]
                group_size = len(idxs)
                
                # Assign to train if under target, else test
                if current_train_for_label + group_size <= train_target_for_label or (current_train_for_label == 0 and train_target_for_label > 0):
                    split_val = "train"
                    current_train_for_label += group_size
                    assigned_train += group_size
                else:
                    split_val = "test"
                    assigned_test += group_size

                for i in idxs:
                    split_records[i].split = split_val

        # Verification of isolation
        train_hashes = {r.contentHash for r in split_records if r.split == "train"}
        test_hashes = {r.contentHash for r in split_records if r.split == "test"}
        overlap = train_hashes.intersection(test_hashes)
        if overlap:
            raise ValueError(f"FATAL: Train/Test content hash leakage detected in {source_name}! Overlap count: {len(overlap)}")

        stats = {
            "source": source_name,
            "totalRawRecords": len(records),
            "exactDuplicates": exact_duplicates,
            "uniqueRecords": len(seen_hashes),
            "trainCount": assigned_train,
            "testCount": assigned_test,
            "trainRatioActual": round(assigned_train / max(1, len(seen_hashes)), 4),
            "testRatioActual": round(assigned_test / max(1, len(seen_hashes)), 4),
            "trainTestHashOverlap": len(overlap),
            "templateGroupsCount": len(template_groups),
        }

        logger.info(
            f"[{source_name.upper()} SPLIT] Total: {len(records):,} | "
            f"Unique: {len(seen_hashes):,} | Train (80%): {assigned_train:,} | "
            f"Test (20%): {assigned_test:,} | Excluded: {exact_duplicates:,}"
        )

        return split_records, stats

    def save_split_manifests(
        self,
        csv_records: List[SplitRecord],
        csv_stats: Dict[str, Any],
        eml_records: List[SplitRecord],
        eml_stats: Dict[str, Any],
        output_dir: str
    ) -> Dict[str, Any]:
        """
        Saves all split manifests into dataset/splits/seed-42/manifests/
        """
        manifest_dir = Path(output_dir) / f"seed-{self.seed}" / "manifests"
        manifest_dir.mkdir(parents=True, exist_ok=True)

        # 1. csv_train.json
        csv_train = [r.to_dict() for r in csv_records if r.split == "train"]
        csv_test = [r.to_dict() for r in csv_records if r.split == "test"]
        with open(manifest_dir / "csv_train.json", "w", encoding="utf-8") as f:
            json.dump(csv_train, f, indent=2)
        with open(manifest_dir / "csv_test.json", "w", encoding="utf-8") as f:
            json.dump(csv_test, f, indent=2)

        # 2. eml_train.json
        eml_train = [r.to_dict() for r in eml_records if r.split == "train"]
        eml_test = [r.to_dict() for r in eml_records if r.split == "test"]
        with open(manifest_dir / "eml_train.json", "w", encoding="utf-8") as f:
            json.dump(eml_train, f, indent=2)
        with open(manifest_dir / "eml_test.json", "w", encoding="utf-8") as f:
            json.dump(eml_test, f, indent=2)

        # 3. Overall dataset_split_manifest.json
        combined_train = len(csv_train) + len(eml_train)
        combined_test = len(csv_test) + len(eml_test)
        combined_total = len(csv_records) + len(eml_records)
        combined_unique = csv_stats["uniqueRecords"] + eml_stats["uniqueRecords"]

        # Class distribution per split
        csv_train_labels: Dict[str, int] = defaultdict(int)
        for r in csv_train:
            csv_train_labels[r["normalizedLabel"]] += 1
            
        csv_test_labels: Dict[str, int] = defaultdict(int)
        for r in csv_test:
            csv_test_labels[r["normalizedLabel"]] += 1

        eml_train_labels: Dict[str, int] = defaultdict(int)
        for r in eml_train:
            eml_train_labels[r["normalizedLabel"]] += 1
            
        eml_test_labels: Dict[str, int] = defaultdict(int)
        for r in eml_test:
            eml_test_labels[r["normalizedLabel"]] += 1

        manifest = {
            "version": "1.0.0",
            "seed": self.seed,
            "strategy": "independent_source_stratified_80_20",
            "trainTargetRatio": self.train_ratio,
            "testTargetRatio": self.test_ratio,
            "sources": {
                "mix-csv": {
                    "total": csv_stats["totalRawRecords"],
                    "unique": csv_stats["uniqueRecords"],
                    "train": len(csv_train),
                    "test": len(csv_test),
                    "excluded": csv_stats["exactDuplicates"],
                    "classDistribution": {
                        "train": dict(csv_train_labels),
                        "test": dict(csv_test_labels),
                    }
                },
                "mix-eml": {
                    "total": eml_stats["totalRawRecords"],
                    "unique": eml_stats["uniqueRecords"],
                    "train": len(eml_train),
                    "test": len(eml_test),
                    "excluded": eml_stats["exactDuplicates"],
                    "classDistribution": {
                        "train": dict(eml_train_labels),
                        "test": dict(eml_test_labels),
                    }
                },
                "combined": {
                    "total": combined_total,
                    "unique": combined_unique,
                    "train": combined_train,
                    "test": combined_test,
                }
            },
            "leakageCheck": {
                "csvTrainTestOverlap": csv_stats["trainTestHashOverlap"],
                "emlTrainTestOverlap": eml_stats["trainTestHashOverlap"],
                "status": "PASS"
            }
        }

        with open(manifest_dir / "dataset_split_manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)

        logger.info(f"All split manifests written successfully to {manifest_dir}")
        return manifest
