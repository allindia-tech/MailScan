"""
MailTrace AI — csv_filtered.json Deterministic 80/20 Dataset Splitter (Seed 42)
================================================================================
Creates authoritative deterministic 80/20 Train/Test splits from dataset/new/csv_filtered.json
Rules:
- Authoritative Source: dataset/new/csv_filtered.json ONLY
- Seed: 42
- Deduplicate before splitting using SHA-256 contentHash.
- Train: 80% (206,912 records)
- Test: 20% (51,728 records)
- Overlap between train and test hashes: Exactly 0.
- Outputs manifests to dataset/splits/csv-filtered-seed-42/manifests/
"""

import os
import sys
import json
import random
import hashlib
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CSV_FILTERED_PATH = PROJECT_ROOT / "dataset" / "new" / "csv_filtered.json"
SPLITS_DIR = PROJECT_ROOT / "dataset" / "splits" / "csv-filtered-seed-42"
MANIFESTS_DIR = SPLITS_DIR / "manifests"
REPORTS_DIR = PROJECT_ROOT / "reports"

MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

SEED = 42
TRAIN_RATIO = 0.80

def compute_sha256(content: str) -> str:
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def create_splits():
    print(f"Loading authoritative data from {CSV_FILTERED_PATH}...")
    with open(CSV_FILTERED_PATH, "r", encoding="utf-8") as f:
        records = json.load(f)

    total_raw = len(records)
    print(f"Loaded {total_raw:,} raw records.")

    # 1. Deduplication by canonical contentHash
    seen_hashes = set()
    deduped_records = []
    duplicate_count = 0

    for r in records:
        h = r.get("contentHash")
        if not h:
            text = f"{r.get('subject', '')} {r.get('sender', '')} {r.get('sourceFile', '')} {r.get('sourceRecordId', '')}"
            h = compute_sha256(text)
            r["contentHash"] = h

        if h in seen_hashes:
            duplicate_count += 1
            continue

        seen_hashes.add(h)
        deduped_records.append(r)

    total_unique = len(deduped_records)
    print(f"Deduplication complete: {total_unique:,} unique records ({duplicate_count} duplicates removed).")

    # Sort deterministically before shuffle
    deduped_records.sort(key=lambda x: x["contentHash"])

    # Shuffle with fixed seed 42
    rng = random.Random(SEED)
    indices = list(range(total_unique))
    rng.shuffle(indices)

    train_count = int(round(total_unique * TRAIN_RATIO))
    test_count = total_unique - train_count

    train_indices = set(indices[:train_count])
    test_indices = set(indices[train_count:])

    train_records = []
    test_records = []

    for idx, rec in enumerate(deduped_records):
        norm_label = rec.get("normalizedLabel", "UNLABELED")
        split_name = "train" if idx in train_indices else "test"

        manifest_entry = {
            "recordId": rec.get("recordId", ""),
            "sourceFile": rec.get("sourceFile", ""),
            "sourceType": rec.get("sourceType", "mix-csv"),
            "sourceRecordId": rec.get("sourceRecordId", ""),
            "sha256": rec.get("contentHash", ""),
            "contentHash": rec.get("contentHash", ""),
            "label": norm_label,
            "normalizedLabel": norm_label,
            "split": split_name,
            "subject": rec.get("subject", ""),
            "sender": rec.get("sender", ""),
            "campaignGroup": rec.get("campaignGroup", ""),
            "exclusionReason": rec.get("exclusionReason", "")
        }

        if split_name == "train":
            train_records.append(manifest_entry)
        else:
            test_records.append(manifest_entry)

    print(f"Split created: {len(train_records):,} Train ({len(train_records)/total_unique*100:.2f}%), {len(test_records):,} Test ({len(test_records)/total_unique*100:.2f}%)")

    # 2. Integrity verifications
    train_hashes = {r["sha256"] for r in train_records}
    test_hashes = {r["sha256"] for r in test_records}
    overlap = train_hashes.intersection(test_hashes)

    assert len(overlap) == 0, f"FATAL: Train/Test hash overlap: {len(overlap)}"
    assert len(train_records) == train_count, f"Train count mismatch: {len(train_records)} != {train_count}"
    assert len(test_records) == test_count, f"Test count mismatch: {len(test_records)} != {test_count}"

    print(f"VERIFIED: Train/Test hash overlap = 0 (Zero Overlap Guaranteed).")

    # 3. Write manifests
    train_manifest_path = MANIFESTS_DIR / "train.json"
    test_manifest_path = MANIFESTS_DIR / "test.json"
    split_manifest_path = MANIFESTS_DIR / "split_manifest.json"

    print(f"Writing {train_manifest_path}...")
    with open(train_manifest_path, "w", encoding="utf-8") as f:
        json.dump(train_records, f, indent=2)

    print(f"Writing {test_manifest_path}...")
    with open(test_manifest_path, "w", encoding="utf-8") as f:
        json.dump(test_records, f, indent=2)

    all_manifest = train_records + test_records
    print(f"Writing {split_manifest_path}...")
    with open(split_manifest_path, "w", encoding="utf-8") as f:
        json.dump(all_manifest, f, indent=2)

    # Hashes of manifest files
    train_file_hash = compute_sha256(open(train_manifest_path, "r", encoding="utf-8").read())
    test_file_hash = compute_sha256(open(test_manifest_path, "r", encoding="utf-8").read())
    split_file_hash = compute_sha256(open(split_manifest_path, "r", encoding="utf-8").read())

    train_labels = Counter(r["label"] for r in train_records)
    test_labels = Counter(r["label"] for r in test_records)

    split_report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "source_dataset": "dataset/new/csv_filtered.json",
        "total_source_records": total_raw,
        "total_unique_records": total_unique,
        "duplicates_removed": duplicate_count,
        "counts": {
            "train_count": len(train_records),
            "test_count": len(test_records),
            "total_split_records": len(all_manifest),
            "train_percentage": round(len(train_records) / total_unique * 100, 4),
            "test_percentage": round(len(test_records) / total_unique * 100, 4)
        },
        "integrity": {
            "unique_train_hashes": len(train_hashes),
            "unique_test_hashes": len(test_hashes),
            "train_test_hash_overlap": len(overlap),
            "hash_overlap_verified_zero": (len(overlap) == 0)
        },
        "checksums": {
            "train_manifest_sha256": train_file_hash,
            "test_manifest_sha256": test_file_hash,
            "split_manifest_sha256": split_file_hash
        },
        "label_distribution": {
            "train": dict(train_labels),
            "test": dict(test_labels)
        }
    }

    json_report_path = REPORTS_DIR / "csv_filtered_split_report.json"
    with open(json_report_path, "w", encoding="utf-8") as f:
        json.dump(split_report, f, indent=2)

    md_report_path = REPORTS_DIR / "csv_filtered_split_report.md"
    with open(md_report_path, "w", encoding="utf-8") as f:
        f.write("# MailTrace AI — `csv_filtered.json` Dataset Split Report (Seed 42)\n\n")
        f.write(f"**Generated:** {split_report['generated_at']}\n")
        f.write(f"**Authoritative Source:** `{split_report['source_dataset']}`\n")
        f.write(f"**Deterministic Seed:** `{SEED}`\n\n")

        f.write("## 1. Split Metrics\n\n")
        f.write("| Metric | Value |\n")
        f.write("| :--- | :--- |\n")
        f.write(f"| **Total Unique Records** | {total_unique:,} |\n")
        f.write(f"| **Training Records (80%)** | {len(train_records):,} ({split_report['counts']['train_percentage']}%) |\n")
        f.write(f"| **Testing Records (20%)** | {len(test_records):,} ({split_report['counts']['test_percentage']}%) |\n")
        f.write(f"| **Train/Test Hash Overlap** | **{len(overlap)} (0% Overlap Guaranteed)** |\n")
        f.write(f"| **Duplicates Removed** | {duplicate_count} |\n\n")

        f.write("## 2. Manifest Checksums (SHA-256)\n\n")
        f.write(f"- `train.json`: `{train_file_hash}`\n")
        f.write(f"- `test.json`: `{test_file_hash}`\n")
        f.write(f"- `split_manifest.json`: `{split_file_hash}`\n\n")

        f.write("## 3. Label Breakdown Across Splits\n\n")
        f.write("| Label | Train Count | Train % | Test Count | Test % |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")
        all_classes = sorted(list(set(train_labels.keys()) | set(test_labels.keys())))
        for c in all_classes:
            tr_c = train_labels.get(c, 0)
            te_c = test_labels.get(c, 0)
            tr_p = round(tr_c / len(train_records) * 100, 2)
            te_p = round(te_c / len(test_records) * 100, 2)
            f.write(f"| `{c}` | {tr_c:,} | {tr_p}% | {te_c:,} | {te_p}% |\n")

    print(f"Saved split reports to {json_report_path} and {md_report_path}")
    return split_report

if __name__ == "__main__":
    create_splits()
