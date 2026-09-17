"""
MailTrace AI — Final Deterministic 80/20 Dataset Splitter (Seed 42)
===================================================================
Creates authoritative deterministic 80/20 Train/Test splits from dataset/new/
Rules:
- Seed: 42
- Deduplicate before splitting using SHA-256 contentHash.
- Train: 80% (212,476 records)
- Test: 20% (53,119 records)
- Overlap between train and test hashes: Exactly 0.
- Outputs manifests & split reports to dataset/splits/final-seed-42/ and reports/.
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
DATASET_NEW_DIR = PROJECT_ROOT / "dataset" / "new"
SPLITS_DIR = PROJECT_ROOT / "dataset" / "splits" / "final-seed-42"
MANIFESTS_DIR = SPLITS_DIR / "manifests"
SPLIT_REPORTS_DIR = SPLITS_DIR / "reports"
GLOBAL_REPORTS_DIR = PROJECT_ROOT / "reports"

MANIFESTS_DIR.mkdir(parents=True, exist_ok=True)
SPLIT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
GLOBAL_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

SEED = 42
TRAIN_RATIO = 0.80

def compute_sha256(content: str) -> str:
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def create_splits():
    print(f"Loading authoritative data from {DATASET_NEW_DIR}...")
    
    with open(DATASET_NEW_DIR / "csv_filtered.json", "r", encoding="utf-8") as f:
        csv_records = json.load(f)
        
    with open(DATASET_NEW_DIR / "filtered_eml_data.json", "r", encoding="utf-8") as f:
        eml_records = json.load(f)
        
    print(f"Loaded {len(csv_records):,} CSV records and {len(eml_records):,} EML records.")
    
    all_raw_records = csv_records + eml_records
    
    # 1. Deduplication by canonical contentHash
    seen_hashes = set()
    deduped_records = []
    duplicate_count = 0
    
    for r in all_raw_records:
        h = r.get("contentHash")
        if not h:
            # compute canonical hash if missing
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
    
    # Sort deterministically by contentHash before shuffling to guarantee total platform-independence
    deduped_records.sort(key=lambda x: x["contentHash"])
    
    # Shuffle with fixed deterministic seed
    rng = random.Random(SEED)
    indices = list(range(total_unique))
    rng.shuffle(indices)
    
    # Exact 80/20 boundary
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
    
    # 2. Split integrity verifications
    train_hashes = {r["sha256"] for r in train_records}
    test_hashes = {r["sha256"] for r in test_records}
    overlap = train_hashes.intersection(test_hashes)
    
    assert len(overlap) == 0, f"FATAL: Train/Test hash overlap detected: {len(overlap)} hashes!"
    assert len(train_records) == train_count, f"Train count mismatch: {len(train_records)} != {train_count}"
    assert len(test_records) == test_count, f"Test count mismatch: {len(test_records)} != {test_count}"
    
    print(f"VERIFIED: Train/Test hash overlap = {len(overlap)} (Zero Overlap Guaranteed).")
    
    # 3. Write manifests
    train_manifest_path = MANIFESTS_DIR / "train.json"
    test_manifest_path = MANIFESTS_DIR / "test.json"
    full_manifest_path = MANIFESTS_DIR / "dataset_split_manifest.json"
    
    print(f"Writing {train_manifest_path}...")
    with open(train_manifest_path, "w", encoding="utf-8") as f:
        json.dump(train_records, f, indent=2)
        
    print(f"Writing {test_manifest_path}...")
    with open(test_manifest_path, "w", encoding="utf-8") as f:
        json.dump(test_records, f, indent=2)
        
    all_manifest_records = train_records + test_records
    print(f"Writing {full_manifest_path}...")
    with open(full_manifest_path, "w", encoding="utf-8") as f:
        json.dump(all_manifest_records, f, indent=2)
        
    # Checksums
    train_file_hash = compute_sha256(open(train_manifest_path, 'r', encoding='utf-8').read())
    test_file_hash = compute_sha256(open(test_manifest_path, 'r', encoding='utf-8').read())
    full_file_hash = compute_sha256(open(full_manifest_path, 'r', encoding='utf-8').read())
    
    # Label distributions
    train_labels = Counter(r["label"] for r in train_records)
    test_labels = Counter(r["label"] for r in test_records)
    train_sources = Counter(r["sourceType"] for r in train_records)
    test_sources = Counter(r["sourceType"] for r in test_records)
    
    split_report_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "source_dataset": "dataset/new/",
        "total_source_records": len(all_raw_records),
        "total_unique_records": total_unique,
        "duplicates_removed": duplicate_count,
        "split_ratio": {"train": TRAIN_RATIO, "test": round(1 - TRAIN_RATIO, 2)},
        "counts": {
            "train_count": len(train_records),
            "test_count": len(test_records),
            "total_split_records": len(train_records) + len(test_records),
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
            "dataset_split_manifest_sha256": full_file_hash
        },
        "label_distribution": {
            "train": dict(train_labels),
            "test": dict(test_labels)
        },
        "source_distribution": {
            "train": dict(train_sources),
            "test": dict(test_sources)
        }
    }
    
    # Save reports in both locations
    for target_dir in [SPLIT_REPORTS_DIR, GLOBAL_REPORTS_DIR]:
        json_report_path = target_dir / "final_dataset_split_report.json"
        with open(json_report_path, "w", encoding="utf-8") as f:
            json.dump(split_report_data, f, indent=2)
            
        md_report_path = target_dir / "final_dataset_split_report.md"
        with open(md_report_path, "w", encoding="utf-8") as f:
            f.write("# MailTrace AI — Final Dataset Split Report (Seed 42)\n\n")
            f.write(f"**Generated:** {split_report_data['generated_at']}\n")
            f.write(f"**Authoritative Source:** `{split_report_data['source_dataset']}`\n")
            f.write(f"**Deterministic Seed:** `{SEED}`\n\n")
            
            f.write("## 1. Split Metrics\n\n")
            f.write("| Metric | Value |\n")
            f.write("| :--- | :--- |\n")
            f.write(f"| **Total Unique Records** | {total_unique:,} |\n")
            f.write(f"| **Training Records (80%)** | {len(train_records):,} ({split_report_data['counts']['train_percentage']}%) |\n")
            f.write(f"| **Testing Records (20%)** | {len(test_records):,} ({split_report_data['counts']['test_percentage']}%) |\n")
            f.write(f"| **Train/Test Hash Overlap** | **{len(overlap)} (0% Overlap)** |\n")
            f.write(f"| **Deduplicated Duplicates** | {duplicate_count} |\n\n")
            
            f.write("## 2. Manifest Checksums (SHA-256)\n\n")
            f.write(f"- `train.json`: `{train_file_hash}`\n")
            f.write(f"- `test.json`: `{test_file_hash}`\n")
            f.write(f"- `dataset_split_manifest.json`: `{full_file_hash}`\n\n")
            
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
                
    print(f"Split reports successfully written.")
    return split_report_data

if __name__ == "__main__":
    create_splits()
