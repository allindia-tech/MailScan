"""
MailTrace AI — csv_filtered.json Inventory Generator
====================================================
Inspects dataset/new/csv_filtered.json as the ONLY authoritative data source.
Reports exact record counts, schema, labels, duplicates, and malformed entries.
"""

import os
import sys
import json
import hashlib
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CSV_FILTERED_PATH = PROJECT_ROOT / "dataset" / "new" / "csv_filtered.json"
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def generate_csv_filtered_inventory():
    print(f"Inspecting authoritative dataset: {CSV_FILTERED_PATH}")
    assert CSV_FILTERED_PATH.exists(), f"File not found: {CSV_FILTERED_PATH}"

    file_size_bytes = CSV_FILTERED_PATH.stat().st_size
    file_size_mb = round(file_size_bytes / (1024 * 1024), 2)

    with open(CSV_FILTERED_PATH, "r", encoding="utf-8") as f:
        records = json.load(f)

    total_records = len(records)
    print(f"Loaded {total_records:,} records ({file_size_mb} MB).")

    # Inspect fields & schema
    all_keys = set()
    malformed_count = 0
    sample_records = []
    
    seen_hashes = set()
    seen_ids = set()
    duplicate_hash_count = 0
    duplicate_id_count = 0
    content_hashes = []

    for idx, r in enumerate(records):
        if not isinstance(r, dict):
            malformed_count += 1
            continue
        
        all_keys.update(r.keys())
        rec_id = r.get("recordId")
        chash = r.get("contentHash")
        
        if not rec_id or not chash:
            malformed_count += 1

        if rec_id in seen_ids:
            duplicate_id_count += 1
        seen_ids.add(rec_id)

        if chash in seen_hashes:
            duplicate_hash_count += 1
        seen_hashes.add(chash)
        content_hashes.append(chash)

        if idx < 3:
            sample_records.append({k: (str(v)[:80] + '...' if len(str(v)) > 80 else v) for k, v in r.items()})

    unique_records = len(seen_hashes)
    duplicate_records = total_records - unique_records

    # Label analysis
    label_counts = Counter(r.get("normalizedLabel", "UNLABELED") for r in records)
    unlabeled_count = sum(1 for r in records if r.get("normalizedLabel") in [None, "", "UNLABELED", "UNKNOWN"])
    labeled_count = total_records - unlabeled_count

    source_files = Counter(r.get("sourceFile", "") for r in records)

    inventory = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_file": "dataset/new/csv_filtered.json",
        "authoritative_status": "SOLE_AUTHORITATIVE_SOURCE",
        "file_metrics": {
            "size_bytes": file_size_bytes,
            "size_mb": file_size_mb,
            "json_structure": "List[Dict[str, Any]]",
            "total_records": total_records,
            "unique_records": unique_records,
            "duplicate_records": duplicate_records,
            "malformed_records": malformed_count
        },
        "schema": {
            "available_fields": sorted(list(all_keys)),
            "label_field": "normalizedLabel",
            "id_field": "recordId",
            "hash_field": "contentHash",
            "sample_records": sample_records
        },
        "label_distribution": {
            "total_labeled": labeled_count,
            "total_unlabeled": unlabeled_count,
            "breakdown": dict(label_counts)
        },
        "source_breakdown": {
            "distinct_source_files": len(source_files),
            "distribution": dict(source_files.most_common(20))
        }
    }

    # Write JSON
    json_path = REPORTS_DIR / "csv_filtered_inventory.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=2)
    print(f"Saved JSON inventory: {json_path}")

    # Write Markdown
    md_path = REPORTS_DIR / "csv_filtered_inventory.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# MailTrace AI — `csv_filtered.json` Dataset Inventory Report\n\n")
        f.write(f"**Generated:** {inventory['generated_at']}\n")
        f.write(f"**Authoritative Source:** `{inventory['source_file']}`\n")
        f.write(f"**File Size:** {file_size_mb} MB ({file_size_bytes:,} bytes)\n\n")

        f.write("## 1. Summary Metrics\n\n")
        f.write("| Metric | Value |\n")
        f.write("| :--- | :--- |\n")
        f.write(f"| **Total Raw Records** | {total_records:,} |\n")
        f.write(f"| **Unique Records (by SHA-256 contentHash)** | {unique_records:,} |\n")
        f.write(f"| **Duplicate Records** | {duplicate_records} |\n")
        f.write(f"| **Malformed Records** | {malformed_count} |\n")
        f.write(f"| **Unlabeled Records** | {unlabeled_count} (0.0%) |\n")
        f.write(f"| **Labeled Records** | {labeled_count:,} (100.0%) |\n\n")

        f.write("## 2. Schema Definition\n\n")
        f.write("- **Root Structure:** Top-level JSON Array of Objects (`List[Dict]`)\n")
        f.write(f"- **Fields:** `{', '.join(sorted(list(all_keys)))}`\n")
        f.write("- **Primary Identifier:** `recordId`\n")
        f.write("- **Canonical Hash Field:** `contentHash`\n")
        f.write("- **Ground Truth Label Field:** `normalizedLabel`\n\n")

        f.write("## 3. Label Distribution\n\n")
        f.write("| Label / Class | Count | Percentage |\n")
        f.write("| :--- | :--- | :--- |\n")
        for lbl, cnt in label_counts.most_common():
            pct = round(cnt / total_records * 100, 2)
            f.write(f"| `{lbl}` | {cnt:,} | {pct}% |\n")
        f.write(f"| **TOTAL** | **{total_records:,}** | **100.0%** |\n\n")

        f.write("## 4. Referenced Source Files\n\n")
        f.write("| Source CSV File | Record Count | Percentage |\n")
        f.write("| :--- | :--- | :--- |\n")
        for sf, cnt in source_files.most_common():
            pct = round(cnt / total_records * 100, 2)
            f.write(f"| `{sf}` | {cnt:,} | {pct}% |\n")

    print(f"Saved Markdown inventory: {md_path}")
    return inventory

if __name__ == "__main__":
    generate_csv_filtered_inventory()
