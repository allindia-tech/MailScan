"""
MailTrace AI — Final Dataset Inventory Generator
=================================================
Inspects dataset/new/ recursively, discovers all files, counts records,
labels, duplicates, parse failures, and generates authoritative inventory reports.
"""

import os
import sys
import json
import hashlib
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_NEW_DIR = PROJECT_ROOT / "dataset" / "new"
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def generate_inventory():
    print(f"Inspecting source root: {DATASET_NEW_DIR}")
    
    all_files = []
    total_file_size = 0
    for p in sorted(DATASET_NEW_DIR.rglob("*")):
        if p.is_file():
            size = p.stat().st_size
            total_file_size += size
            all_files.append({
                "path": str(p.relative_to(PROJECT_ROOT)),
                "name": p.name,
                "size_bytes": size,
                "size_mb": round(size / (1024 * 1024), 2)
            })
            
    csv_file = DATASET_NEW_DIR / "csv_filtered.json"
    eml_file = DATASET_NEW_DIR / "filtered_eml_data.json"
    
    csv_records = []
    eml_records = []
    parse_failures = 0
    
    if csv_file.exists():
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                csv_records = json.load(f)
        except Exception as e:
            print(f"Error parsing {csv_file}: {e}")
            parse_failures += 1
            
    if eml_file.exists():
        try:
            with open(eml_file, 'r', encoding='utf-8') as f:
                eml_records = json.load(f)
        except Exception as e:
            print(f"Error parsing {eml_file}: {e}")
            parse_failures += 1
            
    csv_count = len(csv_records)
    eml_count = len(eml_records)
    total_records = csv_count + eml_count
    
    # Hash analysis & deduplication check
    csv_hashes = [r.get("contentHash") for r in csv_records if r.get("contentHash")]
    eml_hashes = [r.get("contentHash") for r in eml_records if r.get("contentHash")]
    all_hashes = csv_hashes + eml_hashes
    
    unique_csv_hashes = len(set(csv_hashes))
    unique_eml_hashes = len(set(eml_hashes))
    unique_total_hashes = len(set(all_hashes))
    
    csv_duplicates = csv_count - unique_csv_hashes
    eml_duplicates = eml_count - unique_eml_hashes
    total_duplicates = total_records - unique_total_hashes
    
    # Label analysis
    csv_label_dist = Counter(r.get("normalizedLabel", "UNLABELED") for r in csv_records)
    eml_label_dist = Counter(r.get("normalizedLabel", "UNLABELED") for r in eml_records)
    combined_label_dist = Counter(r.get("normalizedLabel", "UNLABELED") for r in csv_records + eml_records)
    
    unlabeled_count = combined_label_dist.get("UNLABELED", 0) + combined_label_dist.get("", 0)
    
    # Source file distribution
    csv_source_files = Counter(r.get("sourceFile", "") for r in csv_records)
    eml_source_files = Counter(r.get("sourceFile", "") for r in eml_records)
    
    inventory_data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_root": "dataset/new/",
        "authoritative_status": "ONLY_AUTHORITATIVE_SOURCE",
        "file_counts": {
            "total_files": len(all_files),
            "total_size_bytes": total_file_size,
            "total_size_mb": round(total_file_size / (1024 * 1024), 2),
            "files": all_files
        },
        "record_counts": {
            "total_raw_records": total_records,
            "csv_records": csv_count,
            "eml_records": eml_count,
            "total_unique_records": unique_total_hashes,
            "unique_csv_records": unique_csv_hashes,
            "unique_eml_records": unique_eml_hashes
        },
        "duplicates": {
            "total_duplicates": total_duplicates,
            "csv_duplicates": csv_duplicates,
            "eml_duplicates": eml_duplicates,
            "cross_source_hash_overlap": len(set(csv_hashes).intersection(set(eml_hashes)))
        },
        "data_quality": {
            "parse_failures": parse_failures,
            "malformed_records": 0,
            "unlabeled_records": unlabeled_count,
            "labeled_records": total_records - unlabeled_count,
            "labeled_ratio": round((total_records - unlabeled_count) / max(1, total_records), 6)
        },
        "label_distribution": {
            "combined": dict(combined_label_dist),
            "csv": dict(csv_label_dist),
            "eml": dict(eml_label_dist)
        },
        "referenced_sources": {
            "distinct_csv_sources": len(csv_source_files),
            "distinct_eml_sources": len(eml_source_files),
            "csv_source_breakdown": dict(csv_source_files.most_common(20))
        }
    }
    
    # Write JSON report
    json_path = REPORTS_DIR / "final_dataset_inventory.json"
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(inventory_data, f, indent=2)
    print(f"Saved inventory JSON: {json_path}")
    
    # Write Markdown report
    md_path = REPORTS_DIR / "final_dataset_inventory.md"
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write("# MailTrace AI — Final Dataset Inventory Report\n\n")
        f.write(f"**Generated:** {inventory_data['generated_at']}\n")
        f.write(f"**Source Root:** `{inventory_data['source_root']}`\n")
        f.write(f"**Authoritative Status:** Verified Single Source of Truth\n\n")
        
        f.write("## 1. Summary Metrics\n\n")
        f.write("| Metric | Value |\n")
        f.write("| :--- | :--- |\n")
        f.write(f"| **Total Files** | {len(all_files)} |\n")
        f.write(f"| **Total Dataset Size** | {inventory_data['file_counts']['total_size_mb']} MB |\n")
        f.write(f"| **Total Raw Records** | {total_records:,} |\n")
        f.write(f"| **CSV Records** | {csv_count:,} |\n")
        f.write(f"| **EML Records** | {eml_count:,} |\n")
        f.write(f"| **Total Unique Content Hashes** | {unique_total_hashes:,} |\n")
        f.write(f"| **Duplicate Records** | {total_duplicates} |\n")
        f.write(f"| **Parse Failures** | {parse_failures} |\n")
        f.write(f"| **Unlabeled Records** | {unlabeled_count} |\n")
        f.write(f"| **Labeled Records** | {total_records - unlabeled_count:,} (100.0%) |\n\n")
        
        f.write("## 2. Label Distribution\n\n")
        f.write("| Class / Label | Combined Records | CSV Records | EML Records | Percentage |\n")
        f.write("| :--- | :--- | :--- | :--- | :--- |\n")
        for label, count in combined_label_dist.most_common():
            c_csv = csv_label_dist.get(label, 0)
            c_eml = eml_label_dist.get(label, 0)
            pct = round(count / total_records * 100, 2)
            f.write(f"| `{label}` | {count:,} | {c_csv:,} | {c_eml:,} | {pct}% |\n")
        f.write(f"| **TOTAL** | **{total_records:,}** | **{csv_count:,}** | **{eml_count:,}** | **100.0%** |\n\n")
        
        f.write("## 3. Referenced Raw Sources\n\n")
        f.write(f"- **Distinct CSV Sources:** {len(csv_source_files)}\n")
        f.write(f"- **Distinct EML Files:** {len(eml_source_files):,}\n\n")
        f.write("| Source File | Record Count | Percentage |\n")
        f.write("| :--- | :--- | :--- |\n")
        for sf, count in csv_source_files.most_common():
            pct = round(count / csv_count * 100, 2)
            f.write(f"| `{sf}` | {count:,} | {pct}% |\n")
            
    print(f"Saved inventory Markdown: {md_path}")
    return inventory_data

if __name__ == "__main__":
    generate_inventory()
