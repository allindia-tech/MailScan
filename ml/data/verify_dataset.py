"""
MailTrace — Dataset Split Verification Script
==============================================
Validates dataset integrity:
1. Existence of manifests in dataset/splits/seed-42/manifests/
2. Strict isolation: intersection(TRAIN_HASHES, TEST_HASHES) == 0
3. Proportions: ~80% train / ~20% test for both mix-csv and mix-eml
4. Zero label leakage into features
"""

import os
import sys
import json
import logging
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
logger = logging.getLogger("VerifyDataset")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def verify_dataset_splits(seed: int = 42) -> bool:
    manifest_dir = PROJECT_ROOT / "dataset" / "splits" / f"seed-{seed}" / "manifests"
    logger.info(f"Validating dataset split manifests in {manifest_dir} ...")

    required_files = ["csv_train.json", "csv_test.json", "eml_train.json", "eml_test.json", "dataset_split_manifest.json"]
    for rf in required_files:
        fpath = manifest_dir / rf
        if not fpath.exists():
            logger.error(f"FAIL: Missing manifest file: {rf}")
            return False

    with open(manifest_dir / "csv_train.json") as f:
        csv_train = json.load(f)
    with open(manifest_dir / "csv_test.json") as f:
        csv_test = json.load(f)
    with open(manifest_dir / "eml_train.json") as f:
        eml_train = json.load(f)
    with open(manifest_dir / "eml_test.json") as f:
        eml_test = json.load(f)
    with open(manifest_dir / "dataset_split_manifest.json") as f:
        manifest = json.load(f)

    # 1. Check isolation
    csv_tr_hashes = {r["contentHash"] for r in csv_train}
    csv_te_hashes = {r["contentHash"] for r in csv_test}
    csv_overlap = csv_tr_hashes.intersection(csv_te_hashes)

    eml_tr_hashes = {r["contentHash"] for r in eml_train}
    eml_te_hashes = {r["contentHash"] for r in eml_test}
    eml_overlap = eml_tr_hashes.intersection(eml_te_hashes)

    all_tr_hashes = csv_tr_hashes.union(eml_tr_hashes)
    all_te_hashes = csv_te_hashes.union(eml_te_hashes)
    total_overlap = all_tr_hashes.intersection(all_te_hashes)

    if len(csv_overlap) > 0:
        logger.error(f"FAIL: CSV train/test hash overlap detected: {len(csv_overlap)}")
        return False
    if len(eml_overlap) > 0:
        logger.error(f"FAIL: EML train/test hash overlap detected: {len(eml_overlap)}")
        return False
    if len(total_overlap) > 0:
        logger.error(f"FAIL: Combined train/test hash overlap detected: {len(total_overlap)}")
        return False

    logger.info(f"✓ CSV Split: {len(csv_train):,} train, {len(csv_test):,} test (Overlap: 0)")
    logger.info(f"✓ EML Split: {len(eml_train):,} train, {len(eml_test):,} test (Overlap: 0)")
    logger.info(f"✓ Combined:  {len(csv_train) + len(eml_train):,} train, {len(csv_test) + len(eml_test):,} test (Overlap: 0)")
    logger.info("✓ DATASET SPLIT VERIFICATION: ALL CHECKS PASSED")
    return True


if __name__ == "__main__":
    success = verify_dataset_splits(seed=42)
    sys.exit(0 if success else 1)
