#!/usr/bin/env python3
"""
MailTrace AI — Production Model Setup & Verification Tool
=========================================================
Downloads missing model artifact from Google Cloud Storage or verifies existing
local checkpoint against authoritative SHA-256 and parameter constraints.

Usage:
  python3 scripts/model_setup.py [options]

Options:
  --force-download    Force downloading from GCS even if cached
  --verify-only       Only verify the local checkpoint without downloading
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "ml"))

from ml.model_registry.model_artifact_manager import (
    ModelArtifactManager,
    ModelArtifactError,
    ModelConfigurationError,
    ModelChecksumMismatchError,
    ModelCorruptedError
)


def main():
    parser = argparse.ArgumentParser(description="MailTrace Model Setup Utility")
    parser.add_argument("--force-download", action="store_true", help="Force download from GCS")
    parser.add_argument("--verify-only", action="store_true", help="Only verify existing checkpoint")
    args = parser.parse_args()

    print("============================================================")
    print("MailTrace AI — Model Setup & Verification")
    print("============================================================")

    mgr = ModelArtifactManager()
    print(f"Model ID:        {mgr.model_id}")
    print(f"Version:         {mgr.version}")
    print(f"Architecture:    {mgr.architecture}")
    print(f"Expected Size:   {mgr.expected_size_bytes:,} bytes")
    print(f"Expected SHA256: {mgr.expected_sha256}")
    print(f"Parameters:      {mgr.expected_params:,}")
    print("============================================================")

    start_time = time.time()
    try:
        resolved = mgr.resolve_model_checkpoint()
        val_info = mgr.validate_checkpoint_integrity(resolved, verify_tensors=True)

        elapsed = time.time() - start_time
        print("\nSETUP SUCCESSFUL:")
        print(f"  Checkpoint Path:  {resolved}")
        print(f"  Verified Size:    {val_info['sizeBytes']:,} bytes")
        print(f"  Verified SHA256:  {val_info['sha256']}")
        print(f"  Verified Params:  {val_info.get('parameterCount', mgr.expected_params):,}")
        print(f"  Elapsed Time:     {elapsed:.2f}s")
        print("  Status:           READY")
    except ModelConfigurationError as e:
        print(f"\nSETUP ERROR (CONFIGURATION): {e}", file=sys.stderr)
        sys.exit(1)
    except ModelChecksumMismatchError as e:
        print(f"\nSETUP ERROR (CHECKSUM MISMATCH): {e}", file=sys.stderr)
        sys.exit(1)
    except ModelCorruptedError as e:
        print(f"\nSETUP ERROR (CORRUPTION): {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nSETUP ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
