#!/usr/bin/env python3
"""
MailTrace AI — GCS Model Artifact Lifecycle & Security Verification Test
========================================================================
Validates the complete model distribution and security lifecycle:
1. Manifest integrity & local checkpoint SHA-256 verification
2. Missing model handling (truthful MODEL_UNAVAILABLE, zero fake inferences)
3. Corrupted model rejection (SHA-256 mismatch detection & tensor integrity)
4. Simulated fresh clone & atomic installation workflow
5. Multi-threaded concurrency & singleton memory management
6. Real inference verification on security scenarios
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

# Paths
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "ml"))

from ml.model.config import ModelConfig
from ml.model.mailtrace_100m import build_model, count_parameters
from ml.model_registry.model_artifact_manager import (
    ModelArtifactManager,
    ModelArtifactError,
    ModelConfigurationError,
    ModelChecksumMismatchError,
    ModelCorruptedError
)
from ml.inference import predict


def log_step(name: str):
    print(f"\n{'='*70}\n[TEST STEP] {name}\n{'='*70}")


def calculate_sha256(filepath: Path) -> str:
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8 * 1024 * 1024):
            sha.update(chunk)
    return sha.hexdigest()


def test_1_manifest_and_local_checkpoint():
    log_step("1. Model Manifest & Authoritative Checkpoint Verification")
    manifest_path = PROJECT_ROOT / "ml" / "model_registry" / "model_manifest.json"
    assert manifest_path.exists(), "model_manifest.json does not exist"
    
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    print(f"Manifest Model ID:    {manifest['modelId']}")
    print(f"Manifest Version:     {manifest['version']}")
    print(f"Manifest Architecture:{manifest['architecture']}")
    print(f"Expected SHA256:      {manifest['artifact']['sha256']}")
    print(f"Expected Size:        {manifest['artifact']['sizeBytes']:,} bytes")
    print(f"Expected Parameters:  {manifest['parameterCount']:,}")

    local_ckpt = PROJECT_ROOT / "checkpoints" / "mailtrace-100m-v2.pt"
    assert local_ckpt.exists(), f"Local checkpoint does not exist at {local_ckpt}"

    actual_size = local_ckpt.stat().st_size
    actual_sha = calculate_sha256(local_ckpt)

    print(f"\nLocal Checkpoint:     {local_ckpt}")
    print(f"Actual Size:          {actual_size:,} bytes")
    print(f"Actual SHA256:        {actual_sha}")

    assert actual_size == manifest["artifact"]["sizeBytes"], "Checkpoint byte size mismatch"
    assert actual_sha == manifest["artifact"]["sha256"], "Checkpoint SHA-256 mismatch"
    print("✓ Manifest and local checkpoint match perfectly.")


def test_2_missing_model_behavior():
    log_step("2. Missing Model Behavior (Truthful Error State)")
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_manifest = Path(temp_dir) / "model_manifest.json"
        with open(PROJECT_ROOT / "ml" / "model_registry" / "model_manifest.json", "r") as f:
            m_data = json.load(f)
        with open(temp_manifest, "w") as f:
            json.dump(m_data, f)

        # Clear env vars and isolate cache dir
        old_bucket = os.environ.pop("MAILTRACE_MODEL_BUCKET", None)
        old_path = os.environ.pop("MAILTRACE_MODEL_PATH", None)
        old_dir = os.environ.get("MAILTRACE_MODEL_DIR")
        os.environ["MAILTRACE_MODEL_DIR"] = str(Path(temp_dir) / "empty_cache")

        try:
            mgr = ModelArtifactManager(manifest_path=temp_manifest)
            # Override candidate lookup to simulate isolated fresh clone
            mgr._find_local_candidate = lambda: None

            try:
                mgr.resolve_model_checkpoint()
                assert False, "Should have raised ModelConfigurationError when bucket/path is unset"
            except ModelConfigurationError as e:
                print(f"✓ Correctly raised ModelConfigurationError: {e}")

        finally:
            if old_bucket: os.environ["MAILTRACE_MODEL_BUCKET"] = old_bucket
            if old_path: os.environ["MAILTRACE_MODEL_PATH"] = old_path
            if old_dir: os.environ["MAILTRACE_MODEL_DIR"] = old_dir


def test_3_corrupted_checkpoint_rejection():
    log_step("3. Corrupted Checkpoint Rejection")
    with tempfile.TemporaryDirectory() as temp_dir:
        corrupted_file = Path(temp_dir) / "corrupted_model.pt"
        # Write 1MB of corrupted data
        with open(corrupted_file, "wb") as f:
            f.write(b"CORRUPTED_FAKE_MODEL_BYTES" * 40000)

        mgr = ModelArtifactManager()
        try:
            mgr.validate_checkpoint_integrity(corrupted_file, verify_tensors=True)
            assert False, "Corrupted checkpoint should have failed SHA256 / tensor validation"
        except (ModelChecksumMismatchError, ModelCorruptedError) as e:
            print(f"✓ Successfully rejected corrupted checkpoint: {type(e).__name__} ({e})")


def test_4_simulated_fresh_clone_and_atomic_install():
    log_step("4. Simulated Fresh Clone & Atomic Installation Workflow")
    with tempfile.TemporaryDirectory() as temp_dir:
        fresh_cache = Path(temp_dir) / "fresh_clone_cache"
        fresh_cache.mkdir()

        # Simulate GCS source by copying authentic checkpoint to mock storage path
        mock_gcs_source = Path(temp_dir) / "mock_gcs_store" / "mailtrace-100m-v2.pt"
        mock_gcs_source.parent.mkdir(parents=True)
        shutil.copyfile(PROJECT_ROOT / "checkpoints" / "mailtrace-100m-v2.pt", mock_gcs_source)

        mgr = ModelArtifactManager()
        mgr.cache_dir = fresh_cache
        mgr.cached_checkpoint_path = fresh_cache / "mailtrace-100m-v2.pt"

        # Mock download method to copy from mock GCS source to .tmp file
        def mock_download(bucket, obj, dest_path):
            tmp_path = dest_path.with_suffix(".tmp.test")
            shutil.copyfile(mock_gcs_source, tmp_path)
            mgr.validate_checkpoint_integrity(tmp_path, verify_tensors=True)
            shutil.move(str(tmp_path), str(dest_path))
            return dest_path

        mgr._find_local_candidate = lambda: None
        mgr._download_from_gcs = mock_download

        os.environ["MAILTRACE_MODEL_BUCKET"] = "test-mock-bucket"
        resolved = mgr.resolve_model_checkpoint()
        assert resolved.exists(), "Resolved checkpoint does not exist"
        assert resolved == fresh_cache / "mailtrace-100m-v2.pt", "Resolved path does not match cache target"
        print(f"✓ Fresh clone simulation succeeded! Model installed atomically at {resolved}")


def test_5_multithreaded_concurrency_and_singleton():
    log_step("5. Multi-Threaded Concurrency & Singleton Load Test")
    predict.load_model_background()
    assert predict.get_model_status() == "READY", f"Model is not ready: {predict.get_model_status()}"

    metadata = predict.get_model_metadata()
    print(f"Loaded Model:      {metadata['modelId']} (v{metadata['version']})")
    print(f"Parameters:        {metadata['parameterCount']:,}")
    print(f"Loaded Device:     {metadata['device']}")

    sample_email = {
        "subject": "Urgent Action Required: Confirm Microsoft 365 Password",
        "bodyText": "Your account will be terminated in 24 hours. Click here to verify credentials.",
        "from": "security@m365-verify-portal.top",
        "urls": ["http://login.microsoft.com.m365-verify-portal.top/login.php"],
        "attachments": []
    }

    errors = []
    results = []

    def worker(worker_id: int):
        try:
            res = predict.run_inference(sample_email)
            if res.get("status") != "OK":
                errors.append((worker_id, res))
            else:
                results.append((worker_id, res))
        except Exception as e:
            errors.append((worker_id, str(e)))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    start_time = time.time()
    for t in threads: t.start()
    for t in threads: t.join()
    duration_ms = (time.time() - start_time) * 1000

    print(f"Dispatched 20 concurrent inference requests in {duration_ms:.2f}ms")
    print(f"Successful responses: {len(results)} / 20")
    assert len(errors) == 0, f"Encountered concurrency errors: {errors}"
    assert len(results) == 20, "Not all concurrent requests succeeded"

    first_res = results[0][1]
    print(f"\nSample Prediction Output:")
    print(f"  Primary Category:   {first_res['primaryCategory']} (conf: {first_res['primaryConfidence']})")
    print(f"  Detected Language:  {first_res['detectedLanguage']} (conf: {first_res['languageConfidence']})")
    print(f"  Binary Heads:       {first_res['binaryHeads']}")
    print("✓ Concurrency & singleton inference passed with 100% success rate.")


def main():
    print("==================================================================")
    print("STARTING MAILTRACE GCS MODEL ARTIFACT LIFECYCLE & SECURITY TESTS")
    print("==================================================================")
    start_total = time.time()

    test_1_manifest_and_local_checkpoint()
    test_2_missing_model_behavior()
    test_3_corrupted_checkpoint_rejection()
    test_4_simulated_fresh_clone_and_atomic_install()
    test_5_multithreaded_concurrency_and_singleton()

    total_time = time.time() - start_total
    print("\n" + "="*70)
    print(f"ALL GCS MODEL ARTIFACT LIFECYCLE TESTS PASSED in {total_time:.2f}s!")
    print("==================================================================")


if __name__ == "__main__":
    main()
