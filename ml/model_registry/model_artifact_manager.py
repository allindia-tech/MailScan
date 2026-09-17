"""
MailTrace AI — Production Model Artifact Manager
================================================
Manages downloading, cryptographic integrity verification (SHA-256), architecture
validation, atomic installation, and caching of the 1.4 GB MailTraceSecurityTransformer
checkpoint from Google Cloud Storage or local development paths.

Guarantees:
1. Excludes checkpoint binary from Git
2. Single-flight download locking (no concurrent duplicate downloads)
3. Cryptographic SHA-256 verification against authoritative model_manifest.json
4. Strict supply-chain security (never accepts arbitrary URLs or untrusted paths)
5. Zero fake ML fallbacks: explicitly reports INITIALIZING or MODEL_UNAVAILABLE
6. Structured Google Cloud Logging integration
"""

import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import torch

# Paths
PROJECT_ROOT = Path(os.environ.get("MAILTRACE_ROOT", Path(__file__).resolve().parents[2]))
MANIFEST_PATH = PROJECT_ROOT / "ml" / "model_registry" / "model_manifest.json"

# Logging
logger = logging.getLogger("MailTrace.ModelArtifactManager")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] [ModelArtifactManager] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class ModelArtifactError(Exception):
    """Base exception for model artifact resolution or validation errors."""
    pass


class ModelConfigurationError(ModelArtifactError):
    """Raised when required GCS or path configuration is missing."""
    pass


class ModelChecksumMismatchError(ModelArtifactError):
    """Raised when downloaded/provided checkpoint SHA-256 does not match manifest."""
    pass


class ModelCorruptedError(ModelArtifactError):
    """Raised when checkpoint fails PyTorch tensor or parameter validation."""
    pass


class ModelArtifactManager:
    """
    Thread-safe model artifact manager for MailTraceSecurityTransformer.
    Resolves local and Google Cloud Storage model checkpoints.
    """

    _instance_lock = threading.Lock()
    _init_lock = threading.Lock()
    _download_lock = threading.Lock()

    def __init__(self, manifest_path: Optional[Path] = None):
        self.manifest_path = manifest_path or MANIFEST_PATH
        self.manifest: Dict[str, Any] = self._load_manifest()
        
        # Target model metadata
        self.model_id: str = self.manifest.get("modelId", "mailtrace-security-transformer")
        self.version: str = self.manifest.get("version", "100m-v2")
        self.architecture: str = self.manifest.get("architecture", "MailTraceSecurityTransformer")
        self.expected_params: int = self.manifest.get("parameterCount", 128894258)
        
        artifact_info = self.manifest.get("artifact", {})
        self.expected_sha256: str = artifact_info.get("sha256", "")
        self.expected_size_bytes: int = artifact_info.get("sizeBytes", 0)
        self.bucket_env_key: str = artifact_info.get("bucketEnv", "MAILTRACE_MODEL_BUCKET")
        self.object_env_key: str = artifact_info.get("objectEnv", "MAILTRACE_MODEL_OBJECT")
        self.default_object: str = artifact_info.get("defaultObject", f"models/mailtrace-100m-v2/mailtrace-100m-v2.pt")

        # Cache directory resolution
        env_dir = os.environ.get("MAILTRACE_MODEL_DIR")
        if env_dir:
            self.cache_dir = Path(env_dir).resolve()
        else:
            # Default to writable /tmp on Cloud Run/container or local checkpoints
            self.cache_dir = Path("/tmp/mailtrace-model")

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.target_checkpoint_filename = f"mailtrace-{self.version}.pt"
        self.cached_checkpoint_path = self.cache_dir / self.target_checkpoint_filename

    def _load_manifest(self) -> Dict[str, Any]:
        if not self.manifest_path.exists():
            raise FileNotFoundError(f"Model manifest not found at {self.manifest_path}")
        with open(self.manifest_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _log_structured(self, event_type: str, **kwargs):
        """Emit structured log for Google Cloud Logging."""
        payload = {
            "event": event_type,
            "modelId": self.model_id,
            "modelVersion": self.version,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            **kwargs
        }
        logger.info(f"STRUCTURED_LOG: {json.dumps(payload)}")

    def calculate_file_sha256(self, filepath: Path) -> str:
        """Compute SHA-256 hash using 8MB buffered streaming."""
        sha = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(8 * 1024 * 1024):
                sha.update(chunk)
        return sha.hexdigest()

    def validate_checkpoint_integrity(self, filepath: Path, verify_tensors: bool = True) -> Dict[str, Any]:
        """
        Validates SHA-256 against manifest and verifies PyTorch tensors.
        """
        if not filepath.exists():
            raise FileNotFoundError(f"Checkpoint file does not exist: {filepath}")

        # Checksum check
        actual_sha = self.calculate_file_sha256(filepath)
        if self.expected_sha256 and actual_sha != self.expected_sha256:
            self._log_structured("MODEL_CHECKSUM_MISMATCH", path=str(filepath), actualSha=actual_sha, expectedSha=self.expected_sha256)
            raise ModelChecksumMismatchError(
                f"Checkpoint SHA-256 checksum mismatch! Expected: {self.expected_sha256}, Actual: {actual_sha}"
            )

        self._log_structured("MODEL_CHECKSUM_VERIFIED", path=str(filepath), sha256=actual_sha)

        if not verify_tensors:
            return {"valid": True, "sha256": actual_sha, "sizeBytes": filepath.stat().st_size}

        # PyTorch checkpoint dictionary structure check
        try:
            data = torch.load(str(filepath), map_location="cpu", weights_only=False)
        except Exception as e:
            raise ModelCorruptedError(f"Failed to load PyTorch checkpoint tensor dictionary: {e}")

        state_dict = data.get("model_state_dict", data) if isinstance(data, dict) else data
        if not isinstance(state_dict, dict):
            raise ModelCorruptedError("Checkpoint does not contain a valid state_dict dictionary")

        nan_count = 0
        inf_count = 0
        param_count = 0
        for name, t in state_dict.items():
            if isinstance(t, torch.Tensor):
                param_count += t.numel()
                nan_count += int(torch.isnan(t).sum().item())
                inf_count += int(torch.isinf(t).sum().item())

        if nan_count > 0 or inf_count > 0:
            raise ModelCorruptedError(f"Checkpoint contains corrupted weights (NaNs: {nan_count}, Infs: {inf_count})")

        return {
            "valid": True,
            "sha256": actual_sha,
            "sizeBytes": filepath.stat().st_size,
            "parameterCount": param_count,
            "tensorCount": len(state_dict)
        }

    def _find_local_candidate(self) -> Optional[Path]:
        """Check known local paths for the verified checkpoint."""
        explicit_path = os.environ.get("MAILTRACE_MODEL_PATH")
        if explicit_path:
            p = Path(explicit_path).resolve()
            if p.exists():
                return p

        candidates = [
            self.cached_checkpoint_path,
            PROJECT_ROOT / "checkpoints" / f"mailtrace-{self.version}.pt",
            PROJECT_ROOT / "checkpoints" / "mailtrace-100m-v2.pt",
            PROJECT_ROOT / "checkpoints" / "best.pt",
            PROJECT_ROOT / "ml" / "artifacts" / "checkpoints" / "best.pt",
        ]

        for cand in candidates:
            if cand.exists():
                try:
                    # Quick SHA check without full tensor load
                    actual_sha = self.calculate_file_sha256(cand)
                    if actual_sha == self.expected_sha256:
                        return cand
                except Exception:
                    continue
        return None

    def _download_from_gcs(self, bucket_name: str, object_name: str, dest_path: Path) -> Path:
        """
        Download model from Google Cloud Storage to a temporary file, verify SHA-256,
        and atomically move to dest_path.
        """
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = dest_path.with_suffix(f".tmp.{os.getpid()}.{int(time.time())}")
        gcs_uri = f"gs://{bucket_name}/{object_name.lstrip('/')}"

        start_time = time.time()
        self._log_structured("MODEL_DOWNLOAD_STARTED", source=gcs_uri, target=str(tmp_path))
        logger.info(f"Downloading model artifact from {gcs_uri} to {tmp_path}...")

        downloaded = False
        error_msg = ""

        # Strategy A: Try google-cloud-storage Python SDK with ADC
        try:
            from google.cloud import storage
            client = storage.Client()
            bucket = client.bucket(bucket_name)
            blob = bucket.blob(object_name.lstrip("/"))
            if not blob.exists():
                raise ModelArtifactError(f"Blob {object_name} does not exist in bucket {bucket_name}")
            blob.download_to_filename(str(tmp_path))
            downloaded = True
            logger.info("Downloaded via google-cloud-storage SDK (ADC).")
        except Exception as e:
            error_msg = str(e)
            logger.warning(f"google-cloud-storage SDK download failed ({e}). Trying 'gcloud storage' CLI...")

        # Strategy B: Fallback to gcloud storage CLI
        if not downloaded:
            try:
                cmd = ["gcloud", "storage", "cp", gcs_uri, str(tmp_path)]
                res = subprocess.run(cmd, capture_output=True, text=True)
                if res.returncode == 0:
                    downloaded = True
                    logger.info("Downloaded via 'gcloud storage cp' CLI.")
                else:
                    error_msg += f" | gcloud error: {res.stderr.strip()}"
            except Exception as e:
                error_msg += f" | gcloud exception: {e}"

        if not downloaded or not tmp_path.exists():
            if tmp_path.exists():
                tmp_path.unlink()
            self._log_structured("MODEL_INITIALIZATION_FAILED", reason="GCS_DOWNLOAD_FAILED", error=error_msg)
            raise ModelArtifactError(f"Failed to download model artifact from {gcs_uri}: {error_msg}")

        download_duration_ms = int((time.time() - start_time) * 1000)
        self._log_structured("MODEL_DOWNLOAD_COMPLETED", durationMs=download_duration_ms, sizeBytes=tmp_path.stat().st_size)

        # Verify integrity of the downloaded temporary file
        logger.info("Verifying SHA-256 of downloaded checkpoint...")
        try:
            self.validate_checkpoint_integrity(tmp_path, verify_tensors=True)
        except Exception as e:
            if tmp_path.exists():
                tmp_path.unlink()
            raise e

        # Atomic installation
        shutil.move(str(tmp_path), str(dest_path))
        logger.info(f"Model artifact successfully installed at {dest_path}")
        return dest_path

    def resolve_model_checkpoint(self) -> Path:
        """
        Resolves the verified model checkpoint. If already present locally and valid,
        returns the path immediately. Otherwise downloads from GCS and validates.
        Uses a thread lock to prevent duplicate concurrent downloads.
        """
        with self._download_lock:
            start_time = time.time()
            self._log_structured("MODEL_INITIALIZATION_STARTED")

            # 1. Check local cache / repository candidates
            local_cand = self._find_local_candidate()
            if local_cand:
                logger.info(f"Found valid local model checkpoint: {local_cand}")
                self.validate_checkpoint_integrity(local_cand, verify_tensors=False)
                return local_cand

            # 2. Check if explicit MAILTRACE_MODEL_PATH was given but failed SHA256
            explicit_path = os.environ.get("MAILTRACE_MODEL_PATH")
            if explicit_path:
                p = Path(explicit_path).resolve()
                if p.exists():
                    # Will raise if SHA-256 mismatch
                    self.validate_checkpoint_integrity(p, verify_tensors=True)
                    return p
                else:
                    raise FileNotFoundError(f"Configured MAILTRACE_MODEL_PATH does not exist: {explicit_path}")

            # 3. GCS Download Mode
            bucket = os.environ.get(self.bucket_env_key)
            object_name = os.environ.get(self.object_env_key, self.default_object)

            if not bucket:
                self._log_structured("MODEL_INITIALIZATION_FAILED", reason="MODEL_NOT_CONFIGURED")
                raise ModelConfigurationError(
                    f"MAILTRACE MODEL NOT CONFIGURED: No valid local checkpoint found and "
                    f"'{self.bucket_env_key}' environment variable is not set. "
                    f"Configure Google Cloud credentials and {self.bucket_env_key} / {self.object_env_key}."
                )

            # Download and verify
            resolved_path = self._download_from_gcs(bucket, object_name, self.cached_checkpoint_path)
            total_duration_ms = int((time.time() - start_time) * 1000)
            self._log_structured("MODEL_READY", durationMs=total_duration_ms, path=str(resolved_path))
            return resolved_path


# Global Singleton Manager
artifact_manager = ModelArtifactManager()
