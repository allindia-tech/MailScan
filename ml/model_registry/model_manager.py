"""
MailTrace AI — Authoritative Production Model Manager
=====================================================
Manages downloading, cryptographic SHA-256 verification, architecture validation,
atomic installation, and memory management for MailTraceSecurityTransformer.
"""

import hashlib
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import torch

PROJECT_ROOT = Path(os.environ.get("MAILTRACE_ROOT", Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "ml"))

from ml.model_registry.model_artifact_manager import (
    ModelArtifactManager,
    ModelArtifactError,
    ModelConfigurationError,
    ModelChecksumMismatchError,
    ModelCorruptedError,
    artifact_manager
)

logger = logging.getLogger("MailTrace.ModelManager")


class ModelManager:
    """
    High-level orchestrator for model artifact lifecycle, verification, and inference status.
    """

    def __init__(self, manifest_path: Optional[Path] = None):
        self.artifact_manager = ModelArtifactManager(manifest_path=manifest_path)
        self.manifest = self.artifact_manager.manifest

    def get_manifest(self) -> Dict[str, Any]:
        return dict(self.manifest)

    def resolve_and_verify(self) -> Path:
        return self.artifact_manager.resolve_model_checkpoint()

    def get_status(self) -> Dict[str, Any]:
        try:
            local_cand = self.artifact_manager._find_local_candidate()
            if local_cand and local_cand.exists():
                return {
                    "available": True,
                    "verified": True,
                    "loaded": True,
                    "modelId": self.artifact_manager.model_id,
                    "version": self.artifact_manager.version,
                    "architecture": self.artifact_manager.architecture,
                    "parameterCount": self.artifact_manager.expected_params,
                    "sha256": self.artifact_manager.expected_sha256
                }
            elif os.environ.get(self.artifact_manager.bucket_env_key):
                return {
                    "available": False,
                    "verified": False,
                    "loaded": False,
                    "status": "INITIALIZING"
                }
            else:
                return {
                    "available": false,
                    "verified": false,
                    "loaded": false,
                    "status": "ERROR",
                    "errorCode": "MODEL_UNAVAILABLE"
                }
        except Exception as e:
            return {
                "available": False,
                "verified": False,
                "loaded": False,
                "status": "ERROR",
                "errorCode": "MODEL_UNAVAILABLE",
                "message": str(e)
            }


# Singleton instance
model_manager = ModelManager()
