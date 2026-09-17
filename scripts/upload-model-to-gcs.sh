#!/usr/bin/env bash
# ==============================================================================
# MailTrace AI — Production Model GCS Upload Script
# ==============================================================================
# Usage:
#   ./scripts/upload-model-to-gcs.sh [BUCKET_NAME] [CHECKPOINT_PATH]
#
# Environment variables:
#   MAILTRACE_MODEL_BUCKET  - Name of the Google Cloud Storage bucket
#   MAILTRACE_MODEL_OBJECT  - Object path (default: models/mailtrace-100m-v2/mailtrace-100m-v2.pt)
#   MAILTRACE_MODEL_PATH    - Local path to checkpoint (default: checkpoints/mailtrace-100m-v2.pt)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BUCKET="${1:-${MAILTRACE_MODEL_BUCKET:-}}"
CHECKPOINT="${2:-${MAILTRACE_MODEL_PATH:-${PROJECT_ROOT}/checkpoints/mailtrace-100m-v2.pt}}"
OBJECT="${MAILTRACE_MODEL_OBJECT:-models/mailtrace-100m-v2/mailtrace-100m-v2.pt}"

echo "============================================================"
echo "MailTrace Model Artifact Upload"
echo "============================================================"
echo "Model:             MailTraceSecurityTransformer"
echo "Version:           100m-v2"
echo "Parameters:        128,894,258"
echo "Local checkpoint:  ${CHECKPOINT}"

if [[ ! -f "${CHECKPOINT}" ]]; then
  echo "ERROR: Local checkpoint file does not exist at ${CHECKPOINT}" >&2
  exit 1
fi

if [[ -z "${BUCKET}" ]]; then
  echo ""
  echo "ERROR: GCS bucket name is required." >&2
  echo "Usage: $0 <BUCKET_NAME> [CHECKPOINT_PATH]" >&2
  echo "Or set MAILTRACE_MODEL_BUCKET environment variable." >&2
  echo ""
  echo "Example:" >&2
  echo "  $0 my-project-mailtrace-models" >&2
  exit 1
fi

# Run python validator & upload utility
python3 "${SCRIPT_DIR}/upload_model_to_gcs.py" \
  --checkpoint "${CHECKPOINT}" \
  --bucket "${BUCKET}" \
  --object "${OBJECT}" \
  --update-manifest
