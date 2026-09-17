#!/usr/bin/env bash
# ==============================================================================
# MailTrace AI — Production Google Cloud Deployment Script
# ==============================================================================
# Deploys the container to Cloud Run and verifies health & model readiness.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROJECT_ID="${GCP_PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="${GCP_SERVICE_NAME:-mailtrace-ai}"
REPOSITORY="${GCP_REPOSITORY:-mailtrace-registry}"
BUCKET_NAME="${MAILTRACE_MODEL_BUCKET:-${PROJECT_ID}-mailtrace-models}"
MODEL_OBJECT="${MAILTRACE_MODEL_OBJECT:-models/mailtrace-100m-v2/mailtrace-100m-v2.pt}"

if [[ -z "${PROJECT_ID}" || "${PROJECT_ID}" == "(unset)" ]]; then
  echo "ERROR: Google Cloud Project ID is not set." >&2
  echo "Set it with: gcloud config set project <PROJECT_ID> or export GCP_PROJECT_ID=<PROJECT_ID>" >&2
  exit 1
fi

echo "============================================================"
echo "MailTrace AI — Google Cloud Production Deployment"
echo "============================================================"
echo "Project ID:       ${PROJECT_ID}"
echo "Region:           ${REGION}"
echo "Cloud Run Service:${SERVICE_NAME}"
echo "Artifact Registry:${REPOSITORY}"
echo "Model GCS Bucket: ${BUCKET_NAME}"
echo "Model GCS Object: ${MODEL_OBJECT}"
echo "============================================================"

# 1. Enable Required GCP APIs
echo ""
echo "[1/6] Enabling Required Google Cloud APIs..."
gcloud services enable \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  storage.googleapis.com \
  logging.googleapis.com \
  --project="${PROJECT_ID}"

# 2. Ensure Artifact Registry Repository Exists
echo ""
echo "[2/6] Ensuring Artifact Registry Repository Exists..."
if ! gcloud artifacts repositories describe "${REPOSITORY}" --location="${REGION}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "Creating Docker repository '${REPOSITORY}' in ${REGION}..."
  gcloud artifacts repositories create "${REPOSITORY}" \
    --repository-format=docker \
    --location="${REGION}" \
    --description="MailTrace AI Container Images" \
    --project="${PROJECT_ID}"
fi

# 3. Ensure GCS Bucket Exists & Upload Model If Needed
echo ""
echo "[3/6] Checking Model Artifact in Google Cloud Storage..."
if ! gcloud storage buckets describe "gs://${BUCKET_NAME}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
  echo "Creating storage bucket 'gs://${BUCKET_NAME}' in ${REGION}..."
  gcloud storage buckets create "gs://${BUCKET_NAME}" \
    --location="${REGION}" \
    --project="${PROJECT_ID}" \
    --uniform-bucket-level-access
fi

if ! gcloud storage stat "gs://${BUCKET_NAME}/${MODEL_OBJECT}" >/dev/null 2>&1; then
  echo "Model artifact not found at gs://${BUCKET_NAME}/${MODEL_OBJECT}."
  LOCAL_CKPT="${PROJECT_ROOT}/checkpoints/mailtrace-100m-v2.pt"
  if [[ -f "${LOCAL_CKPT}" ]]; then
    echo "Uploading local checkpoint ${LOCAL_CKPT}..."
    "${SCRIPT_DIR}/upload-model-to-gcs.sh" "${BUCKET_NAME}" "${LOCAL_CKPT}"
  else
    echo "WARNING: Local checkpoint not found. Ensure the model artifact exists in GCS before serving traffic."
  fi
else
  echo "Verified: GCS Model artifact exists at gs://${BUCKET_NAME}/${MODEL_OBJECT}"
fi

# 4. Build and Push Container via Cloud Build
IMAGE_TAG="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/mailtrace-ai:$(git rev-parse --short HEAD 2>/dev/null || echo 'latest')"
LATEST_TAG="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}/mailtrace-ai:latest"

echo ""
echo "[4/6] Building and pushing container image via Cloud Build..."
gcloud builds submit "${PROJECT_ROOT}" \
  --tag="${IMAGE_TAG}" \
  --project="${PROJECT_ID}"

# 5. Deploy to Cloud Run
echo ""
echo "[5/6] Deploying Service to Google Cloud Run..."
gcloud run deploy "${SERVICE_NAME}" \
  --image="${IMAGE_TAG}" \
  --region="${REGION}" \
  --platform="managed" \
  --allow-unauthenticated \
  --memory="4Gi" \
  --cpu="2" \
  --concurrency="80" \
  --timeout="300" \
  --set-env-vars="NODE_ENV=production,MAILTRACE_MODEL_BUCKET=${BUCKET_NAME},MAILTRACE_MODEL_OBJECT=${MODEL_OBJECT},MAILTRACE_MODEL_VERSION=100m-v2,MAILTRACE_MODEL_DIR=/tmp/mailtrace-model" \
  --project="${PROJECT_ID}"

# 6. Verification and Health Check
echo ""
echo "[6/6] Verifying Cloud Run Deployment Health..."
SERVICE_URL="$(gcloud run services describe "${SERVICE_NAME}" --region="${REGION}" --project="${PROJECT_ID}" --format='value(status.url)')"
echo "Service URL: ${SERVICE_URL}"

echo "Testing Process Health Endpoint: ${SERVICE_URL}/health"
curl -fsS "${SERVICE_URL}/health" || echo "Health check returned non-200"

echo ""
echo "Testing Model Status Endpoint: ${SERVICE_URL}/api/model/status"
curl -fsS "${SERVICE_URL}/api/model/status" || echo "Model status returned non-200"

echo ""
echo "============================================================"
echo "DEPLOYMENT COMPLETED SUCCESSFULLY"
echo "============================================================"
echo "URL: ${SERVICE_URL}"
