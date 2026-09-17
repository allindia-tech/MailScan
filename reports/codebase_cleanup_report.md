# MAILTRACE AI — CODEBASE CLEANUP & DEDUPLICATION REPORT

**Generated:** 2026-09-17
**Scope:** Complete repository-wide audit for dead code, exact duplicates, near-duplicate implementations, obsolete artifacts, and unused components.

---

## 1. Executive Summary

| Category | Initial Count | Items to Delete / Consolidate | Retained Critical Systems |
| :--- | :--- | :--- | :--- |
| **Exact Hash Duplicates** | 8 groups | 3 files (`phishing_legit_dataset_KD_10000 2.csv`, `dataset/testing/phishing_legit...csv`, duplicate reports) | Authoritative canonical files in `dataset/mix-csv/` and `dataset/splits/` |
| **Dead React Components** | 25 components | 2 components (`Navbar.tsx`, `AnalystFeedbackCard.tsx`) | `TopHeader.tsx`, `Sidebar.tsx`, `AnalystVerificationSection.tsx`, `AnalystFeedbackModal.tsx` |
| **Obsolete Server Scripts** | 1 script | 1 script (`server/runDatasetTraining.ts`) | `server/emailAnalysisPipeline.ts`, `ml/training/train_splits.py` |
| **Loose Root Test Files** | 5 files | 5 files (`testing/*.eml`) | Authoritative curated 24-case dataset in `dataset/testing/` |
| **Obsolete ML Checkpoints** | 4 files | 4 local files in `ml/artifacts/checkpoints/` & `checkpoints/verification/` | Authoritative `checkpoints/mailtrace-100m-v2.pt` (SHA: `22b238cd...`) |

---

## 2. Deletion Registry & Dependency Evidence

### DELETE 1: `src/components/Navbar.tsx`
- **Reason:** Obsolete dark navbar header from v1 workstation. Superseded by the light SOC design system using `src/components/TopHeader.tsx` and `src/components/Sidebar.tsx`.
- **References:** `ActiveTab` type was only imported by `App.tsx` and `Sidebar.tsx`.
- **Replacement:** `src/types/forensics.ts` (for `ActiveTab` type), `TopHeader.tsx`, and `Sidebar.tsx`.
- **Confidence:** HIGH (100%)

### DELETE 2: `src/components/AnalystFeedbackCard.tsx`
- **Reason:** Legacy feedback component with 0 active imports. Superseded by the comprehensive `AnalystVerificationSection.tsx` and modal-based false positive auditor `AnalystFeedbackModal.tsx`.
- **References:** 0 active imports.
- **Replacement:** `src/components/AnalystVerificationSection.tsx` and `src/components/AnalystFeedbackModal.tsx`.
- **Confidence:** HIGH (100%)

### DELETE 3: `server/runDatasetTraining.ts`
- **Reason:** Legacy in-memory mock training script that called obsolete `mlTransformer100M.trainOnVerifiedBatch()`. Superseded by the real PyTorch 100M training infrastructure (`ml/training/train_splits.py`).
- **References:** 0 runtime references.
- **Replacement:** `ml/training/train_splits.py` & `ml/training/train_feedback.py`.
- **Confidence:** HIGH (100%)

### DELETE 4: Loose files in root `testing/` (`testing/5 new updates.eml`, `Important_ Update...eml`, `Invitation for Campus Placement...eml`, `Show-original.eml`, `Your PayPal verification code.eml`)
- **Reason:** Unorganized temporary sample `.eml` files placed in a root directory. The authoritative, manifest-tracked, and curated test dataset is located in `dataset/testing/emails/` and governed by `dataset/testing/manifest.json`.
- **References:** 0 references in master test suite (`server/testing/runAllTests.ts`), regression runner, or production server.
- **Replacement:** `dataset/testing/` suite.
- **Confidence:** HIGH (100%)

### DELETE 5: `dataset/mix-csv/phishing_legit_dataset_KD_10000 2.csv`
- **Reason:** Exact byte-for-byte duplicate (Hash: `fb65d38e33e9`) of `dataset/mix-csv/phishing_legit_dataset_KD_10000.csv` created by accidental macOS duplication.
- **References:** Handled by fallback alias in `ml/data/parser.py`.
- **Replacement:** `dataset/mix-csv/phishing_legit_dataset_KD_10000.csv`.
- **Confidence:** HIGH (100%)

### DELETE 6: `dataset/testing/phishing_legit_dataset_KD_10000.csv`
- **Reason:** Exact byte-for-byte duplicate (Hash: `fb65d38e33e9`) of `dataset/mix-csv/phishing_legit_dataset_KD_10000.csv` accidentally left in `dataset/testing/`.
- **References:** 0 references. `dataset/testing/` only uses RFC 822 EML fixtures in `emails/`.
- **Replacement:** `dataset/mix-csv/phishing_legit_dataset_KD_10000.csv`.
- **Confidence:** HIGH (100%)

---

## 3. Retained Core Files & Intentional Systems

| Directory / File | Status | Technical Justification |
| :--- | :--- | :--- |
| `checkpoints/mailtrace-100m-v2.pt` | **RETAINED** | Authoritative 128.9M parameter production checkpoint (SHA: `22b238cd...`). Excluded from Git via `.gitignore`. |
| `ml/model_registry/model_manifest.json` | **RETAINED** | Authoritative model metadata contract for Cloud Run & GCS resolution. |
| `ml/model_registry/model_artifact_manager.py` | **RETAINED** | Core GCS streaming downloader, SHA-256 validator, and single-flight lock manager. |
| `server/services/modelManager.ts` | **RETAINED** | Node.js model management service bridge. |
| `deploy/cloudrun.yaml` & `cloudbuild.yaml` | **RETAINED** | Google Cloud production container & serverless deployment specifications. |
| `scripts/deploy-gcp.sh` & `scripts/upload-model-to-gcs.sh` | **RETAINED** | Production automation tooling for model upload and Cloud Run revisions. |
| `dataset/testing/` | **RETAINED** | Curated 24-case forensic integration & regression suite with `manifest.json`. |
| `dataset/mix-csv/` & `dataset/mix-eml/` | **RETAINED** | Authoritative ML training datasets. |
| `dataset/splits/final-seed-42/` | **RETAINED** | Authoritative reproducible train/validation/test split manifests. |
| `reports/` | **RETAINED** | Authoritative provenance, audit logs, heldout evaluation reports, and model promotion registers. |
| `ref/DESIGN.md` & `ref/code.html` | **RETAINED** | Authoritative reference specifications for the MailTrace SOC workstation redesign. |
