"""
MailTrace — Authoritative Dataset Inventory & Multi-Source Parser
=================================================================
Discovers and normalizes ALL files from:
  1. dataset/mix-csv/ (Universal CSV schema detection & normalization)
  2. dataset/mix-eml/ (RFC 822/5322 & MIME EML email stream parsing)

Rules:
- NO fabricated record counts. Every count is computed from actual files.
- NO synthetic metadata or invented headers. If a field is absent, it is None/unavailable.
- Deterministic canonical SHA-256 IDs for every record.
- Preserves complete provenance (sourceFile, sourceRecordId, sourceType).
"""

import os
import re
import sys
import csv
import json
import email
import hashlib
import logging
from pathlib import Path
from email import policy
from dataclasses import dataclass, field, asdict
from typing import Dict, Generator, List, Optional, Tuple, Any, Set
from datetime import datetime, timezone

# Increase CSV field size limit — email bodies can be very large
csv.field_size_limit(sys.maxsize)

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Label Normalization Map
# ──────────────────────────────────────────────────────────────────────────────
LABEL_MAP: Dict[str, str] = {
    # Binary spam indicators
    "0": "LEGITIMATE",
    "1": "SPAM",
    "0.0": "LEGITIMATE",
    "1.0": "SPAM",
    "ham": "LEGITIMATE",
    "Ham": "LEGITIMATE",
    "HAM": "LEGITIMATE",
    "spam": "SPAM",
    "Spam": "SPAM",
    "SPAM": "SPAM",
    "Spam Email": "SPAM",
    "Safe Email": "LEGITIMATE",
    "Phishing Email": "PHISHING",
    
    # Phishing & Malware
    "phishing": "PHISHING",
    "Phishing": "PHISHING",
    "PHISHING": "PHISHING",
    "Legitimate": "LEGITIMATE",
    "legitimate": "LEGITIMATE",
    "LEGITIMATE": "LEGITIMATE",
    "benign": "LEGITIMATE",
    "Benign": "LEGITIMATE",
    "BENIGN": "LEGITIMATE",
    "malware": "MALWARE_DELIVERY",
    "MALWARE": "MALWARE_DELIVERY",
    "ransomware": "MALWARE_DELIVERY",
    "fraud": "FINANCIAL_FRAUD",
    "FRAUD": "FINANCIAL_FRAUD",
    "scam": "ADVANCE_FEE_SCAM",
    "social_engineering": "PHISHING",
    "SPAM_BULK": "SPAM",
    "CREDENTIAL_THEFT": "CREDENTIAL_THEFT",
    "credential_theft": "CREDENTIAL_THEFT",
    "BEC": "BUSINESS_EMAIL_COMPROMISE",
    "bec": "BUSINESS_EMAIL_COMPROMISE",
}

def normalize_label(raw_label: Any, source_file: str = "") -> Tuple[str, float]:
    """
    Returns (normalizedLabel, labelConfidence).
    If the label cannot be mapped or is empty, returns ("UNLABELED", 0.0) or ("OTHER_MALICIOUS", 0.5).
    """
    if raw_label is None:
        return "UNLABELED", 0.0
    raw = str(raw_label).strip()
    if not raw:
        return "UNLABELED", 0.0
        
    mapped = LABEL_MAP.get(raw)
    if mapped:
        return mapped, 1.0
        
    lower = raw.lower()
    for k, v in LABEL_MAP.items():
        if k.lower() == lower:
            return v, 0.95
            
    if "phish" in lower:
        return "PHISHING", 0.9
    if "spam" in lower:
        return "SPAM", 0.9
    if "ham" in lower or "legit" in lower or "safe" in lower or "clean" in lower:
        return "LEGITIMATE", 0.9
    if "malware" in lower or "virus" in lower:
        return "MALWARE_DELIVERY", 0.9
    if "fraud" in lower:
        return "FINANCIAL_FRAUD", 0.9

    return "OTHER_MALICIOUS", 0.5


# ──────────────────────────────────────────────────────────────────────────────
# Canonical Email Record
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class CanonicalEmailRecord:
    recordId: str
    sourceFile: str
    sourceRecordId: str
    sourceType: str = "mix-csv"   # "mix-csv" | "mix-eml"

    sender: str = ""
    receiver: str = ""
    date: str = ""
    subject: str = ""

    bodyText: str = ""
    bodyHtml: str = ""

    urls: List[str] = field(default_factory=list)
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)

    originalLabel: str = ""
    normalizedLabel: str = "UNLABELED"
    labelSource: str = ""
    labelConfidence: float = 0.0

    phishingType: str = ""
    severity: str = ""
    confidence: float = 0.0

    structuredFeatures: Dict[str, float] = field(default_factory=dict)
    language: str = "UNKNOWN"
    contentHash: str = ""

    def get_canonical_text(self) -> str:
        """Constructs canonical text string for hashing and deduplication."""
        subj = (self.subject or "").strip().lower()
        sender = (self.sender or "").strip().lower()
        body = (self.bodyText or "").strip().lower()
        if not body and self.bodyHtml:
            body = re.sub(r"<[^>]+>", " ", self.bodyHtml).strip().lower()
        return f"subj:{subj}\nfrom:{sender}\nbody:{body}"


# ──────────────────────────────────────────────────────────────────────────────
# File Manifest Entry
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class FileManifestEntry:
    file: str
    filePath: str
    type: str            # "CSV" | "EML" | "JSON" | "SQLITE" | "UNSUPPORTED"
    sourceType: str      # "mix-csv" | "mix-eml"
    status: str          # "CANONICAL" | "DUPLICATE_FILE" | "DERIVED_FEATURE_DATA" | "METADATA_TABLE" | "UNSUPPORTED"
    sizeBytes: int
    rawRecords: int
    uniqueRecords: int
    trainRecords: int
    validationRecords: int
    testRecords: int
    excludedRecords: int
    exclusionReason: str
    fields: List[str]
    sha256: str
    md5: str
    format: str

    def to_dict(self) -> dict:
        return asdict(self)


# ──────────────────────────────────────────────────────────────────────────────
# Inventory Constants & Helper Functions
# ──────────────────────────────────────────────────────────────────────────────
DERIVED_SUFFIX = "_vectorized_data.csv"
UNSUPPORTED_FILES = {".DS_Store"}

KNOWN_DUPLICATES: Dict[str, str] = {
    "CEAS_08.csv": "CEAS-08.csv",
    "full_dataset.json": "full_dataset.csv",
    "phishing_legit_dataset_KD_10000 2.csv": "phishing_legit_dataset_KD_10000.csv",
    "enronThread2001.csv": "enronClean.csv",
}

METADATA_TABLES = {
    "Aliases.csv", "EmailReceivers.csv", "EnronEmployeeInformation.csv",
    "FinalAdjacencyMatrix.csv", "Persons.csv", "Sentiments_employees.csv",
    "enron_org.csv", "enron_sentiments.csv", "temp2001.csv", "data.csv",
    "database.sqlite", "clintongraph.json", "hashes.txt"
}

def sha256_file(path: str, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

def md5_file(path: str, chunk_size: int = 8 * 1024 * 1024) -> str:
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""

def count_csv_rows(path: str) -> Tuple[int, List[str]]:
    count = 0
    fields: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if header:
                fields = header
            for _ in reader:
                count += 1
    except Exception as e:
        logger.warning(f"Could not count rows in {path}: {e}")
    return count, fields


# ──────────────────────────────────────────────────────────────────────────────
# Universal CSV Parser & Dynamic Schema Resolver
# ──────────────────────────────────────────────────────────────────────────────
class UniversalCsvParser:
    """
    Dynamically identifies column roles from any CSV header without assuming static layout.
    """
    
    @staticmethod
    def identify_column_mapping(columns: List[str]) -> Dict[str, Optional[str]]:
        col_lower = {c.strip().lower(): c for c in columns if c}
        mapping: Dict[str, Optional[str]] = {
            "subject": None,
            "body": None,
            "sender": None,
            "receiver": None,
            "date": None,
            "label": None,
            "urls": None,
            "id": None,
            "phishing_type": None,
            "severity": None,
            "confidence": None,
        }
        
        # Subject candidates
        for cand in ["subject", "metadatasubject", "extractedsubject", "title", "subj"]:
            if cand in col_lower:
                mapping["subject"] = col_lower[cand]
                break
                
        # Body / text candidates
        for cand in ["body", "text", "email text", "extractedbodytext", "rawtext", "content", "message"]:
            if cand in col_lower:
                mapping["body"] = col_lower[cand]
                break
                
        # Sender candidates
        for cand in ["sender", "from", "metadatafrom", "extractedfrom", "from_address", "senderpersonid"]:
            if cand in col_lower:
                mapping["sender"] = col_lower[cand]
                break
                
        # Receiver candidates
        for cand in ["receiver", "to", "metadatato", "extractedto", "recipient", "to_address"]:
            if cand in col_lower:
                mapping["receiver"] = col_lower[cand]
                break
                
        # Date candidates
        for cand in ["date", "timestamp", "metadatadatesent", "extracteddatesent", "time", "datetime"]:
            if cand in col_lower:
                mapping["date"] = col_lower[cand]
                break
                
        # Label candidates
        for cand in ["label", "class", "category", "category_id", "spam", "email type", "is_malicious", "threat"]:
            if cand in col_lower:
                mapping["label"] = col_lower[cand]
                break
                
        # URLs candidates
        for cand in ["urls", "url", "links", "link"]:
            if cand in col_lower:
                mapping["urls"] = col_lower[cand]
                break
                
        # ID candidates
        for cand in ["id", "email_id", "tid", "mid", "docnumber"]:
            if cand in col_lower:
                mapping["id"] = col_lower[cand]
                break
                
        if "phishing_type" in col_lower:
            mapping["phishing_type"] = col_lower["phishing_type"]
        if "severity" in col_lower:
            mapping["severity"] = col_lower["severity"]
        if "confidence" in col_lower:
            mapping["confidence"] = col_lower["confidence"]
            
        return mapping


def stream_csv_records(file_path: str) -> Generator[CanonicalEmailRecord, None, None]:
    name = os.path.basename(file_path)
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            return
            
        mapping = UniversalCsvParser.identify_column_mapping(reader.fieldnames)
        
        for idx, row in enumerate(reader):
            if not row:
                continue
            subj = str(row.get(mapping["subject"] or "", "") or "") if mapping["subject"] else ""
            body = str(row.get(mapping["body"] or "", "") or "") if mapping["body"] else ""
            sender = str(row.get(mapping["sender"] or "", "") or "") if mapping["sender"] else ""
            receiver = str(row.get(mapping["receiver"] or "", "") or "") if mapping["receiver"] else ""
            date_val = str(row.get(mapping["date"] or "", "") or "") if mapping["date"] else ""
            raw_label = row.get(mapping["label"] or "", "") if mapping["label"] else ""
            
            # Special case for emails copy.csv: if label is not explicitly mapped, check 'spam'
            if not raw_label and "spam" in row:
                raw_label = row["spam"]
            # Special case for fraud_email_: check 'Class'
            if not raw_label and "Class" in row:
                raw_label = row["Class"]
                
            raw_label_str = str(raw_label) if raw_label is not None else ""
            norm_label, label_conf = normalize_label(raw_label_str, name)
            
            # Extract URLs
            urls = []
            if mapping["urls"] and row.get(mapping["urls"]):
                raw_u = str(row[mapping["urls"]] or "")
                urls = [u.strip() for u in raw_u.split(",") if u.strip()]
            else:
                # Basic URL regex from body
                extracted = re.findall(r"https?://[^\s<>\"']+", body)
                urls = extracted[:20]

            record_id = f"csv_{hashlib.sha256(f'{name}_{idx}_{subj}_{body[:100]}'.encode('utf-8', errors='replace')).hexdigest()[:16]}"
            
            p_type = str(row.get(mapping["phishing_type"] or "", "") or "") if mapping["phishing_type"] else ""
            sev = str(row.get(mapping["severity"] or "", "") or "") if mapping["severity"] else ""
            try:
                conf = float(row.get(mapping["confidence"] or 0, 0)) if mapping["confidence"] else 0.0
            except (ValueError, TypeError):
                conf = 0.0

            rec = CanonicalEmailRecord(
                recordId=record_id,
                sourceFile=name,
                sourceRecordId=str(idx),
                sourceType="mix-csv",
                sender=sender,
                receiver=receiver,
                date=date_val,
                subject=subj,
                bodyText=body,
                urls=urls,
                originalLabel=raw_label_str,
                normalizedLabel=norm_label,
                labelSource=name,
                labelConfidence=label_conf,
                phishingType=p_type,
                severity=sev,
                confidence=conf,
            )
            rec.contentHash = hashlib.sha256(rec.get_canonical_text().encode('utf-8', errors='replace')).hexdigest()
            yield rec


# ──────────────────────────────────────────────────────────────────────────────
# Streaming RFC 822/5322 & MIME EML Parser
# ──────────────────────────────────────────────────────────────────────────────
def parse_single_eml(file_path: str) -> Optional[CanonicalEmailRecord]:
    """
    Parses an RFC 822/5322 / MIME EML file.
    Extracts only authentic, present information (zero fabrication).
    """
    name = os.path.basename(file_path)
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
            msg = email.message_from_bytes(raw_bytes, policy=policy.default)
    except Exception as e:
        logger.debug(f"Malformed EML {name}: {e}")
        return None

    headers: Dict[str, str] = {}
    for k, v in msg.items():
        if k:
            headers[k.lower()] = str(v)

    subject = str(msg.get("Subject") or "")
    sender = str(msg.get("From") or "")
    receiver = str(msg.get("To") or "")
    date_val = str(msg.get("Date") or "")

    # Extract body text and HTML
    body_text = ""
    body_html = ""
    attachments: List[Dict[str, Any]] = []

    try:
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition") or "")
                filename = part.get_filename()

                if filename or "attachment" in content_disposition:
                    payload = part.get_payload(decode=True)
                    size = len(payload) if payload else 0
                    attachments.append({
                        "filename": filename or "unknown_attachment",
                        "contentType": content_type,
                        "sizeBytes": size,
                    })
                elif content_type == "text/plain" and not body_text:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        body_text = payload.decode(charset, errors="replace") if payload else ""
                    except Exception:
                        pass
                elif content_type == "text/html" and not body_html:
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or "utf-8"
                        body_html = payload.decode(charset, errors="replace") if payload else ""
                    except Exception:
                        pass
        else:
            content_type = msg.get_content_type()
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace") if payload else str(msg.get_payload())
            if content_type == "text/html":
                body_html = content
            else:
                body_text = content
    except Exception as e:
        logger.debug(f"Error extracting parts from {name}: {e}")

    # URLs from body or HTML
    urls = []
    search_text = body_text + " " + body_html
    extracted_urls = re.findall(r"https?://[^\s<>\"']+", search_text)
    urls = list(set(extracted_urls))[:20]

    # Check for labels in X-headers (zero fabrication)
    raw_label = ""
    for lk in ["x-spam-flag", "x-spam-status", "x-mailtrace-label", "x-spam", "x-virus-status"]:
        if lk in headers:
            v = headers[lk]
            if "yes" in v.lower() or "spam" in v.lower() or "positive" in v.lower():
                raw_label = "SPAM"
                break
            elif "no" in v.lower() or "clean" in v.lower() or "negative" in v.lower() or "not detected" in v.lower():
                raw_label = "LEGITIMATE"
                break

    norm_label, label_conf = normalize_label(raw_label, name) if raw_label else ("UNLABELED", 0.0)

    # Deterministic record ID based on file content sha256
    file_sha = hashlib.sha256(raw_bytes).hexdigest()
    record_id = f"eml_{file_sha[:16]}"

    rec = CanonicalEmailRecord(
        recordId=record_id,
        sourceFile=name,
        sourceRecordId=name,
        sourceType="mix-eml",
        sender=sender,
        receiver=receiver,
        date=date_val,
        subject=subject,
        bodyText=body_text,
        bodyHtml=body_html,
        urls=urls,
        attachments=attachments,
        headers=headers,
        originalLabel=raw_label,
        normalizedLabel=norm_label,
        labelSource="x-header" if raw_label else "unlabeled",
        labelConfidence=label_conf,
    )
    rec.contentHash = hashlib.sha256(rec.get_canonical_text().encode('utf-8', errors='replace')).hexdigest()
    return rec


# ──────────────────────────────────────────────────────────────────────────────
# Comprehensive Multi-Source Dataset Inventory Scanner
# ──────────────────────────────────────────────────────────────────────────────
class DatasetInventory:
    """
    Discovers all files in dataset/mix-csv/ and dataset/mix-eml/ independently.
    Produces complete manifests with exact measured counts.
    """

    def __init__(self, dataset_dir: str):
        self.dataset_dir = Path(dataset_dir)
        self.mix_csv_dir = self.dataset_dir / "mix-csv"
        self.mix_eml_dir = self.dataset_dir / "mix-eml"
        self.csv_entries: List[FileManifestEntry] = []
        self.eml_entries: List[FileManifestEntry] = []

    def scan_mix_csv(self) -> List[FileManifestEntry]:
        self.csv_entries = []
        if not self.mix_csv_dir.exists():
            logger.warning(f"{self.mix_csv_dir} does not exist.")
            return []

        all_files = sorted(self.mix_csv_dir.glob("**/*"))
        for fp in all_files:
            if not fp.is_file() or fp.name in UNSUPPORTED_FILES:
                continue

            name = fp.name
            size = fp.stat().st_size
            sha = sha256_file(str(fp))
            md5 = md5_file(str(fp))
            ext = fp.suffix.lower()

            if ext != ".csv":
                status = "METADATA_TABLE" if name in METADATA_TABLES else "UNSUPPORTED"
                self.csv_entries.append(FileManifestEntry(
                    file=name, filePath=str(fp), type="NON_CSV", sourceType="mix-csv",
                    status=status, sizeBytes=size, rawRecords=0, uniqueRecords=0,
                    trainRecords=0, validationRecords=0, testRecords=0, excludedRecords=0,
                    exclusionReason="Non-CSV format metadata / graph / database",
                    fields=[], sha256=sha, md5=md5, format="non_csv"
                ))
                continue

            # Check if derived or known duplicate
            if name.endswith(DERIVED_SUFFIX):
                raw_rows, fields = count_csv_rows(str(fp))
                self.csv_entries.append(FileManifestEntry(
                    file=name, filePath=str(fp), type="CSV", sourceType="mix-csv",
                    status="DERIVED_FEATURE_DATA", sizeBytes=size, rawRecords=raw_rows, uniqueRecords=0,
                    trainRecords=0, validationRecords=0, testRecords=0, excludedRecords=raw_rows,
                    exclusionReason="Precomputed dense float vectors (no raw text)",
                    fields=fields, sha256=sha, md5=md5, format="derived_vector"
                ))
            elif name in KNOWN_DUPLICATES:
                raw_rows, fields = count_csv_rows(str(fp))
                canon = KNOWN_DUPLICATES[name]
                self.csv_entries.append(FileManifestEntry(
                    file=name, filePath=str(fp), type="CSV", sourceType="mix-csv",
                    status="DUPLICATE_FILE", sizeBytes=size, rawRecords=raw_rows, uniqueRecords=0,
                    trainRecords=0, validationRecords=0, testRecords=0, excludedRecords=raw_rows,
                    exclusionReason=f"Exact duplicate file of {canon}",
                    fields=fields, sha256=sha, md5=md5, format="duplicate"
                ))
            elif name in METADATA_TABLES:
                raw_rows, fields = count_csv_rows(str(fp))
                self.csv_entries.append(FileManifestEntry(
                    file=name, filePath=str(fp), type="CSV", sourceType="mix-csv",
                    status="METADATA_TABLE", sizeBytes=size, rawRecords=raw_rows, uniqueRecords=0,
                    trainRecords=0, validationRecords=0, testRecords=0, excludedRecords=raw_rows,
                    exclusionReason="Relational/metadata lookup table (no email body)",
                    fields=fields, sha256=sha, md5=md5, format="metadata"
                ))
            else:
                raw_rows, fields = count_csv_rows(str(fp))
                self.csv_entries.append(FileManifestEntry(
                    file=name, filePath=str(fp), type="CSV", sourceType="mix-csv",
                    status="CANONICAL", sizeBytes=size, rawRecords=raw_rows, uniqueRecords=0,
                    trainRecords=0, validationRecords=0, testRecords=0, excludedRecords=0,
                    exclusionReason="",
                    fields=fields, sha256=sha, md5=md5, format="canonical_csv"
                ))

        return self.csv_entries

    def scan_mix_eml(self) -> Dict[str, Any]:
        if not self.mix_eml_dir.exists():
            return {"totalFiles": 0, "validFiles": 0, "malformedFiles": 0}

        eml_files = sorted(self.mix_eml_dir.glob("**/*"))
        eml_files = [f for f in eml_files if f.is_file() and not f.name.endswith(".DS_Store")]
        
        return {
            "totalFiles": len(eml_files),
            "files": [str(f) for f in eml_files]
        }
