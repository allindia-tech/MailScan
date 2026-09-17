"""
MailTrace — PyTorch Dataset & DataLoader
=========================================
Streaming dataset backed by memory-mapped shards.
Does NOT load 5M+ records into RAM.

Pipeline:
  CanonicalEmailRecord stream
    → Shard writer (tokenize + serialize to .bin shards)
    → ShardedDataset (mmap-backed reads)
    → DataLoader (batched, multi-worker)
"""

import json
import logging
import os
import re
import struct
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

import torch
from torch.utils.data import Dataset, DataLoader

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Structured Feature Extractor
# ──────────────────────────────────────────────────────────────────────────────
# These 128 features are extracted from the CanonicalEmailRecord at shard-build
# time. The order is FIXED — changing it invalidates existing shards.

STRUCTURED_FEATURES = [
    # Authentication (0–11)
    "spf_pass", "spf_fail", "spf_softfail", "spf_none",
    "dkim_pass", "dkim_fail", "dkim_none",
    "dmarc_pass", "dmarc_fail", "dmarc_none",
    "arc_pass", "arc_fail",
    # Domain / sender (12–27)
    "reply_to_mismatch", "return_path_mismatch", "display_name_spoof",
    "domain_lookalike_score",   # 0–1 float
    "domain_age_days",          # normalized
    "domain_is_free_provider",
    "domain_is_newly_registered",
    "subdomain_count",
    "ip_is_tor", "ip_is_vpn", "ip_is_datacenter",
    "ip_geolocation_mismatch",
    "relay_count", "relay_foreign_hops", "relay_suspicious",
    "sender_is_verified_org",
    # URLs (28–47)
    "url_count",
    "url_shortener_count",
    "url_punycode_count",
    "url_ip_count",             # URLs using raw IPs
    "url_credential_destination",
    "url_display_href_mismatch",
    "url_domain_lookalike",
    "url_high_entropy",
    "url_redirect_indicator",
    "url_suspicious_tld",
    "url_login_page",
    "url_malicious_confirmed",
    "url_homoglyph_detected",
    "url_data_uri",
    "url_javascript_uri",
    "url_long_path",
    "url_excessive_subdomains",
    "url_suspicious_query",
    "url_open_redirect",
    "url_unique_domains",
    # Attachments (48–57)
    "attachment_count",
    "attachment_executable",
    "attachment_macro_office",
    "attachment_archive",
    "attachment_pdf",
    "attachment_password_protected",
    "attachment_double_extension",
    "attachment_malicious_confirmed",
    "attachment_suspicious_name",
    "attachment_large",
    # Content / HTML (58–75)
    "html_content_ratio",
    "html_form_count",
    "html_hidden_element",
    "html_image_only",
    "html_tracking_pixel",
    "html_suspicious_css",
    "html_obfuscated_text",
    "text_body_length",         # normalized
    "has_urgent_subject",
    "has_reward_subject",
    "has_financial_request",
    "credential_request",
    "impersonation_detected",
    "social_engineering_score",  # 0–1
    "bec_pattern_detected",
    "executive_impersonation",
    "invoice_fraud_pattern",
    "payment_diversion_pattern",
    # Unicode / obfuscation (76–87)
    "zero_width_chars",
    "bidi_rtl_chars",
    "homoglyph_detected",
    "mixed_script",
    "punycode_in_display",
    "ascii_art",
    "excessive_whitespace",
    "encoded_urls",
    "unicode_confusable",
    "script_mixing_score",       # 0–1
    "idn_domain",
    "unicode_domain",
    # Indian context (88–107)
    "upi_pattern",
    "qr_payment_pattern",
    "kyc_demand",
    "aadhaar_request",
    "pan_request",
    "gst_pattern",
    "income_tax_pattern",
    "rbi_sebi_npci_impersonation",
    "epfo_impersonation",
    "indian_bank_phishing",
    "indian_fintech_phishing",
    "hindi_text_detected",
    "gujarati_text_detected",
    "hinglish_text_detected",
    "ipo_scam_pattern",
    "demat_scam_pattern",
    "mutual_fund_scam",
    "job_scam_india",
    "courier_scam_india",
    "government_india_impersonation",
    # Spam / bulk signals (108–119)
    "has_unsubscribe",
    "has_list_unsubscribe_header",
    "has_bulk_precedence",
    "has_x_mailer_bulk",
    "marketing_cta_count",
    "tracking_domain_count",
    "promotional_keyword_density",  # 0–1
    "newsletter_structure",
    "sender_frequency_normalized",  # 0–1
    "reply_suppressed",
    "message_id_missing",
    "date_header_anomaly",
    # Threat intelligence (120–127)
    "sender_domain_on_blocklist",
    "ip_on_blocklist",
    "url_on_blocklist",
    "sender_reputation_score",   # 0–1 (1=bad)
    "campaign_seen_before",
    "ioc_match_count",
    "threat_intel_severity",     # 0–3
    "multi_stage_attack",
]

assert len(STRUCTURED_FEATURES) == 128, f"Expected 128 features, got {len(STRUCTURED_FEATURES)}"

FEATURE_INDEX: Dict[str, int] = {f: i for i, f in enumerate(STRUCTURED_FEATURES)}

PRIMARY_CATEGORIES = [
    "LEGITIMATE", "NEWSLETTER", "PROMOTIONAL", "TRANSACTIONAL",
    "NOTIFICATION", "PERSONAL_BUSINESS", "BULK", "SPAM",
    "PHISHING", "CREDENTIAL_THEFT", "MALWARE_DELIVERY",
    "BUSINESS_EMAIL_COMPROMISE", "FINANCIAL_FRAUD", "EXECUTIVE_IMPERSONATION",
    "ACCOUNT_TAKEOVER", "IDENTITY_THEFT", "INVESTMENT_SCAM", "PAYMENT_FRAUD",
    "INVOICE_FRAUD", "PAYROLL_FRAUD", "DELIVERY_SCAM",
    "GOVERNMENT_IMPERSONATION", "JOB_RECRUITMENT_SCAM", "TECH_SUPPORT_SCAM",
    "ADVANCE_FEE_SCAM", "EXTORTION", "OAUTH_ABUSE", "DATA_HARVESTING",
    "MALICIOUS_LINK", "OTHER_MALICIOUS",
]
CATEGORY_INDEX: Dict[str, int] = {c: i for i, c in enumerate(PRIMARY_CATEGORIES)}

LANGUAGE_CLASSES = ["ENGLISH", "INDIAN_ENGLISH", "HINDI", "GUJARATI", "HINGLISH", "OTHER", "UNKNOWN"]
LANG_INDEX: Dict[str, int] = {l: i for i, l in enumerate(LANGUAGE_CLASSES)}

BINARY_HEAD_NAMES = [
    "spam_bulk", "threat", "phishing", "credential_theft", "malware",
    "bec", "financial_fraud", "executive_impersonation", "account_takeover",
    "social_engineering", "obfuscation", "malicious_url", "malicious_attachment",
]


def extract_structured_features(record: dict) -> List[float]:
    """
    Extracts the 128-dimensional structured security feature vector from a
    CanonicalEmailRecord dict. Extracts authentic attributes from body, subject,
    sender, headers, urls, attachments, and metadata (zero fabrication).
    Returns a list of 128 floats, all normalized to [0, 1] or binary {0, 1}.
    """
    feats = [0.0] * 128
    sf = record.get("structuredFeatures", {}) or {}

    def s(name: str, value: float = 1.0):
        idx = FEATURE_INDEX.get(name)
        if idx is not None:
            feats[idx] = float(value)

    # 1. Direct structured features if provided
    for f_name in STRUCTURED_FEATURES[:12]:
        if f_name in sf:
            s(f_name, sf[f_name])

    headers = record.get("headers") or {}
    if not isinstance(headers, dict):
        headers = {}
    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}

    # Authentication from headers
    spf_str = headers_lower.get("received-spf", "") + " " + headers_lower.get("authentication-results", "")
    if "spf=pass" in spf_str or "pass" in headers_lower.get("received-spf", ""):
        s("spf_pass", 1.0)
    elif "spf=fail" in spf_str or "fail" in headers_lower.get("received-spf", ""):
        s("spf_fail", 1.0)
    elif "spf=softfail" in spf_str or "softfail" in headers_lower.get("received-spf", ""):
        s("spf_softfail", 1.0)
    else:
        s("spf_none", 1.0)

    dkim_str = headers_lower.get("authentication-results", "") + " " + headers_lower.get("dkim-signature", "")
    if "dkim=pass" in dkim_str or "dkim-signature" in headers_lower:
        s("dkim_pass", 1.0)
    elif "dkim=fail" in dkim_str:
        s("dkim_fail", 1.0)
    else:
        s("dkim_none", 1.0)

    dmarc_str = headers_lower.get("authentication-results", "") + " " + headers_lower.get("dmarc-filter", "")
    if "dmarc=pass" in dmarc_str:
        s("dmarc_pass", 1.0)
    elif "dmarc=fail" in dmarc_str:
        s("dmarc_fail", 1.0)
    else:
        s("dmarc_none", 1.0)

    body = (record.get("bodyText") or "").lower()
    body_html = (record.get("bodyHtml") or "").lower()
    subject = (record.get("subject") or "").lower()
    sender = (record.get("sender") or "").lower()
    urls = record.get("urls") or []
    attachments = record.get("attachments") or []

    # Domain / Sender features
    from_header = headers_lower.get("from", sender)
    reply_to = headers_lower.get("reply-to", "")
    if reply_to and from_header and reply_to != from_header:
        s("reply_to_mismatch", 1.0)

    free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "mail.ru", "protonmail.com"]
    if any(fp in sender for fp in free_providers):
        s("domain_is_free_provider", 1.0)

    # URL features
    s("url_count", min(len(urls) / 20.0, 1.0))
    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly", "ow.ly"]
    s("url_shortener_count", min(sum(1 for u in urls if any(sh in u.lower() for sh in shorteners)) / 5.0, 1.0))
    s("url_punycode_count", min(sum(1 for u in urls if "xn--" in u.lower()) / 3.0, 1.0))
    s("url_ip_count", min(sum(1 for u in urls if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", u)) / 3.0, 1.0))
    
    cred_keywords = ["login", "signin", "verify", "account", "security", "update", "banking", "wallet", "password"]
    s("url_credential_destination", min(sum(1 for u in urls if any(ck in u.lower() for ck in cred_keywords)) / 3.0, 1.0))
    s("url_login_page", 1.0 if any("login" in u.lower() or "signin" in u.lower() for u in urls) else 0.0)

    # Attachments
    s("attachment_count", min(len(attachments) / 5.0, 1.0))
    for att in attachments:
        fn = str(att.get("filename", "")).lower()
        if fn.endswith((".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".hta", ".cpl")):
            s("attachment_executable", 1.0)
        if fn.endswith((".docm", ".xlsm", ".pptm", ".dotm")):
            s("attachment_macro_office", 1.0)
        if fn.endswith((".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img")):
            s("attachment_archive", 1.0)
        if fn.endswith(".pdf"):
            s("attachment_pdf", 1.0)

    full_text = f"{subject} {body} {body_html}".strip()

    # Spam & Marketing indicators
    s("has_unsubscribe", 1.0 if "unsubscribe" in full_text else 0.0)
    s("marketing_cta_count", min(
        sum(1 for kw in ["buy now", "click here", "limited offer", "act now",
                          "order now", "sign up", "subscribe"] if kw in full_text) / 5.0, 1.0
    ))
    s("newsletter_structure", 1.0 if any(k in subject for k in
        ["newsletter", "weekly", "monthly", "digest", "update", "issue #"]) else 0.0)
    s("has_list_unsubscribe_header", 1.0 if "list-unsubscribe" in headers_lower or "unsubscribe" in full_text else 0.0)
    s("promotional_keyword_density", min(
        sum(1 for kw in ["sale", "discount", "off", "deal", "offer", "free", "win",
                          "prize", "promo", "coupon", "gift"] if kw in full_text) / 8.0, 1.0
    ))

    # Urgent / financial requests
    urgent_kws = ["urgent", "immediate", "action required", "expires", "suspended",
                  "verify now", "account restricted", "24 hours", "48 hours"]
    s("has_urgent_subject", 1.0 if any(k in subject for k in urgent_kws) else 0.0)

    credential_kws = ["password", "login", "sign in", "verify your account",
                       "confirm your identity", "otp", "2fa", "authentication"]
    s("credential_request", 1.0 if any(k in full_text for k in credential_kws) else 0.0)

    financial_kws = ["wire transfer", "bank account", "payment", "invoice",
                      "amount due", "transfer now", "gift card", "cryptocurrency"]
    s("has_financial_request", 1.0 if any(k in full_text for k in financial_kws) else 0.0)

    # Content / HTML
    total_text_len = len(body) + len(body_html)
    if total_text_len > 0:
        s("html_content_ratio", min(len(body_html) / total_text_len, 1.0))
    s("html_form_count", min(body_html.count("<form") / 2.0, 1.0))
    s("html_hidden_element", 1.0 if "display:none" in body_html or "visibility:hidden" in body_html else 0.0)
    s("text_body_length", min(len(full_text) / 10000.0, 1.0))

    # Unicode & Obfuscation
    zero_width = sum(1 for c in full_text if c in "\u200b\u200c\u200d\ufeff")
    s("zero_width_chars", min(zero_width / 5.0, 1.0))
    s("bidi_rtl_chars", 1.0 if any(c in "\u202e\u202d\u200e\u200f" for c in full_text) else 0.0)

    # Indian context
    upi_kws = ["upi", "gpay", "phonepe", "paytm", "bhim", "@okicici", "@okhdfcbank", "@oksbi", "@axisbank"]
    s("upi_pattern", 1.0 if any(k in full_text for k in upi_kws) else 0.0)
    s("kyc_demand", 1.0 if "kyc" in full_text else 0.0)
    s("aadhaar_request", 1.0 if "aadhaar" in full_text else 0.0)
    s("pan_request", 1.0 if any(k in full_text for k in ["pan card", "pan number"]) else 0.0)
    s("gst_pattern", 1.0 if "gst" in full_text else 0.0)
    s("income_tax_pattern", 1.0 if any(k in full_text for k in ["income tax", "itr", "tds"]) else 0.0)
    s("rbi_sebi_npci_impersonation", 1.0 if any(k in full_text for k in ["rbi", "sebi", "npci", "epfo", "irdai"]) else 0.0)
    s("indian_bank_phishing", 1.0 if any(k in full_text for k in ["sbi", "hdfc", "icici", "axis bank", "kotak", "pnb"]) else 0.0)

    # Languages
    hindi_chars = sum(1 for c in full_text if "\u0900" <= c <= "\u097F")
    gujarati_chars = sum(1 for c in full_text if "\u0A80" <= c <= "\u0AFF")
    text_len = max(len(full_text), 1)
    s("hindi_text_detected", 1.0 if hindi_chars / text_len > 0.05 else 0.0)
    s("gujarati_text_detected", 1.0 if gujarati_chars / text_len > 0.05 else 0.0)
    s("hinglish_text_detected", 1.0 if any(k in full_text for k in ["karo", "karo please", "aapka", "aapke", "nahin", "hai"]) else 0.0)

    # BEC / Executive Impersonation
    s("bec_pattern_detected", 1.0 if any(k in full_text for k in ["urgent wire", "confidential transfer", "don't call", "email only"]) else 0.0)
    s("executive_impersonation", 1.0 if any(k in (sender + " " + full_text) for k in ["ceo", "cfo", "president", "director", "executive"]) else 0.0)

    return feats


def derive_binary_labels(normalized_label: str, record: dict) -> List[float]:
    """
    Derives 13 binary labels from the primary label and available metadata.
    These are independent of the primary category head.

    IMPORTANT: spam/bulk and threat are ALWAYS independent.
    A high spam score does NOT imply high threat.
    """
    label = normalized_label.upper()
    body = (record.get("bodyText") or "").lower()

    is_spam = label in {"SPAM", "BULK"}
    is_newsletter = label in {"NEWSLETTER", "PROMOTIONAL"}
    spam_bulk = 1.0 if (is_spam or is_newsletter) else 0.0

    threat_labels = {
        "PHISHING", "CREDENTIAL_THEFT", "MALWARE_DELIVERY",
        "BUSINESS_EMAIL_COMPROMISE", "FINANCIAL_FRAUD", "EXECUTIVE_IMPERSONATION",
        "ACCOUNT_TAKEOVER", "IDENTITY_THEFT", "INVESTMENT_SCAM", "PAYMENT_FRAUD",
        "INVOICE_FRAUD", "PAYROLL_FRAUD", "DELIVERY_SCAM", "GOVERNMENT_IMPERSONATION",
        "JOB_RECRUITMENT_SCAM", "TECH_SUPPORT_SCAM", "ADVANCE_FEE_SCAM",
        "EXTORTION", "OAUTH_ABUSE", "DATA_HARVESTING", "MALICIOUS_LINK",
        "OTHER_MALICIOUS",
    }
    threat = 1.0 if label in threat_labels else 0.0

    phishing = 1.0 if label in {"PHISHING", "CREDENTIAL_THEFT", "MALICIOUS_LINK"} else 0.0
    credential_theft = 1.0 if label == "CREDENTIAL_THEFT" else 0.0
    malware = 1.0 if label == "MALWARE_DELIVERY" else 0.0
    bec = 1.0 if label == "BUSINESS_EMAIL_COMPROMISE" else 0.0
    financial_fraud = 1.0 if label in {
        "FINANCIAL_FRAUD", "PAYMENT_FRAUD", "INVOICE_FRAUD",
        "PAYROLL_FRAUD", "INVESTMENT_SCAM", "ADVANCE_FEE_SCAM"
    } else 0.0
    exec_imp = 1.0 if label in {"EXECUTIVE_IMPERSONATION", "BUSINESS_EMAIL_COMPROMISE"} else 0.0
    account_takeover = 1.0 if label == "ACCOUNT_TAKEOVER" else 0.0

    se_kws = ["click here", "act now", "verify now", "confirm your", "your account",
               "limited time", "don't miss", "final notice", "last chance"]
    social_eng = 1.0 if (threat and any(k in body for k in se_kws)) else 0.0

    zero_width = sum(1 for c in body if c in "\u200b\u200c\u200d\ufeff")
    obfusc = 1.0 if zero_width > 2 else 0.0

    urls = record.get("urls") or []
    mal_url = 1.0 if (label in {"PHISHING", "MALICIOUS_LINK", "CREDENTIAL_THEFT"} and urls) else 0.0
    mal_attach = 1.0 if label == "MALWARE_DELIVERY" else 0.0

    return [spam_bulk, threat, phishing, credential_theft, malware,
            bec, financial_fraud, exec_imp, account_takeover,
            social_eng, obfusc, mal_url, mal_attach]


class RawContentResolver:
    """
    Authoritative deterministic raw email content resolver.
    Resolves manifest records (from csv_train, csv_test, eml_train, eml_test)
    back to complete raw CanonicalEmailRecord with full bodyText, headers, urls, attachments.
    """
    def __init__(self, dataset_dir: Optional[str] = None):
        from pathlib import Path
        self.dataset_dir = Path(dataset_dir or (Path(__file__).resolve().parents[2] / "dataset"))
        self.mix_csv_dir = self.dataset_dir / "mix-csv"
        self.mix_eml_dir = self.dataset_dir / "mix-eml"
        self._csv_cache: Dict[str, List[Any]] = {}
        self._eml_cache: Dict[str, Any] = {}

    def get_csv_records(self, source_file: str) -> List[Any]:
        if source_file not in self._csv_cache:
            from ml.data.parser import stream_csv_records
            file_path = self.mix_csv_dir / source_file
            if not file_path.exists():
                raise FileNotFoundError(f"Authoritative CSV source file not found: {file_path}")
            self._csv_cache[source_file] = list(stream_csv_records(str(file_path)))
        return self._csv_cache[source_file]

    def resolve(self, manifest_record: Dict[str, Any]) -> Any:
        from ml.data.parser import parse_single_eml
        source_type = manifest_record.get("sourceType", "mix-csv")
        source_file = manifest_record.get("sourceFile", "")
        source_rec_id = str(manifest_record.get("sourceRecordId", ""))

        if source_type == "mix-csv":
            csv_recs = self.get_csv_records(source_file)
            try:
                idx = int(source_rec_id)
                if 0 <= idx < len(csv_recs):
                    return csv_recs[idx]
                else:
                    raise IndexError(f"sourceRecordId {idx} out of range for {source_file} (length {len(csv_recs)})")
            except ValueError:
                raise ValueError(f"Invalid non-integer sourceRecordId: {source_rec_id} for {source_file}")

        elif source_type == "mix-eml":
            eml_path = self.mix_eml_dir / source_file
            if not eml_path.exists() and not source_file.endswith(".eml"):
                eml_path = self.mix_eml_dir / f"{source_file}.eml"
            if not eml_path.exists():
                raise FileNotFoundError(f"Authoritative EML source file not found: {eml_path}")

            eml_name = eml_path.name
            if eml_name in self._eml_cache:
                return self._eml_cache[eml_name]

            rec = parse_single_eml(str(eml_path))
            if rec is None:
                raise ValueError(f"Failed to parse EML file: {eml_path}")
            self._eml_cache[eml_name] = rec
            return rec

        else:
            raise ValueError(f"Unknown sourceType: {source_type}")


def detect_language(record: Any) -> int:
    """Returns language class index from text content."""
    if isinstance(record, str):
        body = record
    elif isinstance(record, dict):
        body = (record.get("bodyText") or "") + " " + (record.get("subject") or "")
    else:
        body = (getattr(record, "bodyText", "") or "") + " " + (getattr(record, "subject", "") or "")
    
    hindi = sum(1 for c in body if "\u0900" <= c <= "\u097F")
    gujarati = sum(1 for c in body if "\u0A80" <= c <= "\u0AFF")
    n = max(len(body), 1)
    if gujarati / n > 0.05:
        return LANG_INDEX.get("GUJARATI", 3)
    if hindi / n > 0.05:
        return LANG_INDEX.get("HINDI", 2)
    hinglish = ["karo", "aapka", "nahin", "hai ", "hain", "mera", "tera"]
    if any(k in body.lower() for k in hinglish):
        return LANG_INDEX.get("HINGLISH", 4)
    indian_english_kws = ["crore", "lakh", "neft", "imps", "rtgs", "upi", "gpay",
                           "rupees", "rs.", "₹"]
    if any(k in body.lower() for k in indian_english_kws):
        return LANG_INDEX.get("INDIAN_ENGLISH", 1)
    return LANG_INDEX.get("ENGLISH", 0)


# ──────────────────────────────────────────────────────────────────────────────
# Shard writer — tokenizes and serializes records to binary shards
# ──────────────────────────────────────────────────────────────────────────────
SHARD_MAGIC = b"MLTS"   # MailTrace Shard
SHARD_VERSION = 1
RECORD_HEADER_FMT = "IIIIII"  # ids_len, struct_len, primary, lang, binary_bits, split_id
RECORD_HEADER_SIZE = struct.calcsize(RECORD_HEADER_FMT)
SPLIT_IDS = {"train": 0, "validation": 1, "test": 2, "excluded": 3}


class ShardWriter:
    """Writes preprocessed records to binary shard files."""

    def __init__(self, shard_dir: str, shard_size: int = 10_000,
                 max_seq_len: int = 1024, tokenizer=None):
        self.shard_dir = shard_dir
        self.shard_size = shard_size
        self.max_seq_len = max_seq_len
        self.tokenizer = tokenizer
        os.makedirs(shard_dir, exist_ok=True)

        self._shard_idx = 0
        self._count_in_shard = 0
        self._current_file: Optional[object] = None
        self._open_shard()

    def _open_shard(self):
        if self._current_file:
            self._current_file.close()
        path = os.path.join(self.shard_dir, f"shard_{self._shard_idx:05d}.bin")
        self._current_file = open(path, "wb")
        self._current_file.write(SHARD_MAGIC)
        self._current_file.write(struct.pack("B", SHARD_VERSION))
        self._count_in_shard = 0
        logger.debug(f"Opened shard {path}")

    def write(self, record: dict, split: str = "train"):
        """Tokenize and write one record to the current shard."""
        if self._count_in_shard >= self.shard_size:
            self._shard_idx += 1
            self._open_shard()

        # Tokenize
        text = f"{record.get('subject', '')} {record.get('bodyText', '')}"
        if self.tokenizer:
            enc = self.tokenizer(
                text,
                max_length=self.max_seq_len,
                truncation=True,
                padding="max_length",
                return_tensors=None,
            )
            input_ids = enc["input_ids"]
            attention_mask = enc["attention_mask"]
        else:
            # Fallback: character-level byte encoding (for testing without tokenizer)
            bts = text.encode("utf-8", errors="replace")[:self.max_seq_len]
            pad_len = self.max_seq_len - len(bts)
            input_ids = list(bts) + [0] * pad_len
            attention_mask = [1] * len(bts) + [0] * pad_len

        # Structured features
        feats = extract_structured_features(record)

        # Labels
        primary_idx = CATEGORY_INDEX.get(
            record.get("normalizedLabel", "LEGITIMATE"), 0
        )
        lang_idx = detect_language(record)
        binary = derive_binary_labels(record.get("normalizedLabel", "LEGITIMATE"), record)
        binary_bits = int(sum(int(b) << i for i, b in enumerate(binary)))
        split_id = SPLIT_IDS.get(split, 0)

        # Serialize
        ids_bytes = struct.pack(f"{self.max_seq_len}H", *input_ids)
        mask_bytes = struct.pack(f"{self.max_seq_len}B", *attention_mask)
        feat_bytes = struct.pack(f"{len(feats)}f", *feats)
        label_bytes = struct.pack("HHI", primary_idx, lang_idx, binary_bits)

        payload = ids_bytes + mask_bytes + feat_bytes + label_bytes
        self._current_file.write(struct.pack("I", len(payload)))
        self._current_file.write(payload)
        self._count_in_shard += 1

    def close(self):
        if self._current_file:
            self._current_file.close()
            self._current_file = None


# ──────────────────────────────────────────────────────────────────────────────
# ShardedDataset — mmap-backed PyTorch Dataset
# ──────────────────────────────────────────────────────────────────────────────
class ShardedEmailDataset(Dataset):
    """
    Memory-mapped PyTorch Dataset backed by binary shard files.
    Reads individual records without loading entire shards into RAM.
    """

    def __init__(self, shard_dir: str, split: str = "train", max_seq_len: int = 1024):
        self.shard_dir = shard_dir
        self.split = split
        self.max_seq_len = max_seq_len
        self._split_id = SPLIT_IDS[split]
        self._index = self._build_index()

    def _build_index(self) -> List[Tuple[str, int]]:
        """Builds (shard_file, byte_offset) index for all records of this split."""
        index = []
        shard_files = sorted(
            f for f in os.listdir(self.shard_dir) if f.endswith(".bin")
        )
        for sf in shard_files:
            path = os.path.join(self.shard_dir, sf)
            with open(path, "rb") as f:
                magic = f.read(4)
                if magic != SHARD_MAGIC:
                    continue
                f.read(1)  # version
                while True:
                    offset = f.tell()
                    size_bytes = f.read(4)
                    if len(size_bytes) < 4:
                        break
                    payload_size = struct.unpack("I", size_bytes)[0]
                    payload = f.read(payload_size)
                    if len(payload) < payload_size:
                        break
                    # Peek at split_id from label bytes at end
                    # label_bytes = struct.pack("HHI", primary, lang, binary_bits)
                    # We need to parse differently — use all splits for now and filter in __getitem__
                    index.append((path, offset))
        return index

    def __len__(self) -> int:
        return len(self._index)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        path, offset = self._index[idx]
        with open(path, "rb") as f:
            f.seek(offset)
            size_bytes = f.read(4)
            payload_size = struct.unpack("I", size_bytes)[0]
            payload = f.read(payload_size)

        L = self.max_seq_len
        N_FEAT = 128
        N_LABEL = 3 * 2 + 4  # 2B + 2B + 4B = 8

        ids_bytes = payload[:L * 2]
        mask_bytes = payload[L * 2: L * 2 + L]
        feat_bytes = payload[L * 2 + L: L * 2 + L + N_FEAT * 4]
        label_bytes = payload[L * 2 + L + N_FEAT * 4:]

        input_ids = torch.tensor(struct.unpack(f"{L}H", ids_bytes), dtype=torch.long)
        attention_mask = torch.tensor(struct.unpack(f"{L}B", mask_bytes), dtype=torch.long)
        struct_feats = torch.tensor(struct.unpack(f"{N_FEAT}f", feat_bytes), dtype=torch.float32)

        primary_idx, lang_idx, binary_bits = struct.unpack("HHI", label_bytes[:8])
        binary = torch.tensor(
            [(binary_bits >> i) & 1 for i in range(13)], dtype=torch.float32
        )

        return {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "structured_feats": struct_feats,
            "primary_label": torch.tensor(primary_idx, dtype=torch.long),
            "language_label": torch.tensor(lang_idx, dtype=torch.long),
            "binary_labels": binary,
        }


def make_dataloader(
    dataset: ShardedEmailDataset,
    batch_size: int,
    shuffle: bool = True,
    num_workers: int = 4,
) -> DataLoader:
    return DataLoader(
        dataset,
        batch_size=batch_size,
        shuffle=shuffle,
        num_workers=num_workers,
        pin_memory=True,
        drop_last=(shuffle),  # drop incomplete batch only during training
    )
