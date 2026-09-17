/**
 * MailTrace AI — Default Authoritative Test Fixtures
 * ===================================================
 * 24 comprehensive test cases covering legitimate emails, phishing, BEC,
 * malware, invoice fraud, lookalikes, newsletters, and edge cases.
 */

import { LoadedTestCase } from './testDatasetLoader.js';

export const DEFAULT_TEST_FIXTURES: Omit<LoadedTestCase, 'fileSizeBytes' | 'sha256' | 'filePath'>[] = [
  {
    id: 'edge-case-01-multipart-nested-boundary',
    name: 'Edge Case 1: Nested MIME Multipart with Empty Part',
    description: 'Edge case fixture for parser stability testing',
    category: 'UNLABELED',
    groundTruth: 'UNLABELED',
    isHardNegative: false,
    rawEml: `From: test@example.org\nTo: user@example.org\nSubject: Test Nested Multipart\nContent-Type: multipart/mixed; boundary="BOUNDARY_1"\n\n--BOUNDARY_1\nContent-Type: text/plain\n\nHello\n--BOUNDARY_1\nContent-Type: multipart/alternative; boundary="BOUNDARY_2"\n\n--BOUNDARY_2\nContent-Type: text/html\n\n<b>Hello HTML</b>\n--BOUNDARY_2--\n--BOUNDARY_1--\n`,
    expected: { classification: [] },
    tags: ['edge_case', 'unlabeled', 'parser_stability']
  },
  {
    id: 'edge-case-02-utf8-encoded-words',
    name: 'Edge Case 2: RFC 2047 Encoded Words in Subject and Headers',
    description: 'Edge case fixture for parser stability testing',
    category: 'UNLABELED',
    groundTruth: 'UNLABELED',
    isHardNegative: false,
    rawEml: `From: =?UTF-8?B?U2VjdXJpdHkgVGVhbQ==?= <alerts@example.com>\nTo: target@example.com\nSubject: =?UTF-8?Q?Security_Alert_=E2=9A=A0_Action_Required?=\nDate: Wed, 18 Mar 2026 12:00:00 +0000\nContent-Type: text/plain; charset="UTF-8"\n\nPlease review your security settings.\n`,
    expected: { classification: [] },
    tags: ['edge_case', 'unlabeled', 'parser_stability']
  },
  {
    id: 'edge-case-03-empty-headers-raw-body',
    name: 'Edge Case 3: Raw Body with Minimal Incomplete Headers',
    description: 'Edge case fixture for parser stability testing',
    category: 'UNLABELED',
    groundTruth: 'UNLABELED',
    isHardNegative: false,
    rawEml: `Subject: Quick notice\n\nNotice content with no other headers present.\n`,
    expected: { classification: [] },
    tags: ['edge_case', 'unlabeled', 'parser_stability']
  },
  {
    id: 'test-case-1-legitimate-microsoft',
    name: '1. Legitimate Microsoft Email',
    description: 'Authentic Microsoft 365 security notification with valid SPF/DKIM',
    category: 'Legitimate',
    groundTruth: 'Legitimate',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=pass (sender IP is 40.92.18.10) smtp.mailfrom=microsoft.com; dkim=pass (signature was verified) header.d=microsoft.com; dmarc=pass action=none header.from=microsoft.com;\nReceived-SPF: Pass (protection.outlook.com: domain of microsoft.com designates 40.92.18.10 as permitted sender)\nFrom: "Microsoft Security Team" <account-security-noreply@accountprotection.microsoft.com>\nTo: john.doe@enterprise.com\nSubject: Microsoft account security info was updated\nDate: Mon, 16 Sep 2026 09:30:00 +0000\nMessage-ID: <MS-SEC-2026-99281@accountprotection.microsoft.com>\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>Hello John,</p><p>The security info for your Microsoft account was recently updated. If this was you, you can safely disregard this email.</p><p><a href="https://account.microsoft.com/security">Review your account activity</a></p><p>Thanks,<br>The Microsoft account team</p></body></html>`,
    expected: {
      classification: ['Legitimate'],
      threatRiskMax: 15,
      action: ['allow']
    },
    tags: ['legitimate', 'microsoft', 'brand_impersonation_check']
  },
  {
    id: 'test-case-2-legitimate-google',
    name: '2. Legitimate Google Email',
    description: 'Authentic Google Workspace account alert with strict SPF/DKIM verification',
    category: 'Legitimate',
    groundTruth: 'Legitimate',
    isHardNegative: false,
    rawEml: `Authentication-Results: mx.google.com; dkim=pass header.i=@google.com; spf=pass smtp.mailfrom=google.com; dmarc=pass header.from=google.com\nFrom: "Google Workspace Team" <no-reply@accounts.google.com>\nTo: analyst@enterprise.com\nSubject: Security alert for your linked Google Account\nDate: Mon, 16 Sep 2026 10:15:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>Your Google Account was accessed from a new device.</p><p><a href="https://myaccount.google.com/notifications">Check activity</a></p></body></html>`,
    expected: {
      classification: ['Legitimate'],
      threatRiskMax: 15,
      action: ['allow']
    },
    tags: ['legitimate', 'google']
  },
  {
    id: 'test-case-3-legitimate-bank',
    name: '3. Legitimate Bank Transaction',
    description: 'Authentic corporate banking monthly e-statement with full transport integrity',
    category: 'Legitimate',
    groundTruth: 'Legitimate',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=pass smtp.mailfrom=chase.com; dkim=pass header.d=chase.com; dmarc=pass header.from=chase.com\nFrom: "Chase Bank Commercial Services" <alerts@chase.com>\nTo: finance.admin@enterprise.com\nSubject: Your Monthly Commercial Account Statement is Ready\nDate: Mon, 16 Sep 2026 11:00:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>Dear Customer,</p><p>Your monthly statement ending in 4491 is now available in Chase Commercial Online.</p><p><a href="https://www.chase.com/commercial-banking">Log in to view statements</a></p></body></html>`,
    expected: {
      classification: ['Legitimate'],
      threatRiskMax: 15,
      action: ['allow']
    },
    tags: ['legitimate', 'financial']
  },
  {
    id: 'test-case-4-legitimate-newsletter',
    name: '4. Legitimate Newsletter',
    description: 'High-volume marketing newsletter with List-Unsubscribe headers and low threat score',
    category: 'Newsletter',
    groundTruth: 'Newsletter',
    isHardNegative: true,
    rawEml: `Authentication-Results: spf=pass smtp.mailfrom=newsletters.wired.com; dkim=pass header.d=wired.com; dmarc=pass header.from=wired.com\nList-Unsubscribe: <https://newsletters.wired.com/unsub?id=88231>\nFrom: "WIRED Daily Dispatch" <newsletters@wired.com>\nTo: subscriber@enterprise.com\nSubject: The Future of Quantum Computing and Enterprise Cyber Defense\nDate: Mon, 16 Sep 2026 12:00:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><h2>Today's Top Story</h2><p>Quantum-safe cryptography reaches production standards.</p><p><a href="https://www.wired.com/story/quantum-computing-standard/">Read Full Article</a></p><hr><p><a href="https://newsletters.wired.com/unsub?id=88231">Unsubscribe</a></p></body></html>`,
    expected: {
      classification: ['Newsletter', 'Legitimate', 'Promotional'],
      threatRiskMax: 20
    },
    tags: ['newsletter', 'bulk_legit']
  },
  {
    id: 'test-case-5-legitimate-promotional',
    name: '5. Legitimate Promotional Email',
    description: 'Promotional SaaS product update with high spam bulk signals but zero threat indicators',
    category: 'Promotional',
    groundTruth: 'Promotional',
    isHardNegative: true,
    rawEml: `Authentication-Results: spf=pass smtp.mailfrom=marketing.atlassian.com; dkim=pass header.d=atlassian.com; dmarc=pass header.from=atlassian.com\nList-Unsubscribe: <https://atlassian.com/unsub>\nFrom: "Atlassian Special Offers" <promotions@atlassian.com>\nTo: dev@enterprise.com\nSubject: Special 30% discount on Jira Cloud Enterprise Plans!\nDate: Mon, 16 Sep 2026 13:00:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><h2>Upgrade your team today!</h2><p>Get 30% off annual plans with promo code ENTERPRISE30.</p><a href="https://www.atlassian.com/software/jira/pricing">Claim Offer</a></body></html>`,
    expected: {
      classification: ['Promotional', 'Newsletter', 'Legitimate'],
      threatRiskMax: 20
    },
    tags: ['promotional', 'marketing']
  },
  {
    id: 'test-case-6-credential-phishing',
    name: '6. Credential Phishing',
    description: 'Direct password reset credential harvesting page disguised as IT Helpdesk',
    category: 'Credential Theft',
    groundTruth: 'Credential Theft',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=fail smtp.mailfrom=evil-spoof.com; dkim=none; dmarc=fail\nFrom: "Corporate IT Support" <helpdesk@corpit-auth-reset.tk>\nTo: victim@enterprise.com\nSubject: URGENT: Your corporate password expires in 2 hours - Immediate Action Required\nDate: Mon, 16 Sep 2026 14:00:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>Your Active Directory credentials will expire today. Please verify your current password immediately to retain access:</p><p><a href="http://192.168.1.100/login/password-verify.php">Verify Active Directory Credentials</a></p></body></html>`,
    expected: {
      classification: ['Credential Theft', 'Phishing'],
      threatRiskMin: 70,
      action: ['block', 'quarantine']
    },
    tags: ['credential_harvesting', 'phishing']
  },
  {
    id: 'test-case-7-fake-microsoft-login',
    name: '7. Fake Microsoft Login (SharePoint Phish)',
    description: 'High-fidelity Microsoft SharePoint phishing lure pointing to external credential capture page',
    category: 'Credential Theft',
    groundTruth: 'Phishing',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=fail; dkim=none; dmarc=fail\nFrom: "SharePoint Online Notification" <sharepoint-secure-doc@microsoft-secure-share.xyz>\nTo: executive@enterprise.com\nSubject: Encrypted Financial Document shared via Microsoft SharePoint\nDate: Mon, 16 Sep 2026 14:30:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>You have received a secure document from Board of Directors.</p><p><a href="http://microsoft-sharepoint-login-verify.top/auth">Sign in with Microsoft 365 to Access Document</a></p></body></html>`,
    expected: {
      classification: ['Credential Theft', 'Phishing'],
      threatRiskMin: 70,
      action: ['block', 'quarantine']
    },
    tags: ['phishing', 'microsoft']
  },
  {
    id: 'test-case-8-lookalike-domain',
    name: '8. Lookalike Domain Phishing',
    description: 'Typosquatting domain attack targeting internal corporate domain',
    category: 'Credential Theft',
    groundTruth: 'Phishing',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=softfail; dkim=none; dmarc=fail\nFrom: "HR Department" <payroll@enterprlse.com>\nTo: employee@enterprise.com\nSubject: Updated Employee Compensation and Direct Deposit Portal\nDate: Mon, 16 Sep 2026 15:00:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>Please review and sign your updated compensation review here:</p><p><a href="http://portal.enterprlse.com/direct-deposit">Access HR Portal</a></p></body></html>`,
    expected: {
      classification: ['Credential Theft', 'Phishing', 'Domain Spoofing'],
      threatRiskMin: 70,
      action: ['block', 'quarantine']
    },
    tags: ['lookalike_domain', 'typosquatting']
  },
  {
    id: 'test-case-9-malicious-url',
    name: '9. Malicious URL Attack',
    description: 'Direct raw IP and suspicious TLD payload targeting user credentials',
    category: 'Credential Theft',
    groundTruth: 'Phishing',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=neutral; dkim=none; dmarc=none\nFrom: "Notification Service" <alert@notice-hub.cc>\nTo: target@enterprise.com\nSubject: Critical System Update Required\nDate: Mon, 16 Sep 2026 15:30:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>Download and run the critical security patch:</p><p><a href="http://185.220.101.5/update.exe">Download Patch</a></p></body></html>`,
    expected: {
      classification: ['Credential Theft', 'Phishing', 'Malware Delivery'],
      threatRiskMin: 70,
      action: ['block', 'quarantine']
    },
    tags: ['malicious_url', 'ip_destination']
  },
  {
    id: 'test-case-10-bec',
    name: '10. Business Email Compromise (BEC)',
    description: 'CEO impersonation requesting immediate confidential wire transfer',
    category: 'Business Email Compromise',
    groundTruth: 'Business Email Compromise',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=none; dkim=none; dmarc=fail\nFrom: "Satya Nadella, CEO" <ceo.office.confidential.direct@gmail.com>\nReply-To: executive-payments-channel@asia-capital.cc\nTo: finance.controller@enterprise.com\nSubject: STRICTLY CONFIDENTIAL: Project Aurora Acquisition Wire Transfer\nDate: Mon, 16 Sep 2026 16:00:00 +0000\nContent-Type: text/plain; charset="UTF-8"\n\nAre you at your desk right now? We are finalizing a confidential strategic acquisition today. Please process an urgent initial deposit of $485,000 USD via wire. Wire routing details attached. Keep this strictly off Slack until officially announced.\n`,
    expected: {
      classification: ['Business Email Compromise', 'Executive Impersonation', 'Financial Fraud'],
      threatRiskMin: 75,
      action: ['block', 'quarantine']
    },
    tags: ['bec', 'wire_fraud', 'executive_impersonation']
  },
  {
    id: 'test-case-11-financial-fraud',
    name: '11. Financial Fraud / Invoice Diversion',
    description: 'Vendor account update scam requesting payment diversion to new bank account',
    category: 'Business Email Compromise',
    groundTruth: 'Financial Fraud',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=fail; dkim=none; dmarc=fail\nFrom: "Accounts Receivable - Cloud Provider" <billing@cloud-services-billing-dept.com>\nReply-To: wire-receivables@cloud-vendor-settlement.com\nTo: accounts.payable@enterprise.com\nSubject: Urgent: Updated Banking Information for Outstanding Invoice #INV-88912\nDate: Mon, 16 Sep 2026 16:30:00 +0000\nContent-Type: text/plain; charset="UTF-8"\n\nPlease note our primary bank account has changed due to financial restructuring. Remit all pending invoice payments for INV-88912 to our new beneficiary details in Hong Kong.\n`,
    expected: {
      classification: ['Business Email Compromise', 'Financial Fraud'],
      threatRiskMin: 75,
      action: ['block', 'quarantine']
    },
    tags: ['invoice_fraud', 'bank_diversion']
  },
  {
    id: 'test-case-12-malware-attachment',
    name: '12. Malware Attachment',
    description: 'Weaponized attachment containing macro-enabled document with suspicious hash',
    category: 'Malware Delivery',
    groundTruth: 'Malware Delivery',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=neutral; dkim=none; dmarc=none\nFrom: "DHL Logistics" <tracking@dhl-parcel-delivery.com>\nTo: recipient@enterprise.com\nSubject: Shipment Delivery Exception - Review Customs Declaration\nDate: Mon, 16 Sep 2026 17:00:00 +0000\nContent-Type: multipart/mixed; boundary="MALWARE_BOUNDARY"\n\n--MALWARE_BOUNDARY\nContent-Type: text/plain\n\nYour package cannot be delivered. Please open the attached document to verify shipping charges.\n\n--MALWARE_BOUNDARY\nContent-Type: application/vnd.ms-excel.sheet.macroEnabled.12; name="Customs_Declaration.xlsm"\nContent-Disposition: attachment; filename="Customs_Declaration.xlsm"\nContent-Transfer-Encoding: base64\n\nUEsDBBQAAAAIAAAAAAAAAAAAAAAAAAAAAAA=\n--MALWARE_BOUNDARY--`,
    expected: {
      classification: ['Malware Delivery', 'Phishing', 'Credential Theft'],
      threatRiskMin: 75,
      action: ['block', 'quarantine']
    },
    tags: ['attachment_macro', 'malware_delivery']
  },
  {
    id: 'test-case-13-unicode-deception',
    name: '13. Unicode Deception (Punycode / Homoglyph)',
    description: 'Internationalized domain name homoglyph attack impersonating Apple',
    category: 'Credential Theft',
    groundTruth: 'Domain Spoofing',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=fail; dkim=none; dmarc=fail\nFrom: "Apple ID Security" <support@xn--pple-43d.com>\nTo: user@enterprise.com\nSubject: Your Apple ID has been locked for security reasons\nDate: Mon, 16 Sep 2026 17:30:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>Your Apple ID was locked. Unlock your account:</p><p><a href="http://xn--pple-43d.com/unlock">Unlock Apple ID</a></p></body></html>`,
    expected: {
      classification: ['Domain Spoofing', 'Credential Theft', 'Business Email Compromise', 'Phishing'],
      threatRiskMin: 70,
      action: ['block', 'quarantine']
    },
    tags: ['unicode_homoglyph', 'punycode']
  },
  {
    id: 'test-case-14-ascii-smuggling',
    name: '14. ASCII Smuggling / Zero-Width Attack',
    description: 'Zero-width Unicode characters used to hide phishing instructions from legacy scanners',
    category: 'Credential Theft',
    groundTruth: 'Phishing',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=fail; dkim=none; dmarc=fail\nFrom: "Security Ops" <admin@security-verification-portal.com>\nTo: user@enterprise.com\nSubject: U​R​G​E​N​T: S​e​c​u​r​i​t​y N​o​t​i​c​e\nDate: Mon, 16 Sep 2026 18:00:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>P​l​e​a​s​e r​e​s​e​t y​o​u​r c​r​e​d​e​n​t​i​a​l​s:</p><p><a href="http://103.20.10.15/login">Reset Password</a></p></body></html>`,
    expected: {
      classification: ['Credential Theft', 'Phishing'],
      threatRiskMin: 75,
      action: ['block', 'quarantine']
    },
    tags: ['ascii_smuggling', 'hidden_payload']
  },
  {
    id: 'test-case-15-otp-scam',
    name: '15. OTP Scam (Indian UPI/NetBanking Fraud)',
    description: 'Urgent KYC mandate lure requesting OTP / debit card verification',
    category: 'Credential Theft',
    groundTruth: 'Financial Fraud',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=fail; dkim=none; dmarc=fail\nFrom: "State Bank Customer Support" <alerts@sbi-kyc-mandate.in>\nTo: citizen@domain.in\nSubject: MANDATORY: Your SBI Account and UPI will be suspended today - Complete KYC\nDate: Mon, 16 Sep 2026 18:30:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>Dear SBI Customer, your YONO account KYC has expired. Update your PAN card and verify OTP immediately:</p><p><a href="http://sbi-kyc-portal-update.in/verify">Update SBI KYC Details</a></p></body></html>`,
    expected: {
      classification: ['Credential Theft', 'Financial Fraud', 'Phishing'],
      threatRiskMin: 70,
      action: ['block', 'quarantine']
    },
    tags: ['otp_fraud', 'kyc_scam']
  },
  {
    id: 'test-case-16-qr-phishing',
    name: '16. QR Phishing (Quishing Attack)',
    description: 'Embedded QR code lure designed to bypass traditional URL scrapers',
    category: 'Credential Theft',
    groundTruth: 'Phishing',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=fail; dkim=none; dmarc=fail\nFrom: "IT 2FA Admin" <mfa@mfa-qr-update.com>\nTo: user@enterprise.com\nSubject: Action Required: Authenticator App 2FA Migration\nDate: Mon, 16 Sep 2026 19:00:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>Scan this QR code with your mobile camera to register your multi-factor token:</p><p><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==" alt="QR Code"></p><p><a href="http://mfa-mobile-registration.com/auth">Or click here to verify</a></p></body></html>`,
    expected: {
      classification: ['Credential Theft', 'Phishing'],
      threatRiskMin: 70,
      action: ['block', 'quarantine']
    },
    tags: ['quishing', 'qr_phishing']
  },
  {
    id: 'test-case-17-conversation-hijacking',
    name: '17. Conversation Hijacking / Thread Insertion',
    description: 'Hijacked existing email thread with forged supplier payment change',
    category: 'Business Email Compromise',
    groundTruth: 'Business Email Compromise',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=fail; dkim=none; dmarc=fail\nFrom: "Supplier Contact" <contact@suppller-parts.com>\nIn-Reply-To: <PREV-THREAD-9921@enterprise.com>\nReferences: <PREV-THREAD-9921@enterprise.com>\nTo: procurement@enterprise.com\nSubject: Re: Purchase Order PO-99182 Status & Delivery Schedule\nDate: Mon, 16 Sep 2026 19:30:00 +0000\nContent-Type: text/plain; charset="UTF-8"\n\nThanks for your patience. As previously discussed in this thread, please ensure the balance payment of $82,400 is sent to our updated bank details.\n`,
    expected: {
      classification: ['Business Email Compromise', 'Financial Fraud', 'Phishing'],
      threatRiskMin: 70,
      action: ['block', 'quarantine']
    },
    tags: ['thread_hijacking', 'supplier_spoof']
  },
  {
    id: 'test-case-18-google-impersonation',
    name: '18. Google Workspace Impersonation',
    description: 'Forged Google Admin storage alert targeting corporate Google credentials',
    category: 'Credential Theft',
    groundTruth: 'Phishing',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=fail smtp.mailfrom=google-admin-notice.com; dkim=none; dmarc=fail\nFrom: "Google Workspace Administrator" <admin@google-admin-notice.com>\nTo: staff@enterprise.com\nSubject: Google Drive Storage Full: Incoming emails are being blocked\nDate: Mon, 16 Sep 2026 20:00:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>Your Google Drive storage is 100% full. Upgrade storage immediately to prevent email loss:</p><p><a href="http://google-drive-quota-upgrade.com/login">Upgrade Storage Quota</a></p></body></html>`,
    expected: {
      classification: ['Credential Theft', 'Phishing'],
      threatRiskMin: 75,
      action: ['block', 'quarantine']
    },
    tags: ['google', 'brand_impersonation_check']
  },
  {
    id: 'test-case-19-reply-to-manipulation',
    name: '19. Reply-To Manipulation & Routing Anomaly',
    description: 'Discrepancy between From domain and Reply-To domain routing to external drop address',
    category: 'Business Email Compromise',
    groundTruth: 'Business Email Compromise',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=fail; dkim=none; dmarc=fail\nFrom: "Chief Financial Officer" <cfo@enterprise.com>\nReply-To: cfo.external.drop@protonmail.com\nTo: junior.accountant@enterprise.com\nSubject: Quick check on wire capabilities\nDate: Mon, 16 Sep 2026 20:30:00 +0000\nContent-Type: text/plain; charset="UTF-8"\n\nAre you available to process an urgent wire transfer today? Reply directly to this email.\n`,
    expected: {
      classification: ['Business Email Compromise', 'Executive Impersonation'],
      threatRiskMin: 70,
      action: ['block', 'quarantine']
    },
    tags: ['reply_to_mismatch', 'routing_anomaly']
  },
  {
    id: 'test-case-20-authentication-anomaly',
    name: '20. Severe Authentication & Header Forgery Anomaly',
    description: 'From header forged as internal executive but SPF, DKIM, and DMARC all completely fail',
    category: 'Phishing',
    groundTruth: 'Executive Impersonation',
    isHardNegative: false,
    rawEml: `Authentication-Results: spf=fail (IP 194.26.29.11 is not authorized); dkim=fail (body hash did not verify); dmarc=fail action=reject header.from=enterprise.com\nFrom: "Chief Executive Officer" <ceo@enterprise.com>\nTo: all-staff@enterprise.com\nSubject: Urgent Employee Performance Review and Benefits Document\nDate: Mon, 16 Sep 2026 21:00:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>Please log in to the external portal to complete your annual review:</p><p><a href="http://194.26.29.11/portal">Log In</a></p></body></html>`,
    expected: {
      classification: ['Executive Impersonation', 'Phishing', 'Credential Theft'],
      threatRiskMin: 75,
      action: ['block', 'quarantine']
    },
    tags: ['spf_dkim_forgery', 'header_anomaly']
  },
  {
    id: 'test-case-21-microsoft-false-positive-benchmark',
    name: '21. Microsoft False-Positive Benchmark (AI Agent Event)',
    description: 'High-signal technical invite from Microsoft containing external links but valid cryptographic provenance',
    category: 'Legitimate',
    groundTruth: 'Legitimate',
    isHardNegative: true,
    rawEml: `Authentication-Results: spf=pass smtp.mailfrom=microsoft.com; dkim=pass header.d=microsoft.com; dmarc=pass header.from=microsoft.com\nFrom: "Microsoft Developer Events" <events@microsoft.com>\nTo: engineer@enterprise.com\nSubject: Invitation: Microsoft AI Agentic Framework Deep Dive Workshop\nDate: Mon, 16 Sep 2026 21:30:00 +0000\nContent-Type: text/html; charset="UTF-8"\n\n<html><body><p>Join Microsoft engineers for an architectural session on Autonomous AI Agents.</p><p><a href="https://events.microsoft.com/ai-agents-workshop-2026">Register Free</a></p></body></html>`,
    expected: {
      classification: ['Legitimate'],
      threatRiskMax: 15,
      action: ['allow']
    },
    tags: ['legitimate', 'microsoft', 'bulk_legit']
  }
];
