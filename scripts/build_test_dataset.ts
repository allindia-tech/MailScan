/**
 * MailTrace AI — Test Dataset Builder
 * ====================================
 * Extracts and organizes all authoritative test emails as real RFC 822 / MIME (.eml)
 * files under dataset/testing/emails/<category>/<caseId>.eml
 * and builds the authoritative dataset/testing/manifest.json.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { TestDatasetLoader } from '../server/testing/testDatasetLoader.js';

const TESTING_ROOT = path.resolve('dataset/testing');
const EMAILS_ROOT = path.join(TESTING_ROOT, 'emails');

interface ManifestCase {
  id: string;
  name: string;
  description: string;
  category: string;
  file: string;
  sha256: string;
  groundTruth: string;
  isHardNegative: boolean;
  expected: {
    classification?: string[];
    threatRiskMin?: number;
    threatRiskMax?: number;
    spamLikelihoodMin?: number;
    spamLikelihoodMax?: number;
    authenticityMin?: number;
    authenticityMax?: number;
    action?: string[];
  };
  tags: string[];
}

interface TestManifest {
  version: string;
  description: string;
  source: string;
  totalCases: number;
  labeledCases: number;
  unlabeledCases: number;
  generatedAt: string;
  categories: Record<string, number>;
  cases: ManifestCase[];
}

function getCategorySubdir(id: string, groundTruth: string): string {
  if (id.includes('microsoft')) return 'microsoft';
  if (id.includes('google')) return 'google';
  if (id.includes('bank') || id.includes('financial')) return 'financial';
  if (id.includes('newsletter')) return 'newsletter';
  if (id.includes('promotional')) return 'promotional';
  if (id.includes('credential')) return 'credential_theft';
  if (id.includes('lookalike') || id.includes('domain')) return 'lookalike_domains';
  if (id.includes('url')) return 'malicious_urls';
  if (id.includes('bec')) return 'bec';
  if (id.includes('malware')) return 'malware';
  if (id.includes('unicode')) return 'unicode_obfuscation';
  if (id.includes('ascii')) return 'ascii_smuggling';
  if (id.includes('otp')) return 'otp_scam';
  if (id.includes('qr')) return 'quishing';
  if (id.includes('conversation')) return 'conversation_hijacking';
  if (id.includes('reply-to')) return 'routing_anomalies';
  if (id.includes('auth')) return 'auth_anomalies';
  return groundTruth.toLowerCase().replace(/[^a-z0-9]/g, '_');
}

function buildTags(id: string, groundTruth: string): string[] {
  const tags: string[] = [groundTruth.toLowerCase()];
  if (id.includes('microsoft')) tags.push('microsoft', 'brand_impersonation_check');
  if (id.includes('google')) tags.push('google', 'brand_impersonation_check');
  if (id.includes('newsletter')) tags.push('newsletter', 'bulk_legit');
  if (id.includes('promotional')) tags.push('promotional', 'marketing');
  if (id.includes('credential')) tags.push('credential_harvesting', 'phishing');
  if (id.includes('lookalike')) tags.push('lookalike_domain', 'typosquatting');
  if (id.includes('url')) tags.push('malicious_url', 'ip_destination');
  if (id.includes('bec')) tags.push('bec', 'wire_fraud', 'executive_impersonation');
  if (id.includes('financial')) tags.push('invoice_fraud', 'bank_diversion');
  if (id.includes('malware')) tags.push('attachment_macro', 'malware_delivery');
  if (id.includes('unicode')) tags.push('unicode_homoglyph', 'punycode');
  if (id.includes('ascii')) tags.push('ascii_smuggling', 'hidden_payload');
  if (id.includes('otp')) tags.push('otp_fraud', 'kyc_scam');
  if (id.includes('qr')) tags.push('quishing', 'qr_phishing');
  if (id.includes('conversation')) tags.push('thread_hijacking', 'supplier_spoof');
  if (id.includes('reply-to')) tags.push('reply_to_mismatch', 'routing_anomaly');
  if (id.includes('auth')) tags.push('spf_dkim_forgery', 'header_anomaly');
  return Array.from(new Set(tags));
}

async function main() {
  console.log('Building authoritative test dataset in dataset/testing/ ...');
  fs.mkdirSync(EMAILS_ROOT, { recursive: true });

  const loader = new TestDatasetLoader();
  const testCases = loader.loadAllTestCases();

  const manifestCases: ManifestCase[] = [];
  const categoryCounts: Record<string, number> = {};

  for (const tc of testCases) {
    const categoryDirName = getCategorySubdir(tc.id, tc.groundTruth);
    const categoryPath = path.join(EMAILS_ROOT, categoryDirName);
    fs.mkdirSync(categoryPath, { recursive: true });

    const emlFileName = `${tc.id}.eml`;
    const emlFilePath = path.join(categoryPath, emlFileName);
    const relativeFilePath = path.relative(TESTING_ROOT, emlFilePath);

    // Write raw EML file
    fs.writeFileSync(emlFilePath, tc.rawEml.trim() + '\n', 'utf-8');

    // Calculate SHA-256
    const hash = crypto.createHash('sha256').update(tc.rawEml.trim()).digest('hex');

    const tags = buildTags(tc.id, tc.groundTruth);
    categoryCounts[tc.groundTruth] = (categoryCounts[tc.groundTruth] || 0) + 1;

    const mCase: ManifestCase = {
      id: tc.id,
      name: tc.name,
      description: tc.description,
      category: tc.groundTruth,
      file: relativeFilePath,
      sha256: hash,
      groundTruth: tc.groundTruth,
      isHardNegative: !!tc.isHardNegative,
      expected: tc.expected,
      tags
    };

    manifestCases.push(mCase);

    // Also write sidecar .meta.json
    const metaPath = path.join(categoryPath, `${tc.id}.meta.json`);
    fs.writeFileSync(metaPath, JSON.stringify(mCase, null, 2), 'utf-8');
  }

  // Add 3 edge-case unlabeled emails to test crash resistance & parser stability
  const edgeCasesDir = path.join(EMAILS_ROOT, 'edge_cases');
  fs.mkdirSync(edgeCasesDir, { recursive: true });

  const edgeCases = [
    {
      id: 'edge-case-01-multipart-nested-boundary',
      name: 'Edge Case 1: Nested MIME Multipart with Empty Part',
      rawEml: `From: test@example.org\nTo: user@example.org\nSubject: Test Nested Multipart\nContent-Type: multipart/mixed; boundary="BOUNDARY_1"\n\n--BOUNDARY_1\nContent-Type: text/plain\n\nHello\n--BOUNDARY_1\nContent-Type: multipart/alternative; boundary="BOUNDARY_2"\n\n--BOUNDARY_2\nContent-Type: text/html\n\n<b>Hello HTML</b>\n--BOUNDARY_2--\n--BOUNDARY_1--\n`
    },
    {
      id: 'edge-case-02-utf8-encoded-words',
      name: 'Edge Case 2: RFC 2047 Encoded Words in Subject and Headers',
      rawEml: `From: =?UTF-8?B?U2VjdXJpdHkgVGVhbQ==?= <alerts@example.com>\nTo: target@example.com\nSubject: =?UTF-8?Q?Security_Alert_=E2=9A=A0_Action_Required?=\nDate: Wed, 18 Mar 2026 12:00:00 +0000\nContent-Type: text/plain; charset="UTF-8"\n\nPlease review your security settings.\n`
    },
    {
      id: 'edge-case-03-empty-headers-raw-body',
      name: 'Edge Case 3: Raw Body with Minimal Incomplete Headers',
      rawEml: `Subject: Quick notice\n\nNotice content with no other headers present.\n`
    }
  ];

  for (const ec of edgeCases) {
    const emlPath = path.join(edgeCasesDir, `${ec.id}.eml`);
    fs.writeFileSync(emlPath, ec.rawEml, 'utf-8');
    const hash = crypto.createHash('sha256').update(ec.rawEml).digest('hex');
    const relPath = path.relative(TESTING_ROOT, emlPath);

    const mCase: ManifestCase = {
      id: ec.id,
      name: ec.name,
      description: 'Edge case fixture for parser stability testing',
      category: 'UNLABELED',
      file: relPath,
      sha256: hash,
      groundTruth: 'UNLABELED',
      isHardNegative: false,
      expected: {
        classification: []
      },
      tags: ['edge_case', 'unlabeled', 'parser_stability']
    };

    manifestCases.push(mCase);
    const metaPath = path.join(edgeCasesDir, `${ec.id}.meta.json`);
    fs.writeFileSync(metaPath, JSON.stringify(mCase, null, 2), 'utf-8');
  }

  const manifest: TestManifest = {
    version: '1.0.0',
    description: 'MailTrace AI Authoritative Security & Forensic Test Dataset',
    source: 'dataset/testing/',
    totalCases: manifestCases.length,
    labeledCases: manifestCases.filter(c => c.category !== 'UNLABELED').length,
    unlabeledCases: manifestCases.filter(c => c.category === 'UNLABELED').length,
    generatedAt: new Date().toISOString(),
    categories: categoryCounts,
    cases: manifestCases
  };

  const manifestPath = path.join(TESTING_ROOT, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2), 'utf-8');

  console.log(`✓ Test dataset successfully compiled:`);
  console.log(`  Total Cases     : ${manifest.totalCases}`);
  console.log(`  Labeled Cases   : ${manifest.labeledCases}`);
  console.log(`  Unlabeled Cases : ${manifest.unlabeledCases}`);
  console.log(`  Manifest File   : ${manifestPath}`);
}

main().catch(err => {
  console.error('Error compiling test dataset:', err);
  process.exit(1);
});
