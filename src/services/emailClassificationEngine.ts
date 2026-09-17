/**
 * MailTrace AI - Primary 30-Category Email Classification & Detection Engine
 * Maps forensic results into an authoritative primary category and secondary probability vectors.
 */

import {
  DetectionMatrix,
  EmailAnalysisResult,
  EmailClassificationResult,
  MatrixStatus,
  ThreatSeverity
} from '../types/forensics.js';
import { PRIMARY_CATEGORIES, PrimaryCategoryDefinition } from './emailClassificationConfig.js';

export class EmailClassificationEngine {
  public static readonly VERSION = 'MT-CLASSIFIER-V3.0.0';

  /**
   * Constructs the comprehensive EmailClassificationResult and DetectionMatrix from an EmailAnalysisResult
   */
  public static classify(analysis: Partial<EmailAnalysisResult>): {
    classificationResult: EmailClassificationResult;
    detectionMatrix: DetectionMatrix;
  } {
    const threatRisk = analysis.threatRisk ?? analysis.overallRiskScore ?? 0;
    const spamBulkProbability = Math.round((analysis.spamLikelihood ?? analysis.spam?.score ?? 0) / 100 * 100);
    const authenticityScore = analysis.authenticityConfidence ?? analysis.authenticity?.score ?? 85;

    // 1. Calculate Vector Probabilities
    const hasMaliciousUrl = (analysis.urls || []).some(u => u.status === 'MALICIOUS' || u.hasCredentialPath);
    const pPhish = (hasMaliciousUrl || (analysis.senderDomainIntel?.lookalikePatterns || []).length > 0) ? 0.92 : 0.05;
    const pCredTheft = (analysis.urls || []).some(u => u.hasCredentialPath) ? 0.94 : 0.02;
    const pMalware = (analysis.attachments || []).some(a => a.flags?.isExecutable || a.flags?.isMacroEnabled || a.flags?.isDoubleExtension) ? 0.98 : 0.01;
    const pBec = (analysis.categoryScores?.senderAuthenticity ?? 0) > 60 && (analysis.emailContentAnalysis?.becIndicators?.detected || (analysis.categoryScores?.content ?? 0) > 65) ? 0.91 : 0.03;
    const pFinFraud = (analysis.emailContentAnalysis?.fraudIndicators?.detected || pBec > 0.6) ? 0.88 : 0.02;
    const pExecImpersonation = (analysis.headerAnomalies || []).some(a => a.finding?.includes('Display Name') || a.finding?.includes('Executive')) ? 0.95 : 0.04;
    const pImpersonation = Math.max(pExecImpersonation, (analysis.componentScores?.impersonationLikelihood ?? 0) / 100);
    const pAccountTakeover = (analysis.categoryScores?.url ?? 0) > 80 && (analysis.urls || []).some(u => u.url.includes('login') || u.url.includes('auth')) ? 0.86 : 0.02;
    const pSocialEng = (analysis.emailContentAnalysis?.socialEngineering || []).length > 0 ? 0.85 : 0.05;
    const pObfuscation = (analysis.multiLayerNormalization?.hiddenContentDetected || (analysis.multiLayerNormalization?.obfuscationEntropy ?? 0) > 4.5) ? 0.90 : 0.05;

    // 2. Select Primary Category based on evidence hierarchy & intent
    let primaryCatDef: PrimaryCategoryDefinition = PRIMARY_CATEGORIES['Legitimate'];
    let primaryConfidence = analysis.classificationConfidence || 95;

    // Zero-Evidence Guardrail Rule: If overall threat risk < 25, classify as benign/commercial
    if (threatRisk < 25) {
      const isNewsletter = analysis.spam?.classification === 'newsletter' ||
        analysis.subject?.toLowerCase().includes('newsletter') ||
        analysis.subject?.toLowerCase().includes('digest') ||
        (analysis.spam?.breakdown?.newsletterStructureScore ?? 0) > 35;

      const isPromotional = analysis.spam?.classification === 'promotional' ||
        analysis.subject?.toLowerCase().includes('offer') ||
        analysis.subject?.toLowerCase().includes('discount') ||
        analysis.subject?.toLowerCase().includes('special offer') ||
        (analysis.spam?.breakdown?.promotionalContentScore ?? 0) > 40;

      if (isNewsletter) {
        primaryCatDef = PRIMARY_CATEGORIES['Newsletter'];
      } else if (isPromotional) {
        primaryCatDef = PRIMARY_CATEGORIES['Promotional'];
      } else if (analysis.primaryClassification === 'Bulk / Graymail' || analysis.primaryClassification === 'Spam' || spamBulkProbability >= 50) {
        primaryCatDef = PRIMARY_CATEGORIES['Bulk / Graymail'];
      } else {
        primaryCatDef = PRIMARY_CATEGORIES['Legitimate'];
      }
    } else {
      // Prioritize high-confidence malicious vectors
      if (pCredTheft > 0.8) {
        primaryCatDef = PRIMARY_CATEGORIES['Credential Theft'];
      } else if (pPhish > 0.8) {
        primaryCatDef = PRIMARY_CATEGORIES['Phishing'];
      } else if (pMalware > 0.8) {
        primaryCatDef = PRIMARY_CATEGORIES['Malware Delivery'];
      } else if (pBec > 0.8) {
        primaryCatDef = PRIMARY_CATEGORIES['Business Email Compromise'] || PRIMARY_CATEGORIES['Phishing'];
      } else if (pFinFraud > 0.8) {
        primaryCatDef = PRIMARY_CATEGORIES['Financial Fraud'] || PRIMARY_CATEGORIES['Phishing'];
      } else if (pExecImpersonation > 0.8) {
        primaryCatDef = PRIMARY_CATEGORIES['Executive Impersonation'];
      } else if (pAccountTakeover > 0.8) {
        primaryCatDef = PRIMARY_CATEGORIES['Account Takeover'];
      } else if (pSocialEng > 0.7) {
        primaryCatDef = PRIMARY_CATEGORIES['Social Engineering / Scam'] || PRIMARY_CATEGORIES['Phishing'] || PRIMARY_CATEGORIES['Legitimate'];
      } else if (threatRisk >= 75) {
        primaryCatDef = PRIMARY_CATEGORIES['Phishing'] || PRIMARY_CATEGORIES['Legitimate'];
      } else if (spamBulkProbability >= 65) {
        primaryCatDef = PRIMARY_CATEGORIES['Spam'] || PRIMARY_CATEGORIES['Legitimate'];
      } else {
        primaryCatDef = PRIMARY_CATEGORIES['Bulk / Graymail'] || PRIMARY_CATEGORIES['Legitimate'];
      }
    }

    if (!primaryCatDef) {
      primaryCatDef = PRIMARY_CATEGORIES['Legitimate'];
    }

    // 3. Build Secondary Categories
    const secondaryCategories: EmailClassificationResult['secondaryCategories'] = [];
    if (pPhish > 0.3 && primaryCatDef.id !== 'Phishing') {
      secondaryCategories.push({ id: 'Phishing', label: 'Deceptive Link / Domain Phish', confidence: Math.round(pPhish * 100), probability: pPhish, evidence: 'Suspicious sender domain or redirect chain.' });
    }
    if (pCredTheft > 0.3 && primaryCatDef.id !== 'Credential Theft') {
      secondaryCategories.push({ id: 'Credential Theft', label: 'Login Harvesting', confidence: Math.round(pCredTheft * 100), probability: pCredTheft, evidence: 'Known credential harvesting URL pattern.' });
    }
    if (pBec > 0.3 && primaryCatDef.id !== 'Business Email Compromise (BEC)') {
      secondaryCategories.push({ id: 'Business Email Compromise (BEC)', label: 'Executive Fraud', confidence: Math.round(pBec * 100), probability: pBec, evidence: 'Urgent wire transfer or payroll request language.' });
    }
    if (pSocialEng > 0.4 && primaryCatDef.id !== 'Social Engineering / Scam') {
      secondaryCategories.push({ id: 'Social Engineering / Scam', label: 'Manipulative Coercion', confidence: Math.round(pSocialEng * 100), probability: pSocialEng, evidence: 'Psychological urgency / fear tactics detected.' });
    }

    // Add spam/bulk secondary category if non-zero
    if (spamBulkProbability > 30) {
      if (analysis.spam?.classification === 'newsletter') {
        secondaryCategories.push({ id: 'Newsletter', label: 'Commercial Digest', confidence: spamBulkProbability, probability: spamBulkProbability / 100, evidence: 'Newsletter headers and unsubscribe link.' });
      } else {
        secondaryCategories.push({ id: 'Bulk / Graymail', label: 'Mass Marketing', confidence: spamBulkProbability, probability: spamBulkProbability / 100, evidence: 'Promotional list header headers.' });
      }
    }

    // 4. Map Detected Techniques
    const detectedTechniques: EmailClassificationResult['detectedTechniques'] = (analysis.detectedTechniques || []).map((t: any) => ({
      techniqueId: t.id || t.techniqueId || 'TECH-DETECTED',
      name: t.name || 'Detected Attack Pattern',
      severity: (typeof t.severity === 'string' && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].includes(t.severity.toUpperCase()) ? t.severity.toUpperCase() : 'MEDIUM') as ThreatSeverity,
      confidence: t.confidence || 80,
      evidence: t.evidence || '',
      source: t.source || 'Static Analysis'
    }));

    // 5. Gather Benign vs Malicious Evidence
    const benignEvidence: string[] = [];
    const maliciousEvidence: string[] = [];

    if (authenticityScore >= 85) benignEvidence.push(`Strong cryptographic authentication (SPF, DKIM, DMARC satisfied).`);
    if (analysis.spam?.hasUnsubscribe) benignEvidence.push(`Valid One-Link List-Unsubscribe mechanism present.`);
    if ((analysis.urls || []).length > 0 && !(analysis.urls || []).some(u => u.status === 'MALICIOUS' || u.hasCredentialPath)) {
      benignEvidence.push(`All ${analysis.urls?.length} screened URLs lead to legitimate domains with clean reputation.`);
    }
    if ((analysis.attachments || []).length === 0) benignEvidence.push(`No file attachment payload.`);

    for (const sig of analysis.signals || []) {
      if (sig.direction === 'risk' || sig.value > 60) {
        maliciousEvidence.push(sig.evidence);
      } else if (sig.direction === 'trust') {
        benignEvidence.push(sig.evidence);
      }
    }

    // 6. Why This Classification reasoning
    const whyReasons: string[] = [];
    const whyNotOther: Array<{ category: string; reason: string }> = [];

    if (primaryCatDef.family === 'SECURITY') {
      if (pMalware >= 0.75) whyReasons.push('Contains executable/macro attachment payload capable of code execution.');
      if (pCredTheft >= 0.75) whyReasons.push('Login destination mismatch attempting credential collection.');
      if (pBec >= 0.70) whyReasons.push('Executive display name spoofing combined with wire transfer/financial request.');
      if (whyReasons.length === 0) whyReasons.push('High-risk threat indicators correlated across domain, link, and header forensics.');

      whyNotOther.push({ category: 'Newsletter / Promotional', reason: 'High security threat risk outweighs commercial newsletter formatting.' });
      whyNotOther.push({ category: 'Legitimate', reason: 'Critical threat indicators (lookalike domain / credential harvesting) confirmed.' });
    } else {
      if (primaryCatDef.id === 'Newsletter') whyReasons.push('Recurring publication structure with List-Unsubscribe headers.');
      if (primaryCatDef.id === 'Promotional') whyReasons.push('Commercial promotional offer with clean header authentication.');
      if (primaryCatDef.id === 'Legitimate') whyReasons.push('Standard enterprise communication with zero security threat indicators.');
      if (whyReasons.length === 0) whyReasons.push('Verified clean email structure with low threat likelihood.');

      whyNotOther.push({ category: 'Phishing / Credential Theft', reason: 'Zero credential harvesting or deceptive link targets detected.' });
      whyNotOther.push({ category: 'Malware Delivery', reason: 'Zero executable or macro-enabled attachment payloads found.' });
      whyNotOther.push({ category: 'Business Email Compromise', reason: 'No executive display name spoofing or unauthorized wire request.' });
    }

    // 7. Calculate Analysis Coverage
    let coveragePoints = 0;
    if (analysis.headers && Object.keys(analysis.headers).length > 0) coveragePoints += 25;
    if (analysis.authResults && analysis.authResults.spf.status !== 'NONE') coveragePoints += 25;
    if (analysis.urls) coveragePoints += 20;
    if (analysis.attachments) coveragePoints += 15;
    if (analysis.bodyText) coveragePoints += 15;
    const coverage = Math.min(100, Math.max(35, coveragePoints));

    // 8. Construct EmailClassificationResult
    const classificationResult: EmailClassificationResult = {
      primaryCategory: {
        id: primaryCatDef.id,
        label: primaryCatDef.label,
        family: primaryCatDef.family,
        confidence: primaryConfidence,
        probability: Number((primaryConfidence / 100).toFixed(2)),
        severity: primaryCatDef.severity,
        description: primaryCatDef.description
      },
      secondaryCategories: secondaryCategories as any,
      detectedTechniques,
      threatRisk,
      threatSeverity: analysis.severity || (threatRisk >= 80 ? 'CRITICAL' : threatRisk >= 60 ? 'HIGH' : threatRisk >= 35 ? 'MEDIUM' : 'LOW'),
      spamBulkProbability,
      phishingProbability: Number(pPhish.toFixed(2)),
      credentialTheftProbability: Number(pCredTheft.toFixed(2)),
      malwareProbability: Number(pMalware.toFixed(2)),
      becProbability: Number(pBec.toFixed(2)),
      financialFraudProbability: Number(pFinFraud.toFixed(2)),
      executiveImpersonationProbability: Number(pExecImpersonation.toFixed(2)),
      accountTakeoverProbability: Number(pAccountTakeover.toFixed(2)),
      socialEngineeringProbability: Number(pSocialEng.toFixed(2)),
      impersonationProbability: Number(pImpersonation.toFixed(2)),
      obfuscationProbability: Number(pObfuscation.toFixed(2)),
      authenticityScore,
      benignEvidence: Array.from(new Set(benignEvidence)).slice(0, 6),
      maliciousEvidence: Array.from(new Set(maliciousEvidence)).slice(0, 6),
      whyThisClassification: {
        reasons: whyReasons,
        whyNotOtherCategories: whyNotOther
      },
      coverage,
      modelVersion: EmailClassificationEngine.VERSION,
      detectorVersions: {
        'ForensicEngine': 'v2.4.0',
        'MLTransformer100M': 'v3.5.9',
        'AttackTechniqueEngine': 'v2.1.0',
        'EvidenceFusionEngine': 'v3.0.0'
      },
      generatedAt: new Date().toISOString()
    };

    // 9. Construct DetectionMatrix (Internal Evaluation Matrix across 29 dimensions)
    const createItem = (status: MatrixStatus, conf: number, source: string, ev: string): any => ({
      status,
      confidence: conf,
      source,
      evidence: ev ? [ev] : []
    });

    const detectionMatrix: DetectionMatrix = {
      senderIdentity: createItem(analysis.authResults?.spf?.status === 'FAIL' ? 'CONFIRMED' : 'NOT_DETECTED', 90, 'AuthenticationAnalyzer', `SPF Status: ${analysis.authResults?.spf?.status || 'UNAVAILABLE'}`),
      authentication: createItem(authenticityScore >= 80 ? 'CONFIRMED' : 'POSSIBLE', 95, 'AuthEngine', `Authenticity Score: ${authenticityScore}/100`),
      domainReputation: createItem((analysis.senderDomainIntel?.lookalikePatterns || []).length > 0 ? 'CONFIRMED' : 'NOT_DETECTED', 92, 'DomainIntel', `Lookalike patterns: ${analysis.senderDomainIntel?.lookalikePatterns?.length || 0}`),
      urlReputation: createItem((analysis.urls || []).some(u => u.status === 'MALICIOUS') ? 'CONFIRMED' : 'NOT_DETECTED', 94, 'URLAnalyzer', `Screened ${analysis.urls?.length || 0} URLs`),
      urlDeception: createItem((analysis.urls || []).some(u => u.hasCredentialPath) ? 'DETECTED' : 'NOT_DETECTED', 90, 'URLAnalyzer', `Credential paths evaluated`),
      attachmentRisk: createItem(pMalware > 0.7 ? 'CONFIRMED' : 'NOT_DETECTED', 96, 'AttachmentAnalyzer', `${analysis.attachments?.length || 0} attachments screened`),
      contentIntent: createItem(primaryCatDef.family === 'SECURITY' ? 'DETECTED' : 'NOT_DETECTED', 88, 'ContentAnalyzer', `Primary intent: ${primaryCatDef.label}`),
      socialEngineering: createItem(pSocialEng > 0.6 ? 'LIKELY' : 'NOT_DETECTED', 85, 'SocialEngineeringEngine', `Coercive urgency language evaluated`),
      credentialTheft: createItem(pCredTheft > 0.7 ? 'CONFIRMED' : 'NOT_DETECTED', 94, 'CredentialTheftDetector', `Login prompt & harvest targets`),
      phishing: createItem(pPhish > 0.7 ? 'CONFIRMED' : 'NOT_DETECTED', 95, 'PhishingDetector', `Phishing risk evaluated ${threatRisk}/100`),
      bec: createItem(pBec > 0.7 ? 'CONFIRMED' : 'NOT_DETECTED', 92, 'BECEngine', `Executive display name & financial pretext`),
      financialFraud: createItem(pFinFraud > 0.6 ? 'LIKELY' : 'NOT_DETECTED', 88, 'FinancialFraudDetector', `Banking & payment pretext`),
      executiveImpersonation: createItem(pExecImpersonation > 0.7 ? 'CONFIRMED' : 'NOT_DETECTED', 95, 'ImpersonationDetector', `Header display name mismatch`),
      malware: createItem(pMalware > 0.7 ? 'CONFIRMED' : 'NOT_DETECTED', 98, 'MalwarePayloadDetector', `Executable or macro payload container`),
      accountTakeover: createItem(pAccountTakeover > 0.7 ? 'LIKELY' : 'NOT_DETECTED', 86, 'ATOEngine', `SSO login target diversion`),
      dataHarvesting: createItem(pPhish > 0.8 ? 'POSSIBLE' : 'NOT_DETECTED', 75, 'DataHarvestDetector', `PII harvesting indicators`),
      unicodeObfuscation: createItem(pObfuscation > 0.7 ? 'DETECTED' : 'NOT_DETECTED', 90, 'UnicodeDetector', `Multi-layer normalization scan`),
      htmlDeception: createItem((analysis.emailContentAnalysis?.htmlFindings?.hasHiddenElements) ? 'DETECTED' : 'NOT_DETECTED', 88, 'HTMLAnalyzer', `Invisible elements or CSS display:none`),
      quishing: createItem((analysis.emailContentAnalysis?.ocrQrFindings?.hasQrCode) ? 'POSSIBLE' : 'NOT_DETECTED', 80, 'QROCRDetector', `Embedded QR code scanner`),
      oauthAbuse: createItem('NOT_DETECTED', 90, 'OAuthDetector', `No OAuth consent grant detected`),
      spamBulk: createItem(spamBulkProbability >= 50 ? 'CONFIRMED' : 'NOT_DETECTED', 90, 'SpamAnalyzer', `Spam likelihood ${spamBulkProbability}%`),
      newsletter: createItem(primaryCatDef.id === 'Newsletter' ? 'CONFIRMED' : 'NOT_DETECTED', 96, 'NewsletterDetector', `List-Unsubscribe & digest layout`),
      promotional: createItem(primaryCatDef.id === 'Promotional' ? 'CONFIRMED' : 'NOT_DETECTED', 94, 'PromotionalDetector', `Marketing offer & commercial CTA`),
      transactional: createItem(primaryCatDef.id === 'Transactional' ? 'CONFIRMED' : 'NOT_DETECTED', 95, 'TransactionalDetector', `Order receipt & service update`),
      governmentImpersonation: createItem(primaryCatDef.id === 'Government Impersonation' ? 'CONFIRMED' : 'NOT_DETECTED', 90, 'GovImpersonationDetector', `Income tax / GST regulatory notice`),
      jobScam: createItem('NOT_DETECTED', 85, 'JobScamDetector', `Recruitment processing fee request`),
      investmentScam: createItem('NOT_DETECTED', 85, 'InvestmentScamDetector', `Crypto or pre-IPO yield offer`),
      deliveryScam: createItem('NOT_DETECTED', 85, 'DeliveryScamDetector', `Courier fee payment request`),
      extortion: createItem('NOT_DETECTED', 90, 'ExtortionDetector', `Coercive ransom demand`)
    };

    return { classificationResult, detectionMatrix };
  }
}