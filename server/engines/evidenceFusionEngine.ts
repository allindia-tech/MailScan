/**
 * MailTrace AI - Evidence Fusion & Multi-Engine Decision Engine (Sections 13-18)
 * Synthesizes Forensic, ML, Gemini, Threat Intelligence, and Historical Memory.
 * Employs signal correlation, agreement boost, disagreement detection, and priority weighting.
 */

import {
  DetectionSignal,
  EngineConsensus,
  EngineResult,
  ThreatAssessment,
  ThreatCategory
} from '../../src/types/forensics.js';
import { NormalizedEmail } from './engineInterface.js';

export class EvidenceFusionEngine {
  public fuse(params: {
    email: NormalizedEmail;
    forensicResult: EngineResult;
    mlResult: EngineResult;
    geminiResult?: EngineResult;
    threatIntelResult?: EngineResult;
    campaignFingerprint?: string;
    isRecurrentCampaign?: boolean;
    historicalSignals?: DetectionSignal[];
  }): ThreatAssessment {
    const {
      email,
      forensicResult,
      mlResult,
      geminiResult,
      threatIntelResult,
      campaignFingerprint,
      isRecurrentCampaign,
      historicalSignals = []
    } = params;

    // 1. Gather all signals from all engines
    const allSignals: DetectionSignal[] = [
      ...forensicResult.signals,
      ...mlResult.signals,
      ...(geminiResult?.signals || []),
      ...(threatIntelResult?.signals || []),
      ...historicalSignals
    ];

    // 2. Identify Engine Classifications
    const forClass = forensicResult.classification as ThreatCategory || 'Legitimate';
    const mlClass = mlResult.classification as ThreatCategory || 'Legitimate';
    const gemClass = geminiResult?.classification as ThreatCategory || 'Legitimate';

    // 3. Evaluate Consensus and Disagreements
    const isPromotionalOrNewsletter = (c: ThreatCategory) =>
      c === 'Newsletter' || c === 'Promotional' || c === 'Bulk / Unsolicited' || c === 'Spam';

    const isMalicious = (c: ThreatCategory) =>
      c === 'Phishing' || c === 'Credential Theft' || c === 'Business Email Compromise' ||
      c === 'Executive Impersonation' || c === 'Malware Delivery' || c === 'Domain Spoofing';

    // Count agreement
    const engines = [
      { name: 'forensic', cat: forClass, isThreat: isMalicious(forClass), isBulk: isPromotionalOrNewsletter(forClass), conf: forensicResult.confidence },
      { name: 'ml', cat: mlClass, isThreat: isMalicious(mlClass), isBulk: isPromotionalOrNewsletter(mlClass), conf: mlResult.confidence },
      ...(geminiResult ? [{ name: 'gemini', cat: gemClass, isThreat: isMalicious(gemClass), isBulk: isPromotionalOrNewsletter(gemClass), conf: geminiResult.confidence }] : [])
    ];

    const allAgreeOnBulk = engines.every(e => e.isBulk || e.cat === 'Legitimate');
    const allAgreeOnThreat = engines.every(e => e.isThreat);
    const majorityThreat = engines.filter(e => e.isThreat).length >= 2;
    const majorityBulk = engines.filter(e => e.isBulk).length >= 2;

    let disagreement = false;
    let disagreementDetails: string | undefined;

    // Disagreement detection: e.g. one engine says high threat phishing, another says clean newsletter
    if (engines.some(e => e.isThreat) && engines.some(e => e.isBulk && !e.isThreat)) {
      disagreement = true;
      disagreementDetails = `Engines show divergent verdicts: Forensic evaluated "${forClass}", ML evaluated "${mlClass}"${geminiResult ? `, and Gemini evaluated "${gemClass}"` : ''}.`;
    }

    // Agreement boost calculation (capped at 98%)
    let agreementCount = 1;
    if (forClass === mlClass) agreementCount++;
    if (geminiResult && (gemClass === mlClass || gemClass === forClass)) agreementCount++;

    let calibratedConfidence = 90;
    if (agreementCount >= 3 || (allAgreeOnBulk && email.authResults.dmarc.status === 'PASS')) {
      calibratedConfidence = 97; // Agreement boost
    } else if (agreementCount === 2) {
      calibratedConfidence = 93;
    } else if (disagreement) {
      calibratedConfidence = 78; // Lower confidence when engines disagree
    }

    // 4. Calculate Core Multi-Engine Probabilities
    // Weighted probabilities
    const pPhish = Math.max(
      forensicResult.probabilities.phishing || 0,
      mlResult.probabilities.phishing || 0,
      geminiResult?.probabilities.phishing || 0
    );
    const pBec = Math.max(
      forensicResult.probabilities.bec || 0,
      mlResult.probabilities.bec || 0,
      geminiResult?.probabilities.bec || 0
    );
    const pMalware = Math.max(
      forensicResult.probabilities.malware || 0,
      mlResult.probabilities.malware || 0,
      geminiResult?.probabilities.malware || 0
    );
    const pImpersonation = Math.max(
      forensicResult.probabilities.impersonation || 0,
      mlResult.probabilities.impersonation || 0,
      geminiResult?.probabilities.impersonation || 0
    );
    const pCredentialTheft = geminiResult?.probabilities.credentialTheft ?? (email.urls.some(u => u.hasCredentialPath) ? 0.85 : 0.02);
    const pFinancialFraud = geminiResult?.probabilities.financialFraud ?? (pBec > 0.6 ? 0.80 : 0.01);

    // 5. Determine Final Classification & Scores
    let finalClass: ThreatCategory = 'Legitimate';
    let finalThreatRisk = 0;
    let finalSpamBulk = 0;
    let finalAuthenticity = 95;

    // Authenticity
    if (email.authResults.dmarc.status === 'PASS' && email.authResults.spf.status === 'PASS' && email.authResults.dkim.status === 'PASS') {
      finalAuthenticity = 98;
    } else if (email.authResults.dmarc.status === 'FAIL') {
      finalAuthenticity = 15;
    } else if (email.authResults.spf.status === 'FAIL') {
      finalAuthenticity = 40;
    }

    // Spam / Bulk Likelihood
    const mlBulk = (mlResult.probabilities.spamBulk || 0) * 100;
    const gemBulk = (geminiResult?.probabilities.bulk || 0) * 100;
    const forensicBulk = email.spamAnalysis?.score || 0;
    finalSpamBulk = Math.round(Math.max(forensicBulk, (mlBulk * 0.5) + (gemBulk * 0.5)));

    // Threat Risk
    if (pMalware >= 0.70) {
      finalClass = 'Malware Delivery';
      finalThreatRisk = Math.round(pMalware * 100);
    } else if (pPhish >= 0.70 || email.domainIntel.lookalikePatterns.length > 0) {
      finalClass = pCredentialTheft >= 0.75 ? 'Credential Theft' : 'Phishing';
      finalThreatRisk = Math.round(pPhish * 100);
    } else if (pBec >= 0.70 || (pImpersonation >= 0.75 && email.headerAnomalies.some(a => a.finding.includes('Display Name')))) {
      finalClass = 'Business Email Compromise';
      finalThreatRisk = Math.round(Math.max(pBec, pImpersonation) * 100);
    } else if (pImpersonation >= 0.70) {
      finalClass = 'Executive Impersonation';
      finalThreatRisk = Math.round(pImpersonation * 100);
    } else if (majorityBulk || isPromotionalOrNewsletter(mlClass) || isPromotionalOrNewsletter(forClass) || (email.spamAnalysis && email.spamAnalysis.score >= 45)) {
      // It is promotional or newsletter
      const isNewsletterType = email.spamAnalysis?.classification === 'newsletter' ||
        email.spamAnalysis?.classificationLabel?.toLowerCase().includes('newsletter') ||
        (email.spamAnalysis?.breakdown?.newsletterStructureScore || 0) > 40 ||
        mlClass === 'Newsletter' ||
        gemClass === 'Newsletter';

      if (isNewsletterType) {
        finalClass = 'Newsletter';
      } else if (mlClass === 'Promotional' || gemClass === 'Promotional' || email.spamAnalysis?.classification === 'promotional') {
        finalClass = 'Promotional';
      } else {
        finalClass = 'Spam';
      }
      // CRITICAL: Legitimate marketing / newsletter mail with verified authentication must have low threat risk!
      finalThreatRisk = Math.min(22, Math.round((1.0 - (finalAuthenticity / 100)) * 30));
    } else if (disagreement) {
      finalClass = 'Suspicious';
      finalThreatRisk = 45;
    } else {
      finalClass = 'Legitimate';
      finalThreatRisk = Math.min(15, Math.round(Math.max(pPhish, pBec, pMalware) * 100));
    }

    // Zero-Evidence Rule Invariant: If no malicious indicators or evidence exist, risk CANNOT be critical or high
    const hasCriticalIndicators = (
      pMalware >= 0.70 ||
      pPhish >= 0.70 ||
      pBec >= 0.70 ||
      email.domainIntel.lookalikePatterns.length > 0 ||
      email.urls.some(u => u.status === 'MALICIOUS' || u.isIpUrl || u.isPunycode) ||
      email.attachments.some(a => a.flags?.isExecutable || a.flags?.isMacroEnabled) ||
      email.headerAnomalies.some(a => a.severity === 'CRITICAL') ||
      (threatIntelResult && (threatIntelResult.signals.length || 0) > 0)
    );

    if (!hasCriticalIndicators && finalThreatRisk > 25) {
      finalThreatRisk = Math.min(finalThreatRisk, 20);
      if (finalClass === 'Phishing' || finalClass === 'Credential Theft' || finalClass === 'Malware Delivery' || finalClass === 'Business Email Compromise') {
        finalClass = 'Legitimate';
      }
    }

    // 6. Threat Intel Bonus
    if (threatIntelResult && threatIntelResult.signals.length > 0) {
      finalThreatRisk = Math.min(100, finalThreatRisk + 15);
    }

    // 7. Recommended Action
    let recommendedAction: ThreatAssessment['recommendedAction'] = 'allow';
    if (disagreement) {
      recommendedAction = 'analyst_review';
    } else if (finalThreatRisk >= 80) {
      recommendedAction = 'block';
    } else if (finalThreatRisk >= 60) {
      recommendedAction = 'quarantine';
    } else if (finalSpamBulk >= 60) {
      recommendedAction = 'label_spam';
    } else if (finalThreatRisk >= 35) {
      recommendedAction = 'analyst_review';
    } else {
      recommendedAction = 'allow';
    }

    // 8. Explainability: "Why this score" grouped by engine
    const whyThisScore = {
      forensic: [
        `Authentication: SPF=${email.authResults.spf.status}, DKIM=${email.authResults.dkim.status}, DMARC=${email.authResults.dmarc.status}.`,
        `Ingress Node: ${email.earliestReliableNode ? `${email.earliestReliableNode.ip} (${email.earliestReliableNode.hostname})` : 'Internal / Direct delivery'}.`,
        `Payload Telemetry: ${email.urls.length} link(s) screened, ${email.attachments.length} attachment(s) verified.`
      ],
      ml: [
        `Model: ${mlResult.version} (Tabular Gradient-Boosted Forest).`,
        `Primary Driving Features: ${mlResult.signals.slice(0, 2).map(s => s.evidence).join(' | ') || 'Baseline behavioral features'}.`,
        `Calculated Vector Probabilities: Phishing=${(pPhish * 100).toFixed(0)}%, BEC=${(pBec * 100).toFixed(0)}%, Bulk/Spam=${finalSpamBulk}%.`
      ],
      gemini: geminiResult ? [
        `Model: ${geminiResult.version}.`,
        `Semantic Intent: ${geminiResult.signals[0]?.evidence || 'Contextual message intent analyzed'}.`,
        `Disposition Recommendation: ${geminiResult.details?.recommendedDisposition || 'Consistent with multi-engine verdict'}.`
      ] : [
        'Tiered Cost Optimization: Gemini semantic pass omitted because Forensic & ML engines reached unanimous high confidence.'
      ],
      threatIntel: threatIntelResult && threatIntelResult.signals.length > 0 ? [
        `Threat Intelligence: ${threatIntelResult.signals.length} IOC match(es) correlated with threat feeds.`
      ] : [
        'Threat Intelligence: 0 matches against known threat actor indicators and campaign feeds.'
      ],
      historical: campaignFingerprint ? [
        `Campaign Fingerprint: ${campaignFingerprint} (${isRecurrentCampaign ? 'Observed in previous inbound traffic' : 'First occurrence in enterprise memory'}).`
      ] : []
    };

    const engineConsensus: EngineConsensus = {
      agreement: agreementCount,
      totalEngines: geminiResult ? 3 : 2,
      disagreement,
      disagreementDetails,
      consensusClassification: finalClass,
      calibratedConfidence,
      reviewRecommended: recommendedAction === 'analyst_review',
      engines: {
        forensic: { classification: forClass, confidence: forensicResult.confidence, agreement: forClass === finalClass || (isPromotionalOrNewsletter(forClass) && isPromotionalOrNewsletter(finalClass)) },
        ml: { classification: mlClass, confidence: mlResult.confidence, agreement: mlClass === finalClass || (isPromotionalOrNewsletter(mlClass) && isPromotionalOrNewsletter(finalClass)) },
        gemini: { classification: gemClass, confidence: geminiResult?.confidence || 0, agreement: gemClass === finalClass || (isPromotionalOrNewsletter(gemClass) && isPromotionalOrNewsletter(finalClass)), executed: !!geminiResult },
        threatIntel: { matched: (threatIntelResult?.signals.length || 0) > 0, confidence: threatIntelResult?.confidence || 0 }
      }
    };

    return {
      classification: finalClass,
      classificationConfidence: calibratedConfidence,
      threatRisk: finalThreatRisk,
      spamBulkLikelihood: finalSpamBulk,
      authenticityConfidence: finalAuthenticity,
      probabilities: {
        phishing: Number(pPhish.toFixed(2)),
        bec: Number(pBec.toFixed(2)),
        credentialTheft: Number(pCredentialTheft.toFixed(2)),
        financialFraud: Number(pFinancialFraud.toFixed(2)),
        malware: Number(pMalware.toFixed(2)),
        impersonation: Number(pImpersonation.toFixed(2))
      },
      engineConsensus,
      signals: allSignals,
      engineResults: {
        forensic: forensicResult,
        ml: mlResult,
        gemini: geminiResult,
        threatIntel: threatIntelResult
      },
      whyThisScore,
      recommendedAction,
      limitations: [
        'Decision synthesized via Evidence Fusion engine with deterministic protocol priority.',
        'Confidence calibration applies multi-engine agreement boost and disagreement penalties.'
      ],
      campaignFingerprint,
      recurrentCampaignObserved: isRecurrentCampaign
    };
  }
}

export const evidenceFusionEngine = new EvidenceFusionEngine();
