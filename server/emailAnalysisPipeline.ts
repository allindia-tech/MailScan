/**
 * MailTrace AI - Master Forensic Analysis Pipeline
 */

import { EmailAnalysisResult, EngineResult } from '../src/types/forensics.js';
import { parseRawEmail } from './analyzers/emailParser.js';
import { reconstructRelayPath } from './analyzers/relayAnalyzer.js';
import { analyzeDomain } from './analyzers/domainAnalyzer.js';
import { analyzeAuthentication } from './analyzers/authAnalyzer.js';
import { analyzeIP } from './analyzers/ipAnalyzer.js';
import { analyzeURLs } from './analyzers/urlAnalyzer.js';
import { analyzeAttachments } from './analyzers/attachmentAnalyzer.js';
import { detectHeaderAnomalies } from './analyzers/anomalyDetector.js';
import { extractIOCs } from './analyzers/iocExtractor.js';
import { buildRelationshipGraph } from './analyzers/graphBuilder.js';
import { classifyEmailThreat } from './analyzers/aiThreatClassifier.js';
import { threatIntelEngine } from './analyzers/threatIntelEngine.js';
import { analyzeSpamAndBulk } from './analyzers/spamBulkAnalyzer.js';
import { analyzeEmailContent } from './analyzers/emailContentAnalyzer.js';
import { socStore } from './store.js';

// Multi-Engine Architecture Imports (Sections 48-51)
import { NormalizedEmail } from './engines/engineInterface.js';
import { forensicEngine } from './engines/forensicEngine.js';
import { mlThreatEngine } from './engines/mlThreatEngine.js';
import { geminiThreatEngine } from './engines/geminiThreatEngine.js';
import { evidenceFusionEngine } from './engines/evidenceFusionEngine.js';
import { campaignMemory } from './engines/campaignMemory.js';
import { AttackTechniqueDetectionEngine } from '../src/services/attackTechniqueEngine.js';
import { EmailClassificationEngine } from '../src/services/emailClassificationEngine.js';

import crypto from 'crypto';

export async function runEmailAnalysisPipeline(
  rawEmail: string,
  scenarioId?: string,
  forceGemini?: boolean,
  options?: { skipExternalAI?: boolean }
): Promise<EmailAnalysisResult> {
  const analysisId = scenarioId || `analysis-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  
  // 1. Parse raw email into MIME structure and headers
  const parsed = parseRawEmail(rawEmail);

  // 2. Reconstruct SMTP Relay Path & isolate untrusted ingress boundary
  const { relayPath, earliestReliableNode } = reconstructRelayPath(parsed.receivedHeaders, parsed.headers);

  // 3. Domain Intelligence & Lookalike Pattern Sweeper
  const domainIntel = analyzeDomain(parsed.fromDomain, parsed.from);

  // 4. IP Intelligence on all relay hops and domain A records
  const allIpStrings = Array.from(new Set([
    ...relayPath.map(r => r.ip).filter(ip => ip && ip !== 'Unknown IP'),
    ...domainIntel.aRecords
  ]));
  const ips = allIpStrings.map(analyzeIP);

  // 5. SPF, DKIM, DMARC Authentication Engine
  const authResults = analyzeAuthentication(
    parsed.authResultsHeader || '',
    parsed.fromDomain,
    parsed.returnPath,
    earliestReliableNode?.ip || '127.0.0.1',
    parsed.dkimSignatures
  );

  // 6. Header Anomalies and Spoofing Checks
  const { score: headerAnomalyScore, anomalies: headerAnomalies } = detectHeaderAnomalies(parsed);

  // 7. URL Security Sandbox Extraction
  const urls = analyzeURLs(parsed.bodyText, parsed.bodyHtml);

  // 8. Attachment Static Analysis & Hashing
  const attachments = analyzeAttachments(parsed.attachments);

  // 9. IOC Consolidator
  const iocs = extractIOCs(
    ips,
    parsed.fromDomain,
    parsed.from,
    parsed.replyTo,
    parsed.messageId,
    urls,
    attachments
  );

  // 9.5. Correlate with Simulated Threat Intelligence Feed
  const threatIntelCorrelation = threatIntelEngine.correlateEmail({
    relayPath,
    earliestReliableNode,
    ips,
    domainIntel,
    fromDomain: parsed.fromDomain,
    fromEmail: parsed.from,
    replyTo: parsed.replyTo,
    returnPath: parsed.returnPath,
    urls,
    attachments
  });

  // Cross-tag matched IOCs with Simulated Threat Intelligence context
  for (const ioc of iocs) {
    const matched = threatIntelCorrelation.matches.find(
      m => m.indicator.toLowerCase() === ioc.indicator.toLowerCase()
    );
    if (matched) {
      ioc.risk = matched.severity;
      ioc.context = `[SIMULATED THREAT INTEL] Matched ${matched.matchedFeedEntry.threatName} (${matched.matchedFeedEntry.threatActor || 'Unattributed'})`;
    }
  }

  // 9.8. Dedicated Spam & Bulk Analysis Engine (Orthogonal to Threat Risk)
  const spamAnalysis = analyzeSpamAndBulk(parsed, urls);

  // 9.9. Complete Email Content & Intent Analysis Engine
  const emailContentAnalysis = analyzeEmailContent(parsed, urls);

  // =========================================================================
  // 10. HYBRID MULTI-ENGINE EXECUTION PIPELINE (Sections 48-51)
  // =========================================================================
  const normalizedEmail: NormalizedEmail = {
    id: analysisId,
    rawMime: rawEmail,
    subject: parsed.subject,
    from: parsed.from,
    fromName: parsed.fromName,
    fromDomain: parsed.fromDomain,
    to: parsed.to,
    cc: parsed.cc,
    replyTo: parsed.replyTo,
    returnPath: parsed.returnPath,
    messageId: parsed.messageId,
    date: parsed.date,
    userAgent: parsed.userAgent || undefined,
    xMailer: parsed.xMailer || undefined,
    headers: parsed.headers,
    rawHeaders: parsed.rawHeaders,
    bodyText: parsed.bodyText,
    bodyHtml: parsed.bodyHtml || undefined,
    normalizedText: parsed.bodyText.replace(/\s+/g, ' ').trim(),
    urls,
    attachments,
    authResults,
    relayPath,
    earliestReliableNode,
    domainIntel,
    ips,
    headerAnomalies,
    spamAnalysis
  };

  const engineContext = {
    scenarioId,
    timestamp: new Date().toISOString(),
    threatIntelCorrelation,
    forceGemini,
    skipExternalAI: options?.skipExternalAI
  };

  // Execute Engine A: Forensic Protocol Engine
  const forensicResult = await forensicEngine.analyze(normalizedEmail, engineContext);

  // Execute Engine B: Self-Learning Tabular Machine Learning Model
  const mlResult = await mlThreatEngine.analyze(normalizedEmail, engineContext);

  // Execute Engine C: Gemini AI Semantic Analysis (Tiered invocation)
  let geminiResult: EngineResult | undefined = undefined;
  if (geminiThreatEngine.shouldInvoke(normalizedEmail, mlResult.confidence, engineContext)) {
    geminiResult = await geminiThreatEngine.analyze(normalizedEmail, engineContext);
  }

  // Execute Campaign Fingerprinting & Detection Memory
  const initialEstRisk = mlResult.probabilities.threat ? Math.round(mlResult.probabilities.threat * 100) : 20;
  const memoryCorr = campaignMemory.rememberAndCorrelate(normalizedEmail, initialEstRisk);

  // Wrap Threat Intelligence Engine result if matches found
  let threatIntelResult: EngineResult | undefined = undefined;
  if (threatIntelCorrelation && threatIntelCorrelation.matchedIndicatorsCount > 0) {
    threatIntelResult = {
      engine: 'threat-intel-feed',
      version: 'Feed v2026.03',
      classification: 'Correlated Threat Actor Activity',
      probabilities: { threat: 0.90 },
      signals: threatIntelCorrelation.matches.map(m => ({
        id: `ti-match-${m.indicator}`,
        category: 'threat-intelligence',
        severity: m.severity.toLowerCase() as any,
        confidence: m.confidence,
        source: 'threat_intel',
        evidence: `Threat feed correlation: Indicator "${m.indicator}" matches ${m.matchedFeedEntry.threatName} (${m.matchedFeedEntry.threatActor || 'Unclassified'}).`,
        relatedIndicators: [m.indicator]
      })),
      confidence: 90,
      processingTimeMs: 5,
      status: 'COMPLETED'
    };
  }

  // Evidence Fusion Engine (The Core Synthesizer)
  const fusedAssessment = evidenceFusionEngine.fuse({
    email: normalizedEmail,
    forensicResult,
    mlResult,
    geminiResult,
    threatIntelResult,
    campaignFingerprint: memoryCorr.fingerprint,
    isRecurrentCampaign: memoryCorr.isRecurrent,
    historicalSignals: memoryCorr.signals
  });

  // 10.5. Backward-Compatible AI Threat Classifier (produces detailed categoryScores, componentScores, audit)
  const threatOutput = await classifyEmailThreat({
    subject: parsed.subject,
    from: parsed.from,
    fromDomain: parsed.fromDomain,
    replyTo: parsed.replyTo,
    returnPath: parsed.returnPath,
    bodyText: parsed.bodyText,
    headerAnomalies,
    authResults,
    relayPath,
    earliestReliableNode,
    domainIntel,
    ips,
    urls,
    attachments,
    threatIntelCorrelation,
    scoringVersion: '2.4.0-hybrid',
    spamAnalysis
  });

  // Reconcile and align with Evidence Fusion engine output
  threatOutput.overallRiskScore = fusedAssessment.threatRisk;
  threatOutput.threatRisk = fusedAssessment.threatRisk;
  threatOutput.spamLikelihood = fusedAssessment.spamBulkLikelihood;
  threatOutput.authenticityConfidence = fusedAssessment.authenticityConfidence;
  threatOutput.primaryClassification = fusedAssessment.classification;
  threatOutput.classificationConfidence = fusedAssessment.classificationConfidence;
  threatOutput.severity = fusedAssessment.threatRisk >= 80 ? 'CRITICAL' : (
    fusedAssessment.threatRisk >= 60 ? 'HIGH' : (
      fusedAssessment.threatRisk >= 35 ? 'MEDIUM' : (
        fusedAssessment.threatRisk >= 20 ? 'LOW' : 'TRUSTED'
      )
    )
  );

  // 11. Correlate with Campaign
  let matchedCampaign: { id: string; name: string } | undefined = undefined;
  for (const [, camp] of socStore.campaigns) {
    if (
      (camp.commonDomain && parsed.fromDomain.toLowerCase().includes(camp.commonDomain.toLowerCase())) ||
      (camp.commonIp && ips.some(i => i.ip === camp.commonIp)) ||
      (parsed.subject.toLowerCase().includes('invoice') && camp.name.includes('Invoice')) ||
      (parsed.subject.toLowerCase().includes('confidential') && camp.name.includes('Executive'))
    ) {
      matchedCampaign = { id: camp.id, name: camp.name };
      break;
    }
  }

  // 12. Build Relationship Graph
  const graph = buildRelationshipGraph(
    parsed.subject,
    parsed.from,
    domainIntel,
    ips,
    urls,
    attachments,
    matchedCampaign?.name
  );

  // 13. Assemble Final Forensic Document with Tripartite Confidence & Auditing
  const result: EmailAnalysisResult = {
    id: analysisId,
    analyzedAt: new Date().toISOString(),
    subject: parsed.subject,
    from: parsed.from,
    fromName: parsed.fromName,
    fromDomain: parsed.fromDomain,
    to: parsed.to,
    cc: parsed.cc,
    replyTo: parsed.replyTo,
    returnPath: parsed.returnPath,
    messageId: parsed.messageId,
    date: parsed.date,
    userAgent: parsed.userAgent || undefined,
    xMailer: parsed.xMailer || undefined,
    overallRiskScore: threatOutput.overallRiskScore,
    threatRisk: threatOutput.threatRisk,
    spamLikelihood: threatOutput.spamLikelihood,
    authenticityConfidence: threatOutput.authenticityConfidence,
    severity: threatOutput.severity,
    primaryClassification: threatOutput.primaryClassification,
    classificationConfidence: threatOutput.classificationConfidence,
    threatConfidence: threatOutput.threatConfidence,
    originConfidence: threatOutput.originConfidence,
    attributionConfidence: threatOutput.attributionConfidence,
    categoryScores: threatOutput.categoryScores,
    componentScores: threatOutput.componentScores,
    signals: threatOutput.signals,
    correlationBonus: threatOutput.correlationBonus,
    scoringVersion: threatOutput.scoringVersion,
    scoreExplanation: threatOutput.scoreExplanation,
    secondaryClassifications: threatOutput.secondaryClassifications,
    findings: threatOutput.findings,
    spam: threatOutput.spam,
    authenticity: threatOutput.authenticity,
    threatDetails: threatOutput.threatDetails,
    scoringAudit: threatOutput.scoringAudit,
    headers: parsed.headers,
    rawHeaders: parsed.rawHeaders,
    headerAnomalyScore,
    headerAnomalies,
    authResults,
    relayPath,
    earliestReliableNode,
    ips,
    senderDomainIntel: domainIntel,
    urls,
    attachments,
    iocs,
    threatIntelCorrelation,
    assessment: threatOutput.assessment,
    graph,
    bodyText: parsed.bodyText,
    bodyHtml: parsed.bodyHtml || undefined,
    rawMime: rawEmail,
    matchedCampaignId: matchedCampaign?.id,
    matchedCampaignName: matchedCampaign?.name,
    campaignFingerprint: memoryCorr.fingerprint,
    threatAssessment: fusedAssessment,
    engineConsensus: fusedAssessment.engineConsensus,
    whyThisScore: fusedAssessment.whyThisScore,
    emailContentAnalysis
  };

  // 12.5. Run Advanced Attack Technique Detection Engine
  const techniqueAnalysis = AttackTechniqueDetectionEngine.analyze({
    from: parsed.from,
    senderDomain: parsed.fromDomain,
    replyTo: parsed.replyTo,
    returnPath: parsed.returnPath,
    subject: parsed.subject,
    bodyText: parsed.bodyText,
    bodyHtml: parsed.bodyHtml || undefined,
    rawMime: rawEmail,
    urls: urls.map(u => ({ url: u.url, domain: u.domain, isShortened: u.isShortened, hasCredentialPath: u.hasCredentialPath })),
    attachments: attachments.map(a => ({ filename: a.filename, mimeType: a.mimeType, isExecutable: a.flags.isExecutable, isMacroEnabled: a.flags.isMacroEnabled, isDoubleExtension: a.flags.isDoubleExtension })),
    spfStatus: authResults.spf.status,
    dkimStatus: authResults.dkim.status,
    dmarcStatus: authResults.dmarc.status
  });

  result.detectedTechniques = techniqueAnalysis.detectedTechniques;
  result.multiLayerNormalization = techniqueAnalysis.normalization;

  // 12.6. Synthesize Authoritative Primary EmailClassificationResult & DetectionMatrix
  const synth = EmailClassificationEngine.classify(result);
  result.classificationResult = synth.classificationResult;
  result.detectionMatrix = synth.detectionMatrix;
  result.primaryClassification = synth.classificationResult.primaryCategory.id as any;

  // 12.7. Authoritative Canonical AnalysisVerdict (Section 3)
  const canonicalVerdict: import('../src/types/forensics.js').AnalysisVerdict = {
    analysisId: result.id,
    modelVersion: 'mailtrace-100m-v2',
    verdictVersion: '2.5.0-authoritative',
    primaryCategory: result.primaryClassification,
    secondaryCategories: (result.secondaryClassifications || []) as any,
    threatRisk: result.overallRiskScore,
    spamBulkProbability: result.spamLikelihood,
    authenticityScore: result.authenticityConfidence,
    phishingProbability: fusedAssessment.probabilities.phishing || 0,
    fraudProbability: fusedAssessment.probabilities.financialFraud || 0,
    becProbability: fusedAssessment.probabilities.bec || 0,
    malwareProbability: fusedAssessment.probabilities.malware || 0,
    credentialTheftProbability: fusedAssessment.probabilities.credentialTheft || 0,
    impersonationProbability: fusedAssessment.probabilities.impersonation || 0,
    socialEngineeringProbability: techniqueAnalysis.detectedTechniques.length > 0 ? 0.75 : 0.05,
    obfuscationProbability: techniqueAnalysis.normalization.hiddenContentDetected || (techniqueAnalysis.normalization.obfuscationEntropy > 4.5) ? 0.85 : 0.02,
    classificationConfidence: result.classificationConfidence,
    severity: result.severity,
    detectedTechniques: techniqueAnalysis.detectedTechniques,
    evidence: fusedAssessment.signals.filter(s => s.severity === 'critical' || s.severity === 'high' || s.severity === 'medium'),
    benignEvidence: fusedAssessment.signals.filter(s => s.severity === 'low' || s.severity === 'info'),
    authentication: authResults,
    urls,
    attachments,
    relayPath,
    infrastructure: {
      originIp: earliestReliableNode?.ip,
      originAsn: earliestReliableNode?.asn,
      originIsp: earliestReliableNode?.isp,
      originCountry: earliestReliableNode?.country,
      relayHopsCount: relayPath.length
    },
    geolocation: {
      available: relayPath.some(r => r.lat && !isNaN(r.lat)),
      label: 'Infrastructure Geolocation',
      locations: relayPath
        .filter(r => r.lat && !isNaN(r.lat))
        .map(r => ({
          id: `geo-${r.index}`,
          ip: r.ip,
          latitude: r.lat,
          longitude: r.lon,
          country: r.country,
          region: r.region,
          city: r.city,
          provider: r.isp,
          asn: r.asn,
          source: 'received-header' as const,
          confidence: r.confidence,
          precision: 'city' as const,
          verified: true
        }))
    },
    threatIntel: {
      configured: threatIntelEngine.isConfigured(),
      provider: threatIntelEngine.isConfigured() ? 'Connected Threat Intel Feed' : undefined,
      matches: threatIntelCorrelation.matches,
      note: threatIntelCorrelation.correlationSummary
    },
    campaignCorrelations: {
      matched: !!result.matchedCampaignId,
      campaignId: result.matchedCampaignId,
      campaignName: result.matchedCampaignName,
      confidence: result.matchedCampaignId ? 85 : 0
    },
    coverage: {
      headerAnalysis: true,
      authenticationAnalysis: true,
      contentAnalysis: true,
      urlAnalysis: true,
      attachmentAnalysis: true,
      threatIntelAnalysis: true
    },
    limitations: fusedAssessment.limitations || [],
    generatedAt: new Date().toISOString()
  };

  result.verdict = canonicalVerdict;

  // Cache in store and audit log
  socStore.analyzedEmails.set(result.id, result);

  // Generate live SOC Alert dynamically if email exhibits notable risk indicators
  if (result.overallRiskScore >= 35 || result.severity === 'CRITICAL' || result.severity === 'HIGH' || result.severity === 'MEDIUM') {
    const existingAlert = Array.from(socStore.alerts.values()).find(a => a.emailId === result.id);
    if (!existingAlert) {
      const alertId = `ALT-${Math.floor(1000 + Math.random() * 9000)}`;
      const alertSeverity = result.severity === 'CRITICAL' ? 'CRITICAL' : (result.severity === 'HIGH' ? 'HIGH' : 'MEDIUM');
      socStore.alerts.set(alertId, {
        id: alertId,
        severity: alertSeverity,
        detectionTime: 'Just now',
        emailSubject: result.subject || 'Analyzed Inbound Message',
        sender: result.from || 'Unknown Sender',
        threatType: result.primaryClassification,
        riskScore: result.overallRiskScore,
        status: 'NEW',
        assignedAnalyst: 'Unassigned',
        emailId: result.id
      });
    }
  }

  // Correlate or cluster into tracked campaign if recurrent patterns detected
  if (result.fromDomain && !result.matchedCampaignId) {
    const matchingEmails = Array.from(socStore.analyzedEmails.values()).filter(
      e => e.id !== result.id && (
        (e.fromDomain && e.fromDomain.toLowerCase() === result.fromDomain.toLowerCase()) ||
        (e.earliestReliableNode?.ip && result.earliestReliableNode?.ip && e.earliestReliableNode.ip === result.earliestReliableNode.ip)
      )
    );

    if (matchingEmails.length >= 1) {
      const campId = `CAM-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
      const campaignName = `${result.fromDomain} Recurrent Activity (${result.primaryClassification})`;
      const newCamp = {
        id: campId,
        name: campaignName,
        emailCount: matchingEmails.length + 1,
        commonDomain: result.fromDomain,
        commonIp: result.earliestReliableNode?.ip || '',
        threatType: result.primaryClassification,
        confidence: Math.round(result.threatConfidence),
        firstSeen: matchingEmails[0].analyzedAt || new Date().toISOString(),
        lastSeen: new Date().toISOString(),
        description: `Correlated cluster of ${matchingEmails.length + 1} analyzed messages targeting enterprise mailboxes.`,
        associatedEmails: [
          ...matchingEmails.map(m => ({ id: m.id, subject: m.subject, from: m.from, date: m.analyzedAt, risk: m.overallRiskScore })),
          { id: result.id, subject: result.subject, from: result.from, date: new Date().toISOString(), risk: result.overallRiskScore }
        ]
      };
      socStore.campaigns.set(campId, newCamp);
      result.matchedCampaignId = campId;
      result.matchedCampaignName = campaignName;
    }
  }

  socStore.logAudit(
    'FORENSIC_ENGINE',
    'SYSTEM',
    'EMAIL_ANALYSIS',
    `Analyzed: "${result.subject.substring(0, 35)}" (Score: ${result.overallRiskScore}/100, Class: ${result.primaryClassification})`,
    '127.0.0.1',
    'SUCCESS'
  );

  return result;
}
