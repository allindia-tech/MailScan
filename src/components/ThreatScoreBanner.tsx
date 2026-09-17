/**
 * MailTrace Workstation - Threat Assessment & Executive Verdict Banner
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Tripartite Scoring Architecture: Threat Risk, Spam Likelihood, Authenticity Confidence
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Shield,
  FileDown,
  Copy,
  Check,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Lock,
  Globe,
  Radio,
  Sliders,
  CheckCircle2,
  HelpCircle,
  ExternalLink,
  Ban,
  Clock
} from 'lucide-react';
import { EmailAnalysisResult } from '../types/forensics.js';

interface ThreatScoreBannerProps {
  analysis: EmailAnalysisResult;
  onOpenCaseModal: () => void;
  onExportReport: () => void;
  onNavigateToThreatIntel?: () => void;
  onUpdateAnalysis?: (updated: EmailAnalysisResult) => void;
  onOpenFeedbackModal?: () => void;
}

export const ThreatScoreBanner: React.FC<ThreatScoreBannerProps> = ({
  analysis,
  onOpenCaseModal,
  onExportReport,
  onNavigateToThreatIntel,
  onUpdateAnalysis,
  onOpenFeedbackModal
}) => {
  const [copiedIocs, setCopiedIocs] = useState(false);
  const [showScoreBreakdown, setShowScoreBreakdown] = useState(false);
  const [isRecalculating, setIsRecalculating] = useState(false);
  const [recalcResult, setRecalcResult] = useState<{
    reproducible: boolean;
    originalScore: number;
    recalculatedScore: number;
    scoringVersion: string;
  } | null>(analysis.recalculationVerified ? {
    reproducible: true,
    originalScore: analysis.overallRiskScore,
    recalculatedScore: analysis.overallRiskScore,
    scoringVersion: analysis.scoringVersion || '2.4.0'
  } : null);

  const threatRiskScore = analysis.threatRisk ?? analysis.overallRiskScore ?? 0;
  const spamLikelihoodScore = analysis.spamLikelihood ?? analysis.spam?.score ?? 0;
  const authenticityScore = analysis.authenticityConfidence ?? analysis.authenticity?.score ?? 85;

  const isBulkCategory = ['Newsletter', 'Promotional', 'Bulk / Unsolicited', 'Spam'].includes(analysis.primaryClassification);
  const isCritical = threatRiskScore >= 70;
  const isWarning = threatRiskScore >= 35 && threatRiskScore < 70;
  const isClean = threatRiskScore < 35;

  const handleCopyIocs = () => {
    const list = analysis.iocs.map(i => `${i.type.toUpperCase()}: ${i.indicator} (${i.risk})`).join('\n');
    navigator.clipboard.writeText(list);
    setCopiedIocs(true);
    setTimeout(() => setCopiedIocs(false), 2000);
  };

  const handleRecalculate = async () => {
    setIsRecalculating(true);
    try {
      const res = await fetch(`/api/recalculate/${analysis.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });

      if (!res.ok) {
        throw new Error(`Recalculate failed with status ${res.status}`);
      }

      const data = await res.json();
      setRecalcResult({
        reproducible: data.reproducible,
        originalScore: data.originalScore,
        recalculatedScore: data.recalculatedScore,
        scoringVersion: data.scoringVersion
      });

      if (data.updatedAnalysis && onUpdateAnalysis) {
        onUpdateAnalysis(data.updatedAnalysis);
      }
    } catch (err) {
      console.error('Recalculation error:', err);
    } finally {
      setIsRecalculating(false);
    }
  };

  // 9-category normalized risk model
  const catScores = analysis.categoryScores || {
    senderAuthenticity: 100 - (analysis.componentScores?.senderAuthenticity ?? 100),
    authentication: 0,
    headerRouting: analysis.headerAnomalyScore || 0,
    domain: analysis.componentScores?.domainRisk || 0,
    url: analysis.componentScores?.urlRisk || 0,
    content: 0,
    attachment: 0,
    infrastructure: analysis.componentScores?.infrastructureRisk || 0,
    threatIntelligence: analysis.componentScores?.threatIntelRisk || 0
  };

  const categories = [
    { key: 'senderAuthenticity', name: 'Sender authenticity', weight: '15%', score: catScores.senderAuthenticity, pts: Number((catScores.senderAuthenticity * 0.15).toFixed(1)) },
    { key: 'authentication', name: 'Authentication', weight: '15%', score: catScores.authentication, pts: Number((catScores.authentication * 0.15).toFixed(1)) },
    { key: 'headerRouting', name: 'Header & routing', weight: '10%', score: catScores.headerRouting, pts: Number((catScores.headerRouting * 0.10).toFixed(1)) },
    { key: 'domain', name: 'Domain', weight: '15%', score: catScores.domain, pts: Number((catScores.domain * 0.15).toFixed(1)) },
    { key: 'url', name: 'URL', weight: '15%', score: catScores.url, pts: Number((catScores.url * 0.15).toFixed(1)) },
    { key: 'content', name: 'Content', weight: '10%', score: catScores.content, pts: Number((catScores.content * 0.10).toFixed(1)) },
    { key: 'attachment', name: 'Attachment', weight: '5%', score: catScores.attachment, pts: Number((catScores.attachment * 0.05).toFixed(1)) },
    { key: 'infrastructure', name: 'Infrastructure', weight: '10%', score: catScores.infrastructure, pts: Number((catScores.infrastructure * 0.10).toFixed(1)) },
    { key: 'threatIntelligence', name: 'Threat intelligence', weight: '5%', score: catScores.threatIntelligence, pts: Number((catScores.threatIntelligence * 0.05).toFixed(1)) }
  ];

  // Origin / Ingress info
  const firstHop = analysis.relayPath?.[0] || analysis.hops?.[0];
  const targetNode = analysis.earliestReliableNode || firstHop;
  const isLocalOnly = targetNode && targetNode.isPublic === false;
  const originIp = targetNode?.ip || analysis.authResults?.spf?.clientIp || (analysis.relayPath?.length ? 'Unresolved IP' : 'No Headers');
  const originLocation = isLocalOnly
    ? (targetNode?.classification === 'LOOPBACK' ? 'Local Loopback' : 'Internal LAN')
    : (targetNode?.country && targetNode.country !== 'Unknown' && targetNode.country !== 'Non-Routable' && targetNode.country !== 'Unverified Location'
        ? `${targetNode.city && targetNode.city !== 'Unknown' ? `${targetNode.city}, ` : ''}${targetNode.country}`
        : (targetNode?.isPublic ? 'Public Node (Unverified Geo)' : 'Observed Ingress'));
  const isTor = targetNode?.isTor || firstHop?.isTor || analysis.iocs?.some(i => i.type === 'ip' && i.risk === 'CRITICAL');

  // Lookalike info
  const lookalikeDomain = analysis.senderDomainIntel?.domain || analysis.fromDomain || 'unknown';
  const isSquatted = analysis.senderDomainIntel?.isLookalike;
  const targetDomain = analysis.senderDomainIntel?.targetDomain || 'Target Organization';

  // DKIM status
  const dkimPassed = analysis.authResults?.dkim?.status === 'PASS';
  const spfPassed = analysis.authResults?.spf?.status === 'PASS';

  return (
    <div className="space-y-4 mb-6">
      
      {/* 1. EXECUTIVE SUMMARY & VERDICT BANNER */}
      <section className={`rounded-xl border shadow-xs overflow-hidden transition-all ${
        isCritical
          ? 'bg-rose-50/90 border-rose-200'
          : isWarning
          ? 'bg-amber-50/90 border-amber-200'
          : isBulkCategory
          ? 'bg-sky-50/90 border-sky-200'
          : 'bg-emerald-50/90 border-emerald-200'
      }`}>
        <div className="p-5 md:p-6 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-5">
          
          <div className="flex items-start gap-4">
            {/* High-Contrast Severity Icon */}
            <div className={`w-12 h-12 rounded-lg border flex items-center justify-center shrink-0 shadow-xs ${
              isCritical
                ? 'bg-rose-100 border-rose-300 text-rose-600'
                : isWarning
                ? 'bg-amber-100 border-amber-300 text-amber-700'
                : isBulkCategory
                ? 'bg-sky-100 border-sky-300 text-sky-700'
                : 'bg-emerald-100 border-emerald-300 text-emerald-700'
            }`}>
              {isCritical ? (
                <ShieldAlert className="w-7 h-7 text-rose-600" />
              ) : isWarning ? (
                <AlertTriangle className="w-7 h-7 text-amber-700" />
              ) : (
                <ShieldCheck className="w-7 h-7 text-emerald-700" />
              )}
            </div>

            <div className="space-y-1.5 max-w-3xl">
              {/* Threat Tags */}
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold shadow-xs ${
                  isCritical
                    ? 'bg-rose-600 text-white'
                    : isWarning
                    ? 'bg-amber-600 text-white'
                    : isBulkCategory
                    ? 'bg-sky-700 text-white'
                    : 'bg-emerald-700 text-white'
                }`}>
                  {isCritical ? `CONFIRMED THREAT: ${threatRiskScore}/100 CVSS` : `${analysis.primaryClassification.toUpperCase()}: ${threatRiskScore}/100`}
                </span>

                <span className="px-2 py-0.5 rounded text-[11px] font-mono text-slate-700 bg-white border border-slate-200 font-medium">
                  CASE #{analysis.id || 'MT-SPECIMEN'}
                </span>

                <span className="text-xs text-slate-500 font-mono">
                  Ingested: {new Date(analysis.timestamp || Date.now()).toLocaleString()}
                </span>
              </div>

              {/* Title */}
              <h1 className="text-lg md:text-xl font-headline font-bold text-slate-900 tracking-tight">
                {analysis.primaryClassification === 'Legitimate' 
                  ? 'Cryptographically Verified & Safe Inbound Communication'
                  : analysis.primaryClassification === 'Credential Theft'
                  ? 'High-Risk Spear Phishing & Executive Credential Theft'
                  : analysis.primaryClassification === 'Extortion / Blackmail'
                  ? 'Coercive Blackmail & Cryptocurrency Extortion Pattern'
                  : analysis.primaryClassification === 'BEC / Wire Fraud'
                  ? 'Business Email Compromise (BEC) & Wire Fraud Vector'
                  : `${analysis.primaryClassification} Pattern Detected`}
              </h1>

              {/* Clinical Description */}
              <p className="text-xs md:text-sm text-slate-700 leading-relaxed">
                Sender: <strong className="text-slate-900 font-semibold">{analysis.from}</strong>
                {analysis.replyTo && analysis.replyTo !== analysis.from && (
                  <> &bull; Reply-To diverted to <strong className="font-mono text-rose-700 bg-rose-100/80 px-1 py-0.5 rounded border border-rose-200">{analysis.replyTo}</strong></>
                )}
                {isSquatted && (
                  <> &bull; Deceptive lookalike domain <strong className="font-mono text-amber-800 bg-amber-100/80 px-1 py-0.5 rounded border border-amber-200">{lookalikeDomain}</strong> targeting <strong className="font-mono text-emerald-800 bg-emerald-100/80 px-1 py-0.5 rounded border border-emerald-200">{targetDomain}</strong></>
                )}
                {analysis.detectedTechniques && analysis.detectedTechniques.length > 0 && (
                  <> &bull; <span className="font-medium text-slate-800">{analysis.detectedTechniques.length} ATT&CK techniques mapped</span></>
                )}
              </p>
            </div>
          </div>

          {/* Quick Immediate Human Recommended Actions */}
          <div className="flex lg:flex-col sm:flex-row flex-wrap gap-2 w-full lg:w-auto shrink-0 pt-2 lg:pt-0">
            {isCritical && (
              <button
                onClick={onOpenCaseModal}
                className="flex-1 lg:flex-initial flex items-center justify-center gap-1.5 px-3.5 py-2 rounded bg-rose-600 hover:bg-rose-700 text-white font-semibold text-xs shadow-xs transition-all"
                type="button"
              >
                <Ban className="w-3.5 h-3.5" />
                <span>Quarantine & Escalate</span>
              </button>
            )}

            <button
              onClick={onExportReport}
              className="flex-1 lg:flex-initial flex items-center justify-center gap-1.5 px-3.5 py-2 rounded bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 font-medium text-xs transition-all shadow-xs"
              type="button"
            >
              <FileDown className="w-3.5 h-3.5 text-slate-600" />
              <span>Court-Ready Report</span>
            </button>

            {analysis.iocs.length > 0 && (
              <button
                onClick={handleCopyIocs}
                className="flex-1 lg:flex-initial flex items-center justify-center gap-1.5 px-3.5 py-2 rounded bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 text-indigo-700 font-semibold text-xs transition-all shadow-xs"
                type="button"
              >
                {copiedIocs ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedIocs ? 'IOCs Copied' : `Copy ${analysis.iocs.length} IOCs`}</span>
              </button>
            )}
          </div>

        </div>
      </section>

      {/* 2. TELEMETRY & TRUST KEY METRICS ROW */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        
        {/* Metric 1: Identity Trust Score */}
        <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide font-mono">
              Identity Trust Score
            </span>
            <Shield className={`w-4 h-4 ${authenticityScore < 50 ? 'text-rose-500' : 'text-emerald-500'}`} />
          </div>
          <div className="my-2">
            <div className="flex items-baseline gap-2">
              <span className={`font-headline font-bold text-2xl ${authenticityScore < 50 ? 'text-rose-600' : 'text-emerald-700'}`}>
                {authenticityScore}%
              </span>
              <span className={`text-[10px] font-semibold font-mono px-1.5 py-0.5 rounded border ${
                authenticityScore < 50
                  ? 'bg-rose-50 text-rose-700 border-rose-200'
                  : 'bg-emerald-50 text-emerald-700 border-emerald-200'
              }`}>
                {authenticityScore < 50 ? 'Untrusted Origin' : 'Verified Baseline'}
              </span>
            </div>
            <p className="text-[11px] text-slate-500 mt-1">
              {authenticityScore < 50 ? 'Sender identity failed cryptographic proof' : 'Headers align with corporate identity'}
            </p>
          </div>
          <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
            <div 
              className={`h-full rounded-full ${authenticityScore < 50 ? 'bg-rose-500' : 'bg-emerald-600'}`} 
              style={{ width: `${authenticityScore}%` }} 
            />
          </div>
        </div>

        {/* Metric 2: Lookalike Domain Squatting */}
        <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide font-mono">
              Domain Squatting
            </span>
            <Globe className={`w-4 h-4 ${isSquatted ? 'text-amber-500' : 'text-slate-400'}`} />
          </div>
          <div className="my-2">
            <div className="flex items-center gap-1.5">
              <span className="font-mono text-xs font-bold text-slate-900 truncate max-w-[150px]">
                {lookalikeDomain}
              </span>
              {isSquatted && (
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-amber-50 text-amber-800 border border-amber-200 font-semibold font-mono">
                  Squatted
                </span>
              )}
            </div>
            <p className="text-xs text-slate-600 mt-1">
              Target: <span className="font-mono text-slate-800 font-medium">{targetDomain}</span>
            </p>
          </div>
          <div className="text-[11px] text-slate-500 font-mono">
            {analysis.senderDomainIntel?.domainAge ? `Domain Age: ${analysis.senderDomainIntel.domainAge}` : 'Registered domain evaluated'}
          </div>
        </div>

        {/* Metric 3: DKIM Integrity Check */}
        <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide font-mono">
              DKIM Integrity Check
            </span>
            <Lock className={`w-4 h-4 ${dkimPassed ? 'text-emerald-500' : 'text-rose-500'}`} />
          </div>
          <div className="my-2">
            <div className="flex items-center gap-1.5">
              <span className={`px-2 py-0.5 rounded border font-mono text-[11px] font-bold ${
                dkimPassed
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-rose-50 text-rose-700 border-rose-200'
              }`}>
                {dkimPassed ? 'SIGNATURE VALID' : 'BODY TAMPERED / FAIL'}
              </span>
            </div>
            <p className="text-xs text-slate-600 mt-1">
              {dkimPassed ? 'Cryptographic body hash verified' : 'Computed hash != Signed hash (bh= mismatch)'}
            </p>
          </div>
          <div className="text-[11px] text-slate-500 flex items-center gap-1 font-mono">
            <span className={spfPassed ? 'text-emerald-600 font-medium' : 'text-rose-600 font-medium'}>
              SPF: {spfPassed ? 'PASS' : 'FAIL'}
            </span>
            <span>&bull;</span>
            <span>DMARC: {analysis.authResults?.dmarc?.status || 'NONE'}</span>
          </div>
        </div>

        {/* Metric 4: Observed Relay Infrastructure */}
        <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs flex flex-col justify-between">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide font-mono">
              Observed Relay Infrastructure
            </span>
            <Radio className={`w-4 h-4 ${isTor ? 'text-rose-500' : 'text-slate-400'}`} />
          </div>
          <div className="my-2">
            <div className="flex items-center gap-1.5 font-mono text-xs text-slate-900 font-medium truncate">
              <span className="font-bold">{originLocation}</span>
              <span className="text-slate-400">&bull;</span>
              <span className="text-slate-600">{originIp}</span>
            </div>
            <p className="text-xs text-slate-600 mt-1">
              {isTor ? (
                <span className="text-rose-700 font-semibold">Anonymized Tor / Proxy Exit Node</span>
              ) : isLocalOnly ? (
                <span className="text-slate-600">Only local/loopback infrastructure observed</span>
              ) : (
                <span>Standard SMTP Transport Gateway</span>
              )}
            </p>
          </div>
          <div className="text-[11px] text-slate-500 font-mono">
            {analysis.relayPath?.length || analysis.hops?.length || 0} Relay Hop(s) Identified
          </div>
        </div>

      </section>

      {/* 3. MULTI-DIMENSION RISK & NORMALIZED BREAKDOWN ACCORDION */}
      <div className="rounded-lg bg-white border border-slate-200 shadow-xs overflow-hidden">
        <button
          onClick={() => setShowScoreBreakdown(!showScoreBreakdown)}
          className="w-full px-4 py-2.5 bg-slate-50/70 hover:bg-slate-100 flex items-center justify-between text-xs text-slate-700 transition-colors"
        >
          <div className="flex items-center gap-2">
            <Sliders className="w-3.5 h-3.5 text-indigo-600" />
            <span className="font-semibold text-slate-900">Multi-Dimension Scoring Engine & Weight Breakdown</span>
            <span className="text-slate-500 font-mono text-[11px]">
              (Deterministic 9-Category Normalization)
            </span>
          </div>
          <div className="flex items-center gap-1 text-slate-500">
            <span className="text-[11px]">{showScoreBreakdown ? 'Hide Breakdown' : 'View Breakdown'}</span>
            {showScoreBreakdown ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </div>
        </button>

        {showScoreBreakdown && (
          <div className="p-4 space-y-4 border-t border-slate-200">
            {/* 9 Category Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {categories.map((cat) => (
                <div key={cat.key} className="p-2.5 rounded bg-slate-50 border border-slate-200 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-slate-700">{cat.name}</span>
                    <span className="text-[10px] font-mono text-slate-500">Weight {cat.weight}</span>
                  </div>
                  <div className="mt-1.5 flex items-baseline justify-between">
                    <span className="font-mono font-bold text-slate-900">{cat.score}/100</span>
                    <span className="font-mono text-[11px] text-slate-600">+{cat.pts} pts</span>
                  </div>
                  <div className="mt-1 w-full bg-slate-200 h-1 rounded-full overflow-hidden">
                    <div 
                      className={`h-full rounded-full ${cat.score >= 70 ? 'bg-rose-500' : cat.score >= 35 ? 'bg-amber-500' : 'bg-emerald-600'}`} 
                      style={{ width: `${cat.score}%` }} 
                    />
                  </div>
                </div>
              ))}
            </div>

            {/* Recalculation Determinism Check */}
            <div className="pt-3 border-t border-slate-100 flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2">
                <button
                  onClick={handleRecalculate}
                  disabled={isRecalculating}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 font-medium transition shadow-xs disabled:opacity-50"
                >
                  <RefreshCw className={`w-3.5 h-3.5 text-indigo-600 ${isRecalculating ? 'animate-spin' : ''}`} />
                  <span>{isRecalculating ? 'Recalculating...' : 'Verify Scoring Determinism'}</span>
                </button>

                {recalcResult && (
                  <div className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-700 bg-emerald-50 px-2 py-1 rounded border border-emerald-200">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                    <span>Reproducible: {recalcResult.originalScore} → {recalcResult.recalculatedScore} (v{recalcResult.scoringVersion})</span>
                  </div>
                )}
              </div>

              {onOpenFeedbackModal && (
                <button
                  onClick={onOpenFeedbackModal}
                  className="text-xs text-indigo-700 hover:text-indigo-900 font-medium hover:underline"
                >
                  Submit Analyst Feedback / False Positive Correction →
                </button>
              )}
            </div>
          </div>
        )}
      </div>

    </div>
  );
};
