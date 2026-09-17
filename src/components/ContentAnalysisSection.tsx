/**
 * MailTrace Workstation - Deep Content, Intent & Linguistic Analysis
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Visualizes intent, call-to-action, social engineering linguistic tactics, and HTML obfuscation.
 */

import React, { useState } from 'react';
import {
  AlertTriangle,
  Flame,
  Shield,
  Eye,
  Crosshair,
  DollarSign,
  UserCheck,
  ExternalLink,
  Code,
  Zap,
  Lock,
  QrCode,
  CheckCircle2,
  FileText,
  EyeOff,
  Split,
  Binary,
  Layers,
  Sparkles,
  AlertCircle
} from 'lucide-react';
import { EmailAnalysisResult } from '../types/forensics.js';

interface ContentAnalysisSectionProps {
  analysis: EmailAnalysisResult;
}

export const ContentAnalysisSection: React.FC<ContentAnalysisSectionProps> = ({ analysis }) => {
  const [diffMode, setDiffMode] = useState<'split' | 'unified'>('split');
  const [highlightOnlyAnomalies, setHighlightOnlyAnomalies] = useState<boolean>(true);
  
  const content = analysis.emailContentAnalysis;

  if (!content) {
    return (
      <div className="bg-white border border-slate-200 rounded-xl p-6 text-center text-slate-500 font-mono text-xs shadow-xs">
        No deep content analysis telemetry available for this email trace.
      </div>
    );
  }

  const {
    intent = { category: 'Unknown', disposition: 'Benign', confidence: 80, description: 'Standard correspondence.' },
    requestedAction = { action: 'None / informational', evidence: 'No immediate coercive action.', riskLevel: 'safe' },
    subjectAnalysis = { flags: [], sentiment: 'neutral', isSuspicious: false },
    socialEngineering = [],
    fraudIndicators = { detected: false, type: 'None', evidence: undefined },
    becIndicators = { detected: false, type: undefined, evidence: undefined },
    htmlFindings = {
      hasHiddenElements: false,
      hasInvisibleText: false,
      hasSuspiciousForms: false,
      trackingPixelsCount: 0,
      mismatchedAnchorsCount: 0,
      findings: []
    },
    ocrQrFindings
  } = content;

  const isMalicious = intent.disposition === 'Malicious' || requestedAction.riskLevel === 'critical' || requestedAction.riskLevel === 'high';
  const isSuspicious = intent.disposition === 'Suspicious' || requestedAction.riskLevel === 'medium';

  return (
    <div className="space-y-5">
      
      {/* 1. Recipient Call-To-Action & Intent Analysis */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <Crosshair className="w-4 h-4 text-rose-600" />
            <h3 className="text-xs font-bold text-slate-900 tracking-wide uppercase font-mono">
              Recipient Call-to-Action & Intent Analysis
            </h3>
          </div>
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className={`px-2 py-0.5 rounded font-bold border ${
              isMalicious
                ? 'bg-rose-50 text-rose-700 border-rose-200'
                : (isSuspicious
                    ? 'bg-amber-50 text-amber-800 border-amber-200'
                    : 'bg-emerald-50 text-emerald-700 border-emerald-200')
            }`}>
              DISPOSITION: {intent.disposition.toUpperCase()}
            </span>
            <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 font-semibold text-[11px]">
              {intent.category} ({intent.confidence}%)
            </span>
          </div>
        </div>

        {/* What does this email want the user to do? */}
        <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-3">
          <div className="text-[11px] font-mono text-slate-600 uppercase font-bold flex items-center gap-1.5">
            <Zap className="w-3.5 h-3.5 text-amber-600" />
            <span>Target Solicitation & Induced Risk</span>
          </div>

          <div className="text-xs sm:text-sm text-slate-900 font-semibold leading-normal">
            "{requestedAction.evidence || requestedAction.action}"
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1 text-xs">
            <div className="bg-white p-2.5 rounded border border-slate-200 shadow-xs">
              <div className="text-[10px] font-mono text-slate-500 uppercase font-bold">Solicited Action</div>
              <div className="text-slate-900 font-semibold mt-0.5">{requestedAction.action}</div>
            </div>
            <div className="bg-white p-2.5 rounded border border-slate-200 shadow-xs">
              <div className="text-[10px] font-mono text-slate-500 uppercase font-bold">Induced Risk Level</div>
              <div className={`font-bold mt-0.5 uppercase font-mono ${
                requestedAction.riskLevel === 'critical' ? 'text-rose-600' : (
                  requestedAction.riskLevel === 'high' ? 'text-rose-700' : (
                    requestedAction.riskLevel === 'medium' ? 'text-amber-700' : 'text-emerald-700'
                  )
                )
              }`}>
                {requestedAction.riskLevel}
              </div>
            </div>
            <div className="bg-white p-2.5 rounded border border-slate-200 shadow-xs">
              <div className="text-[10px] font-mono text-slate-500 uppercase font-bold">Intent Description</div>
              <div className="text-slate-700 truncate mt-0.5" title={intent.description}>
                {intent.description}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 2. Subject Line & Social Engineering Heuristics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        
        {/* Subject Line Forensics */}
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3 lg:col-span-1">
          <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
            <FileText className="w-4 h-4 text-indigo-600" />
            <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide font-mono">
              Subject Line Analysis
            </h4>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between p-2 bg-slate-50 rounded border border-slate-200">
              <span className="text-slate-600">Linguistic Sentiment:</span>
              <span className={`font-bold uppercase font-mono text-[11px] ${
                subjectAnalysis.sentiment === 'urgent' || subjectAnalysis.sentiment === 'alarming'
                  ? 'text-rose-700'
                  : subjectAnalysis.sentiment === 'promotional'
                  ? 'text-amber-800'
                  : 'text-slate-800'
              }`}>
                {subjectAnalysis.sentiment}
              </span>
            </div>

            <div className="flex items-center justify-between p-2 bg-slate-50 rounded border border-slate-200">
              <span className="text-slate-600">Subject Risk:</span>
              <span className={`font-bold font-mono text-[11px] ${subjectAnalysis.isSuspicious ? 'text-rose-700' : 'text-emerald-700'}`}>
                {subjectAnalysis.isSuspicious ? 'FLAGGED ANOMALY' : 'CLEAN / BENIGN'}
              </span>
            </div>

            {subjectAnalysis.flags && subjectAnalysis.flags.length > 0 && (
              <div className="p-2.5 bg-slate-50 rounded border border-slate-200 space-y-1">
                <div className="text-[10px] font-mono text-slate-500 uppercase font-bold">Detected Flags:</div>
                <div className="space-y-1">
                  {subjectAnalysis.flags.map((flag, idx) => (
                    <div key={idx} className="text-[11px] text-amber-800 font-medium">
                      &bull; {flag}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Social Engineering Tactics */}
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-slate-100 pb-2">
            <div className="flex items-center gap-2">
              <Flame className="w-4 h-4 text-amber-600" />
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide font-mono">
                Social Engineering Tactics ({socialEngineering.length})
              </h4>
            </div>
            <span className="text-[11px] font-mono text-slate-500">
              Psychological Pressure Points
            </span>
          </div>

          {socialEngineering.length === 0 ? (
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-lg text-xs font-mono text-slate-500 text-center">
              No overt emotional coercion or psychological pressure triggers detected.
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {socialEngineering.map((se, i) => (
                <div
                  key={i}
                  className="bg-slate-50 border border-slate-200 rounded-lg p-2.5 space-y-1 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold uppercase border ${
                      se.severity === 'critical'
                        ? 'bg-rose-50 text-rose-700 border-rose-200'
                        : se.severity === 'high'
                        ? 'bg-amber-50 text-amber-800 border-amber-200'
                        : 'bg-blue-50 text-blue-800 border-blue-200'
                    }`}>
                      {se.signal}
                    </span>
                    <span className="text-slate-500 text-[10px] font-mono">
                      {se.confidence}% conf
                    </span>
                  </div>

                  <div className="text-slate-700 text-xs pt-0.5">
                    {se.evidence}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

      </div>

      {/* 3. Fraud & BEC Indicators */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        
        {/* Financial Fraud */}
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-100 pb-2">
            <div className="flex items-center gap-2">
              <DollarSign className="w-4 h-4 text-emerald-600" />
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide font-mono">
                Financial Fraud & Payment Signals
              </h4>
            </div>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
              fraudIndicators.detected
                ? 'bg-rose-50 text-rose-700 border-rose-200'
                : 'bg-emerald-50 text-emerald-700 border-emerald-200'
            }`}>
              {fraudIndicators.detected ? 'FRAUD DETECTED' : 'CLEAN'}
            </span>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between p-2 bg-slate-50 rounded border border-slate-200">
              <span className="text-slate-600">Pattern Type:</span>
              <span className="text-slate-900 font-semibold font-mono text-[11px]">
                {fraudIndicators.type || 'None'}
              </span>
            </div>
            {fraudIndicators.evidence && (
              <div className="p-2.5 bg-rose-50/50 rounded border border-rose-200 text-slate-700 text-xs leading-relaxed">
                {fraudIndicators.evidence}
              </div>
            )}
          </div>
        </div>

        {/* BEC Indicators */}
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-100 pb-2">
            <div className="flex items-center gap-2">
              <UserCheck className="w-4 h-4 text-indigo-600" />
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide font-mono">
                Business Email Compromise (BEC)
              </h4>
            </div>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
              becIndicators.detected
                ? 'bg-rose-50 text-rose-700 border-rose-200'
                : 'bg-emerald-50 text-emerald-700 border-emerald-200'
            }`}>
              {becIndicators.detected ? 'BEC DETECTED' : 'CLEAN'}
            </span>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex items-center justify-between p-2 bg-slate-50 rounded border border-slate-200">
              <span className="text-slate-600">BEC Vector:</span>
              <span className="text-indigo-700 font-semibold font-mono text-[11px]">
                {becIndicators.type || 'None identified'}
              </span>
            </div>
            {becIndicators.evidence && (
              <div className="p-2.5 bg-rose-50/50 rounded border border-rose-200 text-slate-700 text-xs leading-relaxed">
                {becIndicators.evidence}
              </div>
            )}
          </div>
        </div>

      </div>

      {/* 4. HTML Obfuscation & Evasion Techniques */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-slate-100 pb-2">
          <div className="flex items-center gap-2">
            <Code className="w-4 h-4 text-indigo-600" />
            <h3 className="text-xs font-bold text-slate-900 tracking-wide uppercase font-mono">
              HTML Obfuscation & Evasion Findings
            </h3>
          </div>
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
            htmlFindings.hasHiddenElements || htmlFindings.hasInvisibleText || (htmlFindings.mismatchedAnchorsCount || 0) > 0 || htmlFindings.hasSuspiciousForms
              ? 'bg-rose-50 text-rose-700 border-rose-200'
              : 'bg-emerald-50 text-emerald-700 border-emerald-200'
          }`}>
            {htmlFindings.hasHiddenElements || htmlFindings.hasInvisibleText || (htmlFindings.mismatchedAnchorsCount || 0) > 0 || htmlFindings.hasSuspiciousForms
              ? 'ACTIVE EVASION DETECTED'
              : 'CLEAN HTML STRUCTURE'}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
          <div className="bg-slate-50 border border-slate-200 p-3 rounded-lg">
            <div className="text-[10px] font-mono text-slate-500 uppercase">Hidden Elements</div>
            <div className={`text-sm font-bold mt-1 font-mono ${htmlFindings.hasHiddenElements ? 'text-rose-700' : 'text-slate-700'}`}>
              {htmlFindings.hasHiddenElements ? 'DETECTED' : 'None'}
            </div>
            <p className="text-[10px] text-slate-500 mt-1">Zero-font or visibility:hidden styles</p>
          </div>

          <div className="bg-slate-50 border border-slate-200 p-3 rounded-lg">
            <div className="text-[10px] font-mono text-slate-500 uppercase">Invisible Text</div>
            <div className={`text-sm font-bold mt-1 font-mono ${htmlFindings.hasInvisibleText ? 'text-rose-700' : 'text-slate-700'}`}>
              {htmlFindings.hasInvisibleText ? 'DETECTED' : 'None'}
            </div>
            <p className="text-[10px] text-slate-500 mt-1">Low-contrast text evasion</p>
          </div>

          <div className="bg-slate-50 border border-slate-200 p-3 rounded-lg">
            <div className="text-[10px] font-mono text-slate-500 uppercase">HREF Mismatch</div>
            <div className={`text-sm font-bold mt-1 font-mono ${(htmlFindings.mismatchedAnchorsCount || 0) > 0 ? 'text-rose-700' : 'text-slate-700'}`}>
              {(htmlFindings.mismatchedAnchorsCount || 0) > 0 ? `${htmlFindings.mismatchedAnchorsCount} Spoofed` : 'Clean'}
            </div>
            <p className="text-[10px] text-slate-500 mt-1">Display URL differs from target href</p>
          </div>

          <div className="bg-slate-50 border border-slate-200 p-3 rounded-lg">
            <div className="text-[10px] font-mono text-slate-500 uppercase">Tracking Beacons</div>
            <div className="text-sm font-bold text-slate-800 mt-1 font-mono">
              {htmlFindings.trackingPixelsCount || 0}
            </div>
            <p className="text-[10px] text-slate-500 mt-1">1x1 tracking pixel beacons</p>
          </div>
        </div>

        {htmlFindings.findings && htmlFindings.findings.length > 0 && (
          <div className="p-3 bg-rose-50 border border-rose-200 rounded-lg space-y-1.5 text-xs">
            <div className="text-[10px] font-bold text-rose-800 uppercase font-mono">Specific HTML Anomalies:</div>
            {htmlFindings.findings.map((f, i) => (
              <div key={i} className="text-slate-800 font-mono text-[11px] bg-white p-2 rounded border border-rose-200">
                &bull; {f}
              </div>
            ))}
          </div>
        )}
      </div>

    </div>
  );
};
