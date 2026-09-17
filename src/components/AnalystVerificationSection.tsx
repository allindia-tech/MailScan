/**
 * MailTrace Workstation - Analyst Verification & Ground-Truth Feedback Section
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Governed analyst feedback loop: safe queuing without mutating live model weights directly.
 */

import React, { useState } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Brain,
  Sliders,
  Layers,
  ArrowRight,
  Database,
  Cpu,
  FileCheck,
  Tag,
  Lock,
  Sparkles,
  Info,
  Check
} from 'lucide-react';
import { EmailAnalysisResult } from '../types/forensics.js';
import { submitAnalystVerification } from '../services/api.js';

interface AnalystVerificationSectionProps {
  analysis: EmailAnalysisResult;
  onVerificationSubmitted?: (record: any) => void;
}

const VERDICT_OPTIONS = [
  'Malicious',
  'Phishing',
  'Credential Theft',
  'Malware',
  'Business Email Compromise',
  'Financial Fraud',
  'Executive Impersonation',
  'Scam',
  'Spam/Bulk',
  'Newsletter',
  'Promotional',
  'Legitimate',
  'Suspicious',
  'Other'
];

export const AnalystVerificationSection: React.FC<AnalystVerificationSectionProps> = ({
  analysis,
  onVerificationSubmitted
}) => {
  const [isCorrect, setIsCorrect] = useState<boolean | null>(null);
  const [selectedVerdict, setSelectedVerdict] = useState<string>(analysis.primaryClassification || 'Legitimate');
  const [primaryCategory, setPrimaryCategory] = useState<string>(analysis.primaryClassification || 'Legitimate');
  const [classificationType, setClassificationType] = useState<'CONFIRMED_BENIGN' | 'CONFIRMED_THREAT' | 'FALSE_POSITIVE' | 'FALSE_NEGATIVE'>(
    (analysis.overallRiskScore || 0) >= 50 ? 'CONFIRMED_THREAT' : 'CONFIRMED_BENIGN'
  );
  const [analystConfidence, setAnalystConfidence] = useState<number>(0.95);
  const [reason, setReason] = useState<string>('');
  const [notes, setNotes] = useState<string>('');
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [submittedResult, setSubmittedResult] = useState<any | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const modelPredCategory = analysis.primaryClassification || 'Legitimate';
  const threatRisk = analysis.overallRiskScore ?? 0;
  const spamBulkScore = analysis.spamLikelihood ?? analysis.spam?.score ?? 0;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (isCorrect === null) {
      setErrorMessage('Please indicate whether the model prediction was confirmed or rejected.');
      return;
    }

    try {
      setSubmitting(true);
      setErrorMessage(null);

      const isMalicious = ['Malicious', 'Phishing', 'Credential Theft', 'Malware', 'Business Email Compromise', 'Financial Fraud', 'Executive Impersonation', 'Scam'].includes(selectedVerdict);
      const isSpam = ['Spam/Bulk', 'Newsletter', 'Promotional'].includes(selectedVerdict) || spamBulkScore >= 50;

      const payload = {
        analysisId: analysis.id,
        emailSubject: analysis.subject,
        sender: analysis.from,
        rawBody: analysis.emailContentAnalysis?.rawBodyText || analysis.subject,
        urls: (analysis.urls || []).map(u => u.url),
        originalPrediction: {
          primaryCategory: modelPredCategory,
          threatRisk,
          spamBulkScore,
          confidence: analysis.classificationConfidence ?? 90,
          detectedTechniques: (analysis.detectedTechniques || []).map(t => typeof t === 'string' ? t : `${t.id} - ${t.name}`)
        },
        verifiedGroundTruth: {
          primaryCategory,
          verdict: selectedVerdict,
          isMalicious,
          isSpam
        },
        isCorrect,
        classificationType,
        analyst: {
          id: 'analyst.soc@mailtrace.workstation',
          name: 'SOC Verification Analyst',
          role: 'SOC L3 Lead',
          confidence: analystConfidence
        },
        reason: reason.trim() || (isCorrect ? 'Analyst verified model verdict.' : 'Analyst corrected classification.'),
        notes: notes.trim(),
        modelVersion: 'mailtrace-100m-v2'
      };

      const result = await submitAnalystVerification(payload);
      setSubmittedResult(result);
      if (onVerificationSubmitted) onVerificationSubmitted(result);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to submit verification.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-5 space-y-4">
      
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded bg-indigo-50 border border-indigo-200 text-indigo-600">
            <Brain className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-xs uppercase font-bold text-slate-900 tracking-wide font-mono">
              Analyst Ground-Truth Verification
            </h2>
            <p className="text-[11px] text-slate-500">
              Governed feedback pipeline &bull; Queued for scheduled offline model retraining
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 bg-slate-50 px-2.5 py-1 rounded border border-slate-200 text-xs font-mono">
          <Database className="w-3.5 h-3.5 text-emerald-600" />
          <span className="text-slate-500">Target Model:</span>
          <span className="text-slate-900 font-semibold" title="MailTraceSecurityTransformer 128,894,258 Parameters">mailtrace-100m-v2 (128.9M)</span>
        </div>
      </div>

      {submittedResult ? (
        <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-lg text-xs space-y-2">
          <div className="flex items-center gap-2 text-emerald-800 font-bold font-mono">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>Ground-Truth Verification Recorded</span>
          </div>
          <p className="text-emerald-900 leading-normal">
            Verification ID <code className="font-mono">{submittedResult.record?.id || 'VERIFIED'}</code> has been queued into the verified training manifest. Model weights remain unchanged until scheduled offline evaluation.
          </p>
          <button
            onClick={() => { setSubmittedResult(null); setIsCorrect(null); }}
            className="mt-1 px-3 py-1 bg-white hover:bg-emerald-100 text-emerald-800 border border-emerald-300 rounded font-semibold text-xs transition"
          >
            Submit Another Feedback
          </button>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          {/* Quick Confirmation Buttons */}
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
            <label className="text-[11px] font-mono uppercase font-bold text-slate-700 block">
              Do you confirm the automated model classification ({modelPredCategory})?
            </label>
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => { setIsCorrect(true); setClassificationType(threatRisk >= 50 ? 'CONFIRMED_THREAT' : 'CONFIRMED_BENIGN'); }}
                className={`flex items-center gap-1.5 px-4 py-2 rounded font-semibold transition border shadow-xs ${
                  isCorrect === true
                    ? 'bg-emerald-600 text-white border-emerald-700'
                    : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-100'
                }`}
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Confirmed Correct</span>
              </button>

              <button
                type="button"
                onClick={() => { setIsCorrect(false); setClassificationType(threatRisk >= 50 ? 'FALSE_POSITIVE' : 'FALSE_NEGATIVE'); }}
                className={`flex items-center gap-1.5 px-4 py-2 rounded font-semibold transition border shadow-xs ${
                  isCorrect === false
                    ? 'bg-rose-600 text-white border-rose-700'
                    : 'bg-white text-slate-700 border-slate-300 hover:bg-slate-100'
                }`}
              >
                <XCircle className="w-3.5 h-3.5" />
                <span>Rejected / Incorrect</span>
              </button>
            </div>
          </div>

          {/* If Incorrect, Select Correct Verdict */}
          {isCorrect === false && (
            <div className="p-3.5 rounded-lg bg-rose-50/50 border border-rose-200 space-y-3">
              <div>
                <label className="text-[11px] font-mono uppercase font-bold text-slate-700 block mb-1">
                  Correct Ground-Truth Verdict
                </label>
                <select
                  value={selectedVerdict}
                  onChange={(e) => { setSelectedVerdict(e.target.value); setPrimaryCategory(e.target.value); }}
                  className="w-full sm:w-72 px-3 py-1.5 bg-white border border-slate-300 rounded font-mono text-xs text-slate-900"
                >
                  {VERDICT_OPTIONS.map((opt) => (
                    <option key={opt} value={opt}>{opt}</option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-[11px] font-mono uppercase font-bold text-slate-700 block mb-1">
                  Correction Rationale / Reason
                </label>
                <input
                  type="text"
                  placeholder="e.g. Valid vendor invoices from known supplier domain; false positive on urgency wording."
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  className="w-full px-3 py-1.5 bg-white border border-slate-300 rounded text-xs text-slate-900"
                />
              </div>
            </div>
          )}

          {errorMessage && (
            <div className="p-2.5 bg-rose-50 border border-rose-200 rounded text-rose-700 text-xs font-mono">
              {errorMessage}
            </div>
          )}

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={submitting || isCorrect === null}
              className="px-4 py-2 rounded bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white font-semibold text-xs shadow-xs transition"
            >
              {submitting ? 'Submitting to Governance Queue...' : 'Commit Ground-Truth Verification'}
            </button>
          </div>
        </form>
      )}

    </div>
  );
};
