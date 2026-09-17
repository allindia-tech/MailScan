/**
 * MailTrace AI - Analyst False Positive & Model Retraining Feedback Modal
 * Triggers when an analyst marks a detection as a false positive.
 * Captures granular error root causes: incorrect 'technique' label vs incorrect 'classification'.
 */

import React, { useState } from 'react';
import {
  X,
  AlertOctagon,
  CheckCircle2,
  ShieldCheck,
  Tag,
  Layers,
  Send,
  Sparkles,
  Info,
  Check,
  AlertTriangle,
  RotateCcw,
  Sliders
} from 'lucide-react';
import { EmailAnalysisResult, ThreatCategory, FeedbackTrustLevel } from '../types/forensics.js';
import { submitAnalystFeedback } from '../services/api.js';

interface AnalystFeedbackModalProps {
  isOpen: boolean;
  onClose: () => void;
  analysis: EmailAnalysisResult;
  initialFeedbackType?: 'technique' | 'classification' | 'both';
  targetTechniqueId?: string;
  onFeedbackSubmitted?: (feedback: any) => void;
}

const CLASSIFICATION_OPTIONS: ThreatCategory[] = [
  'Legitimate',
  'Promotional',
  'Newsletter',
  'Bulk / Unsolicited',
  'Spam',
  'Suspicious',
  'Phishing',
  'Credential Theft',
  'Business Email Compromise',
  'Financial Fraud',
  'Executive Impersonation',
  'Malware Delivery',
  'Domain Spoofing',
  'Account Compromise'
];

export const AnalystFeedbackModal: React.FC<AnalystFeedbackModalProps> = ({
  isOpen,
  onClose,
  analysis,
  initialFeedbackType = 'classification',
  targetTechniqueId,
  onFeedbackSubmitted
}) => {
  const [feedbackType, setFeedbackType] = useState<'technique' | 'classification' | 'both'>(initialFeedbackType);
  const [selectedIncorrectTechniques, setSelectedIncorrectTechniques] = useState<string[]>(
    targetTechniqueId ? [targetTechniqueId] : []
  );
  const [correctedClassification, setCorrectedClassification] = useState<ThreatCategory>('Legitimate');
  const [reason, setReason] = useState<string>('');
  const [trustLevel, setTrustLevel] = useState<FeedbackTrustLevel>('verified_analyst');
  const [trainingTarget, setTrainingTarget] = useState<'retraining_dataset' | 'quarantine_review' | 'telemetry_only'>('retraining_dataset');
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [successResult, setSuccessResult] = useState<any | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  if (!isOpen) return null;

  const detectedTechniques = analysis.detectedTechniques || [];

  const toggleTechniqueSelection = (techId: string) => {
    setSelectedIncorrectTechniques(prev =>
      prev.includes(techId) ? prev.filter(id => id !== techId) : [...prev, techId]
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    try {
      setSubmitting(true);
      setErrorMsg(null);

      const payload = {
        emailId: analysis.id,
        emailSubject: analysis.subject,
        originalClassification: analysis.primaryClassification,
        verifiedClassification: feedbackType === 'technique' ? analysis.primaryClassification : correctedClassification,
        feedbackType,
        incorrectTechniques: selectedIncorrectTechniques,
        reason: reason.trim() || `False positive report: ${feedbackType === 'technique' ? 'Mislabeled technique' : 'Misclassified email'}`,
        analyst: trustLevel === 'administrator' ? 'soc-admin.lead@defense.corp' : 'analyst.taylor@defense.corp',
        trustLevel,
        trainingTarget,
        features: {
          threatRisk: analysis.threatRisk,
          authenticityScore: analysis.authenticityConfidence,
          dmarcStatus: analysis.authResults?.dmarc?.status || 'none',
          spfStatus: analysis.authResults?.spf?.status || 'none',
          detectedTechniqueCount: detectedTechniques.length,
          mislabeledTechniques: selectedIncorrectTechniques
        }
      };

      const res = await submitAnalystFeedback(payload);
      setSuccessResult(res);
      if (onFeedbackSubmitted) {
        onFeedbackSubmitted(res);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to submit analyst feedback');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs overflow-y-auto animate-in fade-in duration-150">
      <div className="bg-white border border-slate-200 rounded-lg shadow-2xl max-w-2xl w-full overflow-hidden text-slate-800 my-8">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between p-4 px-6 border-b border-slate-200 bg-slate-50/60">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded bg-amber-50 border border-amber-200 text-amber-600">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-xs font-bold text-slate-900 tracking-wider uppercase font-mono">
                Analyst Ground-Truth & False Positive Audit
              </h2>
              <p className="text-[11px] text-slate-500">
                Audit detection accuracy and route verified feedback into protected challenger retraining pipelines.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-5">
          {successResult ? (
            <div className="p-5 bg-emerald-50 border border-emerald-200 rounded space-y-3 font-mono text-xs text-emerald-800">
              <div className="flex items-center gap-2 font-bold text-emerald-900 text-sm">
                <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                FEEDBACK RECORDED & QUEUED FOR RETRAINING
              </div>
              <p className="text-slate-700 leading-relaxed font-sans text-xs">
                {successResult.message || 'Analyst verdict successfully committed to the protected ML ground-truth pipeline.'}
              </p>
              <div className="pt-3 border-t border-emerald-200 flex items-center justify-between text-[11px] text-slate-600">
                <span>Recorded ID: <code className="text-emerald-700 font-bold">{successResult.item?.id || 'FBK-LIVE-AUDIT'}</code></span>
                <span>Pipeline Status: <strong className="text-emerald-700">{successResult.item?.status || 'QUEUED_FOR_TRAINING'}</strong></span>
              </div>
              <div className="pt-2 flex justify-end">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white rounded text-xs font-semibold"
                >
                  Close Window
                </button>
              </div>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5">
              
              {/* Context Header */}
              <div className="p-3.5 bg-slate-50 border border-slate-200 rounded text-xs font-mono space-y-1">
                <div className="text-slate-600 flex items-center justify-between">
                  <span>Subject: <strong className="text-slate-900">{analysis.subject || 'Untitled Email'}</strong></span>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-white border border-slate-200 text-slate-600 font-semibold">ID: {analysis.id}</span>
                </div>
                <div className="text-slate-600">
                  Current System Verdict: <span className="text-rose-600 font-bold">{analysis.primaryClassification}</span> (Score: {analysis.threatRisk}%)
                </div>
              </div>

              {/* Step 1: Specify Error Root Cause */}
              <div className="space-y-2">
                <label className="text-xs font-bold text-slate-800 uppercase tracking-wider font-mono flex items-center gap-2">
                  <Sliders className="w-3.5 h-3.5 text-indigo-600" />
                  1. What caused this False Positive / Error?
                </label>
                <div className="grid grid-cols-3 gap-2.5">
                  <button
                    type="button"
                    onClick={() => setFeedbackType('classification')}
                    className={`p-3 rounded border text-left transition ${
                      feedbackType === 'classification'
                        ? 'bg-indigo-50/60 border-indigo-500 text-indigo-900 ring-1 ring-indigo-500'
                        : 'bg-white border-slate-200 text-slate-600 hover:border-slate-300'
                    }`}
                  >
                    <div className="font-mono text-xs font-bold flex items-center gap-1.5 text-slate-900">
                      <Tag className="w-3.5 h-3.5 text-indigo-600" />
                      Classification
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1 leading-snug">
                      Wrong top-level threat verdict (e.g. Benign marked as Phishing).
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setFeedbackType('technique')}
                    className={`p-3 rounded border text-left transition ${
                      feedbackType === 'technique'
                        ? 'bg-amber-50/60 border-amber-500 text-amber-900 ring-1 ring-amber-500'
                        : 'bg-white border-slate-200 text-slate-600 hover:border-slate-300'
                    }`}
                  >
                    <div className="font-mono text-xs font-bold flex items-center gap-1.5 text-slate-900">
                      <Layers className="w-3.5 h-3.5 text-amber-600" />
                      Technique Label
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1 leading-snug">
                      Individual attack tactic or heuristic misidentified.
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => setFeedbackType('both')}
                    className={`p-3 rounded border text-left transition ${
                      feedbackType === 'both'
                        ? 'bg-purple-50/60 border-purple-500 text-purple-900 ring-1 ring-purple-500'
                        : 'bg-white border-slate-200 text-slate-600 hover:border-slate-300'
                    }`}
                  >
                    <div className="font-mono text-xs font-bold flex items-center gap-1.5 text-slate-900">
                      <RotateCcw className="w-3.5 h-3.5 text-purple-600" />
                      Both Errors
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1 leading-snug">
                      Both technique labels and overall verdict require correction.
                    </div>
                  </button>
                </div>
              </div>

              {/* Step 2A: Technique Selection (if technique or both) */}
              {(feedbackType === 'technique' || feedbackType === 'both') && (
                <div className="space-y-2 p-3.5 bg-amber-50/50 border border-amber-200 rounded">
                  <label className="text-xs font-bold text-amber-900 font-mono block">
                    Select Misidentified Technique(s) to Invalidate:
                  </label>
                  {detectedTechniques.length > 0 ? (
                    <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
                      {detectedTechniques.map((tech) => {
                        const isSelected = selectedIncorrectTechniques.includes(tech.id);
                        return (
                          <div
                            key={tech.id}
                            onClick={() => toggleTechniqueSelection(tech.id)}
                            className={`p-2.5 rounded border text-xs font-mono cursor-pointer flex items-center justify-between transition ${
                              isSelected
                                ? 'bg-rose-50 border-rose-400 text-rose-900 font-semibold'
                                : 'bg-white border-slate-200 text-slate-700 hover:border-slate-300'
                            }`}
                          >
                            <div>
                              <span className="text-slate-900 font-bold">{tech.name}</span>
                              <span className="text-[10px] text-slate-500 block mt-0.5">{tech.category} &bull; Detector: {tech.detectorId}</span>
                            </div>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${isSelected ? 'bg-rose-600 text-white' : 'bg-slate-100 text-slate-600'}`}>
                              {isSelected ? 'Mislabeled' : 'Click to Flag'}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="text-xs text-slate-500 italic">
                      No automated techniques were recorded on this sample. You can still specify manual notes below.
                    </div>
                  )}
                </div>
              )}

              {/* Step 2B: Corrected Classification (if classification or both) */}
              {(feedbackType === 'classification' || feedbackType === 'both') && (
                <div className="space-y-2 p-3.5 bg-indigo-50/50 border border-indigo-200 rounded">
                  <label className="text-xs font-bold text-indigo-900 font-mono block">
                    Select True Ground-Truth Classification:
                  </label>
                  <select
                    value={correctedClassification}
                    onChange={(e) => setCorrectedClassification(e.target.value as ThreatCategory)}
                    className="w-full bg-white border border-slate-200 rounded p-2 text-xs font-mono text-slate-800 focus:outline-none focus:border-indigo-500"
                  >
                    {CLASSIFICATION_OPTIONS.map((opt) => (
                      <option key={opt} value={opt}>
                        {opt}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              {/* Step 3: Analyst Reason & Technical Justification */}
              <div className="space-y-1.5">
                <label className="text-xs font-bold text-slate-800 uppercase tracking-wider font-mono">
                  3. Analyst Justification & Forensic Evidence Notes:
                </label>
                <textarea
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="e.g. Legitimate internal payroll system notification with valid SPF/DKIM alignment. Zero-width character was an artifact of regional unicode layout, not smuggling."
                  rows={3}
                  className="w-full bg-slate-50 border border-slate-200 rounded p-3 text-xs text-slate-800 focus:outline-none focus:border-indigo-500 focus:bg-white font-sans transition"
                />
              </div>

              {/* Step 4: Pipeline Routing & Trust Level */}
              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-200">
                <div>
                  <label className="text-[11px] font-mono text-slate-600 block mb-1">
                    Analyst Role / Credentials
                  </label>
                  <select
                    value={trustLevel}
                    onChange={(e) => setTrustLevel(e.target.value as FeedbackTrustLevel)}
                    className="w-full bg-white border border-slate-200 rounded p-2 text-xs font-mono text-slate-800 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="verified_analyst">Verified SOC Tier-2 Analyst (Weight: 1.0)</option>
                    <option value="administrator">SOC Lead / Admin (Weight: 1.0)</option>
                    <option value="user_report">End-User Self Report (Quarantined)</option>
                  </select>
                </div>

                <div>
                  <label className="text-[11px] font-mono text-slate-600 block mb-1">
                    ML Retraining Action
                  </label>
                  <select
                    value={trainingTarget}
                    onChange={(e) => setTrainingTarget(e.target.value as any)}
                    className="w-full bg-white border border-slate-200 rounded p-2 text-xs font-mono text-slate-800 focus:outline-none focus:border-indigo-500"
                  >
                    <option value="retraining_dataset">Commit to Challenger Retraining</option>
                    <option value="quarantine_review">Quarantine for Peer Review</option>
                    <option value="telemetry_only">Audit Log Only (No Dataset Update)</option>
                  </select>
                </div>
              </div>

              {errorMsg && (
                <div className="p-2.5 bg-rose-50 border border-rose-200 rounded text-xs text-rose-700 font-mono">
                  {errorMsg}
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-200">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded text-xs font-medium transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="px-5 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded text-xs font-bold font-mono tracking-wide flex items-center gap-2 shadow-xs transition disabled:opacity-50"
                >
                  {submitting ? (
                    'COMMITTING FEEDBACK...'
                  ) : (
                    <>
                      <Send className="w-3.5 h-3.5" />
                      SUBMIT FOR RETRAINING
                    </>
                  )}
                </button>
              </div>

            </form>
          )}
        </div>

      </div>
    </div>
  );
};
