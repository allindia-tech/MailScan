/**
 * MailTrace AI - Automated Daily Summary Email Modal
 * Generates and previews executive SOC daily threat intelligence briefing.
 */

import React, { useState, useEffect } from 'react';
import {
  Mail,
  FileText,
  Copy,
  Check,
  Send,
  Download,
  X,
  RefreshCw,
  Sparkles,
  ShieldCheck,
  Flame,
  AlertTriangle,
  Clock
} from 'lucide-react';
import { fetchDailySummary, sendDailySummary } from '../services/api.js';

interface DailySummaryModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const DailySummaryModal: React.FC<DailySummaryModalProps> = ({ isOpen, onClose }) => {
  const [data, setData] = useState<any | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [activeFormat, setActiveFormat] = useState<'html' | 'plaintext'>('html');
  const [copied, setCopied] = useState<boolean>(false);
  const [sending, setSending] = useState<boolean>(false);
  const [sendSuccess, setSendSuccess] = useState<string | null>(null);
  const [recipientsInput, setRecipientsInput] = useState<string>('soc-leads@defense.corp, ciso@defense.corp');

  const loadSummary = async () => {
    try {
      setLoading(true);
      const res = await fetchDailySummary();
      setData(res);
      setSendSuccess(null);
    } catch (err) {
      console.error('Failed to load daily summary:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadSummary();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleCopy = () => {
    if (!data) return;
    const textToCopy = activeFormat === 'html' ? data.htmlContent : data.plainTextContent;
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSend = async () => {
    try {
      setSending(true);
      const recipients = recipientsInput.split(',').map(r => r.trim()).filter(Boolean);
      const res = await sendDailySummary(recipients);
      setSendSuccess(res.message || 'Daily summary briefing successfully dispatched.');
    } catch (err: any) {
      alert('Failed to dispatch summary: ' + err.message);
    } finally {
      setSending(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="bg-white border border-slate-200 rounded-lg w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        
        {/* Header */}
        <div className="p-4 px-6 border-b border-slate-200 flex items-center justify-between bg-slate-50/50">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-50 border border-indigo-200 rounded text-indigo-600">
              <Mail className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-slate-900 uppercase tracking-wide">
                  Automated Daily Threat Briefing
                </h2>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200 font-semibold">
                  24H EXECUTIVE DIGEST
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                Compiles open alerts, triage updates, multi-engine consensus, and critical incident containment
              </p>
            </div>
          </div>
          
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-700 rounded hover:bg-slate-100 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Action Controls & Format Switcher */}
        <div className="px-6 py-3 border-b border-slate-200 bg-white flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-500 font-mono text-[11px]">Format:</span>
            <div className="flex bg-slate-100 border border-slate-200 rounded p-0.5">
              <button
                onClick={() => setActiveFormat('html')}
                className={`px-3 py-1 rounded text-xs font-mono font-medium transition ${
                  activeFormat === 'html'
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Formatted HTML
              </button>
              <button
                onClick={() => setActiveFormat('plaintext')}
                className={`px-3 py-1 rounded text-xs font-mono font-medium transition ${
                  activeFormat === 'plaintext'
                    ? 'bg-white text-slate-900 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Plain Text / Markdown
              </button>
            </div>

            <button
              onClick={loadSummary}
              disabled={loading}
              className="p-1.5 rounded border border-slate-200 bg-white text-slate-600 hover:text-slate-900 text-xs ml-2 transition"
              title="Refresh Telemetry"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleCopy}
              disabled={!data}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-mono transition text-xs"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
              {copied ? 'Copied' : (activeFormat === 'html' ? 'Copy HTML' : 'Copy Plain Text')}
            </button>

            <button
              onClick={handleSend}
              disabled={sending || !data}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-indigo-600 hover:bg-indigo-700 text-white font-semibold transition text-xs shadow-xs"
            >
              <Send className={`w-3.5 h-3.5 ${sending ? 'animate-spin' : ''}`} />
              {sending ? 'Dispatching...' : 'Dispatch Briefing'}
            </button>
          </div>
        </div>

        {/* Dispatch Confirmation Banner */}
        {sendSuccess && (
          <div className="px-6 py-2.5 bg-emerald-50 border-b border-emerald-200 text-emerald-800 text-xs font-mono flex items-center justify-between">
            <span className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-600" />
              {sendSuccess}
            </span>
            <button onClick={() => setSendSuccess(null)} className="text-emerald-600 hover:text-emerald-900 font-bold">
              ✕
            </button>
          </div>
        )}

        {/* Recipients input bar */}
        <div className="px-6 py-2.5 bg-slate-50 border-b border-slate-200 flex items-center gap-3 text-xs">
          <span className="text-slate-600 font-mono text-[11px] shrink-0">Distribution List:</span>
          <input
            type="text"
            value={recipientsInput}
            onChange={(e) => setRecipientsInput(e.target.value)}
            className="flex-1 bg-white border border-slate-200 rounded px-3 py-1 text-slate-900 font-mono text-xs focus:outline-none focus:border-indigo-500"
            placeholder="comma-separated emails (e.g. soc@defense.corp, ciso@defense.corp)"
          />
        </div>

        {/* Content Area */}
        <div className="flex-1 overflow-y-auto p-6 bg-slate-50/50">
          {loading && (
            <div className="flex flex-col items-center justify-center py-20 text-slate-500 font-mono text-xs space-y-3">
              <RefreshCw className="w-6 h-6 animate-spin text-indigo-600" />
              <span>Compiling daily alerts, incidents, and threat statistics...</span>
            </div>
          )}

          {!loading && data && activeFormat === 'html' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs text-slate-500 font-mono px-1">
                <span>PREVIEWING RESPONSIVE HTML EMAIL FORMAT:</span>
                <span>{data.reportDate}</span>
              </div>
              <div
                className="rounded border border-slate-200 overflow-hidden shadow-xs bg-white p-4 text-slate-900"
                dangerouslySetInnerHTML={{ __html: data.htmlContent }}
              />
            </div>
          )}

          {!loading && data && activeFormat === 'plaintext' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-500 font-mono px-1">
                <span>ASCII / MARKDOWN EMAIL FORMAT:</span>
                <span>{data.plainTextContent?.length || 0} characters</span>
              </div>
              <pre className="p-4 bg-slate-900 text-slate-100 rounded border border-slate-800 font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed">
                {data.plainTextContent}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-3.5 px-6 border-t border-slate-200 bg-white flex items-center justify-between text-xs font-mono text-slate-500">
          <div className="flex items-center gap-2">
            <Clock className="w-3.5 h-3.5 text-slate-400" />
            <span>Automated Schedule: Daily 07:00 UTC Dispatch</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
