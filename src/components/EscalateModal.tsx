/**
 * MailTrace AI - Escalate to Incident Case Modal
 * Clean Enterprise DFIR Case Creation Dialog
 */

import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Plus,
  AlertTriangle,
  UserCheck,
  FileText,
  Lock
} from 'lucide-react';
import { EmailAnalysisResult } from '../types/forensics.js';

interface EscalateModalProps {
  isOpen: boolean;
  onClose: () => void;
  analysis: EmailAnalysisResult;
  onSubmitCase: (caseData: {
    title: string;
    description: string;
    severity: string;
    assignedTo: string;
  }) => void;
}

export const EscalateModal: React.FC<EscalateModalProps> = ({
  isOpen,
  onClose,
  analysis,
  onSubmitCase
}) => {
  const [title, setTitle] = useState(`[${analysis.severity}] ${analysis.primaryClassification}: "${analysis.subject}"`);
  const [assignedTo, setAssignedTo] = useState('SOC Tier 2 - DFIR Specialist');
  const [description, setDescription] = useState(
    `Email analysis yielded threat risk score ${analysis.overallRiskScore}/100.
Sender: ${analysis.from}
Origin IP: ${analysis.earliestReliableNode?.ip || 'Unknown'} (${analysis.earliestReliableNode?.city || 'Unknown'}, ${analysis.earliestReliableNode?.country || 'Unknown'})
Authentication: SPF=${analysis.authResults?.spf?.status || 'none'}, DKIM=${analysis.authResults?.dkim?.status || 'none'}, DMARC=${analysis.authResults?.dmarc?.status || 'none'}.
Active IOCs: ${analysis.iocs?.length || 0} detected. Immediate containment action required.`
  );

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmitCase({
      title,
      description,
      severity: analysis.severity,
      assignedTo
    });
    onClose();
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev?.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-50 text-rose-700 border-rose-200';
      case 'HIGH':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'MEDIUM':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      default:
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="bg-white border border-slate-200 rounded-lg max-w-lg w-full p-6 shadow-2xl relative">
        <button
          onClick={onClose}
          className="absolute right-4 top-4 p-1.5 rounded text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition"
        >
          <X className="w-4 h-4" />
        </button>

        <div className="flex items-center gap-3 pb-4 mb-5 border-b border-slate-100">
          <div className="w-9 h-9 rounded-md bg-rose-50 border border-rose-200 text-rose-600 flex items-center justify-center shrink-0">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-xs uppercase tracking-wider font-bold text-slate-900">
              Escalate to Incident Registry
            </h2>
            <p className="text-[11px] text-slate-500">Initiate formal DFIR case and lock cryptographic chain of custody</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-slate-600 font-medium text-[11px] mb-1.5">Incident Title</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full bg-slate-50 text-slate-900 rounded border border-slate-200 px-3 py-2 focus:outline-none focus:border-indigo-500 focus:bg-white font-mono text-xs transition"
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-600 font-medium text-[11px] mb-1.5">Severity Tier</label>
              <div className={`font-mono font-semibold rounded border px-3 py-2 flex items-center justify-between text-xs ${getSeverityBadge(analysis.severity)}`}>
                <span>{analysis.severity}</span>
                <span className="text-[10px] opacity-75">{analysis.overallRiskScore}/100</span>
              </div>
            </div>
            <div>
              <label className="block text-slate-600 font-medium text-[11px] mb-1.5">Assignee</label>
              <input
                type="text"
                value={assignedTo}
                onChange={(e) => setAssignedTo(e.target.value)}
                className="w-full bg-slate-50 text-slate-900 rounded border border-slate-200 px-3 py-2 focus:outline-none focus:border-indigo-500 focus:bg-white text-xs transition"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-600 font-medium text-[11px] mb-1.5">Initial Case Notes & Observations</label>
            <textarea
              rows={4}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full bg-slate-50 text-slate-900 rounded border border-slate-200 px-3 py-2 focus:outline-none focus:border-indigo-500 focus:bg-white leading-relaxed font-mono text-[11px] transition"
              required
            />
          </div>

          <div className="p-3 bg-slate-50 border border-slate-100 rounded text-[11px] text-slate-500 flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
            <span>Associated RFC headers, MIME artifacts, and IOC registry tokens will be sealed to the case record.</span>
          </div>

          <div className="pt-4 border-t border-slate-100 flex items-center justify-end gap-2.5">
            <button
              type="button"
              onClick={onClose}
              className="px-3.5 py-1.5 rounded text-xs font-medium text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-xs transition"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Create Case</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
