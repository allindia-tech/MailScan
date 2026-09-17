/**
 * MailTrace Workstation - DFIR Case Management & Incident Reports
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Incident cases list, immutable evidence locker, investigator notes, and STIX 2.1 exporter.
 */

import React, { useState } from 'react';
import {
  Briefcase,
  FileDown,
  Lock,
  MessageSquare,
  Send,
  FileText,
  FileCode,
  Share2,
  Clock,
  Plus,
  ShieldCheck,
  CheckCircle2
} from 'lucide-react';
import { AuditLogItem, CaseItem, EmailAnalysisResult, EvidenceItem } from '../types/forensics.js';

interface CasesAndReportsViewProps {
  cases: CaseItem[];
  evidence: EvidenceItem[];
  auditLogs: AuditLogItem[];
  onAddCaseNote: (caseId: string, noteText: string) => void;
  activeAnalysis?: EmailAnalysisResult;
  onExportReport: (format: 'markdown' | 'json' | 'stix') => void;
}

export const CasesAndReportsView: React.FC<CasesAndReportsViewProps> = ({
  cases,
  evidence,
  auditLogs,
  onAddCaseNote,
  activeAnalysis,
  onExportReport
}) => {
  const [selectedCaseId, setSelectedCaseId] = useState<string>(cases[0]?.id || '');
  const [newNote, setNewNote] = useState('');
  const [activeTab, setActiveTab] = useState<'cases' | 'evidence' | 'audit' | 'export'>('cases');

  const selectedCase = cases.find(c => c.id === selectedCaseId) || cases[0];

  const handleSendNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    onAddCaseNote(selectedCaseId, newNote);
    setNewNote('');
  };

  return (
    <div className="space-y-5">
      
      {/* Top Header & Tab Controls */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-3.5 flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-1 bg-slate-50 p-1 rounded border border-slate-200 text-xs">
          <button
            onClick={() => setActiveTab('cases')}
            className={`px-3 py-1.5 rounded text-xs font-semibold transition ${
              activeTab === 'cases' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Incident Cases ({cases.length})
          </button>
          <button
            onClick={() => setActiveTab('evidence')}
            className={`px-3 py-1.5 rounded text-xs font-semibold transition ${
              activeTab === 'evidence' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Evidence Vault ({evidence.length})
          </button>
          <button
            onClick={() => setActiveTab('audit')}
            className={`px-3 py-1.5 rounded text-xs font-semibold transition ${
              activeTab === 'audit' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            DFIR Audit Logs ({auditLogs.length})
          </button>
          <button
            onClick={() => setActiveTab('export')}
            className={`px-3 py-1.5 rounded text-xs font-semibold transition ${
              activeTab === 'export' ? 'bg-indigo-600 text-white shadow-xs' : 'text-slate-600 hover:text-slate-900'
            }`}
          >
            Export & STIX 2.1
          </button>
        </div>

        <button
          onClick={() => onExportReport('markdown')}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 text-indigo-700 text-xs font-semibold shadow-xs transition"
        >
          <FileDown className="w-3.5 h-3.5" />
          <span>Export Markdown Report</span>
        </button>
      </div>

      {/* VIEW 1: Incident Cases */}
      {activeTab === 'cases' && (
        cases.length === 0 ? (
          <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-12 text-center flex flex-col items-center justify-center">
            <Briefcase className="w-10 h-10 text-slate-400 mb-3" />
            <h3 className="text-sm font-bold text-slate-900 font-mono">No Incident Cases Registered</h3>
            <p className="text-xs text-slate-500 max-w-md mt-1 leading-relaxed">
              When analyzing an email, click "Quarantine & Escalate" to track artifacts and custody notes.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            
            {/* Cases List */}
            <div className="lg:col-span-5 rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
              <div className="pb-3 border-b border-slate-100 flex items-center justify-between">
                <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
                  Active Incident Registry
                </h3>
                <span className="text-[11px] text-slate-500 font-mono">{cases.length} cases</span>
              </div>

              <div className="space-y-2">
                {cases.map((c) => (
                  <div
                    key={c.id}
                    onClick={() => setSelectedCaseId(c.id)}
                    className={`p-3 rounded-lg cursor-pointer transition border text-xs ${
                      selectedCaseId === c.id
                        ? 'bg-indigo-50 border-indigo-400 shadow-xs'
                        : 'bg-slate-50 border-slate-200 hover:border-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono text-[11px] font-bold text-indigo-700">{c.id}</span>
                      <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold border ${
                        c.priority === 'CRITICAL'
                          ? 'bg-rose-50 text-rose-700 border-rose-200'
                          : 'bg-amber-50 text-amber-800 border-amber-200'
                      }`}>
                        {c.priority}
                      </span>
                    </div>
                    <div className="font-semibold text-slate-900 line-clamp-1">{c.title}</div>
                    <div className="text-[11px] text-slate-500 mt-1 flex items-center justify-between font-mono">
                      <span>{c.analyst}</span>
                      <span>{c.createdAt.substring(0, 10)}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Selected Case Details */}
            {selectedCase && (
              <div className="lg:col-span-7 rounded-xl bg-white border border-slate-200 shadow-xs p-5 flex flex-col justify-between">
                <div>
                  <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-100">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-mono font-bold text-indigo-700">{selectedCase.id}</span>
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-100 text-slate-700 border border-slate-200">
                          {selectedCase.status}
                        </span>
                      </div>
                      <h3 className="text-sm font-bold text-slate-900">{selectedCase.title}</h3>
                    </div>
                    <div className="text-right text-xs text-slate-500 font-mono">
                      <div>Lead: <strong className="text-slate-800">{selectedCase.analyst}</strong></div>
                    </div>
                  </div>

                  <div className="text-xs text-slate-700 leading-relaxed bg-slate-50 p-3 rounded-lg border border-slate-200 mb-4">
                    {selectedCase.description}
                  </div>

                  {/* Case Notes Thread */}
                  <div>
                    <h4 className="text-xs uppercase tracking-wider font-bold text-slate-900 mb-2 flex items-center gap-1.5 font-mono">
                      <MessageSquare className="w-3.5 h-3.5 text-indigo-600" />
                      <span>Investigator Notes ({selectedCase.notes.length})</span>
                    </h4>
                    <div className="space-y-2 max-h-52 overflow-y-auto pr-1">
                      {selectedCase.notes.map((note) => (
                        <div key={note.id} className="p-2.5 rounded bg-slate-50 border border-slate-200 text-xs">
                          <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1 font-mono">
                            <span className="font-bold text-indigo-700">{note.author}</span>
                            <span>{note.timestamp}</span>
                          </div>
                          <p className="text-slate-800 leading-relaxed">{note.text}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Add Note Form */}
                <form onSubmit={handleSendNote} className="mt-4 pt-3 border-t border-slate-100 flex items-center gap-2">
                  <input
                    type="text"
                    placeholder="Append forensic observation or containment step..."
                    value={newNote}
                    onChange={(e) => setNewNote(e.target.value)}
                    className="flex-1 bg-slate-50 text-slate-900 text-xs rounded px-3 py-1.5 border border-slate-300 focus:outline-none focus:ring-1 focus:ring-indigo-600"
                  />
                  <button
                    type="submit"
                    disabled={!newNote.trim()}
                    className="px-3.5 py-1.5 rounded bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white text-xs font-semibold transition shadow-xs"
                  >
                    Add note
                  </button>
                </form>
              </div>
            )}

          </div>
        )
      )}

      {/* VIEW 2: Evidence Vault */}
      {activeTab === 'evidence' && (
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
          <div className="pb-3 border-b border-slate-100 flex items-center justify-between">
            <div>
              <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
                Cryptographic Evidence Vault
              </h3>
              <span className="text-[11px] text-slate-500">
                Artifacts hashed at ingestion with SHA-256 for chain-of-custody preservation
              </span>
            </div>
          </div>

          {evidence.length === 0 ? (
            <div className="py-8 text-center text-slate-500 text-xs font-mono">
              Evidence vault empty. Artifacts are automatically archived when cases are escalated.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-500 uppercase text-[10px] tracking-wider bg-slate-50 font-mono">
                    <th className="py-2.5 px-3 font-semibold w-28">Evidence ID</th>
                    <th className="py-2.5 px-3 font-semibold w-48">Artifact Name</th>
                    <th className="py-2.5 px-3 font-semibold w-28">Type</th>
                    <th className="py-2.5 px-3 font-semibold">SHA-256 Hash</th>
                    <th className="py-2.5 px-3 font-semibold w-28 text-right">Integrity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                  {evidence.map((ev) => (
                    <tr key={ev.id} className="hover:bg-slate-50 transition-colors">
                      <td className="py-3 px-3 font-bold text-indigo-700">{ev.id}</td>
                      <td className="py-3 px-3 text-slate-900 font-medium">{ev.title}</td>
                      <td className="py-3 px-3 text-slate-600">{ev.type}</td>
                      <td className="py-3 px-3 text-slate-700 break-all">{ev.sha256}</td>
                      <td className="py-3 px-3 text-right">
                        <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 text-[10px] font-bold">
                          LOCKED
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* VIEW 3: Audit Logs */}
      {activeTab === 'audit' && (
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
          <div className="pb-3 border-b border-slate-100 flex items-center justify-between">
            <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              SOC DFIR Audit & Governance Log
            </h3>
            <span className="text-[11px] font-mono text-slate-500">{auditLogs.length} Records</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500 uppercase text-[10px] tracking-wider bg-slate-50 font-mono">
                  <th className="py-2.5 px-3 font-semibold w-36">Timestamp</th>
                  <th className="py-2.5 px-3 font-semibold w-32">Analyst</th>
                  <th className="py-2.5 px-3 font-semibold w-40">Action</th>
                  <th className="py-2.5 px-3 font-semibold">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-slate-50 transition-colors">
                    <td className="py-2.5 px-3 text-slate-500">{log.timestamp}</td>
                    <td className="py-2.5 px-3 font-bold text-slate-800">{log.analyst}</td>
                    <td className="py-2.5 px-3 font-semibold text-indigo-700">{log.action}</td>
                    <td className="py-2.5 px-3 text-slate-700">{log.details}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* VIEW 4: Export & STIX */}
      {activeTab === 'export' && (
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-5 space-y-4">
          <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
            Court-Ready Forensic Report Exporter
          </h3>
          <p className="text-xs text-slate-600 leading-relaxed max-w-2xl">
            Export comprehensive incident reports, cryptographic header hashes, and STIX 2.1 threat intelligence bundles for SIEM ingestion or forensic court admissibility.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
            <button
              onClick={() => onExportReport('markdown')}
              className="p-4 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 text-left transition shadow-xs space-y-1"
            >
              <FileText className="w-5 h-5 text-indigo-600 mb-1" />
              <div className="font-bold text-slate-900 text-xs font-mono">Markdown Investigation Report</div>
              <p className="text-[11px] text-slate-500">Executive & technical DFIR summary with header breakdowns.</p>
            </button>

            <button
              onClick={() => onExportReport('stix')}
              className="p-4 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 text-left transition shadow-xs space-y-1"
            >
              <Share2 className="w-5 h-5 text-indigo-600 mb-1" />
              <div className="font-bold text-slate-900 text-xs font-mono">STIX 2.1 Bundle</div>
              <p className="text-[11px] text-slate-500">OASIS Open format for MISP, OpenCTI, and Sentinel integration.</p>
            </button>

            <button
              onClick={() => onExportReport('json')}
              className="p-4 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 text-left transition shadow-xs space-y-1"
            >
              <FileCode className="w-5 h-5 text-indigo-600 mb-1" />
              <div className="font-bold text-slate-900 text-xs font-mono">Full Telemetry JSON</div>
              <p className="text-[11px] text-slate-500">Raw deterministic JSON object with ML features & scores.</p>
            </button>
          </div>
        </div>
      )}

    </div>
  );
};
