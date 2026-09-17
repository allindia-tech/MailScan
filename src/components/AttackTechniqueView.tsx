/**
 * MailTrace Workstation - Attack Technique & Multi-Layer Normalization View
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Visualizes detected deception tactics (Unicode smuggling, Bidi, Homoglyphs, Quishing, BEC) and raw vs normalized views.
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  Code,
  Eye,
  AlertTriangle,
  FileCode,
  Layers,
  Sparkles,
  CheckCircle2,
  Terminal,
  Zap,
  Flame,
  Binary
} from 'lucide-react';
import { EmailAnalysisResult, DetectedAttackTechnique } from '../types/forensics.js';

interface AttackTechniqueViewProps {
  analysis: EmailAnalysisResult;
}

export const AttackTechniqueView: React.FC<AttackTechniqueViewProps> = ({ analysis }) => {
  const techniques = analysis.detectedTechniques || [];
  const normalization = analysis.multiLayerNormalization;

  const [activeTab, setActiveTab] = useState<'techniques' | 'normalization' | 'html-dom'>('techniques');
  const [selectedTechniqueId, setSelectedTechniqueId] = useState<string | null>(
    techniques.length > 0 ? techniques[0].id : null
  );

  const selectedTechnique = techniques.find(t => t.id === selectedTechniqueId) || techniques[0];

  const criticalCount = techniques.filter(t => t.severity === 'critical').length;
  const highCount = techniques.filter(t => t.severity === 'high').length;
  const mediumCount = techniques.filter(t => t.severity === 'medium').length;

  return (
    <div className="space-y-5">
      
      {/* 1. Header Banner with Metric Summary */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <ShieldAlert className="w-4 h-4 text-indigo-600" />
              <h2 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
                MITRE ATT&CK Mapping & Technique Engine
              </h2>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-100 text-slate-700 border border-slate-200">
                Taxonomy v2.4
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Multi-layer heuristic analysis detecting Unicode smuggling, Bidi overrides, homoglyphs, quishing, and credential harvesting.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono">
            <div className="px-2.5 py-1 rounded bg-rose-50 border border-rose-200 text-rose-700 font-semibold">
              <span className="font-bold mr-1">{criticalCount}</span> Critical
            </div>
            <div className="px-2.5 py-1 rounded bg-amber-50 border border-amber-200 text-amber-800 font-semibold">
              <span className="font-bold mr-1">{highCount}</span> High
            </div>
            <div className="px-2.5 py-1 rounded bg-blue-50 border border-blue-200 text-blue-700 font-semibold">
              <span className="font-bold mr-1">{mediumCount}</span> Medium
            </div>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex items-center gap-2 mt-4 pt-3 border-t border-slate-100 text-xs">
          <button
            onClick={() => setActiveTab('techniques')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition font-medium ${
              activeTab === 'techniques'
                ? 'bg-indigo-600 text-white font-semibold shadow-xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Zap className="w-3.5 h-3.5" />
            <span>Detected Techniques ({techniques.length})</span>
          </button>

          <button
            onClick={() => setActiveTab('normalization')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition font-medium ${
              activeTab === 'normalization'
                ? 'bg-indigo-600 text-white font-semibold shadow-xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Multi-Layer Normalization</span>
          </button>

          <button
            onClick={() => setActiveTab('html-dom')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition font-medium ${
              activeTab === 'html-dom'
                ? 'bg-indigo-600 text-white font-semibold shadow-xs'
                : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
            }`}
          >
            <Code className="w-3.5 h-3.5" />
            <span>HTML Structure Scan</span>
          </button>
        </div>
      </div>

      {/* 2. TAB 1: Detected Attack Techniques Breakdown */}
      {activeTab === 'techniques' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
          
          {/* Left Column: Techniques List */}
          <div className="lg:col-span-1 space-y-2">
            {techniques.length === 0 ? (
              <div className="p-6 bg-white border border-slate-200 rounded-xl text-center text-xs text-slate-500 shadow-xs">
                <CheckCircle2 className="w-6 h-6 text-emerald-600 mx-auto mb-2" />
                No obfuscation, homoglyph, or deceptive attack techniques detected in this message.
              </div>
            ) : (
              techniques.map((t) => {
                const isSelected = (selectedTechnique && selectedTechnique.id === t.id) || (selectedTechniqueId === t.id);
                return (
                  <div
                    key={t.id}
                    onClick={() => setSelectedTechniqueId(t.id)}
                    className={`p-3 rounded-lg border cursor-pointer transition ${
                      isSelected
                        ? 'bg-indigo-50 border-indigo-500 shadow-xs ring-1 ring-indigo-500/20'
                        : 'bg-white border-slate-200 hover:border-slate-300 hover:bg-slate-50'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <span className="text-xs font-semibold text-slate-900 leading-snug">
                        {t.name}
                      </span>
                      <span className={`text-[9px] font-mono uppercase px-1.5 py-0.2 rounded font-bold shrink-0 border ${
                        t.severity === 'critical'
                          ? 'bg-rose-50 text-rose-700 border-rose-200'
                          : t.severity === 'high'
                          ? 'bg-amber-50 text-amber-800 border-amber-200'
                          : 'bg-blue-50 text-blue-700 border-blue-200'
                      }`}>
                        {t.severity}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-slate-500">
                      <span>{t.category}</span>
                      <span className="font-mono text-slate-700 font-semibold">{t.confidence}% conf</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Right 2 Columns: Selected Technique Deep Dive */}
          <div className="lg:col-span-2">
            {selectedTechnique ? (
              <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-5 space-y-4">
                
                {/* Header */}
                <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-100">
                  <div>
                    <span className="text-[10px] font-mono text-slate-400 uppercase">
                      Technique ID: {selectedTechnique.id}
                    </span>
                    <h3 className="text-sm font-bold text-slate-900 mt-0.5">
                      {selectedTechnique.name}
                    </h3>
                    <div className="text-xs text-slate-500 mt-0.5">
                      Category: <span className="text-slate-800 font-medium">{selectedTechnique.category}</span>
                    </div>
                  </div>

                  <div className="text-right">
                    <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded font-bold border ${
                      selectedTechnique.severity === 'critical'
                        ? 'bg-rose-50 text-rose-700 border-rose-200'
                        : selectedTechnique.severity === 'high'
                        ? 'bg-amber-50 text-amber-800 border-amber-200'
                        : 'bg-blue-50 text-blue-700 border-blue-200'
                    }`}>
                      {selectedTechnique.severity} SEVERITY
                    </span>
                    <div className="text-[11px] font-mono text-slate-500 mt-1">
                      Confidence: <span className="text-indigo-600 font-bold">{selectedTechnique.confidence}%</span>
                    </div>
                  </div>
                </div>

                {/* Evidence Details */}
                <div>
                  <h4 className="text-xs font-semibold text-slate-900 uppercase tracking-wider mb-1.5 flex items-center gap-1.5 font-mono">
                    <Terminal className="w-3.5 h-3.5 text-indigo-600" />
                    <span>Forensic Evidence & Findings</span>
                  </h4>
                  <div className="p-3 bg-slate-50 rounded border border-slate-200 text-xs text-slate-800 leading-relaxed font-mono">
                    {selectedTechnique.evidence}
                  </div>
                </div>

                {/* Raw vs Normalized Stream Diff */}
                {selectedTechnique.rawRepresentation && (
                  <div>
                    <h4 className="text-xs font-semibold text-slate-900 uppercase tracking-wider mb-1.5 flex items-center gap-1.5 font-mono">
                      <Binary className="w-3.5 h-3.5 text-amber-600" />
                      <span>Observed Raw Representation</span>
                    </h4>
                    <div className="p-2.5 bg-slate-900 rounded text-[11px] font-mono text-amber-300 break-all leading-normal">
                      {selectedTechnique.rawRepresentation}
                    </div>
                  </div>
                )}

                {selectedTechnique.normalizedRepresentation && (
                  <div>
                    <h4 className="text-xs font-semibold text-slate-900 uppercase tracking-wider mb-1.5 flex items-center gap-1.5 font-mono">
                      <Eye className="w-3.5 h-3.5 text-emerald-600" />
                      <span>Normalized Target Representation</span>
                    </h4>
                    <div className="p-2.5 bg-slate-900 rounded text-[11px] font-mono text-emerald-300 break-all leading-normal">
                      {selectedTechnique.normalizedRepresentation}
                    </div>
                  </div>
                )}

                {/* Detector Source & Metadata */}
                <div className="pt-3 border-t border-slate-100 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                  <span>Engine: {selectedTechnique.detectorId || 'Core Classifier'} ({selectedTechnique.detectorVersion || 'v2.4'})</span>
                  <span>Source: {selectedTechnique.source}</span>
                </div>

              </div>
            ) : (
              <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-8 text-center text-xs text-slate-500">
                Select a detected technique on the left to view detailed forensic evidence and raw vs normalized representations.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2 & 3: Normalization & HTML DOM Views */}
      {activeTab === 'normalization' && (
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-5 space-y-4">
          <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide font-mono">
            Multi-Layer Normalization Architecture
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <div className="text-[11px] font-mono text-slate-500 uppercase mb-1 font-bold">Input Plain Text</div>
              <pre className="p-3 bg-slate-900 text-slate-200 text-xs font-mono rounded overflow-auto max-h-60 leading-relaxed">
                {normalization?.plainText || analysis.bodyText || 'No plain text stream.'}
              </pre>
            </div>
            <div>
              <div className="text-[11px] font-mono text-slate-500 uppercase mb-1 font-bold">Extracted URLs & Normalized Targets</div>
              <div className="p-3 bg-slate-50 border border-slate-200 text-xs font-mono rounded space-y-1.5">
                {analysis.urls.map((u, i) => (
                  <div key={i} className="text-slate-800 break-all">
                    &bull; {u.url} <span className="text-slate-500">({u.domain})</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'html-dom' && (
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-5 space-y-4">
          <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide font-mono">
            HTML Structure & Sanitized DOM Scan
          </h3>
          <pre className="p-4 bg-slate-900 text-slate-200 text-xs font-mono rounded overflow-auto max-h-80 leading-relaxed">
            {normalization?.htmlCleaned || analysis.bodyText || 'No raw HTML parts present in specimen.'}
          </pre>
        </div>
      )}

    </div>
  );
};
