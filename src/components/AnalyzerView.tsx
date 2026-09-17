/**
 * MailTrace Workstation - Specimen Ingestion & Analyzer View
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Precision specimen ingest, RFC 5322 parsing sandbox, and scenario selection.
 */

import React, { useState } from 'react';
import {
  UploadCloud,
  Play,
  Copy,
  Check,
  FileCode,
  FileText,
  Terminal,
  Maximize2,
  Minimize2,
  ArrowRight,
  ShieldAlert,
  Clock,
  Layers,
  Sparkles,
  Zap,
  CheckCircle2
} from 'lucide-react';
import { SampleSummary } from '../services/api.js';

interface AnalyzerViewProps {
  samples: SampleSummary[];
  currentSampleId?: string;
  onSelectSample: (id: string) => void;
  rawInput: string;
  setRawInput: (val: string) => void;
  onRunAnalysis: () => void;
  analyzing: boolean;
}

export const AnalyzerView: React.FC<AnalyzerViewProps> = ({
  samples,
  currentSampleId,
  onSelectSample,
  rawInput,
  setRawInput,
  onRunAnalysis,
  analyzing
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [copied, setCopied] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [viewTab, setViewTab] = useState<'full' | 'headers' | 'body'>('full');

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      const reader = new FileReader();
      reader.onload = (event) => {
        if (event.target?.result) {
          setRawInput(event.target.result as string);
        }
      };
      reader.readAsText(file);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const reader = new FileReader();
      reader.onload = (event) => {
        if (event.target?.result) {
          setRawInput(event.target.result as string);
        }
      };
      reader.readAsText(file);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(rawInput);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Helper to split raw input into headers and body
  const splitContent = () => {
    const doubleNewline = rawInput.indexOf('\n\n');
    const doubleCrlf = rawInput.indexOf('\r\n\r\n');
    let splitPos = -1;
    if (doubleNewline !== -1 && doubleCrlf !== -1) {
      splitPos = Math.min(doubleNewline, doubleCrlf);
    } else if (doubleNewline !== -1) {
      splitPos = doubleNewline;
    } else {
      splitPos = doubleCrlf;
    }

    if (splitPos === -1) {
      return { headers: rawInput, body: '' };
    }

    const headers = rawInput.slice(0, splitPos);
    const body = rawInput.slice(splitPos).trimStart();
    return { headers, body };
  };

  const { headers, body } = splitContent();

  const getDisplayedContent = () => {
    if (viewTab === 'headers') return headers;
    if (viewTab === 'body') return body || '(No separate MIME body found in specimen)';
    return rawInput;
  };

  const lineCount = rawInput ? rawInput.split('\n').length : 0;
  const byteCount = new Blob([rawInput]).size;

  return (
    <div className="space-y-5">
      
      {/* 1. INVESTIGATION SCENARIOS SELECTOR */}
      {samples && samples.length > 0 && (
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-100">
            <div>
              <h2 className="text-xs uppercase font-bold text-slate-900 tracking-wider font-mono">
                Investigation Scenarios & Artifacts
              </h2>
              <p className="text-[11px] text-slate-500">
                Pre-indexed forensic email vectors for SOC validation & triage tests
              </p>
            </div>
            <span className="text-[11px] font-mono text-slate-500 bg-slate-100 px-2 py-0.5 rounded border border-slate-200">
              {samples.length} Artifacts Indexed
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {samples.map((s) => {
              const isSelected = s.id === currentSampleId;
              const isCrit = s.expectedRisk >= 75;
              const isLow = s.expectedRisk <= 25;

              return (
                <button
                  key={s.id}
                  onClick={() => onSelectSample(s.id)}
                  disabled={analyzing}
                  className={`p-3 rounded-lg text-left transition-all border flex flex-col justify-between ${
                    isSelected
                      ? 'bg-indigo-50/80 border-indigo-500 shadow-xs ring-1 ring-indigo-500/20'
                      : 'bg-slate-50/60 border-slate-200 hover:border-slate-300 hover:bg-slate-100'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between gap-1 mb-1.5">
                      <span className="text-[10px] font-mono font-semibold px-1.5 py-0.2 rounded bg-white text-slate-700 border border-slate-200">
                        {s.scenarioTag}
                      </span>
                      <span className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border ${
                        isCrit
                          ? 'bg-rose-50 text-rose-700 border-rose-200'
                          : isLow
                          ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                          : 'bg-amber-50 text-amber-800 border-amber-200'
                      }`}>
                        {s.expectedRisk}/100
                      </span>
                    </div>

                    <div className="text-xs font-semibold text-slate-900 line-clamp-1">
                      {s.name}
                    </div>

                    <p className="text-[11px] text-slate-600 mt-1 line-clamp-2 leading-relaxed">
                      {s.description}
                    </p>
                  </div>

                  <div className="mt-2.5 pt-2 border-t border-slate-200/80 flex items-center justify-between text-[11px] font-medium text-indigo-600">
                    <span>{isSelected ? 'Currently Loaded' : 'Load Specimen'}</span>
                    <ArrowRight className="w-3 h-3" />
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* 2. SPECIMEN INGESTION & RAW RFC 822 WORKSPACE */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        
        {/* Left / Center: Raw Email Editor Viewport */}
        <div className={`rounded-xl bg-white border border-slate-200 shadow-xs overflow-hidden ${
          isExpanded ? 'lg:col-span-12' : 'lg:col-span-8'
        }`}>
          {/* Top Bar with View Tabs */}
          <div className="p-3 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center p-0.5 bg-white rounded border border-slate-200 shadow-xs">
              <button
                onClick={() => setViewTab('full')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-all ${
                  viewTab === 'full'
                    ? 'bg-indigo-600 text-white font-semibold shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>Full MIME Stream</span>
              </button>
              <button
                onClick={() => setViewTab('headers')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-all ${
                  viewTab === 'headers'
                    ? 'bg-indigo-600 text-white font-semibold shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>RFC Headers</span>
              </button>
              <button
                onClick={() => setViewTab('body')}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-all ${
                  viewTab === 'body'
                    ? 'bg-indigo-600 text-white font-semibold shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Body Content</span>
              </button>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleCopy}
                disabled={!rawInput}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-medium transition-colors shadow-xs disabled:opacity-50"
                title="Copy headers to clipboard"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>

              <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="p-1.5 rounded bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 transition shadow-xs"
                title={isExpanded ? 'Collapse' : 'Expand'}
              >
                {isExpanded ? <Minimize2 className="w-3.5 h-3.5" /> : <Maximize2 className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {/* Technical Viewport / Editor Area */}
          <div className="relative">
            <div className="px-4 py-1.5 bg-slate-100 flex items-center justify-between border-b border-slate-200 text-[11px] font-mono text-slate-600">
              <span>Encoding: UTF-8 &bull; {lineCount} Lines &bull; {byteCount.toLocaleString()} Bytes</span>
              <span className="text-emerald-700 flex items-center gap-1 font-semibold">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
                RFC 5322 Compliant Sandbox
              </span>
            </div>

            {viewTab === 'full' ? (
              <textarea
                value={rawInput}
                onChange={(e) => setRawInput(e.target.value)}
                placeholder="Paste raw RFC 5322 / RFC 822 email message here (including Received headers, Authentication-Results, and MIME parts)..."
                className="w-full h-80 p-4 font-mono text-xs bg-slate-900 text-slate-200 focus:outline-none resize-y selection:bg-indigo-600 selection:text-white leading-relaxed"
                spellCheck={false}
              />
            ) : (
              <pre className="w-full h-80 p-4 font-mono text-xs bg-slate-900 text-slate-200 overflow-auto select-text leading-relaxed">
                {getDisplayedContent()}
              </pre>
            )}
          </div>

          {/* Action Bar Footer */}
          <div className="p-3 bg-slate-50 border-t border-slate-200 flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-1.5 text-slate-600">
              <span className="font-mono text-[11px]">
                {rawInput.trim() ? `${lineCount} lines ready for parsing` : 'No specimen loaded'}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setRawInput('')}
                disabled={!rawInput || analyzing}
                className="px-3 py-1.5 rounded bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 font-medium transition shadow-xs disabled:opacity-50"
              >
                Clear Specimen
              </button>

              <button
                onClick={onRunAnalysis}
                disabled={!rawInput.trim() || analyzing}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs shadow-xs transition-all disabled:opacity-50"
              >
                {analyzing ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    <span>Analyzing Pipeline...</span>
                  </>
                ) : (
                  <>
                    <Zap className="w-3.5 h-3.5" />
                    <span>Execute Multi-Engine Forensics</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Right Side / Ingestion Dropzone Panel */}
        {!isExpanded && (
          <div className="lg:col-span-4 space-y-4">
            
            {/* Dropzone Card */}
            <div
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              className={`rounded-xl border-2 border-dashed p-6 text-center flex flex-col items-center justify-center transition-all bg-white shadow-xs ${
                dragActive
                  ? 'border-indigo-500 bg-indigo-50/50'
                  : 'border-slate-300 hover:border-indigo-400'
              }`}
            >
              <div className="w-12 h-12 rounded-lg bg-indigo-50 border border-indigo-200 text-indigo-600 flex items-center justify-center mb-3">
                <UploadCloud className="w-6 h-6 text-indigo-600" />
              </div>

              <h3 className="text-xs font-bold text-slate-900 uppercase tracking-wide font-mono">
                Upload Suspicious Email File
              </h3>
              <p className="text-[11px] text-slate-500 mt-1 max-w-xs leading-normal">
                Drop <strong className="text-slate-700">.eml</strong>, <strong className="text-slate-700">.msg</strong>, or raw RFC text. Parsed 100% locally in browser memory.
              </p>

              <label className="mt-3 cursor-pointer">
                <span className="px-3.5 py-1.5 rounded bg-white hover:bg-slate-50 border border-slate-300 text-slate-700 text-xs font-semibold shadow-xs transition inline-block">
                  Browse Specimen File
                </span>
                <input
                  type="file"
                  accept=".eml,.msg,.txt"
                  onChange={handleFileInput}
                  className="hidden"
                />
              </label>
            </div>

            {/* Analysis Engine Pipeline Info */}
            <div className="p-4 rounded-xl bg-white border border-slate-200 shadow-xs space-y-3">
              <h4 className="text-xs font-bold text-slate-900 uppercase tracking-wide font-mono flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-indigo-600" />
                <span>Forensic Inspection Engine</span>
              </h4>

              <div className="space-y-2 text-xs">
                <div className="p-2 rounded bg-slate-50 border border-slate-200 flex items-center justify-between">
                  <span className="text-slate-700 font-medium">Header RFC Parser</span>
                  <span className="font-mono text-emerald-700 font-bold text-[11px]">RFC 5322 / 822</span>
                </div>
                <div className="p-2 rounded bg-slate-50 border border-slate-200 flex items-center justify-between">
                  <span className="text-slate-700 font-medium">Cryptographic Auth</span>
                  <span className="font-mono text-emerald-700 font-bold text-[11px]">DKIM / SPF / DMARC</span>
                </div>
                <div className="p-2 rounded bg-slate-50 border border-slate-200 flex items-center justify-between">
                  <span className="text-slate-700 font-medium">ML Threat Classifier</span>
                  <span className="font-mono text-indigo-700 font-bold text-[11px]">Transformer 100M</span>
                </div>
                <div className="p-2 rounded bg-slate-50 border border-slate-200 flex items-center justify-between">
                  <span className="text-slate-700 font-medium">Evidence Fusion</span>
                  <span className="font-mono text-indigo-700 font-bold text-[11px]">Deterministic Engine</span>
                </div>
              </div>
            </div>

          </div>
        )}

      </div>

    </div>
  );
};
