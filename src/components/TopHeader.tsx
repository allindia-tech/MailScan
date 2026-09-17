/**
 * MailTrace Workstation - Top Enterprise Navigation Header
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Restrained, high-density, authoritative SOC header.
 */

import React from 'react';
import {
  Shield,
  Search,
  UploadCloud,
  HelpCircle,
  Sparkles,
  Command
} from 'lucide-react';

interface TopHeaderProps {
  onNavigateToAnalyzer: () => void;
  onOpenCopilot: () => void;
  copilotOpen: boolean;
  analyzing: boolean;
  searchQuery: string;
  onSearchChange: (query: string) => void;
  onOpenDailySummary?: () => void;
  currentCaseId?: string;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  onNavigateToAnalyzer,
  onOpenCopilot,
  copilotOpen,
  analyzing,
  searchQuery,
  onSearchChange,
  onOpenDailySummary,
  currentCaseId
}) => {
  const [modelStatus, setModelStatus] = React.useState<{
    available?: boolean;
    loaded?: boolean;
    status?: string;
    version?: string;
    parameterCount?: number;
  } | null>(null);

  React.useEffect(() => {
    fetch('/api/model/status')
      .then(res => res.json())
      .then(data => setModelStatus(data))
      .catch(() => setModelStatus({ status: 'ERROR' }));
  }, []);

  return (
    <header className="w-full h-14 bg-white border-b border-slate-200 z-40 shrink-0 sticky top-0 shadow-[0_1px_2px_rgba(15,23,42,0.04)]">
      <div className="w-full h-full px-4 sm:px-6 flex items-center justify-between gap-4">
        
        {/* Left: Brand & Engine Security Status */}
        <div className="flex items-center gap-4 sm:gap-6 shrink-0">
          <div 
            onClick={onNavigateToAnalyzer} 
            className="flex items-center gap-2.5 cursor-pointer select-none group"
            title="MailTrace Workstation"
          >
            <div className="w-8 h-8 rounded bg-indigo-900 border border-indigo-800 text-indigo-100 flex items-center justify-center shadow-xs group-hover:bg-indigo-950 transition-colors">
              <Shield className="w-4 h-4 text-indigo-200" />
            </div>
            <div className="flex flex-col leading-none">
              <div className="flex items-center gap-1.5">
                <span className="font-headline font-bold text-base text-slate-900 tracking-tight">MailTrace</span>
                <span className="text-[10px] uppercase font-mono tracking-wider px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-700 font-semibold border border-indigo-200">
                  Enterprise SOC
                </span>
              </div>
              <span className="text-[10px] text-slate-500 font-normal mt-0.5">
                Forensic Workstation
              </span>
            </div>
          </div>

          {/* Model Status Indicator */}
          {modelStatus?.available && modelStatus.loaded ? (
            <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-800 text-[11px] font-medium" title="MailTraceSecurityTransformer 128.9M Parameters Loaded">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span>ML ENGINE • READY • 100m-v2 (128.9M PARAMS)</span>
            </div>
          ) : modelStatus?.status === 'INITIALIZING' ? (
            <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-full bg-amber-50 border border-amber-200 text-amber-800 text-[11px] font-medium">
              <span className="w-2 h-2 rounded-full bg-amber-500 animate-pulse" />
              <span>ML ENGINE • INITIALIZING FROM GCS...</span>
            </div>
          ) : (
            <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-100 border border-slate-200 text-slate-700 text-[11px] font-medium" title="Model artifact is not loaded from GCS/local path">
              <span className="w-2 h-2 rounded-full bg-slate-400" />
              <span>ML ENGINE • ZERO-RETENTION PROTOCOL</span>
            </div>
          )}
        </div>

        {/* Center: Global Omnisearch Bar for Analysts */}
        <div className="hidden md:flex flex-1 max-w-md items-center relative">
          <Search className="w-3.5 h-3.5 absolute left-3 text-slate-400 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search Message-ID, Sender, IP, SHA-256, or Case..."
            className="w-full pl-8 pr-12 py-1.5 text-xs bg-slate-50 border border-slate-200 rounded text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-indigo-600 focus:border-indigo-600 focus:bg-white transition-all font-mono"
          />
          <div className="absolute right-2 px-1.5 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-white border border-slate-200 flex items-center gap-0.5">
            <Command className="w-2.5 h-2.5" />
            <span>K</span>
          </div>
        </div>

        {/* Right: Quick Action Controls & Analyst Avatar */}
        <div className="flex items-center gap-2.5 shrink-0">
          
          {onOpenDailySummary && (
            <button
              onClick={onOpenDailySummary}
              className="hidden sm:flex items-center gap-1.5 text-xs text-slate-600 hover:text-slate-900 transition-colors px-2.5 py-1.5 rounded hover:bg-slate-100 border border-transparent hover:border-slate-200"
              title="Daily Executive Summary"
            >
              <HelpCircle className="w-3.5 h-3.5 text-slate-500" />
              <span>Analyst Guide</span>
            </button>
          )}

          <button
            onClick={onOpenCopilot}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-semibold border transition-all ${
              copilotOpen
                ? 'bg-indigo-600 text-white border-indigo-700 shadow-xs'
                : 'bg-white hover:bg-slate-50 border-slate-200 text-slate-700 shadow-xs'
            }`}
            title="SOC Forensic Copilot Assistant"
          >
            <Sparkles className="w-3.5 h-3.5 text-indigo-500" />
            <span>Copilot</span>
          </button>

          <button
            onClick={onNavigateToAnalyzer}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs shadow-xs transition-all"
            type="button"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>Ingest Specimen</span>
          </button>

          {/* Analyst Avatar Badge */}
          <div className="flex items-center gap-2 pl-1 border-l border-slate-200">
            <div className="relative cursor-pointer" title="Active Analyst: Dev Sharma (SOC L3 Lead)">
              <div className="w-7 h-7 rounded bg-indigo-700 text-white flex items-center justify-center font-headline font-semibold text-[11px] border border-indigo-300 shadow-xs">
                DS
              </div>
              <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 rounded-full bg-emerald-500 ring-1 ring-white" />
            </div>
            <div className="hidden xl:flex flex-col text-left leading-tight">
              <span className="text-xs font-semibold text-slate-900">Dev Sharma</span>
              <span className="text-[10px] text-slate-500">SOC L3 Lead</span>
            </div>
          </div>

        </div>

      </div>
    </header>
  );
};
