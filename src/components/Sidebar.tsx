/**
 * MailTrace Workstation - Left Navigation Rail & System Telemetry
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * 240px structured workstation rail with operational groups and live engine status.
 */

import React from 'react';
import {
  Activity,
  ShieldAlert,
  Inbox,
  Briefcase,
  Terminal,
  MapPin,
  GitGraph,
  ShieldCheck,
  Radio,
  Globe,
  Link2,
  Chrome,
  Sparkles,
  FileCheck,
  FileText,
  Gavel,
  CheckCircle2
} from 'lucide-react';
import { ActiveTab } from '../types/forensics.js';

interface SidebarProps {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  analyzerSubTab?: string;
  setAnalyzerSubTab?: (subTab: any) => void;
  alertCount?: number;
  casesCount?: number;
  onOpenCopilot: () => void;
  analyzing?: boolean;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  analyzerSubTab,
  setAnalyzerSubTab,
  alertCount = 0,
  casesCount = 0,
  onOpenCopilot,
  analyzing = false
}) => {
  return (
    <aside className="w-60 shrink-0 bg-slate-50 border-r border-slate-200 hidden md:flex flex-col justify-between py-4 px-3 overflow-y-auto select-none">
      <div className="space-y-5">
        
        {/* SECTION: OVERVIEW */}
        <div>
          <p className="px-3 mb-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-wider font-mono">
            Overview
          </p>
          <nav className="space-y-0.5 text-xs">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded text-left transition-colors ${
                activeTab === 'dashboard'
                  ? 'bg-indigo-50 text-indigo-700 font-semibold border-l-3 border-indigo-600 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 font-medium'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Activity className={`w-4 h-4 ${activeTab === 'dashboard' ? 'text-indigo-600' : 'text-slate-400'}`} />
                <span>SOC Dashboard</span>
              </div>
              {alertCount > 0 && (
                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-700 border border-rose-200">
                  {alertCount}
                </span>
              )}
            </button>
          </nav>
        </div>

        {/* SECTION: INVESTIGATION */}
        <div>
          <p className="px-3 mb-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-wider font-mono">
            Investigation
          </p>
          <nav className="space-y-0.5 text-xs">
            <button
              onClick={() => setActiveTab('analyzer')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded text-left transition-colors ${
                activeTab === 'analyzer'
                  ? 'bg-indigo-50 text-indigo-700 font-semibold border-l-3 border-indigo-600 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 font-medium'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <ShieldAlert className={`w-4 h-4 ${activeTab === 'analyzer' ? 'text-indigo-600' : 'text-slate-400'}`} />
                <span>Active Forensic Triage</span>
              </div>
              <span className={`w-1.5 h-1.5 rounded-full ${analyzing ? 'bg-amber-500 animate-pulse' : 'bg-indigo-600'}`} />
            </button>

            <button
              onClick={() => setActiveTab('cases')}
              className={`w-full flex items-center justify-between px-3 py-2 rounded text-left transition-colors ${
                activeTab === 'cases'
                  ? 'bg-indigo-50 text-indigo-700 font-semibold border-l-3 border-indigo-600 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 font-medium'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Briefcase className={`w-4 h-4 ${activeTab === 'cases' ? 'text-indigo-600' : 'text-slate-400'}`} />
                <span>Cases & DFIR Reports</span>
              </div>
              {casesCount > 0 && (
                <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-slate-200 text-slate-700">
                  {casesCount}
                </span>
              )}
            </button>
          </nav>
        </div>

        {/* SECTION: FORENSICS */}
        <div>
          <p className="px-3 mb-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-wider font-mono">
            Forensic Telemetry
          </p>
          <nav className="space-y-0.5 text-xs">
            <button
              onClick={() => setActiveTab('forensics')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded text-left transition-colors ${
                activeTab === 'forensics'
                  ? 'bg-indigo-50 text-indigo-700 font-semibold border-l-3 border-indigo-600 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 font-medium'
              }`}
            >
              <Terminal className={`w-4 h-4 ${activeTab === 'forensics' ? 'text-indigo-600' : 'text-slate-400'}`} />
              <span>Header Matrix & Anomaly</span>
            </button>

            <button
              onClick={() => setActiveTab('relay-trace')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded text-left transition-colors ${
                activeTab === 'relay-trace'
                  ? 'bg-indigo-50 text-indigo-700 font-semibold border-l-3 border-indigo-600 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 font-medium'
              }`}
            >
              <MapPin className={`w-4 h-4 ${activeTab === 'relay-trace' ? 'text-indigo-600' : 'text-slate-400'}`} />
              <span>Hop Geo-Trace Map</span>
            </button>

            <button
              onClick={() => setActiveTab('graph')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded text-left transition-colors ${
                activeTab === 'graph'
                  ? 'bg-indigo-50 text-indigo-700 font-semibold border-l-3 border-indigo-600 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 font-medium'
              }`}
            >
              <GitGraph className={`w-4 h-4 ${activeTab === 'graph' ? 'text-indigo-600' : 'text-slate-400'}`} />
              <span>Entity Threat Graph</span>
            </button>
          </nav>
        </div>

        {/* SECTION: THREAT INTELLIGENCE */}
        <div>
          <p className="px-3 mb-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-wider font-mono">
            Intelligence Feeds
          </p>
          <nav className="space-y-0.5 text-xs">
            <button
              onClick={() => setActiveTab('threat-intel')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded text-left transition-colors ${
                activeTab === 'threat-intel'
                  ? 'bg-indigo-50 text-indigo-700 font-semibold border-l-3 border-indigo-600 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 font-medium'
              }`}
            >
              <Radio className={`w-4 h-4 ${activeTab === 'threat-intel' ? 'text-indigo-600' : 'text-slate-400'}`} />
              <span>IOC & Threat Feeds</span>
            </button>
          </nav>
        </div>

        {/* SECTION: INTEGRATIONS & OPERATIONS */}
        <div>
          <p className="px-3 mb-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-wider font-mono">
            Integrations & Copilot
          </p>
          <nav className="space-y-0.5 text-xs">
            <button
              onClick={() => setActiveTab('extension')}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded text-left transition-colors ${
                activeTab === 'extension'
                  ? 'bg-indigo-50 text-indigo-700 font-semibold border-l-3 border-indigo-600 shadow-xs'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100 font-medium'
              }`}
            >
              <Chrome className={`w-4 h-4 ${activeTab === 'extension' ? 'text-indigo-600' : 'text-slate-400'}`} />
              <span>Chrome / Edge Extension</span>
            </button>

            <button
              onClick={onOpenCopilot}
              className="w-full flex items-center gap-2.5 px-3 py-2 rounded text-left text-slate-600 hover:text-slate-900 hover:bg-slate-100 font-medium transition-colors"
            >
              <Sparkles className="w-4 h-4 text-indigo-500" />
              <span>Gemini SOC Copilot</span>
            </button>
          </nav>
        </div>

        {/* Real-Time Engine Reliability Status */}
        <div className="p-3 rounded-lg bg-white border border-slate-200 shadow-xs space-y-2">
          <p className="text-[10px] font-bold text-slate-400 uppercase tracking-wider font-mono">
            Engine Health
          </p>
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-500">RFC 5322 Parser</span>
            <span className="font-mono text-emerald-700 font-semibold bg-emerald-50 px-1.5 py-0.2 rounded border border-emerald-200">
              Validated
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-500">Evidence Fusion</span>
            <span className="font-mono text-emerald-700 font-semibold">
              Deterministic
            </span>
          </div>
          <div className="flex items-center justify-between text-[11px]">
            <span className="text-slate-500">Transformer ML</span>
            <span className="font-mono text-slate-700 font-medium" title="128,894,258 Parameters">
              128.9M (128,894,258)
            </span>
          </div>
        </div>

      </div>

      {/* Docked Court-Ready Evidence Status */}
      <div className="pt-4 mt-auto">
        <div className="p-2.5 rounded-lg bg-white border border-slate-200 shadow-xs flex items-center gap-2.5">
          <div className="w-7 h-7 rounded bg-emerald-50 border border-emerald-200 text-emerald-600 flex items-center justify-center shrink-0">
            <Gavel className="w-3.5 h-3.5" />
          </div>
          <div className="overflow-hidden leading-tight">
            <p className="text-[11px] font-semibold text-slate-900 truncate">DFIR Audit Standard</p>
            <p className="text-[10px] text-slate-500 font-mono">Immutable Evidence</p>
          </div>
        </div>
      </div>

    </aside>
  );
};
