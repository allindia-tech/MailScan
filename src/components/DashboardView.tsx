/**
 * MailTrace Workstation - Modern Enterprise SOC Command Dashboard
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Clinical, high-density operations surface with real telemetry, alert triage queue, and campaign tracking.
 */

import React, { useState } from 'react';
import {
  ShieldAlert,
  Activity,
  Flame,
  ArrowUpRight,
  Layers,
  ShieldCheck,
  Radio,
  FileSearch,
  ChevronRight,
  Download,
  CheckCircle,
  Chrome,
  Mail,
  Zap,
  Globe,
  Filter,
  Eye,
  Crosshair,
  TrendingUp,
  Sliders,
  AlertTriangle,
  Lock,
  Cpu
} from 'lucide-react';
import { AlertItem, CampaignItem, AnalyzedEmailSummary } from '../types/forensics.js';
import { FeedbackGovernanceHub } from './FeedbackGovernanceHub.js';

interface DashboardViewProps {
  alerts: AlertItem[];
  campaigns: CampaignItem[];
  analyzedHistory: AnalyzedEmailSummary[];
  onSelectAnalyzedEmail: (id: string) => void;
  onUpdateAlertStatus: (id: string, status: string) => void;
  onNavigateToAnalyzer: () => void;
  onNavigateToExtension?: () => void;
  onOpenDailySummary?: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  alerts,
  campaigns,
  analyzedHistory,
  onSelectAnalyzedEmail,
  onUpdateAlertStatus,
  onNavigateToAnalyzer,
  onNavigateToExtension,
  onOpenDailySummary
}) => {
  const [selectedSeverityFilter, setSelectedSeverityFilter] = useState<string>('ALL');

  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const highCount = alerts.filter(a => a.severity === 'HIGH').length;
  const totalAnalyzed = Math.max(analyzedHistory.length, alerts.length);
  const containedCount = alerts.filter(a => a.status === 'CONTAINED' || a.status === 'RESOLVED').length;
  const quarantineRate = alerts.length > 0 ? Math.round((containedCount / alerts.length) * 100) : 0;

  const filteredAlerts = selectedSeverityFilter === 'ALL'
    ? alerts
    : alerts.filter(a => a.severity === selectedSeverityFilter);

  // Dynamic classification distribution
  const categoryCounts: Record<string, number> = {};
  for (const item of analyzedHistory) {
    const cat = item.primaryClassification || 'Unknown';
    categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
  }

  return (
    <div className="space-y-5 max-w-[1600px] mx-auto pb-8">
      
      {/* 1. Security Overview Header */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 mb-1">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full bg-emerald-50 border border-emerald-200 text-emerald-800 font-mono text-[10px] font-semibold tracking-wide uppercase">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                Live SOC Telemetry Active
              </span>
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full bg-indigo-50 border border-indigo-200 text-indigo-700 font-mono text-[10px]">
                <Cpu className="w-3 h-3 text-indigo-600" />
                Transformer ML 100M Model
              </span>
            </div>

            <h1 className="text-lg sm:text-xl font-headline font-bold text-slate-900 tracking-tight">
              Security Operations Command & Threat Triage
            </h1>
            <p className="text-xs text-slate-500 leading-relaxed max-w-2xl">
              Continuous multi-engine email forensics, real-time threat containment, and intelligence correlation.
            </p>
          </div>

          {/* Quick Command Actions */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            <button
              onClick={onNavigateToAnalyzer}
              className="flex items-center gap-2 px-3.5 py-2 rounded bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-xs transition-all"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Ingest Raw MIME</span>
            </button>

            {onOpenDailySummary && (
              <button
                onClick={onOpenDailySummary}
                className="flex items-center gap-2 px-3.5 py-2 rounded bg-white hover:bg-slate-50 text-slate-800 border border-slate-300 text-xs font-medium transition-all shadow-xs"
              >
                <Mail className="w-3.5 h-3.5 text-indigo-600" />
                <span>Executive Summary</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* 2. Top Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        
        {/* Metric 1: Total Inbound Traces */}
        <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">Total Inbound Traces</span>
            <div className="p-1.5 bg-indigo-50 border border-indigo-100 rounded text-indigo-600">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-mono font-bold text-slate-900">{totalAnalyzed}</span>
            <span className="text-[11px] text-slate-500 font-mono">messages triaged</span>
          </div>
          <div className="mt-2 w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
            <div className="h-full bg-indigo-600" style={{ width: `${Math.min(100, (totalAnalyzed / 50) * 100)}%` }} />
          </div>
        </div>

        {/* Metric 2: High & Critical Alerts */}
        <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">High & Critical Alerts</span>
            <div className="p-1.5 bg-rose-50 border border-rose-100 rounded text-rose-600">
              <Flame className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-mono font-bold text-rose-700">{criticalCount + highCount}</span>
            <span className="text-[11px] text-rose-700 font-mono font-bold">({criticalCount} critical)</span>
          </div>
          <div className="mt-2 w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
            <div className="h-full bg-rose-500" style={{ width: `${Math.min(100, ((criticalCount + highCount) / Math.max(1, alerts.length)) * 100)}%` }} />
          </div>
        </div>

        {/* Metric 3: Active Campaigns */}
        <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">Tracked Campaigns</span>
            <div className="p-1.5 bg-indigo-50 border border-indigo-100 rounded text-indigo-600">
              <Layers className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-mono font-bold text-slate-900">{campaigns.length}</span>
            <span className="text-[11px] text-slate-500 font-mono">active clusters</span>
          </div>
          <div className="mt-2 w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
            <div className="h-full bg-indigo-600" style={{ width: `${Math.min(100, campaigns.length * 20)}%` }} />
          </div>
        </div>

        {/* Metric 4: Quarantine Containment Rate */}
        <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-400">Quarantine Rate</span>
            <div className="p-1.5 bg-emerald-50 border border-emerald-100 rounded text-emerald-600">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-mono font-bold text-emerald-700">{quarantineRate}%</span>
            <span className="text-[11px] text-slate-500 font-mono">{containedCount}/{alerts.length} contained</span>
          </div>
          <div className="mt-2 w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
            <div className="h-full bg-emerald-600" style={{ width: `${quarantineRate}%` }} />
          </div>
        </div>

      </div>

      {/* 3. Inbound Threat Triage Queue */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-indigo-600" />
            <div>
              <h2 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
                Inbound Threat Triage Queue
              </h2>
              <span className="text-[11px] text-slate-500">
                {filteredAlerts.length} threat incident(s) pending analyst resolution
              </span>
            </div>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1 bg-slate-50 p-0.5 rounded border border-slate-200 text-xs">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverityFilter(sev)}
                className={`px-2.5 py-1 rounded text-[11px] font-mono font-semibold transition ${
                  selectedSeverityFilter === sev
                    ? 'bg-white text-indigo-700 border border-slate-200 shadow-xs'
                    : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* Triage Queue Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-200 text-slate-500 uppercase text-[10px] tracking-wider bg-slate-50 font-mono">
                <th className="py-2.5 px-3 font-semibold">Threat Classification</th>
                <th className="py-2.5 px-3 font-semibold w-48">Sender / Origin</th>
                <th className="py-2.5 px-3 font-semibold w-24">Severity</th>
                <th className="py-2.5 px-3 font-semibold w-24">Status</th>
                <th className="py-2.5 px-3 font-semibold text-right w-36">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-50 transition-colors">
                    <td className="py-3 px-3">
                      <div className="font-bold text-slate-900 text-xs font-sans">{alert.title}</div>
                      <div className="text-[10px] text-slate-500 mt-0.5 truncate max-w-sm">{alert.description}</div>
                    </td>
                    <td className="py-3 px-3 text-slate-700 truncate max-w-[200px]">{alert.sender || 'External Ingress'}</td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                        alert.severity === 'CRITICAL'
                          ? 'bg-rose-50 text-rose-700 border-rose-200'
                          : alert.severity === 'HIGH'
                          ? 'bg-amber-50 text-amber-800 border-amber-200'
                          : 'bg-blue-50 text-blue-700 border-blue-200'
                      }`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                        alert.status === 'CONTAINED' || alert.status === 'RESOLVED'
                          ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                          : 'bg-slate-100 text-slate-700 border border-slate-200'
                      }`}>
                        {alert.status}
                      </span>
                    </td>
                    <td className="py-3 px-3 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => onUpdateAlertStatus(alert.id, alert.status === 'CONTAINED' ? 'NEW' : 'CONTAINED')}
                          className="px-2 py-1 rounded bg-slate-100 hover:bg-slate-200 border border-slate-200 text-slate-700 text-[10px] font-semibold"
                        >
                          {alert.status === 'CONTAINED' ? 'Unquarantine' : 'Quarantine'}
                        </button>
                        {alert.emailId && (
                          <button
                            onClick={() => onSelectAnalyzedEmail(alert.emailId!)}
                            className="px-2 py-1 rounded bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 text-indigo-700 text-[10px] font-semibold"
                          >
                            Inspect
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-500 font-mono">
                    No active threat incidents matching selected severity criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 4. Attack Campaigns & Classification Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        
        {/* Tracked Attack Campaigns */}
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-100">
            <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              Tracked Attack Campaigns ({campaigns.length})
            </h3>
            <span className="text-[11px] font-mono text-slate-500">Correlated Clusters</span>
          </div>

          <div className="space-y-2.5">
            {campaigns.length > 0 ? (
              campaigns.map((camp) => (
                <div key={camp.id} className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-900">{camp.name}</span>
                    <span className="text-[10px] font-mono font-bold text-indigo-700 bg-indigo-50 px-1.5 py-0.2 rounded border border-indigo-200">
                      {camp.threatActor || 'Adversary Cluster'}
                    </span>
                  </div>
                  <p className="text-slate-600 text-[11px] leading-relaxed">{camp.description}</p>
                </div>
              ))
            ) : (
              <div className="py-6 text-center text-xs font-mono text-slate-500">
                No multi-specimen attack campaigns currently clustered.
              </div>
            )}
          </div>
        </div>

        {/* Classification Distribution */}
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-slate-100">
            <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              Classification Distribution
            </h3>
            <span className="text-[11px] font-mono text-slate-500">Historical Telemetry</span>
          </div>

          <div className="space-y-2 text-xs">
            {Object.keys(categoryCounts).length > 0 ? (
              Object.entries(categoryCounts).map(([cat, count]) => (
                <div key={cat} className="flex items-center justify-between p-2 rounded bg-slate-50 border border-slate-200 font-mono">
                  <span className="font-semibold text-slate-800">{cat}</span>
                  <span className="font-bold text-indigo-700 bg-white px-2 py-0.5 rounded border border-slate-200 text-[11px]">
                    {count} specimen(s)
                  </span>
                </div>
              ))
            ) : (
              <div className="py-6 text-center text-xs font-mono text-slate-500">
                No historical classifications recorded yet.
              </div>
            )}
          </div>
        </div>

      </div>

      {/* 5. Feedback Governance Hub */}
      <FeedbackGovernanceHub />

    </div>
  );
};
