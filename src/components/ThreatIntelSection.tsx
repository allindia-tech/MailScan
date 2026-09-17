/**
 * MailTrace Workstation - Threat Intelligence & Extracted IOCs Matrix
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * High-density IOC tables, threat feed correlation, and incident escalation.
 */

import React, { useState, useEffect } from 'react';
import {
  Database,
  ShieldAlert,
  ShieldCheck,
  Search,
  PlusCircle,
  RotateCcw,
  Copy,
  Check,
  Trash2,
  Filter,
  Shield,
  FileSearch,
  Plus,
  Layers,
  Network,
  GitBranch,
  Fingerprint,
  Link,
  Calendar,
  AlertCircle,
  CheckCircle2,
  ExternalLink,
  Radio
} from 'lucide-react';
import {
  EmailAnalysisResult,
  IOC,
  SimulatedThreatIndicator,
  ThreatIntelMatch,
  ThreatSeverity,
  AnalyzedEmailSummary
} from '../types/forensics.js';
import {
  fetchThreatIntelFeed,
  fetchThreatIntelStats,
  ingestThreatIndicator,
  removeThreatIndicator,
  resetThreatIntelFeed
} from '../services/api.js';

interface ThreatIntelSectionProps {
  analysis?: EmailAnalysisResult | null;
  onOpenCaseModal?: (prefillTitle?: string, prefillDesc?: string) => void;
  analyzedHistory?: AnalyzedEmailSummary[];
}

export const ThreatIntelSection: React.FC<ThreatIntelSectionProps> = ({
  analysis,
  onOpenCaseModal,
  analyzedHistory = []
}) => {
  const [activeSubView, setActiveSubView] = useState<'iocs' | 'matches' | 'feed' | 'cluster'>('iocs');
  
  // Feed Registry State
  const [feedIndicators, setFeedIndicators] = useState<SimulatedThreatIndicator[]>([]);
  const [stats, setStats] = useState<{
    totalIndicators: number;
    ipsCount: number;
    domainsCount: number;
    hashesCount: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lastUpdated: string;
  } | null>(null);
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedType, setSelectedType] = useState<string>('all');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('all');
  
  // Ingest form state
  const [showIngestForm, setShowIngestForm] = useState(false);
  const [newIndicator, setNewIndicator] = useState({
    indicator: '',
    type: 'ip' as 'ip' | 'domain' | 'hash',
    threatName: '',
    threatActor: '',
    severity: 'HIGH' as ThreatSeverity,
    category: 'Command & Control / Phishing',
    confidence: 90,
    description: '',
    recommendedMitigation: ''
  });
  const [ingesting, setIngesting] = useState(false);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Load feed and stats
  const loadFeedData = async () => {
    try {
      setLoading(true);
      const [feedRes, statsRes] = await Promise.all([
        fetchThreatIntelFeed({
          type: selectedType,
          severity: selectedSeverity,
          query: searchQuery
        }),
        fetchThreatIntelStats()
      ]);
      setFeedIndicators(feedRes.indicators);
      setStats(statsRes);
    } catch (err) {
      console.error('Failed to load threat intel data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFeedData();
  }, [selectedType, selectedSeverity, searchQuery]);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleSearchInFeed = (indicator: string) => {
    setSearchQuery(indicator);
    setActiveSubView('feed');
  };

  const handleIngestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIndicator.indicator.trim()) return;
    try {
      setIngesting(true);
      await ingestThreatIndicator({
        ...newIndicator,
        label: 'Threat Intelligence Indicator'
      });
      setNewIndicator({
        indicator: '',
        type: 'ip',
        threatName: '',
        threatActor: '',
        severity: 'HIGH',
        category: 'Command & Control / Phishing',
        confidence: 90,
        description: '',
        recommendedMitigation: ''
      });
      setShowIngestForm(false);
      await loadFeedData();
    } catch (err) {
      console.error('Ingest error:', err);
    } finally {
      setIngesting(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await removeThreatIndicator(id);
      await loadFeedData();
    } catch (err) {
      console.error('Delete indicator error:', err);
    }
  };

  const handleResetFeed = async () => {
    if (!window.confirm('Reset threat feed to default indicators?')) return;
    try {
      await resetThreatIntelFeed();
      await loadFeedData();
    } catch (err) {
      console.error('Reset feed error:', err);
    }
  };

  const getSeverityBadge = (sev: ThreatSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-50 text-rose-700 border border-rose-200">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-50 text-amber-800 border border-amber-200">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200">LOW</span>;
    }
  };

  const correlationReport = analysis?.threatIntelCorrelation;
  const matches = correlationReport?.matches || [];
  const iocs = analysis?.iocs || [];

  return (
    <div className="space-y-5">
      
      {/* 1. Header & Navigation */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-indigo-50 text-indigo-700 border border-indigo-200 uppercase">
                Threat Intelligence & IOCs
              </span>
              <span className="text-xs text-slate-500 font-mono">
                {matches.length > 0 ? `${matches.length} Active Match(es)` : 'Clean Feed Match State'}
              </span>
            </div>
            <h2 className="text-sm font-bold text-slate-900 font-mono">
              Indicators of Compromise & Global Feed Correlation
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Extracted forensic artifacts mapped against threat feeds and adversary infrastructure.
            </p>
          </div>

          {/* Sub-view Switcher */}
          <div className="flex items-center bg-slate-50 p-1 rounded border border-slate-200 text-xs">
            <button
              onClick={() => setActiveSubView('iocs')}
              className={`px-3 py-1.5 rounded text-xs font-semibold transition ${
                activeSubView === 'iocs'
                  ? 'bg-indigo-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Extracted IOCs ({iocs.length})
            </button>

            <button
              onClick={() => setActiveSubView('matches')}
              className={`px-3 py-1.5 rounded text-xs font-semibold transition flex items-center gap-1.5 ${
                activeSubView === 'matches'
                  ? 'bg-indigo-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              <span>Feed Matches</span>
              {matches.length > 0 && (
                <span className="px-1.5 py-0.2 rounded text-[10px] bg-rose-600 text-white font-mono font-bold">
                  {matches.length}
                </span>
              )}
            </button>

            <button
              onClick={() => setActiveSubView('feed')}
              className={`px-3 py-1.5 rounded text-xs font-semibold transition ${
                activeSubView === 'feed'
                  ? 'bg-indigo-600 text-white shadow-xs'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Registry ({stats?.totalIndicators || feedIndicators.length})
            </button>
          </div>
        </div>
      </div>

      {/* 2. SUB-VIEW 1: Extracted IOCs Table */}
      {activeSubView === 'iocs' && (
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              Observed Forensic IOCs ({iocs.length})
            </h3>
            <span className="text-[11px] font-mono text-slate-500">Extracted from Active Specimen</span>
          </div>

          {iocs.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-200 text-slate-500 uppercase text-[10px] tracking-wider bg-slate-50 font-mono">
                    <th className="py-2.5 px-3 font-semibold w-24">Type</th>
                    <th className="py-2.5 px-3 font-semibold">Indicator Value</th>
                    <th className="py-2.5 px-3 font-semibold w-32">Risk Severity</th>
                    <th className="py-2.5 px-3 font-semibold text-right w-36">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                  {iocs.map((ioc, idx) => (
                    <tr key={idx} className="hover:bg-slate-50 transition-colors">
                      <td className="py-3 px-3 font-bold text-slate-700">{ioc.type.toUpperCase()}</td>
                      <td className="py-3 px-3 text-slate-900 font-semibold break-all">{ioc.indicator}</td>
                      <td className="py-3 px-3">{getSeverityBadge(ioc.risk as ThreatSeverity)}</td>
                      <td className="py-3 px-3 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => handleCopy(ioc.indicator)}
                            className="p-1 rounded bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 shadow-xs"
                            title="Copy indicator"
                          >
                            {copiedText === ioc.indicator ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          </button>
                          <button
                            onClick={() => handleSearchInFeed(ioc.indicator)}
                            className="px-2 py-1 rounded bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 text-indigo-700 text-[10px] font-semibold"
                          >
                            Correlate
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-8 text-center text-xs font-mono text-slate-500">
              No IOCs extracted from the current investigation specimen.
            </div>
          )}
        </div>
      )}

      {/* 3. SUB-VIEW 2: Feed Correlation Matches */}
      {activeSubView === 'matches' && (
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              Threat Feed Correlation Matches ({matches.length})
            </h3>
            <span className="text-[11px] font-mono text-slate-500">Automated Threat Feed Cross-Reference</span>
          </div>

          {matches.length > 0 ? (
            <div className="space-y-3">
              {matches.map((m, idx) => (
                <div key={idx} className="p-4 rounded-lg bg-rose-50/50 border border-rose-200 text-xs space-y-2">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-slate-900 text-sm">{m.matchedIndicator}</span>
                      {getSeverityBadge(m.severity as ThreatSeverity)}
                    </div>
                    <span className="text-[11px] font-mono text-slate-600 font-semibold">
                      Threat Actor: {m.threatActor || 'Unknown Adversary'}
                    </span>
                  </div>
                  <p className="text-slate-700 leading-relaxed">{m.description}</p>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-8 text-center text-xs font-mono text-slate-500">
              No threat feed matches found for the currently extracted indicators.
            </div>
          )}
        </div>
      )}

      {/* 4. SUB-VIEW 3: Threat Feed Registry */}
      {activeSubView === 'feed' && (
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <Database className="w-4 h-4 text-indigo-600" />
              <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
                Threat Intelligence Database ({feedIndicators.length})
              </h3>
            </div>

            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="Search IOC database..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="px-2.5 py-1 text-xs bg-slate-50 border border-slate-200 rounded font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-indigo-600"
              />
              <button
                onClick={() => setShowIngestForm(!showIngestForm)}
                className="flex items-center gap-1 px-3 py-1 rounded bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs shadow-xs transition"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add IOC</span>
              </button>
            </div>
          </div>

          {/* Ingest IOC Modal / Form Drawer */}
          {showIngestForm && (
            <form onSubmit={handleIngestSubmit} className="p-4 rounded-lg bg-slate-50 border border-slate-200 space-y-3 text-xs">
              <h4 className="font-bold text-slate-900 font-mono uppercase text-xs">Ingest New Threat Indicator</h4>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="text-[10px] font-mono text-slate-500 uppercase font-bold block mb-1">Indicator Value</label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. 185.220.101.44 or corp-in.co"
                    value={newIndicator.indicator}
                    onChange={(e) => setNewIndicator({ ...newIndicator, indicator: e.target.value })}
                    className="w-full px-2.5 py-1.5 bg-white border border-slate-300 rounded font-mono text-xs text-slate-900"
                  />
                </div>
                <div>
                  <label className="text-[10px] font-mono text-slate-500 uppercase font-bold block mb-1">Type</label>
                  <select
                    value={newIndicator.type}
                    onChange={(e) => setNewIndicator({ ...newIndicator, type: e.target.value as any })}
                    className="w-full px-2.5 py-1.5 bg-white border border-slate-300 rounded font-mono text-xs text-slate-900"
                  >
                    <option value="ip">IP Address</option>
                    <option value="domain">Domain Name</option>
                    <option value="hash">File Hash (SHA-256)</option>
                  </select>
                </div>
                <div>
                  <label className="text-[10px] font-mono text-slate-500 uppercase font-bold block mb-1">Threat Name</label>
                  <input
                    type="text"
                    placeholder="e.g. Tor Exit Relay / BEC Scammer"
                    value={newIndicator.threatName}
                    onChange={(e) => setNewIndicator({ ...newIndicator, threatName: e.target.value })}
                    className="w-full px-2.5 py-1.5 bg-white border border-slate-300 rounded text-xs text-slate-900"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowIngestForm(false)}
                  className="px-3 py-1.5 rounded bg-white hover:bg-slate-100 border border-slate-300 text-slate-700 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={ingesting}
                  className="px-4 py-1.5 rounded bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-xs"
                >
                  {ingesting ? 'Saving...' : 'Save Indicator'}
                </button>
              </div>
            </form>
          )}

          {/* Indicators List */}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500 uppercase text-[10px] tracking-wider bg-slate-50 font-mono">
                  <th className="py-2.5 px-3 font-semibold w-20">Type</th>
                  <th className="py-2.5 px-3 font-semibold">Indicator</th>
                  <th className="py-2.5 px-3 font-semibold w-40">Threat Name</th>
                  <th className="py-2.5 px-3 font-semibold w-28">Severity</th>
                  <th className="py-2.5 px-3 font-semibold text-right w-20">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                {feedIndicators.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-50 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-slate-700">{item.type.toUpperCase()}</td>
                    <td className="py-2.5 px-3 text-slate-900 font-semibold break-all">{item.indicator}</td>
                    <td className="py-2.5 px-3 text-slate-700">{item.threatName}</td>
                    <td className="py-2.5 px-3">{getSeverityBadge(item.severity)}</td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => handleDelete(item.id)}
                        className="p-1 text-slate-400 hover:text-rose-600 transition"
                        title="Delete indicator"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
};
