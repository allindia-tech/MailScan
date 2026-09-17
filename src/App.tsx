/**
 * MailTrace AI - Master Cybersecurity SOC Workstation
 * Precision Forensics, Evidence-Centered SOC Workflow, AI-Powered Threat Detection
 * Source of Truth: ref/DESIGN.md & ref/code.html
 */

import React, { useState, useEffect, useMemo } from 'react';
import { TopHeader } from './components/TopHeader.js';
import { Sidebar } from './components/Sidebar.js';
import { ThreatScoreBanner } from './components/ThreatScoreBanner.js';
import { DashboardView } from './components/DashboardView.js';
import { AnalyzerView } from './components/AnalyzerView.js';
import { RelayTraceView } from './components/RelayTraceView.js';
import { HeaderForensicsTab } from './components/HeaderForensicsTab.js';
import { DomainIntelTab } from './components/DomainIntelTab.js';
import { UrlAttachmentTab } from './components/UrlAttachmentTab.js';
import { ThreatIntelSection } from './components/ThreatIntelSection.js';
import { RelationshipGraphView } from './components/RelationshipGraphView.js';
import { CasesAndReportsView } from './components/CasesAndReportsView.js';
import { ExtensionView } from './components/ExtensionView.js';
import { CopilotDrawer } from './components/CopilotDrawer.js';
import { EscalateModal } from './components/EscalateModal.js';
import { DailySummaryModal } from './components/DailySummaryModal.js';
import { AnalystFeedbackModal } from './components/AnalystFeedbackModal.js';
import { AnalysisBreakdownSection } from './components/AnalysisBreakdownSection.js';
import { AnalystVerificationSection } from './components/AnalystVerificationSection.js';
import { ContentAnalysisSection } from './components/ContentAnalysisSection.js';
import { AttackTechniqueView } from './components/AttackTechniqueView.js';
import { FeedbackGovernanceHub } from './components/FeedbackGovernanceHub.js';
import { ActiveTab } from './types/forensics.js';
import {
  fetchSampleScenarios,
  fetchSampleRaw,
  analyzeEmail,
  fetchAnalysis,
  fetchAnalyzedHistory,
  fetchAlerts,
  updateAlertStatus,
  fetchCases,
  createCase,
  addCaseNote,
  fetchEvidence,
  fetchCampaigns,
  fetchAuditLogs,
  SampleSummary
} from './services/api.js';
import {
  AlertItem,
  AuditLogItem,
  CampaignItem,
  CaseItem,
  EmailAnalysisResult,
  EvidenceItem,
  AnalyzedEmailSummary
} from './types/forensics.js';
import {
  generateMarkdownReport,
  generateStixBundle,
  downloadFile
} from './utils/reportExporter.js';
import { deviceIdentityManager } from './utils/deviceIdentity.js';
import {
  Terminal,
  Globe,
  Link2,
  ShieldCheck,
  MapPin,
  GitGraph,
  Radio,
  ArrowUpRight,
  Search,
  ExternalLink,
  Layers,
  HelpCircle,
  FileText,
  Clock,
  Shield
} from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('analyzer');
  const [analyzerSubTab, setAnalyzerSubTab] = useState<'techniques' | 'headers' | 'domain' | 'threat-intel' | 'urls'>('techniques');
  const [samples, setSamples] = useState<SampleSummary[]>([]);
  const [currentSampleId, setCurrentSampleId] = useState<string>('');
  const [rawInput, setRawInput] = useState<string>('');
  const [analysis, setAnalysis] = useState<EmailAnalysisResult | null>(null);
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [analyzedHistory, setAnalyzedHistory] = useState<AnalyzedEmailSummary[]>([]);
  const [searchQuery, setSearchQuery] = useState<string>('');

  // SOC Data Stores
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [cases, setCases] = useState<CaseItem[]>([]);
  const [evidence, setEvidence] = useState<EvidenceItem[]>([]);
  const [campaigns, setCampaigns] = useState<CampaignItem[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);

  // Modals & Panels
  const [copilotOpen, setCopilotOpen] = useState<boolean>(false);
  const [escalateModalOpen, setEscalateModalOpen] = useState<boolean>(false);
  const [dailySummaryModalOpen, setDailySummaryModalOpen] = useState<boolean>(false);
  const [feedbackModalOpen, setFeedbackModalOpen] = useState<boolean>(false);
  const [feedbackModalType, setFeedbackModalType] = useState<'technique' | 'classification' | 'both'>('classification');
  const [feedbackTargetTechniqueId, setFeedbackTargetTechniqueId] = useState<string | undefined>(undefined);

  // Initial Load: Fetch dynamic SOC telemetry & analyzed email history
  useEffect(() => {
    async function initData() {
      try {
        const [sampleList, historyList, alertsList, casesList, evidenceList, campaignsList, logsList] = await Promise.all([
          fetchSampleScenarios(),
          fetchAnalyzedHistory(),
          fetchAlerts(),
          fetchCases(),
          fetchEvidence(),
          fetchCampaigns(),
          fetchAuditLogs()
        ]);

        setSamples(sampleList);
        setAnalyzedHistory(historyList);
        setAlerts(alertsList);
        setCases(casesList);
        setEvidence(evidenceList);
        setCampaigns(campaignsList);
        setAuditLogs(logsList);

        // Check for extension deep-linking or URL params
        const urlParams = new URLSearchParams(window.location.search);
        const deepInvestigationId = urlParams.get('investigation') || urlParams.get('analysis');
        const initialTab = urlParams.get('tab');

        if (deepInvestigationId) {
          try {
            const deepAnalysis = await fetchAnalysis(deepInvestigationId);
            setAnalysis(deepAnalysis);
            if (deepAnalysis.rawHeaders) {
              setRawInput(`${deepAnalysis.rawHeaders}\n\n${deepAnalysis.bodyText || ''}`);
            }
            setActiveTab('analyzer');
          } catch (e) {
            console.warn('Deep link analysis not found, falling back to history:', e);
          }
        } else if (initialTab === 'extension') {
          setActiveTab('extension');
        } else if (historyList.length > 0 && !analysis) {
          // If previously analyzed emails exist, populate the most recent one into view
          const latestId = historyList[0].id;
          const loadedAnalysis = await fetchAnalysis(latestId);
          setAnalysis(loadedAnalysis);
          if (loadedAnalysis.rawHeaders) {
            setRawInput(`${loadedAnalysis.rawHeaders}\n\n${loadedAnalysis.bodyText || ''}`);
          }
        }
      } catch (err) {
        console.error('Initial dynamic data fetch error:', err);
      }
    }

    initData();

    // Keyboard shortcut for Command+K focus search
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('input[placeholder*="Search Message-ID"]') as HTMLInputElement;
        if (searchInput) searchInput.focus();
      }
    };
    window.addEventListener('keydown', handleKeyDown);

    // Subscribe to real-time state synchronization from paired Chrome Extension & devices
    const unsubscribe = deviceIdentityManager.subscribe((syncState) => {
      if (syncState.analysisResult) {
        setAnalysis(syncState.analysisResult);
        if (syncState.analysisResult.rawHeaders) {
          setRawInput(`${syncState.analysisResult.rawHeaders}\n\n${syncState.analysisResult.bodyText || ''}`);
        }
        setActiveTab('analyzer');
      } else if (syncState.activeEmailId) {
        fetchAnalysis(syncState.activeEmailId)
          .then((res) => {
            setAnalysis(res);
            if (res.rawHeaders) {
              setRawInput(`${res.rawHeaders}\n\n${res.bodyText || ''}`);
            }
            setActiveTab('analyzer');
          })
          .catch((e) => console.warn('Failed to fetch synchronized analysis ID:', e));
      }
    });

    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      unsubscribe();
    };
  }, []);

  // Filtered search results across history & cases
  const searchResults = useMemo(() => {
    if (!searchQuery.trim()) return null;
    const q = searchQuery.toLowerCase();
    const matchedHistory = analyzedHistory.filter(
      h => h.subject?.toLowerCase().includes(q) || h.from?.toLowerCase().includes(q) || h.id?.toLowerCase().includes(q)
    );
    const matchedCases = cases.filter(
      c => c.title?.toLowerCase().includes(q) || c.id?.toLowerCase().includes(q) || c.sender?.toLowerCase().includes(q)
    );
    return { history: matchedHistory, cases: matchedCases };
  }, [searchQuery, analyzedHistory, cases]);

  // Handle Loading Previous Analysis
  const handleSelectAnalyzedEmail = async (id: string) => {
    try {
      setAnalyzing(true);
      const res = await fetchAnalysis(id);
      setAnalysis(res);
      if (res.rawHeaders) {
        setRawInput(`${res.rawHeaders}\n\n${res.bodyText || ''}`);
      }
      setActiveTab('analyzer');
      setSearchQuery('');
    } catch (err) {
      console.error('Failed to load analyzed email:', err);
    } finally {
      setAnalyzing(false);
    }
  };

  // Handle Scenario Selection
  const handleSelectSample = async (id: string) => {
    try {
      setCurrentSampleId(id);
      setAnalyzing(true);
      const rawData = await fetchSampleRaw(id);
      setRawInput(rawData.rawEml);
      const res = await analyzeEmail(rawData.rawEml, id);
      setAnalysis(res);
      const [updatedHistory, updatedAlerts, updatedCampaigns, updatedLogs] = await Promise.all([
        fetchAnalyzedHistory(),
        fetchAlerts(),
        fetchCampaigns(),
        fetchAuditLogs()
      ]);
      setAnalyzedHistory(updatedHistory);
      setAlerts(updatedAlerts);
      setCampaigns(updatedCampaigns);
      setAuditLogs(updatedLogs);
    } catch (err) {
      console.error('Failed to analyze sample scenario:', err);
    } finally {
      setAnalyzing(false);
    }
  };

  // Run Analysis on Current Raw Input
  const handleRunAnalysis = async () => {
    if (!rawInput.trim()) return;
    try {
      setAnalyzing(true);
      const res = await analyzeEmail(rawInput, currentSampleId);
      setAnalysis(res);
      const [updatedHistory, updatedAlerts, updatedCampaigns, updatedLogs] = await Promise.all([
        fetchAnalyzedHistory(),
        fetchAlerts(),
        fetchCampaigns(),
        fetchAuditLogs()
      ]);
      setAnalyzedHistory(updatedHistory);
      setAlerts(updatedAlerts);
      setCampaigns(updatedCampaigns);
      setAuditLogs(updatedLogs);
    } catch (err) {
      console.error('Analysis execution failed:', err);
    } finally {
      setAnalyzing(false);
    }
  };

  // Handle Alert Status Triage
  const handleUpdateAlertStatus = async (alertId: string, status: string) => {
    try {
      await updateAlertStatus(alertId, status);
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status: status as any } : a));
    } catch (err) {
      console.error('Failed to update alert:', err);
    }
  };

  // Handle Adding Case Note
  const handleAddCaseNote = async (caseId: string, noteText: string) => {
    try {
      const updatedCase = await addCaseNote(caseId, noteText);
      setCases(prev => prev.map(c => c.id === caseId ? updatedCase : c));
    } catch (err) {
      console.error('Failed to add note:', err);
    }
  };

  // Handle Case Escalation Submission
  const handleCreateCaseSubmit = async (caseData: {
    title: string;
    description: string;
    severity: string;
    assignedTo: string;
  }) => {
    try {
      const newCase = await createCase({
        title: caseData.title,
        description: caseData.description,
        priority: caseData.severity as any,
        analyst: caseData.assignedTo,
        emailId: analysis?.id,
        emailSubject: analysis?.subject,
        sender: analysis?.from,
        status: 'OPEN',
        relatedIocs: analysis?.iocs.map(i => i.indicator) || []
      });
      setCases(prev => [newCase, ...prev]);
      setActiveTab('cases');
    } catch (err) {
      console.error('Failed to create case:', err);
    }
  };

  // Handle Exporting Reports
  const handleExportReport = (format: 'markdown' | 'json' | 'stix' = 'markdown') => {
    if (!analysis) return;
    const baseFilename = `MailTrace-Report-${analysis.id}`;

    if (format === 'markdown') {
      const md = generateMarkdownReport(analysis);
      downloadFile(md, `${baseFilename}.md`, 'text/markdown');
    } else if (format === 'stix') {
      const stix = generateStixBundle(analysis);
      downloadFile(JSON.stringify(stix, null, 2), `${baseFilename}-stix2.1.json`, 'application/json');
    } else {
      downloadFile(JSON.stringify(analysis, null, 2), `${baseFilename}-telemetry.json`, 'application/json');
    }
  };

  return (
    <div className="flex flex-col h-screen w-screen overflow-hidden bg-[#f8f9fc] text-slate-900 font-sans selection:bg-indigo-600 selection:text-white">
      
      {/* Top Navigation Header */}
      <TopHeader
        onNavigateToAnalyzer={() => setActiveTab('analyzer')}
        onOpenCopilot={() => setCopilotOpen(prev => !prev)}
        copilotOpen={copilotOpen}
        analyzing={analyzing}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        onOpenDailySummary={() => setDailySummaryModalOpen(true)}
        currentCaseId={cases.length > 0 ? cases[0].id : undefined}
      />

      {/* Omnisearch Dropdown Results Overlay (when searching) */}
      {searchResults && (searchResults.history.length > 0 || searchResults.cases.length > 0) && (
        <div className="absolute top-14 left-1/2 -translate-x-1/2 w-full max-w-xl z-50 bg-white border border-slate-200 rounded-b-lg shadow-xl p-3 text-xs space-y-3">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pb-1.5 border-b border-slate-100">
            <span>Search Results for "{searchQuery}"</span>
            <button onClick={() => setSearchQuery('')} className="text-slate-400 hover:text-slate-700">Clear</button>
          </div>
          
          {searchResults.history.length > 0 && (
            <div>
              <p className="text-[10px] font-mono uppercase font-bold text-slate-400 mb-1">Analyzed Specimens</p>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {searchResults.history.map((h) => (
                  <div
                    key={h.id}
                    onClick={() => handleSelectAnalyzedEmail(h.id)}
                    className="p-2 rounded hover:bg-indigo-50/60 cursor-pointer flex items-center justify-between border border-transparent hover:border-indigo-100 transition"
                  >
                    <div>
                      <span className="font-semibold text-slate-900 block truncate max-w-sm">{h.subject}</span>
                      <span className="text-[10px] text-slate-500 font-mono">{h.from} • {h.timestamp}</span>
                    </div>
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-700">
                      {h.riskScore}/100
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {searchResults.cases.length > 0 && (
            <div>
              <p className="text-[10px] font-mono uppercase font-bold text-slate-400 mb-1">Incident Cases</p>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {searchResults.cases.map((c) => (
                  <div
                    key={c.id}
                    onClick={() => {
                      setActiveTab('cases');
                      setSearchQuery('');
                    }}
                    className="p-2 rounded hover:bg-slate-50 cursor-pointer flex items-center justify-between border border-transparent hover:border-slate-200 transition"
                  >
                    <div>
                      <span className="font-semibold text-slate-900">{c.title}</span>
                      <span className="text-[10px] text-slate-500 font-mono block">Case ID: {c.id} • Assigned: {c.analyst}</span>
                    </div>
                    <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200">
                      {c.priority}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Main Workstation Layout: Left Navigation Rail + Scrollable Content */}
      <div className="flex flex-1 overflow-hidden">
        
        {/* Left Structured 240px Navigation Rail */}
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          analyzerSubTab={analyzerSubTab}
          setAnalyzerSubTab={setAnalyzerSubTab}
          alertCount={alerts.filter(a => a.status === 'NEW').length}
          casesCount={cases.filter(c => c.status === 'OPEN' || c.status === 'INVESTIGATING').length}
          onOpenCopilot={() => setCopilotOpen(prev => !prev)}
          analyzing={analyzing}
        />

        {/* Fluid Main Workspace Viewport */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 space-y-6 max-w-7xl mx-auto w-full">
          
          {/* Executive Verdict Banner (Shown on investigative views when an analysis specimen is active) */}
          {analysis && activeTab !== 'dashboard' && activeTab !== 'cases' && activeTab !== 'extension' && (
            <ThreatScoreBanner
              analysis={analysis}
              onOpenCaseModal={() => setEscalateModalOpen(true)}
              onExportReport={() => handleExportReport('markdown')}
              onNavigateToThreatIntel={() => setActiveTab('threat-intel')}
              onUpdateAnalysis={(updated) => setAnalysis(updated)}
              onOpenFeedbackModal={() => {
                setFeedbackModalType('classification');
                setFeedbackTargetTechniqueId(undefined);
                setFeedbackModalOpen(true);
              }}
            />
          )}

          {/* VIEW 1: SOC Command Dashboard */}
          {activeTab === 'dashboard' && (
            <DashboardView
              alerts={alerts}
              campaigns={campaigns}
              analyzedHistory={analyzedHistory}
              onSelectAnalyzedEmail={handleSelectAnalyzedEmail}
              onUpdateAlertStatus={handleUpdateAlertStatus}
              onNavigateToAnalyzer={() => setActiveTab('analyzer')}
              onNavigateToExtension={() => setActiveTab('extension')}
              onOpenDailySummary={() => setDailySummaryModalOpen(true)}
            />
          )}

          {/* VIEW 2: Active Forensic Triage / Email Analyzer */}
          {activeTab === 'analyzer' && (
            <div className="space-y-6">
              <AnalyzerView
                samples={samples}
                currentSampleId={currentSampleId}
                onSelectSample={handleSelectSample}
                rawInput={rawInput}
                setRawInput={setRawInput}
                onRunAnalysis={handleRunAnalysis}
                analyzing={analyzing}
              />

              {/* Comprehensive Threat & Forensic Analysis Results */}
              {analysis && (
                <div className="space-y-6">
                  
                  {/* Multi-Engine Consensus Breakdown */}
                  <AnalysisBreakdownSection analysis={analysis} />

                  {/* Intent & Content Analysis Section */}
                  <ContentAnalysisSection analysis={analysis} />

                  {/* Deep Forensic Subtabs (Techniques, Headers, Domains, Threat Intel, URLs) */}
                  <div className="bg-white border border-slate-200 rounded-lg p-5 shadow-xs">
                    <div className="flex items-center justify-between border-b border-slate-200 pb-3 mb-6 flex-wrap gap-2">
                      <div className="flex items-center gap-1.5 bg-slate-100 p-1 rounded border border-slate-200 text-xs font-mono">
                        <button
                          onClick={() => setAnalyzerSubTab('techniques')}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition ${
                            analyzerSubTab === 'techniques' ? 'bg-indigo-600 text-white font-bold shadow-xs' : 'text-slate-600 hover:text-slate-900'
                          }`}
                        >
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>Attack Techniques</span>
                          {analysis.detectedTechniques && analysis.detectedTechniques.length > 0 && (
                            <span className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                              analyzerSubTab === 'techniques' ? 'bg-indigo-800 text-indigo-100' : 'bg-slate-200 text-slate-700'
                            }`}>
                              {analysis.detectedTechniques.length}
                            </span>
                          )}
                        </button>
                        <button
                          onClick={() => setAnalyzerSubTab('headers')}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition ${
                            analyzerSubTab === 'headers' ? 'bg-indigo-600 text-white font-bold shadow-xs' : 'text-slate-600 hover:text-slate-900'
                          }`}
                        >
                          <Terminal className="w-3.5 h-3.5" />
                          <span>Header Matrix</span>
                        </button>
                        <button
                          onClick={() => setAnalyzerSubTab('domain')}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition ${
                            analyzerSubTab === 'domain' ? 'bg-indigo-600 text-white font-bold shadow-xs' : 'text-slate-600 hover:text-slate-900'
                          }`}
                        >
                          <Globe className="w-3.5 h-3.5" />
                          <span>Domain Intel</span>
                        </button>
                        <button
                          onClick={() => setAnalyzerSubTab('threat-intel')}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition ${
                            analyzerSubTab === 'threat-intel' ? 'bg-indigo-600 text-white font-bold shadow-xs' : 'text-slate-600 hover:text-slate-900'
                          }`}
                        >
                          <Radio className="w-3.5 h-3.5" />
                          <span>Threat Intel</span>
                          {analysis.threatIntelCorrelation && analysis.threatIntelCorrelation.matchedIndicatorsCount > 0 && (
                            <span className="px-1.5 py-0.2 rounded bg-rose-600 text-white text-[10px] font-bold">
                              {analysis.threatIntelCorrelation.matchedIndicatorsCount}
                            </span>
                          )}
                        </button>
                        <button
                          onClick={() => setAnalyzerSubTab('urls')}
                          className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition ${
                            analyzerSubTab === 'urls' ? 'bg-indigo-600 text-white font-bold shadow-xs' : 'text-slate-600 hover:text-slate-900'
                          }`}
                        >
                          <Link2 className="w-3.5 h-3.5" />
                          <span>URLs & Attachments</span>
                        </button>
                      </div>

                      <span className="text-xs font-mono text-slate-500">
                        Inspected Domain: <strong className="text-slate-900 font-semibold">{analysis.fromDomain}</strong>
                      </span>
                    </div>

                    {analyzerSubTab === 'techniques' && <AttackTechniqueView analysis={analysis} />}
                    {analyzerSubTab === 'headers' && <HeaderForensicsTab analysis={analysis} />}
                    {analyzerSubTab === 'domain' && <DomainIntelTab analysis={analysis} />}
                    {analyzerSubTab === 'threat-intel' && (
                      <ThreatIntelSection
                        analysis={analysis}
                        onOpenCaseModal={() => setEscalateModalOpen(true)}
                        analyzedHistory={analyzedHistory}
                      />
                    )}
                    {analyzerSubTab === 'urls' && <UrlAttachmentTab analysis={analysis} />}
                  </div>

                  {/* Analyst Verification & Retraining Feedback */}
                  <AnalystVerificationSection
                    analysis={analysis}
                    onVerificationSubmitted={(res) => {
                      console.log('Ground truth verification recorded:', res);
                    }}
                  />

                </div>
              )}
            </div>
          )}

          {/* VIEW 3: Dedicated Threat Intelligence Feeds */}
          {activeTab === 'threat-intel' && (
            <ThreatIntelSection
              analysis={analysis}
              onOpenCaseModal={() => setEscalateModalOpen(true)}
              analyzedHistory={analyzedHistory}
            />
          )}

          {/* VIEW 4: Hop Geo-Trace Map */}
          {activeTab === 'relay-trace' && (
            analysis ? (
              <RelayTraceView analysis={analysis} />
            ) : (
              <div className="bg-white border border-slate-200 rounded-lg p-12 text-center flex flex-col items-center justify-center shadow-xs">
                <MapPin className="w-10 h-10 text-slate-400 mb-3" />
                <h3 className="text-sm font-mono font-bold text-slate-900 uppercase">No Active Relay Trace Loaded</h3>
                <p className="text-xs text-slate-500 max-w-md mt-1.5 leading-relaxed">
                  Ingest or paste a raw RFC 5322 email message in the Email Analyzer to map hops, SMTP gateways, and geo-IP telemetry.
                </p>
                <button
                  onClick={() => setActiveTab('analyzer')}
                  className="mt-4 px-4 py-2 rounded bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-xs transition flex items-center gap-1.5"
                >
                  <span>Go to Email Analyzer</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )
          )}

          {/* VIEW 5: Header Forensics & Matrix */}
          {activeTab === 'forensics' && (
            analysis ? (
              <div className="space-y-6">
                <HeaderForensicsTab analysis={analysis} />
                <DomainIntelTab analysis={analysis} />
                <UrlAttachmentTab analysis={analysis} />
              </div>
            ) : (
              <div className="bg-white border border-slate-200 rounded-lg p-12 text-center flex flex-col items-center justify-center shadow-xs">
                <Terminal className="w-10 h-10 text-slate-400 mb-3" />
                <h3 className="text-sm font-mono font-bold text-slate-900 uppercase">No Forensics Matrix Available</h3>
                <p className="text-xs text-slate-500 max-w-md mt-1.5 leading-relaxed">
                  Ingest or paste a raw email in the Email Analyzer to evaluate RFC 822 headers, DKIM/SPF/DMARC alignment, and typosquatting vectors.
                </p>
                <button
                  onClick={() => setActiveTab('analyzer')}
                  className="mt-4 px-4 py-2 rounded bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-xs transition flex items-center gap-1.5"
                >
                  <span>Go to Email Analyzer</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )
          )}

          {/* VIEW 6: Entity Threat Graph */}
          {activeTab === 'graph' && (
            analysis ? (
              <RelationshipGraphView analysis={analysis} />
            ) : (
              <div className="bg-white border border-slate-200 rounded-lg p-12 text-center flex flex-col items-center justify-center shadow-xs">
                <GitGraph className="w-10 h-10 text-slate-400 mb-3" />
                <h3 className="text-sm font-mono font-bold text-slate-900 uppercase">No Entity Graph Available</h3>
                <p className="text-xs text-slate-500 max-w-md mt-1.5 leading-relaxed">
                  Ingest an email in the Email Analyzer to visualize interconnected nodes: senders, reply-to, ingress hops, domains, IP addresses, and IOCs.
                </p>
                <button
                  onClick={() => setActiveTab('analyzer')}
                  className="mt-4 px-4 py-2 rounded bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-xs transition flex items-center gap-1.5"
                >
                  <span>Go to Email Analyzer</span>
                  <ArrowUpRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )
          )}

          {/* VIEW 7: DFIR Incident Cases & Reports */}
          {activeTab === 'cases' && (
            <CasesAndReportsView
              cases={cases}
              evidence={evidence}
              auditLogs={auditLogs}
              onAddCaseNote={handleAddCaseNote}
              activeAnalysis={analysis || undefined}
              onExportReport={handleExportReport}
            />
          )}

          {/* VIEW 8: Chrome Companion Extension Hub */}
          {activeTab === 'extension' && (
            <ExtensionView
              onLoadInvestigation={(loaded) => {
                setAnalysis(loaded);
                if (loaded.rawHeaders) {
                  setRawInput(`${loaded.rawHeaders}\n\n${loaded.bodyText || ''}`);
                }
                setActiveTab('analyzer');
              }}
              currentAnalysis={analysis}
            />
          )}

          {/* Workstation Footer Note */}
          <footer className="pt-4 border-t border-slate-200 text-slate-500 text-[11px] font-mono flex flex-col sm:flex-row items-center justify-between gap-2 pb-6">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              <span>MailTrace Enterprise SOC Workstation • RFC 5322 Ingestion Active</span>
            </div>
            <div>
              <span>Network geolocation and IP hops identify infrastructure, never human individuals.</span>
            </div>
          </footer>

        </main>

      </div>

      {/* Slide-over SOC Copilot Assistant */}
      <CopilotDrawer
        isOpen={copilotOpen}
        onClose={() => setCopilotOpen(false)}
        activeAnalysis={analysis || undefined}
      />

      {/* Escalate to Incident Case Modal */}
      {analysis && (
        <EscalateModal
          isOpen={escalateModalOpen}
          onClose={() => setEscalateModalOpen(false)}
          analysis={analysis}
          onSubmitCase={handleCreateCaseSubmit}
        />
      )}

      {/* Analyst Ground-Truth & False Positive Modal */}
      {analysis && (
        <AnalystFeedbackModal
          isOpen={feedbackModalOpen}
          onClose={() => setFeedbackModalOpen(false)}
          analysis={analysis}
          initialFeedbackType={feedbackModalType}
          targetTechniqueId={feedbackTargetTechniqueId}
          onFeedbackSubmitted={(res) => {
            console.log('Feedback committed:', res);
          }}
        />
      )}

      {/* Automated Daily Summary Email Modal */}
      <DailySummaryModal
        isOpen={dailySummaryModalOpen}
        onClose={() => setDailySummaryModalOpen(false)}
      />

    </div>
  );
}
