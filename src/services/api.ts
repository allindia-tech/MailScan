/**
 * MailTrace AI - Frontend API Service Client
 */

import {
  AlertItem,
  AuditLogItem,
  CampaignItem,
  CaseItem,
  EmailAnalysisResult,
  EvidenceItem,
  SimulatedThreatIndicator,
  ThreatIntelCorrelationReport,
  AnalyzedEmailSummary,
  SocStats
} from '../types/forensics.js';

export interface SampleSummary {
  id: string;
  name: string;
  scenarioTag: string;
  threatType: string;
  expectedRisk: number;
  description: string;
}

export async function fetchHealth(): Promise<any> {
  const res = await fetch('/api/health');
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function fetchSampleScenarios(): Promise<SampleSummary[]> {
  const res = await fetch('/api/samples');
  if (!res.ok) throw new Error('Failed to fetch samples');
  return res.json();
}

export async function fetchSampleRaw(id: string): Promise<{ id: string; name: string; rawEml: string }> {
  const res = await fetch(`/api/samples/${id}`);
  if (!res.ok) throw new Error('Failed to fetch sample');
  return res.json();
}

export async function analyzeEmail(rawEmail: string, scenarioId?: string): Promise<EmailAnalysisResult> {
  const res = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rawEmail, scenarioId })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Analysis failed' }));
    throw new Error(err.error || 'Failed to analyze email');
  }
  return res.json();
}

export async function fetchAnalysis(id: string): Promise<EmailAnalysisResult> {
  const res = await fetch(`/api/analysis/${id}`);
  if (!res.ok) throw new Error('Analysis not found');
  return res.json();
}

export async function fetchAnalyzedHistory(): Promise<AnalyzedEmailSummary[]> {
  const res = await fetch('/api/history');
  if (!res.ok) throw new Error('Failed to fetch analyzed history');
  return res.json();
}

export async function fetchSocStats(): Promise<SocStats> {
  const res = await fetch('/api/stats');
  if (!res.ok) throw new Error('Failed to fetch SOC stats');
  return res.json();
}

export async function askCopilot(messages: Array<{ role: 'user' | 'model'; content: string }>, contextEmail?: EmailAnalysisResult, deepThinking?: boolean): Promise<{ reply: string; modelUsed: string; thinkingMode: boolean }> {
  const res = await fetch('/api/copilot', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messages, contextEmail, deepThinking })
  });
  if (!res.ok) throw new Error('Copilot query failed');
  return res.json();
}

export async function fetchAlerts(): Promise<AlertItem[]> {
  const res = await fetch('/api/alerts');
  if (!res.ok) throw new Error('Failed to fetch alerts');
  return res.json();
}

export async function updateAlertStatus(id: string, status: string): Promise<AlertItem> {
  const res = await fetch(`/api/alerts/${id}/status`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ status })
  });
  if (!res.ok) throw new Error('Failed to update alert');
  return res.json();
}

export async function fetchCases(): Promise<CaseItem[]> {
  const res = await fetch('/api/cases');
  if (!res.ok) throw new Error('Failed to fetch cases');
  return res.json();
}

export async function createCase(data: Partial<CaseItem>): Promise<CaseItem> {
  const res = await fetch('/api/cases', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  if (!res.ok) throw new Error('Failed to create case');
  return res.json();
}

export async function addCaseNote(caseId: string, text: string, author?: string): Promise<CaseItem> {
  const res = await fetch(`/api/cases/${caseId}/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text, author })
  });
  if (!res.ok) throw new Error('Failed to add note');
  return res.json();
}

export async function fetchEvidence(): Promise<EvidenceItem[]> {
  const res = await fetch('/api/evidence');
  if (!res.ok) throw new Error('Failed to fetch evidence');
  return res.json();
}

export async function fetchCampaigns(): Promise<CampaignItem[]> {
  const res = await fetch('/api/campaigns');
  if (!res.ok) throw new Error('Failed to fetch campaigns');
  return res.json();
}

export async function fetchAuditLogs(): Promise<AuditLogItem[]> {
  const res = await fetch('/api/audit-logs');
  if (!res.ok) throw new Error('Failed to fetch audit logs');
  return res.json();
}

// Threat Intelligence Services (SIMULATED THREAT INTELLIGENCE)
export async function fetchThreatIntelFeed(params?: {
  type?: string;
  severity?: string;
  query?: string;
}): Promise<{ provenance: string; count: number; indicators: SimulatedThreatIndicator[] }> {
  const searchParams = new URLSearchParams();
  if (params?.type && params.type !== 'all') searchParams.set('type', params.type);
  if (params?.severity && params.severity !== 'all') searchParams.set('severity', params.severity);
  if (params?.query) searchParams.set('query', params.query);

  const qs = searchParams.toString();
  const url = `/api/threat-intel/feed${qs ? `?${qs}` : ''}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch threat intelligence feed');
  return res.json();
}

export async function fetchThreatIntelStats(): Promise<{
  totalIndicators: number;
  ipsCount: number;
  domainsCount: number;
  hashesCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lastUpdated: string;
  feedProvenance: string;
}> {
  const res = await fetch('/api/threat-intel/stats');
  if (!res.ok) throw new Error('Failed to fetch threat intelligence stats');
  return res.json();
}

export async function ingestThreatIndicator(data: Partial<SimulatedThreatIndicator>): Promise<SimulatedThreatIndicator> {
  const res = await fetch('/api/threat-intel/indicators', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Failed to ingest indicator' }));
    throw new Error(err.error || 'Failed to ingest indicator');
  }
  return res.json();
}

export async function removeThreatIndicator(id: string): Promise<boolean> {
  const res = await fetch(`/api/threat-intel/indicators/${id}`, {
    method: 'DELETE'
  });
  if (!res.ok) throw new Error('Failed to remove indicator');
  return true;
}

export async function resetThreatIntelFeed(): Promise<boolean> {
  const res = await fetch('/api/threat-intel/reset', {
    method: 'POST'
  });
  if (!res.ok) throw new Error('Failed to reset threat intelligence feed');
  return true;
}

export async function testThreatIntelCorrelate(indicators: string[]): Promise<{
  provenance: string;
  testedCount: number;
  matchedCount: number;
  matches: any[];
  disclaimer: string;
}> {
  const res = await fetch('/api/threat-intel/correlate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ indicators })
  });
  if (!res.ok) throw new Error('Failed to correlate indicators');
  return res.json();
}

// ==========================================
// DAILY SUMMARY & EXECUTIVE REPORTING
// ==========================================
export async function fetchDailySummary(): Promise<any> {
  const res = await fetch('/api/reports/daily-summary');
  if (!res.ok) throw new Error('Failed to fetch daily summary report');
  return res.json();
}

export async function sendDailySummary(recipients?: string[]): Promise<any> {
  const res = await fetch('/api/reports/send-daily-summary', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ recipients })
  });
  if (!res.ok) throw new Error('Failed to send daily summary report');
  return res.json();
}

// ==========================================
// REAL-TIME GLOBAL THREAT ACTIVITY MAP
// ==========================================
export interface ThreatMapData {
  activeOriginsCount: number;
  socDefenseLocation: {
    name: string;
    city: string;
    latitude: number;
    longitude: number;
  };
  threatNodes: Array<{
    id: string;
    ip: string;
    city: string;
    country: string;
    countryCode: string;
    latitude: number;
    longitude: number;
    threatType: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    riskScore: number;
    timestamp: string;
    subject: string;
    sender: string;
    campaign?: string;
  }>;
}

export async function fetchThreatMapActivity(): Promise<ThreatMapData> {
  const res = await fetch('/api/threat-map/activity');
  if (!res.ok) throw new Error('Failed to fetch threat map activity');
  return res.json();
}

// ==========================================
// REGRESSION TEST SUITE & ML GOVERNANCE
// ==========================================
export async function runRegressionTests(): Promise<any> {
  const res = await fetch('/api/ml/regression-tests/run', {
    method: 'POST'
  });
  if (!res.ok) throw new Error('Failed to run regression test suite');
  return res.json();
}

export async function submitAnalystFeedback(data: {
  emailId: string;
  emailSubject: string;
  originalClassification: string;
  verifiedClassification: string;
  reason: string;
  analyst: string;
  trustLevel: 'verified_analyst' | 'administrator' | 'user_report';
  features?: Record<string, any>;
}): Promise<any> {
  const res = await fetch('/api/ml/feedback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
  if (!res.ok) throw new Error('Failed to submit analyst feedback');
  return res.json();
}

// ==========================================
// CHROME EXTENSION INGESTION & BRIDGE
// ==========================================
export async function analyzeBrowserEmail(payload: {
  emailData?: any;
  rawEmail?: string;
  sourceContext?: string;
}): Promise<{
  analysis: EmailAnalysisResult;
  analysisId: string;
  deepLinkPath: string;
}> {
  const res = await fetch('/api/extension/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Extension analysis failed' }));
    throw new Error(err.error || 'Failed to analyze browser email');
  }
  return res.json();
}

export async function pingExtensionService(): Promise<{ status: string; version: string }> {
  const res = await fetch('/api/extension/ping');
  if (!res.ok) throw new Error('Extension service ping failed');
  return res.json();
}

// ==========================================
// DEVICE IDENTITY & SHARED STATE SYNCHRONIZATION
// ==========================================

export async function registerDevice(info: {
  deviceId: string;
  clientType: 'extension' | 'website';
  browser?: string;
  os?: string;
  userAgent?: string;
  extensionVersion?: string;
}): Promise<any> {
  const res = await fetch('/api/device/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(info)
  });
  if (!res.ok) throw new Error('Failed to register device identity');
  return res.json();
}

export async function fetchDeviceList(): Promise<any> {
  const res = await fetch('/api/device/list');
  if (!res.ok) throw new Error('Failed to fetch device list');
  return res.json();
}

export async function syncDeviceState(payload: {
  deviceId: string;
  source: 'extension' | 'website';
  activeEmailId?: string;
  activeSubject?: string;
  riskScore?: number;
  verdict?: string;
  analysisResult?: any;
  deepLinkPath?: string;
}): Promise<any> {
  const res = await fetch('/api/device/sync', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) throw new Error('Failed to sync state');
  return res.json();
}

export async function fetchLatestSyncState(): Promise<any> {
  const res = await fetch('/api/device/latest-sync');
  if (!res.ok) throw new Error('Failed to fetch latest sync state');
  return res.json();
}

// ==========================================
// 100M PARAMETER NEURAL TRANSFORMER
// ==========================================

export async function fetch100MArchitecture(): Promise<any> {
  const res = await fetch('/api/ml/100m/architecture');
  if (!res.ok) throw new Error('Failed to fetch 100M model architecture');
  return res.json();
}

export async function test100MForwardPass(emailData: any): Promise<any> {
  const res = await fetch('/api/ml/100m/forward-pass', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ emailData })
  });
  if (!res.ok) throw new Error('100M forward pass failed');
  return res.json();
}

export async function retrainChallengerModel(): Promise<any> {
  const res = await fetch('/api/ml/retrain', { method: 'POST' });
  if (!res.ok) throw new Error('Challenger retrain failed');
  return res.json();
}

export async function promoteChallengerModel(): Promise<any> {
  const res = await fetch('/api/ml/promote', { method: 'POST' });
  if (!res.ok) throw new Error('Challenger promotion failed');
  return res.json();
}

// ==========================================
// ANALYST VERIFICATION & GROUND-TRUTH APIs
// ==========================================

export async function submitAnalystVerification(payload: {
  analysisId: string;
  emailSubject: string;
  sender?: string;
  rawBody?: string;
  urls?: string[];
  originalPrediction: {
    primaryCategory: string;
    secondaryCategories?: string[];
    threatRisk: number;
    spamBulkScore?: number;
    confidence?: number;
    probabilities?: Record<string, number>;
    detectedTechniques?: string[];
    evidence?: string[];
  };
  verifiedGroundTruth: {
    primaryCategory: string;
    secondaryCategories?: string[];
    verdict: string;
    isMalicious?: boolean;
    isSpam?: boolean;
    correctedEvidence?: string[];
  };
  isCorrect: boolean;
  classificationType?: string;
  analyst: {
    id: string;
    name?: string;
    role?: string;
    confidence?: number;
  };
  reason: string;
  notes?: string;
  modelVersion?: string;
  structuredFeatures?: Record<string, number>;
}): Promise<any> {
  const res = await fetch('/api/feedback/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Verification submission failed' }));
    throw new Error(err.error || 'Failed to submit analyst verification');
  }
  return res.json();
}

export async function fetchFeedbackById(id: string): Promise<any> {
  const res = await fetch(`/api/feedback/${id}`);
  if (!res.ok) throw new Error('Feedback not found');
  return res.json();
}

export async function fetchFeedbackStats(): Promise<any> {
  const res = await fetch('/api/feedback/stats');
  if (!res.ok) throw new Error('Failed to fetch feedback statistics');
  return res.json();
}

export async function fetchFeedbackList(status?: string): Promise<any[]> {
  const url = status ? `/api/feedback?status=${status}` : '/api/feedback';
  const res = await fetch(url);
  if (!res.ok) throw new Error('Failed to fetch feedback list');
  return res.json();
}

export async function createFeedbackDataset(nameSuffix?: string): Promise<any> {
  const res = await fetch('/api/training/feedback-dataset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ nameSuffix })
  });
  if (!res.ok) throw new Error('Failed to compile feedback dataset');
  return res.json();
}

export async function startFeedbackTraining(params?: {
  datasetVersion?: string;
  baseModelVersion?: string;
  targetModelVersion?: string;
  epochs?: number;
  batchSize?: number;
}): Promise<any> {
  const res = await fetch('/api/training/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params || {})
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Failed to trigger training' }));
    throw new Error(err.error || 'Failed to start model training');
  }
  return res.json();
}

export async function fetchTrainingRun(runId: string): Promise<any> {
  const res = await fetch(`/api/training/runs/${runId}`);
  if (!res.ok) throw new Error('Training run not found');
  return res.json();
}

export async function fetchAllTrainingRuns(): Promise<any[]> {
  const res = await fetch('/api/training/runs');
  if (!res.ok) throw new Error('Failed to fetch training runs');
  return res.json();
}

export async function fetchModels(): Promise<any[]> {
  const res = await fetch('/api/models');
  if (!res.ok) throw new Error('Failed to fetch model registry');
  return res.json();
}

export async function evaluateModel(id: string): Promise<any> {
  const res = await fetch(`/api/models/${id}/evaluate`, { method: 'POST' });
  if (!res.ok) throw new Error('Model evaluation failed');
  return res.json();
}

export async function promoteModelVersion(id: string, approvedBy?: string): Promise<any> {
  const res = await fetch(`/api/models/${id}/promote`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ approvedBy })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Promotion failed' }));
    throw new Error(err.error || 'Failed to promote model');
  }
  return res.json();
}


