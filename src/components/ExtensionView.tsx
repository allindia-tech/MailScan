/**
 * MailTrace Workstation - Chrome Extension & Model Governance Center
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Live extension synchronization, provider detection, and model architecture status.
 */

import React, { useState, useEffect } from 'react';
import {
  Download,
  CheckCircle2,
  Terminal,
  Layers,
  Copy,
  Check,
  Lock,
  Eye,
  Activity,
  Sparkles,
  RefreshCw,
  FolderArchive,
  ExternalLink,
  ShieldCheck,
  Cpu,
  Radio,
  GitBranch,
  Network,
  Zap,
  Sliders,
  CheckCircle,
  Chrome
} from 'lucide-react';
import { EmailAnalysisResult } from '../types/forensics.js';
import { deviceIdentityManager, DeviceIdentityState } from '../utils/deviceIdentity.js';
import { fetch100MArchitecture, retrainChallengerModel, promoteChallengerModel } from '../services/api.js';

interface ExtensionViewProps {
  onLoadInvestigation?: (analysis: EmailAnalysisResult) => void;
  currentAnalysis?: EmailAnalysisResult | null;
}

export const ExtensionView: React.FC<ExtensionViewProps> = ({ onLoadInvestigation, currentAnalysis }) => {
  const [downloaded, setDownloaded] = useState(false);
  const [copiedUrl, setCopiedUrl] = useState(false);
  const [copiedDeviceId, setCopiedDeviceId] = useState(false);
  const [backendPing, setBackendPing] = useState<{ status: string; latencyMs: number } | null>(null);
  const [pinging, setPinging] = useState(false);

  // Device Identity State
  const [deviceState, setDeviceState] = useState<DeviceIdentityState | null>(null);
  const [modelArch, setModelArch] = useState<any | null>(null);
  const [isRetraining, setIsRetraining] = useState(false);
  const [retrainResult, setRetrainResult] = useState<any | null>(null);
  const [isPromoting, setIsPromoting] = useState(false);

  // Simulator State
  const [simStep, setSimStep] = useState<'idle' | 'detecting' | 'analyzing' | 'result'>('idle');
  const [simProgressStep, setSimProgressStep] = useState(0);
  const [simEmail] = useState({
    subject: 'URGENT: Outstanding Vendor Wire Transfer Authorization Notice #INV-9821',
    sender: 'Accounts Payable <billing@paypa1-update.com>',
    links: ['http://portal-quickbooks-security-auth.cc/login?token=894328492', 'http://paypa1-update.com/disclaimer'],
    attachments: [{ name: 'Wire_Authorization_Notice_9821.pdf.exe', type: 'Executable' }]
  });

  const STEPS = [
    'Extracting email content...',
    'Parsing MIME & headers...',
    'Checking sender & lookalike typosquatting...',
    'Analyzing embedded links...',
    'Running AI forensic models (Gemini)...',
    'Correlating threat indicators & IOCs...',
    'Generating risk assessment...'
  ];

  // Ping Backend Health Check
  const checkBackendHealth = async () => {
    setPinging(true);
    const start = Date.now();
    try {
      const res = await fetch('/api/extension/ping');
      const latency = Date.now() - start;
      if (res.ok) {
        setBackendPing({ status: 'ONLINE', latencyMs: latency });
      } else {
        setBackendPing({ status: 'DEGRADED', latencyMs: latency });
      }
    } catch {
      setBackendPing({ status: 'OFFLINE', latencyMs: 0 });
    } finally {
      setPinging(false);
    }
  };

  useEffect(() => {
    checkBackendHealth();

    // Initialize Device Identity Manager
    deviceIdentityManager.init().then((state) => {
      setDeviceState(state);
    });

    // Fetch 100M model architecture
    fetch100MArchitecture()
      .then((data) => setModelArch(data))
      .catch((e) => console.warn('Architecture fetch error:', e));
  }, []);

  const handleCopyDeviceId = () => {
    if (deviceState?.deviceId) {
      navigator.clipboard.writeText(deviceState.deviceId);
      setCopiedDeviceId(true);
      setTimeout(() => setCopiedDeviceId(false), 2000);
    }
  };

  const handleRetrainChallenger = async () => {
    try {
      setIsRetraining(true);
      setRetrainResult(null);
      const res = await retrainChallengerModel();
      setRetrainResult(res);
      const updated = await fetch100MArchitecture();
      setModelArch(updated);
    } catch (e: any) {
      alert(`Retraining error: ${e.message}`);
    } finally {
      setIsRetraining(false);
    }
  };

  const handlePromoteChallenger = async () => {
    try {
      setIsPromoting(true);
      await promoteChallengerModel();
      const updated = await fetch100MArchitecture();
      setModelArch(updated);
      alert('Challenger candidate successfully promoted to Production Champion.');
    } catch (e: any) {
      alert(`Promotion error: ${e.message}`);
    } finally {
      setIsPromoting(false);
    }
  };

  const handleDownload = () => {
    setDownloaded(true);
    const link = document.createElement('a');
    link.href = '/downloads/mailtrace-ai-extension.zip';
    link.download = 'mailtrace-ai-extension.zip';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleCopyChromeUrl = () => {
    navigator.clipboard.writeText('chrome://extensions');
    setCopiedUrl(true);
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  // Run Simulator Pipeline
  const runSimulator = () => {
    setSimStep('analyzing');
    setSimProgressStep(0);

    let current = 0;
    const interval = setInterval(() => {
      current++;
      if (current < STEPS.length) {
        setSimProgressStep(current);
      } else {
        clearInterval(interval);
        setSimStep('result');
      }
    }, 250);
  };

  return (
    <div className="space-y-5 max-w-6xl mx-auto pb-8">
      
      {/* Top Banner / Technical Header */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-5">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div className="max-w-2xl">
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-mono text-[10px] uppercase font-semibold">
                Manifest V3
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200 font-mono text-[10px] font-semibold">
                Gmail & Outlook Web Ready
              </span>
              {backendPing && (
                <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-semibold border ${
                  backendPing.status === 'ONLINE'
                    ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                    : 'bg-rose-50 text-rose-700 border-rose-200'
                }`}>
                  API: {backendPing.status} ({backendPing.latencyMs}ms)
                </span>
              )}
            </div>

            <h1 className="text-lg font-bold text-slate-900 font-mono">
              MailTrace Webmail Companion & Synchronization Hub
            </h1>
            <p className="mt-1 text-xs text-slate-500 leading-relaxed">
              Analyze suspicious emails directly inside webmail without manual header extraction. Real-time background sync with the MailTrace Forensic Workstation.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={handleDownload}
              className="flex items-center gap-2 px-3.5 py-2 rounded bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs shadow-xs transition"
            >
              <Download className="w-4 h-4" />
              <span>Download Extension (.ZIP)</span>
            </button>
          </div>
        </div>
      </div>

      {/* 5-Step Installation Walkthrough */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
          <div>
            <h2 className="text-xs uppercase tracking-wider font-bold text-slate-900 flex items-center gap-2 font-mono">
              <Chrome className="w-4 h-4 text-indigo-600" />
              <span>Browser Installation Workflow</span>
            </h2>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Load unpacked extension directly in Chrome / Edge Developer Mode
            </p>
          </div>

          <button
            onClick={handleCopyChromeUrl}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-50 hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-medium transition shadow-xs"
          >
            {copiedUrl ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
            <span className="font-mono text-[11px]">{copiedUrl ? 'Copied' : 'Copy chrome://extensions'}</span>
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-3 text-xs">
          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <div className="font-mono font-bold text-indigo-700 text-xs">Step 1</div>
            <div className="font-semibold text-slate-900">Download ZIP</div>
            <p className="text-[11px] text-slate-500 leading-normal">Download and extract the <code className="text-indigo-700 font-mono">mailtrace-ai-extension.zip</code> file.</p>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <div className="font-mono font-bold text-indigo-700 text-xs">Step 2</div>
            <div className="font-semibold text-slate-900">Open Extensions</div>
            <p className="text-[11px] text-slate-500 leading-normal">Navigate to <code className="text-slate-800 font-mono">chrome://extensions</code> in your browser.</p>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <div className="font-mono font-bold text-indigo-700 text-xs">Step 3</div>
            <div className="font-semibold text-slate-900">Enable Dev Mode</div>
            <p className="text-[11px] text-slate-500 leading-normal">Toggle the <strong>Developer mode</strong> switch in the top-right corner.</p>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <div className="font-mono font-bold text-indigo-700 text-xs">Step 4</div>
            <div className="font-semibold text-slate-900">Load Unpacked</div>
            <p className="text-[11px] text-slate-500 leading-normal">Click <strong>Load unpacked</strong> and select the extracted extension folder.</p>
          </div>

          <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
            <div className="font-mono font-bold text-emerald-700 text-xs">Step 5</div>
            <div className="font-semibold text-slate-900">Inspect Webmail</div>
            <p className="text-[11px] text-slate-500 leading-normal">Open Gmail or Outlook Web to inspect any message with 1-click.</p>
          </div>
        </div>
      </div>

      {/* Model Architecture & Challenger Training */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-indigo-600" />
            <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              Transformer ML Model Architecture & Governance
            </h3>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleRetrainChallenger}
              disabled={isRetraining}
              className="px-3 py-1.5 rounded bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 text-xs font-medium transition shadow-xs disabled:opacity-50 flex items-center gap-1.5"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-indigo-600 ${isRetraining ? 'animate-spin' : ''}`} />
              <span>{isRetraining ? 'Training Model...' : 'Train Challenger Candidate'}</span>
            </button>

            <button
              onClick={handlePromoteChallenger}
              disabled={isPromoting}
              className="px-3 py-1.5 rounded bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold shadow-xs transition disabled:opacity-50"
            >
              <span>Promote to Production</span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
          <div className="p-3 rounded bg-slate-50 border border-slate-200">
            <div className="text-[10px] text-slate-500 uppercase font-bold">Champion Model</div>
            <div className="text-sm font-bold text-slate-900 mt-1">MailTrace-100M Transformer</div>
            <div className="text-[10px] text-emerald-700 font-semibold mt-1">Production Active</div>
          </div>

          <div className="p-3 rounded bg-slate-50 border border-slate-200">
            <div className="text-[10px] text-slate-500 uppercase font-bold">Parameters</div>
            <div className="text-sm font-bold text-indigo-700 mt-1">128,894,258 Parameters</div>
            <div className="text-[10px] text-slate-500 mt-1">Self-Attention Classifier</div>
          </div>

          <div className="p-3 rounded bg-slate-50 border border-slate-200">
            <div className="text-[10px] text-slate-500 uppercase font-bold">Governance Status</div>
            <div className="text-sm font-bold text-slate-900 mt-1">Deterministic Seed</div>
            <div className="text-[10px] text-slate-500 mt-1">Immutable Training Checkpoint</div>
          </div>
        </div>
      </div>

    </div>
  );
};
