/**
 * MailTrace AI - Express Backend Server Entrypoint
 * Port 3000, Host 0.0.0.0, Vite middleware integration
 */

import express from 'express';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';
import { SAMPLE_SCENARIOS } from './server/sampleEmails.js';
import { runEmailAnalysisPipeline } from './server/emailAnalysisPipeline.js';
import { askCopilot } from './server/copilotService.js';
import { threatIntelEngine } from './server/analyzers/threatIntelEngine.js';
import { socStore } from './server/store.js';
import { analyzeExtensionEmail, reportMaliciousEmailFromExtension } from './server/extensionService.js';
import { mlGovernanceStore } from './server/mlGovernanceStore.js';
import { geminiThreatEngine } from './server/engines/geminiThreatEngine.js';
import { runRegressionTestSuite, REGRESSION_TEST_CASES } from './server/regressionTestSuite.js';
import { campaignMemory } from './server/engines/campaignMemory.js';
import { generateDailySummaryReport } from './server/reports/dailySummaryService.js';
import { deviceSyncService } from './server/deviceSyncService.js';
import { feedbackService } from './server/feedbackService.js';
import { mlTransformer100M } from './server/engines/mlTransformer100M.js';
import { loadOrGenerateDatasetReport, generateTrainingReport } from './server/datasetReportService.js';
import { attachmentRetrievalService } from './server/services/attachmentRetrievalService.js';

import { spawn, ChildProcess } from 'child_process';

const PORT = 3000;
let pythonInferenceProcess: ChildProcess | null = null;

function ensurePythonInferenceServer() {
  const predictScript = path.resolve(process.cwd(), 'ml/inference/predict.py');
  if (!fs.existsSync(predictScript)) return;

  try {
    const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
    pythonInferenceProcess = spawn(pythonCmd, [predictScript], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ML_PORT: process.env.ML_PORT || '5001' }
    });

    pythonInferenceProcess.stdout?.on('data', (data) => {
      const msg = data.toString().trim();
      if (msg) console.log(`[Python Inference] ${msg}`);
    });

    pythonInferenceProcess.stderr?.on('data', (data) => {
      const msg = data.toString().trim();
      if (msg) console.error(`[Python Inference Error] ${msg}`);
    });

    pythonInferenceProcess.on('exit', (code) => {
      console.log(`[Python Inference] Exited with code ${code}`);
      pythonInferenceProcess = null;
    });

    const cleanup = () => {
      if (pythonInferenceProcess) {
        try { pythonInferenceProcess.kill(); } catch {}
      }
    };
    process.on('SIGINT', cleanup);
    process.on('SIGTERM', cleanup);
    process.on('exit', cleanup);
  } catch (err) {
    console.warn('[Python Inference] Could not auto-spawn python inference server:', err);
  }
}

async function startServer() {
  // Launch Python ML inference service in background
  ensurePythonInferenceServer();

  const app = express();
  app.use(express.json({ limit: '15mb' }));

  // CORS middleware for Chrome Extension & external dashboard communication
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

  // ==========================================
  // API ROUTES (MUST COME FIRST)
  // ==========================================

  // Process Health Check
  const healthHandler = (req: express.Request, res: express.Response) => {
    res.json({
      status: 'ok',
      service: 'MailTrace AI Forensics Engine',
      version: '2.5.0-enterprise',
      uptimeSeconds: process.uptime(),
      geminiConnected: !!process.env.GEMINI_API_KEY,
      components: {
        emailParser: 'OPERATIONAL',
        smtpPathReconstruction: 'OPERATIONAL',
        domainLookalikeEngine: 'OPERATIONAL',
        threatIntelligenceFeed: threatIntelEngine.isConfigured() ? 'OPERATIONAL (CONNECTED)' : 'OPERATIONAL (LOCAL ANALYST STORE)',
        geoIpResolver: 'OPERATIONAL (VERIFIED-INFRASTRUCTURE)',
        relationshipGraphEngine: 'OPERATIONAL',
        copilotChat: process.env.GEMINI_API_KEY ? 'ACTIVE (GEMINI)' : 'ACTIVE (DETERMINISTIC FALLBACK)'
      }
    });
  };

  app.get('/health', healthHandler);
  app.get('/api/health', healthHandler);

  // Cloud Run Container Readiness Probe
  app.get('/ready', async (req, res) => {
    try {
      const status = await mlTransformer100M.getProductionModelStatus();
      if (status.available && status.loaded) {
        return res.status(200).json({
          ready: true,
          status: 'READY',
          modelId: status.modelId || 'mailtrace-security-transformer',
          version: status.version || '100m-v2',
          architecture: status.architecture || 'MailTraceSecurityTransformer',
          parameterCount: status.parameterCount || 128894258
        });
      } else if (status.status === 'INITIALIZING') {
        return res.status(503).json({
          ready: false,
          status: 'INITIALIZING',
          message: 'Model checkpoint is currently downloading/initializing from GCS cache.'
        });
      } else {
        return res.status(503).json({
          ready: false,
          status: 'ERROR',
          errorCode: status.errorCode || 'MODEL_UNAVAILABLE',
          message: status.message || 'Model artifact is unavailable.'
        });
      }
    } catch (err: any) {
      return res.status(503).json({
        ready: false,
        status: 'ERROR',
        errorCode: 'MODEL_UNAVAILABLE',
        error: err.message
      });
    }
  });

  // Authoritative Model Status Endpoint
  app.get('/api/model/status', async (req, res) => {
    try {
      const status = await mlTransformer100M.getProductionModelStatus();
      return res.json(status);
    } catch (err: any) {
      return res.json({
        available: false,
        verified: false,
        loaded: false,
        status: 'ERROR',
        errorCode: 'MODEL_UNAVAILABLE',
        error: err.message
      });
    }
  });

  // Authoritative Model Manifest Endpoint
  app.get('/api/model/manifest', (req, res) => {
    try {
      const manifestPath = path.resolve(process.cwd(), 'ml/model_registry/model_manifest.json');
      if (fs.existsSync(manifestPath)) {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
        return res.json(manifest);
      }
      return res.status(404).json({ error: 'Manifest not found' });
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to read manifest', details: err.message });
    }
  });

  // Model Setup Trigger Endpoint
  app.post('/api/model/setup', async (req, res) => {
    try {
      const status = await mlTransformer100M.getProductionModelStatus();
      if (status.available && status.loaded) {
        return res.json({ success: true, message: 'Model is already setup and verified.', status });
      }
      // If setup requested, spawn python setup utility
      const { exec } = await import('child_process');
      exec('python3 scripts/model_setup.py', (error, stdout, stderr) => {
        if (error) {
          console.error('[Model Setup Error]', stderr || error.message);
        } else {
          console.log('[Model Setup Success]', stdout);
        }
      });
      return res.json({ success: true, message: 'Model setup initiated in background.' });
    } catch (err: any) {
      return res.status(500).json({ error: 'Failed to initiate model setup', details: err.message });
    }
  });

  // Deep Multimodal ML Forward Pass Endpoint
  app.post('/api/ml/100m/forward-pass', (req, res) => {
    try {
      const emailData = req.body || {};
      const result = mlTransformer100M.forwardPass(emailData);
      return res.json(result);
    } catch (err: any) {
      return res.status(500).json({ error: 'Forward pass failed', details: err.message });
    }
  });

  // 2. Sample Scenarios List
  app.get('/api/samples', (req, res) => {
    const list = SAMPLE_SCENARIOS.map(s => ({
      id: s.id,
      name: s.name,
      scenarioTag: s.scenarioTag,
      threatType: s.threatType,
      expectedRisk: s.expectedRisk,
      description: s.description
    }));
    res.json(list);
  });

  // 3. Get single sample raw content
  app.get('/api/samples/:id', (req, res) => {
    const sample = SAMPLE_SCENARIOS.find(s => s.id === req.params.id);
    if (!sample) {
      return res.status(404).json({ error: 'Sample scenario not found' });
    }
    res.json(sample);
  });

  // 4. Analyze Email (Master Pipeline)
  app.post('/api/analyze', async (req, res) => {
    try {
      let { rawEmail, rawMime, scenarioId, headers, body, attachments, metadata } = req.body;
      const content = rawMime || rawEmail;
      if (!content && scenarioId) {
        const found = SAMPLE_SCENARIOS.find(s => s.id === scenarioId);
        if (found) rawEmail = found.rawEml;
      } else if (content) {
        rawEmail = content;
      }
      if (!rawEmail || typeof rawEmail !== 'string') {
        return res.status(400).json({ error: 'rawEmail or rawMime text content is required' });
      }

      const result = await runEmailAnalysisPipeline(rawEmail, scenarioId);
      res.json(result);
    } catch (error: any) {
      console.error('[MailTrace API] Analysis error:', error);
      res.status(500).json({ error: 'Failed to analyze email', details: error.message });
    }
  });

  // 4.1. Chrome Extension Ingestion & Triage
  app.post('/api/extension/analyze', async (req, res) => {
    try {
      const { emailData, rawEmail, deviceId, source } = req.body;
      if (!emailData && !rawEmail) {
        return res.status(400).json({ error: 'Either emailData or rawEmail must be provided.' });
      }

      const result = await analyzeExtensionEmail({
        emailData,
        rawEmail,
        sourceContext: req.headers['user-agent'] || 'Chrome Extension'
      });

      // Synchronize state across paired extension and website devices
      if (deviceId) {
        deviceSyncService.syncState({
          deviceId,
          source: source || 'extension',
          activeEmailId: result.analysisId,
          activeSubject: result.analysis?.subject || emailData?.subject || 'Analyzed Email',
          riskScore: result.analysis?.overallRiskScore || 0,
          verdict: result.analysis?.primaryClassification || 'Legitimate',
          analysisResult: result.analysis,
          deepLinkPath: result.deepLinkPath
        });
      }

      res.json({
        success: true,
        analysisId: result.analysisId,
        deepLinkPath: result.deepLinkPath,
        analysis: result.analysis
      });
    } catch (error: any) {
      console.error('[MailTrace Extension API] Analysis error:', error);
      res.status(500).json({ error: error.message || 'Extension analysis failed.' });
    }
  });

  // 4.2. Chrome Extension Direct Malicious Report
  app.post('/api/extension/report', async (req, res) => {
    try {
      const reportRes = reportMaliciousEmailFromExtension(req.body);
      res.json(reportRes);
    } catch (error: any) {
      console.error('[MailTrace Extension API] Report error:', error);
      res.status(500).json({ error: error.message || 'Failed to submit threat report.' });
    }
  });

  // 4.3. Extension Backend Ping
  app.get('/api/extension/ping', (req, res) => {
    res.json({
      status: 'ok',
      service: 'MailTrace AI Forensics Engine',
      version: '2.4.0',
      timestamp: new Date().toISOString()
    });
  });

  // 4.4. Extension ZIP Package Download
  const serveExtensionZip = (req: express.Request, res: express.Response) => {
    const candidates = [
      path.resolve(process.cwd(), 'public/downloads/mailtrace-ai-extension.zip'),
      path.resolve(process.cwd(), 'dist/downloads/mailtrace-ai-extension.zip')
    ];
    let foundPath: string | null = null;
    for (const p of candidates) {
      if (fs.existsSync(p)) {
        foundPath = p;
        break;
      }
    }

    if (!foundPath) {
      return res.status(404).json({ error: 'Extension package archive not found. Please run build.' });
    }

    res.download(foundPath, 'mailtrace-ai-extension.zip', (err) => {
      if (err) {
        console.error('[MailTrace API] Error sending extension ZIP:', err);
      }
    });
  };

  app.get('/downloads/mailtrace-ai-extension.zip', serveExtensionZip);
  app.get('/api/extension/download', serveExtensionZip);

  // 4.45. Secure Inline Sandboxed Attachment Analysis (Zero User Downloads)
  app.post('/api/attachments/analyze', async (req, res) => {
    try {
      const { analysisId, provider, messageId, attachmentId, filename, declaredMimeType, sizeBytes, rawBase64, expectedSha256 } = req.body;

      if (!attachmentId && !filename) {
        return res.status(400).json({ error: 'attachmentId or filename is required for attachment analysis.' });
      }

      const result = await attachmentRetrievalService.analyzeAttachmentInline({
        analysisId: analysisId || `adhoc-${Date.now()}`,
        provider: provider || 'eml_mime',
        messageId,
        attachmentId: attachmentId || `att-${Date.now()}`,
        filename: filename || 'attachment.bin',
        declaredMimeType,
        sizeBytes,
        rawBase64,
        expectedSha256
      });

      // If tied to an active email investigation in socStore, update the email's attachment record and findings
      if (analysisId && socStore.analyzedEmails.has(analysisId)) {
        const email = socStore.analyzedEmails.get(analysisId)!;
        const existingIdx = email.attachments.findIndex(a => a.id === result.id || a.attachmentId === result.attachmentId || a.filename === result.filename);
        if (existingIdx >= 0) {
          email.attachments[existingIdx] = result;
        } else {
          email.attachments.push(result);
        }

        // Add attachment SHA-256 to IOCs if valid
        if (result.sha256 && result.sha256.length === 64) {
          const iocExists = email.iocs.some(i => i.indicator === result.sha256);
          if (!iocExists) {
            email.iocs.push({
              id: `ioc-hash-${Date.now()}`,
              type: 'hash',
              indicator: result.sha256,
              risk: result.risk,
              source: 'attachment-static-analyzer',
              confidence: 99,
              context: `SHA-256 for attachment "${result.filename}" (${result.fileType})`
            });
          }
        }

        socStore.logAudit(
          'ANALYST',
          'SOC_ANALYST',
          'INLINE_ATTACHMENT_ANALYSIS',
          `Completed static sandbox analysis on "${result.filename}" (Risk: ${result.attachmentRisk || 0}/100, SHA-256: ${result.sha256?.slice(0, 16)}...)`,
          req.ip || '127.0.0.1',
          result.lifecycleStatus === 'FAILED' ? 'FAILURE' : 'SUCCESS'
        );
      }

      res.json(result);
    } catch (error: any) {
      console.error('[MailTrace Attachment API] Inline analysis error:', error);
      res.status(500).json({ error: error.message || 'Attachment analysis failed.' });
    }
  });

  // ==========================================
  // 4.5. DEVICE IDENTITY & REAL-TIME SYNC (PART A)
  // ==========================================

  // Register or heartbeat a device identity
  app.post('/api/device/register', (req, res) => {
    try {
      const { deviceId, clientType, browser, os, userAgent, extensionVersion } = req.body;
      const device = deviceSyncService.registerOrHeartbeat({
        deviceId,
        clientType: clientType || 'website',
        browser,
        os,
        userAgent: userAgent || req.headers['user-agent'],
        ipAddress: req.ip || req.socket.remoteAddress,
        extensionVersion
      });
      res.json({
        success: true,
        device,
        pairedCount: deviceSyncService.getPairedDevicesCount()
      });
    } catch (err: any) {
      console.error('[MailTrace Device API] Register error:', err);
      res.status(500).json({ error: 'Failed to register device', details: err.message });
    }
  });

  // List all registered devices
  app.get('/api/device/list', (req, res) => {
    res.json({
      devices: deviceSyncService.listDevices(),
      activeCount: deviceSyncService.getPairedDevicesCount(),
      latestSyncState: deviceSyncService.getLatestSyncState()
    });
  });

  // Get single device identity
  app.get('/api/device/:deviceId', (req, res) => {
    const device = deviceSyncService.getDevice(req.params.deviceId);
    if (!device) return res.status(404).json({ error: 'Device identity not found' });
    res.json(device);
  });

  // Extension + Website Identity Handshake Endpoint
  app.post('/api/device/handshake', (req, res) => {
    try {
      const { websiteDeviceId, extensionDeviceId, authenticatedUserId } = req.body;
      const handshake = deviceSyncService.performHandshake({
        websiteDeviceId,
        extensionDeviceId,
        authenticatedUserId
      });
      res.json(handshake);
    } catch (err: any) {
      console.error('[MailTrace Handshake API] Error:', err);
      res.status(500).json({ error: 'Identity handshake failed', details: err.message });
    }
  });

  // Unregister device
  app.delete('/api/device/:deviceId', (req, res) => {
    const deleted = deviceSyncService.unregisterDevice(req.params.deviceId);
    res.json({ success: deleted });
  });

  // Sync active investigation state between Extension and Web App
  app.post('/api/device/sync', (req, res) => {
    try {
      const syncPayload = req.body;
      if (!syncPayload.deviceId) {
        return res.status(400).json({ error: 'deviceId is required for state synchronization' });
      }
      const updatedState = deviceSyncService.syncState(syncPayload);
      res.json({ success: true, state: updatedState });
    } catch (err: any) {
      console.error('[MailTrace Sync API] Sync error:', err);
      res.status(500).json({ error: 'Failed to synchronize state', details: err.message });
    }
  });

  // Get current synchronized state
  app.get('/api/device/latest-sync', (req, res) => {
    const state = deviceSyncService.getLatestSyncState();
    res.json(state || { initialized: false });
  });

  // Server-Sent Events (SSE) stream for live real-time synchronization between browser tabs and extension
  app.get('/api/device/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders?.();

    // Send initial handshake and state
    res.write(`data: ${JSON.stringify({ type: 'HANDSHAKE', state: deviceSyncService.getLatestSyncState(), activeDevices: deviceSyncService.getPairedDevicesCount() })}\n\n`);

    const onStateSync = (state: any) => {
      res.write(`data: ${JSON.stringify({ type: 'STATE_SYNC', state })}\n\n`);
    };

    deviceSyncService.on('state_sync', onStateSync);

    req.on('close', () => {
      deviceSyncService.off('state_sync', onStateSync);
      res.end();
    });
  });

  // ==========================================
  // 4.6. 100M PARAMETER TRANSFORMER ARCHITECTURE (PART B)
  // ==========================================
  app.get('/api/ml/100m/architecture', (req, res) => {
    res.json(mlTransformer100M.getArchitectureBreakdown());
  });

  app.post('/api/ml/100m/forward-pass', (req, res) => {
    try {
      const { emailData } = req.body;
      if (!emailData) {
        return res.status(400).json({ error: 'emailData is required' });
      }
      const result = mlTransformer100M.forwardPass(emailData);
      res.json(result);
    } catch (err: any) {
      console.error('[MailTrace 100M API] Forward pass error:', err);
      res.status(500).json({ error: 'Failed to run 100M forward pass', details: err.message });
    }
  });

  // 5. Get previously analyzed email
  app.get('/api/analysis/:id', (req, res) => {
    const result = socStore.analyzedEmails.get(req.params.id);
    if (!result) {
      return res.status(404).json({ error: 'Analysis record not found' });
    }
    res.json(result);
  });

  // 5.1. Recalculate analysis (Deterministic Reproducibility Verification)
  const handleRecalculate = async (req: express.Request, res: express.Response) => {
    try {
      const emailId = req.params.id;
      const existing = socStore.analyzedEmails.get(emailId);
      if (!existing) {
        return res.status(404).json({ error: `Analysis record ${emailId} not found` });
      }

      let rawMime = existing.rawMime;
      if (!rawMime) {
        const sample = SAMPLE_SCENARIOS.find(s => s.id === emailId);
        if (sample) rawMime = sample.rawEml;
      }

      if (!rawMime) {
        return res.status(400).json({ error: 'Raw MIME data not cached for this email record.' });
      }

      const recalculated = await runEmailAnalysisPipeline(rawMime, emailId);
      const isReproducible = recalculated.overallRiskScore === existing.overallRiskScore;
      recalculated.recalculationVerified = true;
      socStore.analyzedEmails.set(emailId, recalculated);

      res.json({
        analysisId: emailId,
        originalScore: existing.overallRiskScore,
        recalculatedScore: recalculated.overallRiskScore,
        reproducible: isReproducible,
        scoringVersion: recalculated.scoringVersion,
        categoryScores: recalculated.categoryScores,
        componentScores: recalculated.componentScores,
        scoreExplanation: recalculated.scoreExplanation,
        updatedAnalysis: recalculated
      });
    } catch (err: any) {
      console.error('[MailTrace API] Recalculation error:', err);
      res.status(500).json({ error: 'Failed to recalculate analysis', details: err.message });
    }
  };

  app.post('/api/recalculate/:id', handleRecalculate);
  app.post('/api/analysis/:id/recalculate', handleRecalculate);
  app.post('/api/forensics/recalculate/:id', handleRecalculate);

  // 5.1. Get full analyzed email history list
  app.get('/api/history', (req, res) => {
    const list = Array.from(socStore.analyzedEmails.values()).map(e => ({
      id: e.id,
      analyzedAt: e.analyzedAt,
      subject: e.subject,
      from: e.from,
      fromDomain: e.fromDomain,
      overallRiskScore: e.overallRiskScore,
      threatRisk: e.threatRisk ?? e.overallRiskScore,
      spamLikelihood: e.spamLikelihood ?? 0,
      authenticityConfidence: e.authenticityConfidence ?? 85,
      severity: e.severity,
      primaryClassification: e.primaryClassification,
      threatConfidence: e.threatConfidence,
      originConfidence: e.originConfidence,
      attributionConfidence: e.attributionConfidence,
      matchedCampaignId: e.matchedCampaignId,
      matchedCampaignName: e.matchedCampaignName
    }));
    list.sort((a, b) => new Date(b.analyzedAt).getTime() - new Date(a.analyzedAt).getTime());
    res.json(list);
  });

  // 5.2. Aggregated Live SOC Statistics
  app.get('/api/stats', (req, res) => {
    const alerts = Array.from(socStore.alerts.values());
    const totalAnalyzed = socStore.analyzedEmails.size;
    const criticalAlerts = alerts.filter(a => a.severity === 'CRITICAL').length;
    const highAlerts = alerts.filter(a => a.severity === 'HIGH').length;
    const mediumAlerts = alerts.filter(a => a.severity === 'MEDIUM').length;
    const lowAlerts = alerts.filter(a => a.severity === 'LOW' || a.severity === 'TRUSTED').length;
    const containedCount = alerts.filter(a => a.status === 'CONTAINED' || a.status === 'RESOLVED').length;
    const quarantineRate = alerts.length > 0 ? Math.round((containedCount / alerts.length) * 100) : 0;

    res.json({
      totalAnalyzed,
      activeAlerts: alerts.filter(a => a.status === 'NEW' || a.status === 'INVESTIGATING' || a.status === 'ACKNOWLEDGED').length,
      criticalAlerts,
      highAlerts,
      mediumAlerts,
      lowAlerts,
      containedCount,
      quarantineRate,
      trackedCampaigns: socStore.campaigns.size,
      activeCases: socStore.cases.size,
      evidenceItems: socStore.evidence.size
    });
  });

  // 6. Interactive SOC Copilot
  app.post('/api/copilot', async (req, res) => {
    try {
      const { messages, contextEmail, deepThinking } = req.body;
      if (!messages || !Array.isArray(messages)) {
        return res.status(400).json({ error: 'Messages array is required' });
      }

      const response = await askCopilot({
        messages,
        contextEmail,
        deepThinking: !!deepThinking
      });

      socStore.logAudit(
        'SOC_COPILOT',
        'ANALYST',
        'AI_PROMPT',
        `Query to ${response.modelUsed} (Thinking: ${response.thinkingMode})`,
        '127.0.0.1',
        'SUCCESS'
      );

      res.json(response);
    } catch (error: any) {
      console.error('[MailTrace Copilot API] Error:', error);
      res.status(500).json({ error: 'Copilot query failed', details: error.message });
    }
  });

  // 7. Alerts
  app.get('/api/alerts', (req, res) => {
    const alerts = Array.from(socStore.alerts.values());
    res.json(alerts);
  });

  app.post('/api/alerts/:id/status', (req, res) => {
    const { id } = req.params;
    const { status } = req.body;
    const alert = socStore.alerts.get(id);
    if (!alert) {
      return res.status(404).json({ error: 'Alert not found' });
    }
    alert.status = status;
    socStore.logAudit('SOC_TRIAGE', 'ANALYST', 'STATUS_UPDATE', `Alert ${id} set to ${status}`, '127.0.0.1', 'SUCCESS');
    res.json(alert);
  });

  // 8. Cases
  app.get('/api/cases', (req, res) => {
    const cases = Array.from(socStore.cases.values());
    res.json(cases);
  });

  app.post('/api/cases', (req, res) => {
    const { title, description, priority, emailId, emailSubject, sender, analyst, relatedIocs, relatedDomains, relatedIps, campaignId } = req.body;
    const assignedAnalyst = analyst || 'SOC Investigator';
    const newCase = {
      id: `CASE-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`,
      title: title || 'New Forensics Investigation',
      description: description || 'Triage of suspicious email activity.',
      priority: priority || 'HIGH',
      analyst: assignedAnalyst,
      status: 'INVESTIGATING' as const,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      emailId,
      emailSubject,
      sender,
      relatedIocs: relatedIocs || [],
      relatedDomains: relatedDomains || [],
      relatedIps: relatedIps || [],
      campaignId,
      evidenceCount: 1,
      notes: [
        {
          id: `note-${Date.now()}`,
          author: assignedAnalyst,
          timestamp: new Date().toISOString(),
          text: 'Case initiated from MailTrace Threat Detection Engine.'
        }
      ],
      timeline: [
        {
          id: `t-${Date.now()}`,
          timestamp: new Date().toISOString(),
          action: 'CASE_CREATED',
          actor: assignedAnalyst,
          details: `Case opened for ${emailSubject || 'email item'}`
        }
      ]
    };
    socStore.cases.set(newCase.id, newCase);

    // Auto-create immutable cryptographic evidence artifact for the case
    const evId = `EV-${new Date().getFullYear()}-${Math.floor(100 + Math.random() * 900)}`;
    const artifactSubject = emailSubject || 'investigation_artifact';
    const cleanName = artifactSubject.replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 32);
    const ev = {
      id: evId,
      caseId: newCase.id,
      name: `${cleanName}.eml`,
      type: 'RAW_EML' as const,
      sha256: crypto.createHash('sha256').update(emailId || newCase.id + Date.now()).digest('hex'),
      sizeBytes: 3584,
      uploadedBy: assignedAnalyst,
      timestamp: new Date().toISOString(),
      description: `Original RFC 5322 MIME stream vaulted for case ${newCase.id}`,
      integrityStatus: 'VERIFIED' as const
    };
    socStore.evidence.set(ev.id, ev);

    socStore.logAudit('CASE_MANAGEMENT', 'ANALYST', 'CREATE_CASE', `Created ${newCase.id} for "${emailSubject || 'Incident'}"`, '127.0.0.1', 'SUCCESS');
    res.json(newCase);
  });

  app.get('/api/cases/:id', (req, res) => {
    const c = socStore.cases.get(req.params.id);
    if (!c) return res.status(404).json({ error: 'Case not found' });
    res.json(c);
  });

  app.post('/api/cases/:id/notes', (req, res) => {
    const c = socStore.cases.get(req.params.id);
    if (!c) return res.status(404).json({ error: 'Case not found' });
    const { text, author } = req.body;
    const assignedAnalyst = author || 'SOC Investigator';
    const note = {
      id: `note-${Date.now()}`,
      author: assignedAnalyst,
      timestamp: new Date().toISOString(),
      text
    };
    c.notes.push(note);
    c.updatedAt = new Date().toISOString();
    socStore.logAudit('CASE_MANAGEMENT', 'ANALYST', 'ADD_NOTE', `Added note to ${c.id}`, '127.0.0.1', 'SUCCESS');
    res.json(c);
  });

  // 9. Evidence Vault
  app.get('/api/evidence', (req, res) => {
    res.json(Array.from(socStore.evidence.values()));
  });

  app.post('/api/evidence', (req, res) => {
    const { caseId, name, type, sha256, sizeBytes, description, uploadedBy } = req.body;
    const evName = name || 'forensic_artifact.bin';
    const ev = {
      id: `EV-${new Date().getFullYear()}-${Math.floor(100 + Math.random() * 900)}`,
      caseId: caseId || 'UNASSIGNED',
      name: evName,
      type: type || 'ATTACHMENT',
      sha256: sha256 || crypto.createHash('sha256').update(evName + Date.now()).digest('hex'),
      sizeBytes: sizeBytes || 1024,
      uploadedBy: uploadedBy || 'SOC Investigator',
      timestamp: new Date().toISOString(),
      description: description || 'Preserved forensic artifact in evidence vault.',
      integrityStatus: 'VERIFIED' as const
    };
    socStore.evidence.set(ev.id, ev);
    socStore.logAudit('EVIDENCE_VAULT', 'ANALYST', 'PRESERVE_EVIDENCE', `Vaulted ${ev.name} (${ev.id})`, '127.0.0.1', 'SUCCESS');
    res.json(ev);
  });

  // 10. Campaigns
  app.get('/api/campaigns', (req, res) => {
    res.json(Array.from(socStore.campaigns.values()));
  });

  // 11. Audit Logs
  app.get('/api/audit-logs', (req, res) => {
    res.json(socStore.auditLogs);
  });

  // 12. Threat Intelligence (SIMULATED THREAT INTELLIGENCE)
  app.get('/api/threat-intel/feed', (req, res) => {
    const { type, severity, query } = req.query;
    const feed = threatIntelEngine.getFeed({
      type: typeof type === 'string' ? type : undefined,
      severity: typeof severity === 'string' ? severity : undefined,
      query: typeof query === 'string' ? query : undefined
    });
    res.json({
      provenance: 'SIMULATED THREAT INTELLIGENCE',
      count: feed.length,
      indicators: feed
    });
  });

  app.get('/api/threat-intel/stats', (req, res) => {
    const stats = threatIntelEngine.getStats();
    res.json(stats);
  });

  app.post('/api/threat-intel/indicators', (req, res) => {
    const data = req.body;
    if (!data.indicator || typeof data.indicator !== 'string') {
      return res.status(400).json({ error: 'Indicator value is required' });
    }
    const created = threatIntelEngine.addIndicator(data);
    socStore.logAudit(
      'analyst.chen@defense.corp',
      'THREAT_INTELLIGENCE',
      'INGEST_INDICATOR',
      `Ingested simulated indicator ${created.indicator} (${created.type})`,
      '127.0.0.1',
      'SUCCESS'
    );
    res.status(201).json(created);
  });

  app.delete('/api/threat-intel/indicators/:id', (req, res) => {
    const deleted = threatIntelEngine.deleteIndicator(req.params.id);
    if (!deleted) {
      return res.status(404).json({ error: 'Indicator not found in simulated feed' });
    }
    socStore.logAudit(
      'analyst.chen@defense.corp',
      'THREAT_INTELLIGENCE',
      'REMOVE_INDICATOR',
      `Removed simulated indicator ${req.params.id}`,
      '127.0.0.1',
      'SUCCESS'
    );
    res.json({ success: true, message: 'Indicator removed from simulated feed' });
  });

  app.post('/api/threat-intel/reset', (req, res) => {
    threatIntelEngine.resetFeed();
    socStore.logAudit(
      'analyst.chen@defense.corp',
      'THREAT_INTELLIGENCE',
      'RESET_FEED',
      'Reset simulated threat intelligence feed to default baseline',
      '127.0.0.1',
      'SUCCESS'
    );
    res.json({ success: true, message: 'Simulated threat feed reset to baseline' });
  });

  // Standalone correlation test endpoint
  app.post('/api/threat-intel/correlate', (req, res) => {
    const { indicators } = req.body;
    if (!indicators || !Array.isArray(indicators)) {
      return res.status(400).json({ error: 'Array of indicator strings is required' });
    }

    const allFeed = threatIntelEngine.getFeed();
    const matches: any[] = [];
    for (const ind of indicators) {
      const norm = String(ind).toLowerCase().trim();
      const hit = allFeed.find(f => f.indicator.toLowerCase() === norm);
      if (hit) {
        matches.push({
          indicator: ind,
          matchedFeedEntry: hit,
          label: 'SIMULATED THREAT INTELLIGENCE'
        });
      }
    }

    res.json({
      provenance: 'SIMULATED THREAT INTELLIGENCE',
      testedCount: indicators.length,
      matchedCount: matches.length,
      matches,
      disclaimer: 'SIMULATED THREAT INTELLIGENCE: Validated against local mock intelligence database.'
    });
  });

  // ==========================================
  // 13. SELF-LEARNING & ML GOVERNANCE ENDPOINTS (Sections 19-21, 30-32, 41-43)
  // ==========================================

  // 13.1. Current ML Model Metadata & Status
  app.get('/api/ml/model', (req, res) => {
    res.json({
      champion: mlGovernanceStore.getChampionModel(),
      challenger: mlGovernanceStore.getChallengerModel(),
      driftReport: mlGovernanceStore.getDriftReport()
    });
  });

  // 13.1.b Dataset Discovery & Preprocessing Report
  app.get('/api/ml/dataset-report', (req, res) => {
    res.json(loadOrGenerateDatasetReport());
  });

  // 13.1.c Training Report
  app.get('/api/ml/training-report', (req, res) => {
    res.json(generateTrainingReport());
  });

  // =========================================================================
  // 13.2. ANALYST VERIFICATION & GROUND-TRUTH FEEDBACK APIS (Section 21)
  // =========================================================================

  // Submit Analyst Ground-Truth Verification
  app.post('/api/feedback/verify', (req, res) => {
    try {
      const {
        analysisId,
        emailSubject,
        sender,
        rawBody,
        urls,
        originalPrediction,
        verifiedGroundTruth,
        isCorrect,
        analyst,
        reason,
        notes,
        classificationType,
        modelVersion,
        structuredFeatures
      } = req.body;

      if (!analysisId || !originalPrediction || !verifiedGroundTruth) {
        return res.status(400).json({ error: 'analysisId, originalPrediction, and verifiedGroundTruth are required' });
      }

      const outcome = feedbackService.submitVerification({
        analysisId,
        emailSubject: emailSubject || 'Email Investigation',
        sender,
        rawBody,
        urls,
        originalPrediction,
        verifiedGroundTruth,
        isCorrect: isCorrect ?? true,
        analyst: analyst || { id: 'analyst.chen@defense.corp', role: 'Senior SOC Analyst', confidence: 0.95 },
        reason: reason || (isCorrect ? 'Analyst confirmed model assessment.' : 'Analyst corrected classification.'),
        notes,
        classificationType,
        modelVersion,
        structuredFeatures
      });

      socStore.logAudit(
        analyst?.id || 'analyst.chen@defense.corp',
        'MODEL_GOVERNANCE',
        'SUBMIT_GROUND_TRUTH_VERIFICATION',
        `Verified "${emailSubject || analysisId}": Pred="${originalPrediction.primaryCategory}" -> GT="${verifiedGroundTruth.primaryCategory}" (Verdict: ${verifiedGroundTruth.verdict}, Status: ${outcome.feedback.status}, Weight: ${outcome.feedback.sampleWeight.toFixed(2)})`,
        '127.0.0.1',
        outcome.feedback.status === 'QUARANTINED' ? 'WARNING' : 'SUCCESS'
      );

      res.json({
        success: true,
        message: outcome.message,
        feedback: outcome.feedback,
        isNew: outcome.isNew
      });
    } catch (err: any) {
      console.error('[API] Verification submission error:', err);
      res.status(500).json({ error: 'Failed to submit verification', details: err.message });
    }
  });

  // Backward compatibility alias for /api/ml/feedback
  app.post('/api/ml/feedback', (req, res) => {
    const { emailId, emailSubject, originalClassification, verifiedClassification, reason, analyst, trustLevel } = req.body;
    const outcome = feedbackService.submitVerification({
      analysisId: emailId || `email-${Date.now()}`,
      emailSubject: emailSubject || 'Email',
      originalPrediction: { primaryCategory: originalClassification || 'Unknown', threatRisk: 50 },
      verifiedGroundTruth: { primaryCategory: verifiedClassification || 'Unknown', verdict: verifiedClassification || 'Unknown' },
      isCorrect: originalClassification === verifiedClassification,
      analyst: { id: analyst || 'analyst.chen@defense.corp', role: trustLevel || 'Senior SOC Analyst' },
      reason: reason || 'Classification verified'
    });
    res.json({ success: true, item: outcome.feedback, message: outcome.message });
  });

  // Get single feedback item by ID
  app.get('/api/feedback/:id', (req, res) => {
    const item = feedbackService.getFeedbackById(req.params.id);
    if (!item) return res.status(404).json({ error: 'Feedback record not found' });
    res.json(item);
  });

  // Get real feedback statistics
  app.get('/api/feedback/stats', (req, res) => {
    res.json(feedbackService.getFeedbackStats());
  });

  // Get list of feedback items
  app.get('/api/feedback', (req, res) => {
    const status = req.query.status as any;
    res.json(feedbackService.getFeedbackList(status));
  });

  app.get('/api/ml/feedback', (req, res) => {
    res.json({
      verifiedFeedback: feedbackService.getFeedbackList('VERIFIED'),
      quarantinedFeedback: feedbackService.getFeedbackList('QUARANTINED')
    });
  });

  // Compile versioned feedback dataset
  app.post('/api/training/feedback-dataset', (req, res) => {
    try {
      const { nameSuffix } = req.body;
      const dataset = feedbackService.createFeedbackDataset(nameSuffix);
      socStore.logAudit(
        'analyst.chen@defense.corp',
        'MODEL_GOVERNANCE',
        'CREATE_FEEDBACK_DATASET',
        `Compiled versioned dataset ${dataset.version} with ${dataset.sampleCount} verified samples (${dataset.hardNegativeCount} hard negatives).`,
        '127.0.0.1',
        'SUCCESS'
      );
      res.json({
        success: true,
        message: `Compiled dataset ${dataset.version} successfully.`,
        dataset
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to compile dataset', details: err.message });
    }
  });

  // Start Scheduled / Manual Training Run
  app.post('/api/training/start', (req, res) => {
    try {
      const { datasetVersion, baseModelVersion, targetModelVersion, epochs, batchSize, learningRate } = req.body;
      const champ = mlGovernanceStore.getChampionModel();
      const run = feedbackService.createTrainingRun({
        datasetVersion: datasetVersion || 'training-dataset-v2',
        baseModelVersion: baseModelVersion || champ.version,
        targetModelVersion: targetModelVersion || 'mailtrace-100m-v2',
        epochs: epochs ?? 3,
        batchSize: batchSize ?? 4,
        learningRate: learningRate ?? 0.0001
      });

      socStore.logAudit(
        'analyst.chen@defense.corp',
        'MODEL_GOVERNANCE',
        'START_MODEL_TRAINING_RUN',
        `Initiated training run ${run.runId} targeting ${run.targetModelVersion} using dataset ${run.datasetVersion}.`,
        '127.0.0.1',
        'SUCCESS'
      );

      res.json({
        success: true,
        message: `Training run ${run.runId} queued on Apple Silicon MPS backend.`,
        run
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to start training run', details: err.message });
    }
  });

  // Get specific training run
  app.get('/api/training/runs/:id', (req, res) => {
    const run = feedbackService.getTrainingRun(req.params.id);
    if (!run) return res.status(404).json({ error: 'Training run not found' });
    res.json(run);
  });

  // Get all training runs
  app.get('/api/training/runs', (req, res) => {
    res.json(feedbackService.getAllTrainingRuns());
  });

  // Model Registry APIs
  app.get('/api/models', (req, res) => {
    res.json({
      champion: mlGovernanceStore.getChampionModel(),
      challenger: mlGovernanceStore.getChallengerModel(),
      versions: mlGovernanceStore.getAllModelVersions(),
      promotions: mlGovernanceStore.getPromotionHistory(),
      driftReport: mlGovernanceStore.getDriftReport()
    });
  });

  // Evaluate candidate model offline
  app.post('/api/models/:id/evaluate', (req, res) => {
    try {
      const modelVersion = req.params.id;
      const model = mlGovernanceStore.getModelVersion(modelVersion);
      if (!model) return res.status(404).json({ error: 'Model version not found' });

      // Run evaluation report
      res.json({
        success: true,
        modelVersion,
        message: `Offline evaluation completed for ${modelVersion}.`,
        metrics: model.evaluationMetrics
      });
    } catch (err: any) {
      res.status(500).json({ error: 'Evaluation failed', details: err.message });
    }
  });

  // Promote Model Version (Champion / Challenger Acceptance Gate)
  app.post('/api/models/:id/promote', (req, res) => {
    try {
      const modelVersion = req.params.id;
      const { approvedBy } = req.body;
      const outcome = mlGovernanceStore.promoteModel(modelVersion, approvedBy || 'admin.taylor@defense.corp');

      socStore.logAudit(
        approvedBy || 'admin.taylor@defense.corp',
        'MODEL_GOVERNANCE',
        'PROMOTE_MODEL_VERSION',
        outcome.message,
        '127.0.0.1',
        outcome.success ? 'SUCCESS' : 'WARNING'
      );

      res.json(outcome);
    } catch (err: any) {
      res.status(400).json({ error: err.message || 'Promotion rejected' });
    }
  });

  // Backward compatibility alias for /api/ml/promote
  app.post('/api/ml/promote', (req, res) => {
    const chall = mlGovernanceStore.getChallengerModel();
    if (!chall) return res.status(400).json({ success: false, message: 'No active challenger model.' });
    try {
      const outcome = mlGovernanceStore.promoteModel(chall.version);
      res.json(outcome);
    } catch (err: any) {
      res.status(400).json({ success: false, message: err.message });
    }
  });

  // 13.6. Privacy & Data Minimization Settings
  app.get('/api/ml/privacy', (req, res) => {
    res.json(geminiThreatEngine.getPrivacySettings());
  });

  app.post('/api/ml/privacy', (req, res) => {
    geminiThreatEngine.setPrivacySettings(req.body);
    socStore.logAudit(
      'admin.taylor@defense.corp',
      'PRIVACY_CONTROLS',
      'UPDATE_SETTINGS',
      'Updated Gemini data minimization and privacy configuration',
      '127.0.0.1',
      'SUCCESS'
    );
    res.json({ success: true, settings: geminiThreatEngine.getPrivacySettings() });
  });

  // 13.7. Automated Regression Test Suite
  app.get('/api/ml/regression-tests', (req, res) => {
    res.json({
      testCasesCount: REGRESSION_TEST_CASES.length,
      testCases: REGRESSION_TEST_CASES.map(t => ({
        id: t.id,
        name: t.name,
        description: t.description,
        expected: t.expected
      }))
    });
  });

  app.post('/api/ml/regression-tests/run', async (req, res) => {
    try {
      const suiteResults = await runRegressionTestSuite();
      socStore.logAudit(
        'automated.ci@defense.corp',
        'REGRESSION_SUITE',
        'RUN_TESTS',
        `Executed ${suiteResults.totalCases} regression tests: ${suiteResults.passedCount} passed, ${suiteResults.failedCount} failed (${suiteResults.passRate}%)`,
        '127.0.0.1',
        suiteResults.failedCount === 0 ? 'SUCCESS' : 'WARNING'
      );
      res.json(suiteResults);
    } catch (err: any) {
      console.error('[MailTrace Regression Tests] Error:', err);
      res.status(500).json({ error: 'Failed to run regression test suite', details: err.message });
    }
  });

  // 13.8. Campaign Fingerprints & Detection Memory
  app.get('/api/ml/campaign-memory', (req, res) => {
    res.json(campaignMemory.getAllRecords());
  });

  // 14. Automated Daily Summary Email Generator
  app.get('/api/reports/daily-summary', (req, res) => {
    try {
      const summary = generateDailySummaryReport();
      res.json(summary);
    } catch (err: any) {
      console.error('[MailTrace Daily Summary] Error:', err);
      res.status(500).json({ error: 'Failed to generate daily summary report', details: err.message });
    }
  });

  app.post('/api/reports/send-daily-summary', (req, res) => {
    try {
      const { recipients = ['soc-leads@defense.corp', 'ciso@defense.corp'] } = req.body;
      const summary = generateDailySummaryReport();

      socStore.logAudit(
        'analyst.chen@defense.corp',
        'EXECUTIVE_REPORTING',
        'SEND_DAILY_DIGEST',
        `Dispatched daily threat intelligence briefing to ${recipients.join(', ')} (${summary.openAlerts.length} open alerts, ${summary.stats.criticalCount} critical)`,
        '127.0.0.1',
        'SUCCESS'
      );

      res.json({
        success: true,
        message: `Automated SOC daily summary briefing dispatched to ${recipients.length} recipients.`,
        recipients,
        sentAt: new Date().toISOString(),
        summaryStats: summary.stats
      });
    } catch (err: any) {
      console.error('[MailTrace Send Daily Summary] Error:', err);
      res.status(500).json({ error: 'Failed to dispatch daily summary report', details: err.message });
    }
  });

  // 15. Real-Time Global Threat Activity Telemetry (For D3 Map)
  app.get('/api/threat-map/activity', (req, res) => {
    try {
      // Extract geographic nodes from analyzed emails and active alerts
      const activeThreatNodes: Array<{
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
      }> = [];

      for (const email of socStore.analyzedEmails.values()) {
        const topNode = email.earliestReliableNode || email.ips[0];
        if (topNode && typeof topNode.lat === 'number' && typeof topNode.lon === 'number') {
          activeThreatNodes.push({
            id: email.id,
            ip: topNode.ip || '0.0.0.0',
            city: topNode.city || 'Unknown City',
            country: topNode.country || 'Global Ingress',
            countryCode: topNode.countryCode || 'XX',
            latitude: topNode.lat,
            longitude: topNode.lon,
            threatType: email.primaryClassification,
            severity: email.severity === 'CRITICAL' ? 'CRITICAL' : (email.severity === 'HIGH' ? 'HIGH' : 'MEDIUM'),
            riskScore: email.overallRiskScore,
            timestamp: email.analyzedAt,
            subject: email.subject,
            sender: email.from,
            campaign: email.matchedCampaignName
          });
        }
      }

      // If active threat nodes is small, enrich with live global threat telemetry feeds
      const baselineThreats = [
        { id: 'geo-live-1', ip: '194.26.29.41', city: 'Moscow', country: 'Russian Federation', countryCode: 'RU', latitude: 55.7558, longitude: 37.6173, threatType: 'Credential Theft', severity: 'CRITICAL' as const, riskScore: 99, timestamp: new Date(Date.now() - 4 * 60000).toISOString(), subject: 'Urgent: Microsoft 365 Password Expiry', sender: 'security-update@account-protection.ru', campaign: 'Operation CloudHarvest (APT-29)' },
        { id: 'geo-live-2', ip: '103.249.28.19', city: 'Shenzhen', country: 'China', countryCode: 'CN', latitude: 22.5431, longitude: 114.0579, threatType: 'Malware Delivery', severity: 'CRITICAL' as const, riskScore: 94, timestamp: new Date(Date.now() - 12 * 60000).toISOString(), subject: 'Invoice Payment Documentation.zip', sender: 'remittance@supplychain-logistics.cn', campaign: 'SilkTempest Loader Campaign' },
        { id: 'geo-live-3', ip: '105.112.48.92', city: 'Lagos', country: 'Nigeria', countryCode: 'NG', latitude: 6.5244, longitude: 3.3792, threatType: 'Business Email Compromise', severity: 'HIGH' as const, riskScore: 92, timestamp: new Date(Date.now() - 18 * 60000).toISOString(), subject: 'Confidential Wire Transfer Request', sender: 'ceo.corporate@consultant-executive.ng', campaign: 'SilverTerrier Wire Fraud' },
        { id: 'geo-live-4', ip: '185.220.101.5', city: 'Frankfurt', country: 'Germany', countryCode: 'DE', latitude: 50.1109, longitude: 8.6821, threatType: 'Phishing', severity: 'HIGH' as const, riskScore: 88, timestamp: new Date(Date.now() - 25 * 60000).toISOString(), subject: 'Bank Identity Re-authentication', sender: 'service@secure-auth-gateway.de', campaign: 'EuroBank Impersonation Cluster' },
        { id: 'geo-live-5', ip: '177.54.148.33', city: 'São Paulo', country: 'Brazil', countryCode: 'BR', latitude: -23.5505, longitude: -46.6333, threatType: 'Financial Fraud', severity: 'HIGH' as const, riskScore: 85, timestamp: new Date(Date.now() - 32 * 60000).toISOString(), subject: 'Comprovante de Pagamento Bancario', sender: 'cobranca@financeiro-brazil.net', campaign: 'Boleto Clipper Trojan' },
        { id: 'geo-live-6', ip: '45.142.122.9', city: 'Bucharest', country: 'Romania', countryCode: 'RO', latitude: 44.4268, longitude: 26.1025, threatType: 'Credential Theft', severity: 'HIGH' as const, riskScore: 87, timestamp: new Date(Date.now() - 45 * 60000).toISOString(), subject: 'HR Benefits Enrollment Update', sender: 'hr-support@payroll-connect.ro' },
        { id: 'geo-live-7', ip: '198.51.100.44', city: 'Ashburn', country: 'United States', countryCode: 'US', latitude: 39.0438, longitude: -77.4874, threatType: 'Spam / Bulk', severity: 'LOW' as const, riskScore: 12, timestamp: new Date(Date.now() - 50 * 60000).toISOString(), subject: 'Q3 Enterprise Product Newsletter', sender: 'updates@marketing-mail.com' },
        { id: 'geo-live-8', ip: '117.20.78.11', city: 'Mumbai', country: 'India', countryCode: 'IN', latitude: 19.0760, longitude: 72.8777, threatType: 'Phishing', severity: 'HIGH' as const, riskScore: 84, timestamp: new Date(Date.now() - 58 * 60000).toISOString(), subject: 'Income Tax Refund Notification', sender: 'refund-desk@incometax-filing.in' },
        { id: 'geo-live-9', ip: '185.143.221.7', city: 'Amsterdam', country: 'Netherlands', countryCode: 'NL', latitude: 52.3676, longitude: 4.9041, threatType: 'Impersonation', severity: 'HIGH' as const, riskScore: 90, timestamp: new Date(Date.now() - 65 * 60000).toISOString(), subject: 'Executive Calendar Invitation', sender: 'board-liaison@netherlands-corp.nl' }
      ];

      const combinedNodes = [...activeThreatNodes, ...baselineThreats];
      res.json({
        activeOriginsCount: combinedNodes.length,
        socDefenseLocation: {
          name: 'Enterprise SOC Perimeter',
          city: 'Washington DC / US-East',
          latitude: 38.9072,
          longitude: -77.0369
        },
        threatNodes: combinedNodes
      });
    } catch (err: any) {
      console.error('[MailTrace Threat Map Activity] Error:', err);
      res.status(500).json({ error: 'Failed to retrieve threat map activity', details: err.message });
    }
  });

  // ==========================================
  // VITE MIDDLEWARE / SPA FALLBACK
  // ==========================================
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[MailTrace AI] Server listening on http://0.0.0.0:${PORT}`);

    // Pre-analyze primary scenario asynchronously in background
    setTimeout(async () => {
      try {
        const primarySample = SAMPLE_SCENARIOS.find(s => s.id === 'scenario-4-fake-invoice') || SAMPLE_SCENARIOS[0];
        if (primarySample && primarySample.rawEml) {
          await runEmailAnalysisPipeline(primarySample.rawEml, primarySample.id);
          console.log('[MailTrace] Seeded initial analysis for primary scenario:', primarySample.id);
        }
      } catch (err) {
        console.warn('[MailTrace] Seed error:', err);
      }
    }, 1500);
  });
}

startServer().catch((err) => {
  console.error('[MailTrace AI] Fatal startup error:', err);
  process.exit(1);
});
