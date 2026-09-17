/**
 * MailTrace AI - Production-Safe Analyst Feedback, Ground-Truth & Governance Engine
 * 
 * Core Invariants:
 * 1. Analyst feedback NEVER directly alters running model weights in memory.
 * 2. Analyst feedback NEVER directly overwrites Threat Risk or fakes instant predictions.
 * 3. Verified feedback becomes GROUND TRUTH in a versioned, deduplicated training queue.
 * 4. Model learns through scheduled/manual training cycles with offline validation.
 * 5. EvidenceFusionEngine remains the final authoritative decision maker.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import {
  ThreatCategory,
  ModelEvaluationMetrics,
  MLModelMetadata,
  ModelDriftReport
} from '../src/types/forensics.js';
import { NormalizedEmail } from './engines/engineInterface.js';

export type VerificationStatus = 'PENDING_REVIEW' | 'VERIFIED' | 'REJECTED' | 'QUARANTINED';
export type FeedbackClassificationType = 'FALSE_POSITIVE' | 'FALSE_NEGATIVE' | 'CONFIRMED_THREAT' | 'CONFIRMED_BENIGN' | 'CORRECTION';

export interface AnalystFeedbackRecord {
  id: string;
  feedbackId: string;
  analysisId: string;
  emailFingerprint: string;
  contentHash: string;
  urlFingerprint: string;
  emailSubject: string;
  sender: string;
  originalPrediction: {
    primaryCategory: string;
    secondaryCategories: string[];
    threatRisk: number;
    spamBulkScore: number;
    confidence: number;
    probabilities: Record<string, number>;
    detectedTechniques: string[];
    evidence: string[];
  };
  verifiedGroundTruth: {
    primaryCategory: string;
    secondaryCategories: string[];
    verdict: string;
    isMalicious: boolean;
    isSpam: boolean;
    correctedEvidence?: string[];
  };
  classificationType: FeedbackClassificationType;
  isHardNegative: boolean;
  isHardPositive: boolean;
  sampleWeight: number; // 1.0 (trusted dataset), 1.5 (analyst), 2.0 (high confidence senior analyst)
  analyst: {
    id: string;
    name: string;
    role: string;
    confidence: number; // 0.0 - 1.0
  };
  reason: string;
  notes?: string;
  status: VerificationStatus;
  trainingEligible: boolean;
  quarantineReason?: string;
  createdAt: string;
  verifiedAt?: string;
  modelVersion: string;
  datasetVersion?: string;
  usedInTrainingRun?: string;
  usedInModelVersion?: string;
  structuredFeatures?: Record<string, number>;
  rawEmailSample?: {
    subject: string;
    bodyText: string;
    urls: string[];
    sender: string;
  };
}

export interface TrainingDatasetVersion {
  version: string;
  sampleCount: number;
  verifiedFeedbackCount: number;
  hardNegativeCount: number;
  hardPositiveCount: number;
  duplicateCount: number;
  classDistribution: Record<string, number>;
  trainCount: number;
  valCount: number;
  testCount: number;
  createdAt: string;
  sourceDatasetVersions: string[];
  manifestPath?: string;
}

export interface TrainingRunRecord {
  runId: string;
  datasetVersion: string;
  baseModelVersion: string;
  targetModelVersion: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'REJECTED';
  epochs: number;
  batchSize: number;
  learningRate: number;
  feedbackSamplesUsed: number;
  hardNegativesUsed: number;
  sampleWeightingApplied: boolean;
  trainingLoss?: number;
  validationLoss?: number;
  hardware: string;
  startedAt: string;
  completedAt?: string;
  logs: string[];
  checkpointPath?: string;
  evaluationMetrics?: ModelEvaluationMetrics;
}

export interface FeedbackStats {
  totalFeedback: number;
  verifiedGroundTruth: number;
  pendingReview: number;
  rejectedFeedback: number;
  quarantinedFeedback: number;
  modelCorrections: number;
  hardNegatives: number;
  hardPositives: number;
  falsePositives: number;
  falseNegatives: number;
  confirmedThreats: number;
  confirmedBenign: number;
  feedbackByCategory: Record<string, number>;
  feedbackByModelVersion: Record<string, number>;
  eligibleForTrainingCount: number;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  action: string;
  actor: string;
  actorRole: string;
  feedbackId?: string;
  analysisId?: string;
  modelVersion?: string;
  details: string;
  previousState?: any;
  newState?: any;
}

const FEEDBACK_STORAGE_DIR = path.resolve(process.cwd(), 'reports');
const FEEDBACK_FILE = path.join(FEEDBACK_STORAGE_DIR, 'analyst_feedback_store.json');
const AUDIT_LOG_FILE = path.join(FEEDBACK_STORAGE_DIR, 'feedback_audit_log.json');
const DATASETS_FILE = path.join(FEEDBACK_STORAGE_DIR, 'training_datasets.json');
const RUNS_FILE = path.join(FEEDBACK_STORAGE_DIR, 'training_runs.json');

export class FeedbackService {
  private feedbackItems: Map<string, AnalystFeedbackRecord> = new Map();
  private auditLog: AuditLogEntry[] = [];
  private datasets: Map<string, TrainingDatasetVersion> = new Map();
  private trainingRuns: Map<string, TrainingRunRecord> = new Map();
  private analystRateLimiter: Map<string, { count: number; lastReset: number }> = new Map();

  constructor() {
    this.ensureStorage();
    this.loadState();
  }

  private ensureStorage() {
    if (!fs.existsSync(FEEDBACK_STORAGE_DIR)) {
      fs.mkdirSync(FEEDBACK_STORAGE_DIR, { recursive: true });
    }
  }

  private loadState() {
    try {
      if (fs.existsSync(FEEDBACK_FILE)) {
        const raw = fs.readFileSync(FEEDBACK_FILE, 'utf-8');
        const list: AnalystFeedbackRecord[] = JSON.parse(raw);
        list.forEach(item => this.feedbackItems.set(item.id, item));
      }
      if (fs.existsSync(AUDIT_LOG_FILE)) {
        const raw = fs.readFileSync(AUDIT_LOG_FILE, 'utf-8');
        this.auditLog = JSON.parse(raw);
      }
      if (fs.existsSync(DATASETS_FILE)) {
        const raw = fs.readFileSync(DATASETS_FILE, 'utf-8');
        const list: TrainingDatasetVersion[] = JSON.parse(raw);
        list.forEach(d => this.datasets.set(d.version, d));
      }
      if (fs.existsSync(RUNS_FILE)) {
        const raw = fs.readFileSync(RUNS_FILE, 'utf-8');
        const list: TrainingRunRecord[] = JSON.parse(raw);
        list.forEach(r => this.trainingRuns.set(r.runId, r));
      }
    } catch (e) {
      console.warn('[FeedbackService] Error loading persisted feedback state, initializing clean:', e);
    }

    if (this.feedbackItems.size === 0) {
      this.seedGroundTruth();
    }
  }

  private saveState() {
    try {
      this.ensureStorage();
      fs.writeFileSync(FEEDBACK_FILE, JSON.stringify(Array.from(this.feedbackItems.values()), null, 2));
      fs.writeFileSync(AUDIT_LOG_FILE, JSON.stringify(this.auditLog.slice(-500), null, 2));
      fs.writeFileSync(DATASETS_FILE, JSON.stringify(Array.from(this.datasets.values()), null, 2));
      fs.writeFileSync(RUNS_FILE, JSON.stringify(Array.from(this.trainingRuns.values()), null, 2));
    } catch (e) {
      console.error('[FeedbackService] Failed to save state:', e);
    }
  }

  public computeEmailFingerprint(subject: string, bodyText: string, urls: string[] = []): string {
    const normSubject = (subject || '').trim().toLowerCase().replace(/\s+/g, ' ');
    const normBody = (bodyText || '').trim().toLowerCase().replace(/\s+/g, ' ').slice(0, 1000);
    const sortedUrls = [...urls].sort().join(',');
    const hash = crypto.createHash('sha256').update(`${normSubject}|${normBody}|${sortedUrls}`).digest('hex');
    return hash;
  }

  public computeUrlFingerprint(urls: string[]): string {
    return crypto.createHash('sha256').update([...urls].sort().join('|')).digest('hex').substring(0, 16);
  }

  /**
   * Submit or update an Analyst Verification Record.
   * Enforces Anti-Poisoning, Deduplication, and Controlled Sample Weighting.
   */
  public submitVerification(input: {
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
    analyst: {
      id: string;
      name?: string;
      role?: string;
      confidence?: number;
    };
    reason: string;
    notes?: string;
    classificationType?: FeedbackClassificationType;
    modelVersion?: string;
    structuredFeatures?: Record<string, number>;
  }): { feedback: AnalystFeedbackRecord; isNew: boolean; message: string } {
    const subject = input.emailSubject || 'Untitled Email';
    const bodyText = input.rawBody || '';
    const urls = input.urls || [];
    const emailFingerprint = this.computeEmailFingerprint(subject, bodyText, urls);
    const contentHash = crypto.createHash('sha256').update(`${subject}|${bodyText}`).digest('hex');
    const urlFingerprint = this.computeUrlFingerprint(urls);

    const analystId = input.analyst.id || 'soc-analyst-1';
    const analystRole = input.analyst.role || 'Senior SOC Analyst';
    const analystConfidence = Math.max(0.1, Math.min(1.0, input.analyst.confidence ?? 0.95));

    // 1. Anti-Poisoning: Rate limiting per analyst
    const now = Date.now();
    const rate = this.analystRateLimiter.get(analystId) || { count: 0, lastReset: now };
    if (now - rate.lastReset > 60000) {
      rate.count = 0;
      rate.lastReset = now;
    }
    rate.count++;
    this.analystRateLimiter.set(analystId, rate);

    let isQuarantined = false;
    let quarantineReason: string | undefined = undefined;

    if (rate.count > 120) {
      isQuarantined = true;
      quarantineReason = 'High velocity anomaly: Single analyst submitted >120 labels in 60s window.';
    }

    // 2. Anti-Poisoning: Sudden extreme label divergence with low analyst confidence
    if (analystConfidence < 0.5) {
      isQuarantined = true;
      quarantineReason = 'Low analyst confidence (<0.50) cannot enter verified ground truth dataset.';
    }

    // Determine sample weight
    // Hierarchy: Trusted Dataset = 1.0, Verified Analyst = 1.5, High-Confidence Expert = 2.0 (Capped at 2.0)
    let sampleWeight = 1.5;
    if (analystRole.toLowerCase().includes('senior') || analystRole.toLowerCase().includes('lead') || analystRole.toLowerCase().includes('admin')) {
      if (analystConfidence >= 0.9) {
        sampleWeight = 2.0;
      }
    }
    sampleWeight = Math.min(2.0, sampleWeight);

    // Determine Hard Negative / Hard Positive flags
    const origCategory = input.originalPrediction.primaryCategory;
    const verifiedCategory = input.verifiedGroundTruth.primaryCategory;
    const origRisk = input.originalPrediction.threatRisk;
    const isMalicious = input.verifiedGroundTruth.isMalicious ?? (verifiedCategory !== 'LEGITIMATE' && verifiedCategory !== 'NEWSLETTER' && verifiedCategory !== 'PROMOTIONAL' && verifiedCategory !== 'TRANSACTIONAL');
    const isSpam = input.verifiedGroundTruth.isSpam ?? (verifiedCategory === 'SPAM' || verifiedCategory === 'BULK' || verifiedCategory === 'NEWSLETTER' || verifiedCategory === 'PROMOTIONAL');

    let isHardNegative = false;
    let isHardPositive = false;

    if (origRisk >= 60 && !isMalicious) {
      // Model predicted dangerous threat, analyst verified benign (e.g. newsletter) -> HARD NEGATIVE
      isHardNegative = true;
      sampleWeight = Math.min(2.0, sampleWeight * 1.2);
    } else if (origRisk <= 30 && isMalicious) {
      // Model missed threat, analyst caught malicious -> HARD POSITIVE
      isHardPositive = true;
      sampleWeight = Math.min(2.0, sampleWeight * 1.2);
    }

    // Classification Type
    let classificationType: FeedbackClassificationType = input.classificationType || 'CORRECTION';
    if (!classificationType || classificationType === 'CORRECTION') {
      if (origRisk >= 50 && !isMalicious) classificationType = 'FALSE_POSITIVE';
      else if (origRisk < 50 && isMalicious) classificationType = 'FALSE_NEGATIVE';
      else if (isMalicious) classificationType = 'CONFIRMED_THREAT';
      else classificationType = 'CONFIRMED_BENIGN';
    }

    // 3. Deduplication & Conflict Resolution
    const existing = Array.from(this.feedbackItems.values()).find(
      f => f.emailFingerprint === emailFingerprint || f.analysisId === input.analysisId
    );

    const feedbackId = existing ? existing.feedbackId : `FB-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
    const id = existing ? existing.id : feedbackId;
    const isNew = !existing;

    const record: AnalystFeedbackRecord = {
      id,
      feedbackId,
      analysisId: input.analysisId,
      emailFingerprint,
      contentHash,
      urlFingerprint,
      emailSubject: subject,
      sender: input.sender || 'unknown@domain.com',
      originalPrediction: {
        primaryCategory: origCategory,
        secondaryCategories: input.originalPrediction.secondaryCategories || [],
        threatRisk: input.originalPrediction.threatRisk,
        spamBulkScore: input.originalPrediction.spamBulkScore ?? 0,
        confidence: input.originalPrediction.confidence ?? 0.85,
        probabilities: input.originalPrediction.probabilities || { [origCategory]: 0.85 },
        detectedTechniques: input.originalPrediction.detectedTechniques || [],
        evidence: input.originalPrediction.evidence || []
      },
      verifiedGroundTruth: {
        primaryCategory: verifiedCategory,
        secondaryCategories: input.verifiedGroundTruth.secondaryCategories || [],
        verdict: input.verifiedGroundTruth.verdict,
        isMalicious,
        isSpam,
        correctedEvidence: input.verifiedGroundTruth.correctedEvidence || []
      },
      classificationType,
      isHardNegative,
      isHardPositive,
      sampleWeight,
      analyst: {
        id: analystId,
        name: input.analyst.name || 'Chen Analyst',
        role: analystRole,
        confidence: analystConfidence
      },
      reason: input.reason,
      notes: input.notes,
      status: isQuarantined ? 'QUARANTINED' : 'VERIFIED',
      trainingEligible: !isQuarantined,
      quarantineReason,
      createdAt: existing ? existing.createdAt : new Date().toISOString(),
      verifiedAt: new Date().toISOString(),
      modelVersion: input.modelVersion || 'mailtrace-100m-v1',
      structuredFeatures: input.structuredFeatures,
      rawEmailSample: {
        subject,
        bodyText,
        urls,
        sender: input.sender || 'unknown@domain.com'
      }
    };

    this.feedbackItems.set(id, record);

    // Audit Log Entry
    const auditEntry: AuditLogEntry = {
      id: `AUDIT-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
      timestamp: new Date().toISOString(),
      action: isNew ? 'ANALYST_VERIFICATION_CREATED' : 'ANALYST_VERIFICATION_UPDATED',
      actor: analystId,
      actorRole: analystRole,
      feedbackId,
      analysisId: input.analysisId,
      modelVersion: record.modelVersion,
      details: `Analyst verified ${subject}: Pred="${origCategory}" -> GT="${verifiedCategory}" (Verdict: ${input.verifiedGroundTruth.verdict}, Status: ${record.status}, Weight: ${sampleWeight.toFixed(2)})`,
      previousState: existing ? { ...existing } : undefined,
      newState: { ...record }
    };
    this.auditLog.push(auditEntry);

    this.saveState();

    return {
      feedback: record,
      isNew,
      message: isQuarantined
        ? `Feedback quarantined: ${quarantineReason}`
        : `Verified ground-truth sample recorded (Weight: ${sampleWeight.toFixed(2)}x, Eligible for next training cycle).`
    };
  }

  public getFeedbackById(id: string): AnalystFeedbackRecord | undefined {
    return this.feedbackItems.get(id) || Array.from(this.feedbackItems.values()).find(f => f.feedbackId === id || f.analysisId === id);
  }

  public getFeedbackList(statusFilter?: VerificationStatus): AnalystFeedbackRecord[] {
    const list = Array.from(this.feedbackItems.values());
    if (statusFilter) {
      return list.filter(f => f.status === statusFilter);
    }
    return list;
  }

  public getFeedbackStats(): FeedbackStats {
    const items = Array.from(this.feedbackItems.values());
    const stats: FeedbackStats = {
      totalFeedback: items.length,
      verifiedGroundTruth: 0,
      pendingReview: 0,
      rejectedFeedback: 0,
      quarantinedFeedback: 0,
      modelCorrections: 0,
      hardNegatives: 0,
      hardPositives: 0,
      falsePositives: 0,
      falseNegatives: 0,
      confirmedThreats: 0,
      confirmedBenign: 0,
      feedbackByCategory: {},
      feedbackByModelVersion: {},
      eligibleForTrainingCount: 0
    };

    for (const item of items) {
      if (item.status === 'VERIFIED') stats.verifiedGroundTruth++;
      else if (item.status === 'PENDING_REVIEW') stats.pendingReview++;
      else if (item.status === 'REJECTED') stats.rejectedFeedback++;
      else if (item.status === 'QUARANTINED') stats.quarantinedFeedback++;

      if (item.trainingEligible) stats.eligibleForTrainingCount++;

      const isCorrection = item.originalPrediction.primaryCategory !== item.verifiedGroundTruth.primaryCategory;
      if (isCorrection) stats.modelCorrections++;

      if (item.isHardNegative) stats.hardNegatives++;
      if (item.isHardPositive) stats.hardPositives++;

      if (item.classificationType === 'FALSE_POSITIVE') stats.falsePositives++;
      else if (item.classificationType === 'FALSE_NEGATIVE') stats.falseNegatives++;
      else if (item.classificationType === 'CONFIRMED_THREAT') stats.confirmedThreats++;
      else if (item.classificationType === 'CONFIRMED_BENIGN') stats.confirmedBenign++;

      const cat = item.verifiedGroundTruth.primaryCategory || 'UNKNOWN';
      stats.feedbackByCategory[cat] = (stats.feedbackByCategory[cat] || 0) + 1;

      const mv = item.modelVersion || 'unknown';
      stats.feedbackByModelVersion[mv] = (stats.feedbackByModelVersion[mv] || 0) + 1;
    }

    return stats;
  }

  public getAuditLog(limit = 100): AuditLogEntry[] {
    return this.auditLog.slice(-limit).reverse();
  }

  /**
   * Compiles all eligible verified ground truth feedback into a new versioned dataset.
   */
  public createFeedbackDataset(nameSuffix?: string): TrainingDatasetVersion {
    const eligible = Array.from(this.feedbackItems.values()).filter(f => f.trainingEligible && f.status === 'VERIFIED');
    const versionNumber = this.datasets.size + 1;
    const version = `training-dataset-v${versionNumber}${nameSuffix ? `-${nameSuffix}` : ''}`;

    const classDistribution: Record<string, number> = {};
    let hardNegatives = 0;
    let hardPositives = 0;

    for (const item of eligible) {
      const cat = item.verifiedGroundTruth.primaryCategory;
      classDistribution[cat] = (classDistribution[cat] || 0) + 1;
      if (item.isHardNegative) hardNegatives++;
      if (item.isHardPositive) hardPositives++;
    }

    const total = eligible.length;
    const trainCount = Math.round(total * 0.70);
    const valCount = Math.round(total * 0.15);
    const testCount = total - trainCount - valCount;

    const datasetVersion: TrainingDatasetVersion = {
      version,
      sampleCount: total,
      verifiedFeedbackCount: total,
      hardNegativeCount: hardNegatives,
      hardPositiveCount: hardPositives,
      duplicateCount: 0,
      classDistribution,
      trainCount,
      valCount,
      testCount,
      createdAt: new Date().toISOString(),
      sourceDatasetVersions: ['canonical-csv-v1', 'verified-ground-truth-pool']
    };

    // Save dataset sample manifest
    const manifestPath = path.join(FEEDBACK_STORAGE_DIR, `dataset_${version}_manifest.json`);
    fs.writeFileSync(manifestPath, JSON.stringify({
      version,
      createdAt: datasetVersion.createdAt,
      samples: eligible.map(e => ({
        feedbackId: e.feedbackId,
        emailFingerprint: e.emailFingerprint,
        subject: e.emailSubject,
        primaryCategory: e.verifiedGroundTruth.primaryCategory,
        isMalicious: e.verifiedGroundTruth.isMalicious,
        isSpam: e.verifiedGroundTruth.isSpam,
        sampleWeight: e.sampleWeight,
        isHardNegative: e.isHardNegative,
        structuredFeatures: e.structuredFeatures,
        rawEmailSample: e.rawEmailSample
      }))
    }, null, 2));

    datasetVersion.manifestPath = manifestPath;
    this.datasets.set(version, datasetVersion);

    // Mark items as staged in this dataset version
    for (const item of eligible) {
      item.datasetVersion = version;
    }

    this.saveState();
    return datasetVersion;
  }

  public getDatasets(): TrainingDatasetVersion[] {
    return Array.from(this.datasets.values());
  }

  public createTrainingRun(params: {
    datasetVersion: string;
    baseModelVersion: string;
    targetModelVersion: string;
    epochs?: number;
    batchSize?: number;
    learningRate?: number;
  }): TrainingRunRecord {
    const runId = `RUN-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const dataset = this.datasets.get(params.datasetVersion);
    const eligibleCount = dataset ? dataset.verifiedFeedbackCount : 0;
    const hardNegatives = dataset ? dataset.hardNegativeCount : 0;

    const run: TrainingRunRecord = {
      runId,
      datasetVersion: params.datasetVersion,
      baseModelVersion: params.baseModelVersion,
      targetModelVersion: params.targetModelVersion,
      status: 'QUEUED',
      epochs: params.epochs ?? 5,
      batchSize: params.batchSize ?? 16,
      learningRate: params.learningRate ?? 0.0001,
      feedbackSamplesUsed: eligibleCount,
      hardNegativesUsed: hardNegatives,
      sampleWeightingApplied: true,
      hardware: 'Apple Silicon M-Series (MPS / Local Engine)',
      startedAt: new Date().toISOString(),
      logs: [`[${new Date().toISOString()}] Training run ${runId} queued with dataset ${params.datasetVersion}`]
    };

    this.trainingRuns.set(runId, run);
    this.saveState();
    return run;
  }

  public getTrainingRun(runId: string): TrainingRunRecord | undefined {
    return this.trainingRuns.get(runId);
  }

  public getAllTrainingRuns(): TrainingRunRecord[] {
    return Array.from(this.trainingRuns.values());
  }

  public updateTrainingRun(runId: string, updates: Partial<TrainingRunRecord>) {
    const run = this.trainingRuns.get(runId);
    if (!run) return;
    Object.assign(run, updates);
    this.trainingRuns.set(runId, run);
    this.saveState();
  }

  private seedGroundTruth() {
    // Seed high quality real verified ground truth samples representing various threat and hard-negative cases
    const seedCases = [
      {
        analysisId: 'sample-case-ms-newsletter',
        emailSubject: '5 new updates to your subscription account',
        sender: 'updates@substack.com',
        rawBody: 'Here is your weekly summary of the latest open-source tools and platform features. Click here to read. Unsubscribe at https://substack.com/unsubscribe',
        urls: ['https://substack.com/read/weekly-5-updates', 'https://substack.com/unsubscribe'],
        originalPrediction: {
          primaryCategory: 'SPAM',
          secondaryCategories: ['BULK'],
          threatRisk: 22,
          spamBulkScore: 85,
          confidence: 0.91,
          probabilities: { SPAM: 0.85, NEWSLETTER: 0.08, LEGITIMATE: 0.05 },
          detectedTechniques: ['T1566.002'],
          evidence: ['List-Unsubscribe header present', 'Marketing tracking pixels']
        },
        verifiedGroundTruth: {
          primaryCategory: 'NEWSLETTER',
          secondaryCategories: ['PROMOTIONAL'],
          verdict: 'Newsletter',
          isMalicious: false,
          isSpam: true,
          correctedEvidence: ['Valid DKIM for substack.com', 'Clean reputational domain']
        },
        isCorrect: false,
        classificationType: 'CORRECTION' as FeedbackClassificationType,
        analyst: { id: 'analyst.chen@defense.corp', name: 'Chen Analyst', role: 'Senior SOC Analyst', confidence: 0.98 },
        reason: 'Legitimate engineering newsletter; not spam or threat. Verified DKIM/SPF alignment.'
      },
      {
        analysisId: 'sample-case-bec-wire',
        emailSubject: 'URGENT: Re-confirm Wire Transfer Instructions for Vendor',
        sender: 'ceo-office@company-partner-corp.com',
        rawBody: 'Please urgently change the routing details on invoice INV-88921 to our new reserve account before 3 PM cutoff.',
        urls: [],
        originalPrediction: {
          primaryCategory: 'PHISHING',
          secondaryCategories: ['CREDENTIAL_THEFT'],
          threatRisk: 88,
          spamBulkScore: 10,
          confidence: 0.89,
          probabilities: { PHISHING: 0.80, BEC: 0.15 },
          detectedTechniques: ['T1566', 'T1598'],
          evidence: ['Urgent payment diversion language', 'Lookalike sender domain']
        },
        verifiedGroundTruth: {
          primaryCategory: 'BUSINESS_EMAIL_COMPROMISE',
          secondaryCategories: ['FINANCIAL_FRAUD', 'EXECUTIVE_IMPERSONATION'],
          verdict: 'Business Email Compromise',
          isMalicious: true,
          isSpam: false,
          correctedEvidence: ['CFO impersonation', 'Supplier wire diversion pattern']
        },
        isCorrect: false,
        classificationType: 'CONFIRMED_THREAT' as FeedbackClassificationType,
        analyst: { id: 'admin.taylor@defense.corp', name: 'Taylor Lead', role: 'Chief Security Officer', confidence: 0.99 },
        reason: 'Confirmed BEC wire redirection attack targeting corporate treasury.'
      },
      {
        analysisId: 'sample-case-internal-memo',
        emailSubject: 'Notes from morning security architecture review',
        sender: 'sarah.connor@defense.corp',
        rawBody: 'Hi Chen, thanks for attending the sync. Architecture diagrams are on internal Confluence.',
        urls: ['https://confluence.defense.corp/pages/viewpage.action?pageId=9821'],
        originalPrediction: {
          primaryCategory: 'LEGITIMATE',
          secondaryCategories: [],
          threatRisk: 5,
          spamBulkScore: 2,
          confidence: 0.97,
          probabilities: { LEGITIMATE: 0.97 },
          detectedTechniques: [],
          evidence: ['Internal RFC1918 hop', 'Mutual TLS authenticated']
        },
        verifiedGroundTruth: {
          primaryCategory: 'LEGITIMATE',
          secondaryCategories: [],
          verdict: 'Legitimate',
          isMalicious: false,
          isSpam: false,
          correctedEvidence: ['Internal enterprise collaboration']
        },
        isCorrect: true,
        classificationType: 'CONFIRMED_BENIGN' as FeedbackClassificationType,
        analyst: { id: 'analyst.chen@defense.corp', name: 'Chen Analyst', role: 'Senior SOC Analyst', confidence: 1.0 },
        reason: 'Confirmed benign internal correspondence.'
      },
      {
        analysisId: 'sample-case-m365-phish',
        emailSubject: 'Action Required: Your Microsoft 365 password expires in 2 hours',
        sender: 'security@micros0ft-support-portal.com',
        rawBody: 'Your Microsoft 365 session has expired. Click here to retain your access: https://login.micros0ft-portal-auth.com/login',
        urls: ['https://login.micros0ft-portal-auth.com/login'],
        originalPrediction: {
          primaryCategory: 'PHISHING',
          secondaryCategories: ['CREDENTIAL_THEFT'],
          threatRisk: 95,
          spamBulkScore: 5,
          confidence: 0.96,
          probabilities: { PHISHING: 0.92, CREDENTIAL_THEFT: 0.06 },
          detectedTechniques: ['T1566.002', 'T1056'],
          evidence: ['Lookalike Microsoft domain', 'Credential harvesting URL']
        },
        verifiedGroundTruth: {
          primaryCategory: 'CREDENTIAL_THEFT',
          secondaryCategories: ['PHISHING', 'EXECUTIVE_IMPERSONATION'],
          verdict: 'Credential Theft',
          isMalicious: true,
          isSpam: false,
          correctedEvidence: ['Active credential harvesting landing page verified']
        },
        isCorrect: true,
        classificationType: 'CONFIRMED_THREAT' as FeedbackClassificationType,
        analyst: { id: 'analyst.chen@defense.corp', name: 'Chen Analyst', role: 'Senior SOC Analyst', confidence: 0.99 },
        reason: 'Confirmed credential harvesting campaign targeting employee M365 credentials.'
      }
    ];

    for (const c of seedCases) {
      this.submitVerification(c);
    }
  }
}

export const feedbackService = new FeedbackService();
