/**
 * MailTrace AI - Campaign Fingerprinting & Detection Memory Engine (Sections 22-24)
 */

import crypto from 'crypto';
import { NormalizedEmail } from './engineInterface.js';
import { DetectionSignal } from '../../src/types/forensics.js';

export interface CampaignMemoryRecord {
  fingerprint: string;
  firstObserved: string;
  lastObserved: string;
  occurrences: number;
  senderDomains: string[];
  ingressIps: string[];
  sampleSubjects: string[];
  verifiedLabel?: string;
  threatRiskAverage: number;
  associatedCampaignId?: string;
}

class CampaignMemoryStore {
  private records: Map<string, CampaignMemoryRecord> = new Map();

  /**
   * Generates a deterministic campaign fingerprint CMP-XXXXXX
   */
  public generateFingerprint(email: NormalizedEmail): string {
    // 1. Normalized subject (strip Re:, Fwd:, dynamic invoice numbers, brackets)
    const normSubject = email.subject
      .toLowerCase()
      .replace(/^(re|fwd|fw|aw):\s*/gi, '')
      .replace(/\b(inv|order|ref|ticket|case)[-#\s]*[0-9a-z]{4,}\b/gi, '{NUM}')
      .replace(/\s+/g, ' ')
      .trim();

    // 2. Sender domain
    const senderDomain = email.fromDomain.toLowerCase();

    // 3. Extracted URL domain patterns
    const urlDomains = Array.from(
      new Set(
        email.urls
          .map(u => {
            try {
              return new URL(u.url).hostname.toLowerCase();
            } catch {
              return u.url;
            }
          })
          .filter(Boolean)
      )
    ).sort().slice(0, 5).join('|');

    // 4. Attachment hash patterns
    const attachmentPattern = email.attachments
      .map(a => `${a.fileType}:${a.filename.split('.').pop() || ''}`)
      .sort()
      .join('|');

    // 5. Template & HTML structural characteristics
    const hasUnsubscribe = email.spamAnalysis?.hasUnsubscribe || false;
    const trackingPixelPresent = email.spamAnalysis?.hasTrackingPixel || false;
    const bodyCharBuckets = Math.floor((email.bodyText?.length || 0) / 250);

    const rawSignature = [
      normSubject,
      senderDomain,
      urlDomains,
      attachmentPattern,
      `unsub:${hasUnsubscribe}`,
      `pixel:${trackingPixelPresent}`,
      `len:${bodyCharBuckets}`
    ].join('::');

    const hash = crypto.createHash('sha256').update(rawSignature).digest('hex').toUpperCase();
    const shortToken = hash.substring(0, 6);
    return `CMP-${shortToken}`;
  }

  /**
   * Records an observed email in detection memory and returns historical correlation signals
   */
  public rememberAndCorrelate(email: NormalizedEmail, calculatedRisk: number): {
    fingerprint: string;
    isRecurrent: boolean;
    record: CampaignMemoryRecord;
    signals: DetectionSignal[];
  } {
    const fingerprint = this.generateFingerprint(email);
    const existing = this.records.get(fingerprint);
    const now = new Date().toISOString();
    const signals: DetectionSignal[] = [];

    let isRecurrent = false;
    let record: CampaignMemoryRecord;

    if (existing) {
      existing.occurrences += 1;
      existing.lastObserved = now;
      if (!existing.senderDomains.includes(email.fromDomain)) {
        existing.senderDomains.push(email.fromDomain);
      }
      if (email.earliestReliableNode?.ip && !existing.ingressIps.includes(email.earliestReliableNode.ip)) {
        existing.ingressIps.push(email.earliestReliableNode.ip);
      }
      if (existing.sampleSubjects.length < 3 && !existing.sampleSubjects.includes(email.subject)) {
        existing.sampleSubjects.push(email.subject);
      }
      existing.threatRiskAverage = Math.round((existing.threatRiskAverage * 0.7) + (calculatedRisk * 0.3));
      record = existing;
      isRecurrent = true;

      signals.push({
        id: `sig-mem-${Date.now()}`,
        category: 'campaign-memory',
        severity: existing.threatRiskAverage >= 60 ? 'high' : 'info',
        confidence: 88,
        source: 'historical',
        evidence: `Fingerprint [${fingerprint}] matches previously observed campaign cluster (${existing.occurrences} total instances seen across ${existing.senderDomains.length} domains).`,
        relatedIndicators: [fingerprint, ...existing.ingressIps]
      });
    } else {
      record = {
        fingerprint,
        firstObserved: now,
        lastObserved: now,
        occurrences: 1,
        senderDomains: [email.fromDomain],
        ingressIps: email.earliestReliableNode?.ip ? [email.earliestReliableNode.ip] : [],
        sampleSubjects: [email.subject],
        threatRiskAverage: calculatedRisk
      };
      this.records.set(fingerprint, record);

      signals.push({
        id: `sig-mem-${Date.now()}`,
        category: 'campaign-memory',
        severity: 'info',
        confidence: 90,
        source: 'historical',
        evidence: `Fingerprint [${fingerprint}] generated: new unique pattern recorded in detection memory.`,
        relatedIndicators: [fingerprint]
      });
    }

    return {
      fingerprint,
      isRecurrent,
      record,
      signals
    };
  }

  public getRecord(fingerprint: string): CampaignMemoryRecord | undefined {
    return this.records.get(fingerprint);
  }

  public getAllRecords(): CampaignMemoryRecord[] {
    return Array.from(this.records.values());
  }
}

export const campaignMemory = new CampaignMemoryStore();
