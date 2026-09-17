/**
 * MailTrace AI - In-Memory State & SOC Data Store
 */

import crypto from 'crypto';
import {
  AlertItem,
  AuditLogItem,
  CampaignItem,
  CaseItem,
  EmailAnalysisResult,
  EvidenceItem
} from '../src/types/forensics.js';

class SocDataStore {
  public analyzedEmails: Map<string, EmailAnalysisResult> = new Map();
  public cases: Map<string, CaseItem> = new Map();
  public evidence: Map<string, EvidenceItem> = new Map();
  public alerts: Map<string, AlertItem> = new Map();
  public campaigns: Map<string, CampaignItem> = new Map();
  public auditLogs: AuditLogItem[] = [];

  constructor() {
    this.seedInitialData();
  }

  private seedInitialData() {
    // Initialize SOC Engine runtime audit log - no dummy mock records
    this.logAudit('SYSTEM', 'PLATFORM', 'INITIALIZE', 'SOC Engine Booted & Ready for Live Ingestion', '127.0.0.1', 'SUCCESS');
  }

  public logAudit(actor: string, role: string, action: string, target: string, ipAddress: string, status: 'SUCCESS' | 'WARNING' | 'FAILURE') {
    this.auditLogs.unshift({
      id: `audit-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
      timestamp: new Date().toISOString(),
      actor,
      role,
      action,
      target,
      ipAddress,
      status
    });
    if (this.auditLogs.length > 500) {
      this.auditLogs.pop();
    }
  }
}

export const socStore = new SocDataStore();
