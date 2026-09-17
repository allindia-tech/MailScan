/**
 * MailTrace AI - Chrome Extension Backend Integration Service
 * Handles normalized email payload ingestion, synthetic RFC 5322 generation,
 * alert triggers, and case creation.
 */

import crypto from 'crypto';
import { runEmailAnalysisPipeline } from './emailAnalysisPipeline.js';
import { socStore } from './store.js';
import { EmailAnalysisResult } from '../src/types/forensics.js';

export interface ExtensionEmailPayload {
  provider?: 'gmail' | 'outlook' | 'webmail' | 'generic';
  sender?: string;
  senderName?: string;
  replyTo?: string;
  recipients?: string[];
  cc?: string[];
  subject?: string;
  timestamp?: string;
  body?: string;
  links?: Array<{
    href: string;
    text?: string;
  }> | string[];
  attachments?: Array<{
    name: string;
    type?: string;
    sizeBytes?: number;
  }>;
  threadMessageCount?: number;
  hasFullHeaders?: boolean;
  rawHeaders?: string;
}

/**
 * Reconstructs a clean, standard RFC 5322 MIME message from visible webmail DOM data
 * Preserves sender identity, recipients, headers, links, and attachment descriptors.
 */
export function buildSyntheticRfc5322FromExtension(data: ExtensionEmailPayload): string {
  const dateStr = data.timestamp || new Date().toUTCString();
  const providerTag = data.provider || 'webmail';
  const cleanRandom = crypto.randomBytes(4).toString('hex');
  const msgId = `<ext-${Date.now()}-${cleanRandom}@${providerTag}.client.mailtrace>`;

  const sender = data.sender ? data.sender.trim() : 'unknown-sender@external.net';
  const recipients = (data.recipients && data.recipients.length > 0)
    ? data.recipients.join(', ')
    : 'undisclosed-recipients:;';
  const subject = data.subject ? data.subject.trim() : '(No Subject)';

  // Infer sender domain
  let senderDomain = 'external.net';
  const domainMatch = sender.match(/@([a-zA-Z0-9.-]+)/);
  if (domainMatch) {
    senderDomain = domainMatch[1];
  }

  // Construct standard MIME headers
  const headerLines = [
    `From: ${sender}`,
    `To: ${recipients}`,
    data.cc && data.cc.length > 0 ? `Cc: ${data.cc.join(', ')}` : null,
    data.replyTo ? `Reply-To: ${data.replyTo.trim()}` : null,
    `Subject: ${subject}`,
    `Date: ${dateStr}`,
    `Message-ID: ${msgId}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset=UTF-8`,
    `X-Mailer: MailTrace AI Chrome Extension v1.0.0 (${providerTag.toUpperCase()} Provider)`,
    `X-MailTrace-Extracted-By: Chrome Extension Manifest V3`,
    `X-Header-Notice: Extracted from active browser DOM context. Full transport relay path unavailable.`
  ].filter(Boolean);

  let bodyContent = data.body || '';

  // Append extracted links section
  const linkStrings: string[] = (data.links || []).map(l => typeof l === 'string' ? l : l.href);
  if (linkStrings.length > 0) {
    const uniqueLinks = Array.from(new Set(linkStrings));
    bodyContent += `\n\n--- Extracted In-Message Hyperlinks (${uniqueLinks.length}) ---\n`;
    uniqueLinks.forEach((link, idx) => {
      bodyContent += `[Link ${idx + 1}]: ${link}\n`;
    });
  }

  // Append detected attachments section
  if (data.attachments && data.attachments.length > 0) {
    bodyContent += `\n\n--- Detected Attachments (${data.attachments.length}) ---\n`;
    data.attachments.forEach((att, idx) => {
      const sizeStr = att.sizeBytes ? `${Math.round(att.sizeBytes / 1024)} KB` : 'Unknown Size';
      bodyContent += `[Attachment ${idx + 1}]: ${att.name} (${att.type || 'file'}, ${sizeStr})\n`;
    });
  }

  return `${headerLines.join('\n')}\n\n${bodyContent}`;
}

/**
 * Analyzes incoming extension payload through the core engine
 */
export async function analyzeExtensionEmail(payload: {
  emailData?: ExtensionEmailPayload;
  rawEmail?: string;
  sourceContext?: string;
}): Promise<{
  analysis: EmailAnalysisResult;
  analysisId: string;
  deepLinkPath: string;
}> {
  let rawEml = payload.rawEmail;

  if (!rawEml && payload.emailData) {
    rawEml = buildSyntheticRfc5322FromExtension(payload.emailData);
  }

  if (!rawEml || typeof rawEml !== 'string' || !rawEml.trim()) {
    throw new Error('Valid email content (either rawEmail or emailData) is required for analysis.');
  }

  // Run full forensic pipeline
  const analysis = await runEmailAnalysisPipeline(rawEml, undefined);

  // If high or critical threat, verify alert is present in SOC store
  if (analysis.overallRiskScore >= 35) {
    const existingAlert = Array.from(socStore.alerts.values()).find(a => a.emailId === analysis.id);
    if (!existingAlert) {
      const alertId = `ALT-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
      socStore.alerts.set(alertId, {
        id: alertId,
        emailId: analysis.id,
        detectionTime: new Date().toISOString(),
        severity: analysis.severity,
        threatType: analysis.primaryClassification,
        riskScore: analysis.overallRiskScore,
        emailSubject: analysis.subject,
        sender: analysis.from,
        status: 'NEW',
        assignedAnalyst: 'Direct Extension Ingest'
      });
    }
  }

  // Log audit
  socStore.logAudit(
    'CHROME_EXTENSION',
    'EXTENSION_USER',
    'DIRECT_INBOX_ANALYSIS',
    `Analyzed email "${analysis.subject}" from ${analysis.from} (Score: ${analysis.overallRiskScore}/100, ${analysis.severity})`,
    '127.0.0.1',
    'SUCCESS'
  );

  return {
    analysis,
    analysisId: analysis.id,
    deepLinkPath: `/?investigation=${analysis.id}`
  };
}

/**
 * Handles reporting malicious email from the Chrome Extension
 */
export function reportMaliciousEmailFromExtension(data: {
  analysisId?: string;
  subject?: string;
  sender?: string;
  reason?: string;
  reporter?: string;
  emailData?: ExtensionEmailPayload;
}) {
  const reporter = data.reporter || 'Chrome Extension User';
  const reason = data.reason || 'User reported suspicious phishing / BEC attempt directly from inbox.';

  const caseId = `CASE-${new Date().getFullYear()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
  const title = `Direct Inbox Report: ${data.subject || 'Suspicious Email'}`;

  const newCase = {
    id: caseId,
    title,
    description: reason,
    priority: 'HIGH' as const,
    analyst: 'Tier-1 Triage',
    status: 'INVESTIGATING' as const,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    emailId: data.analysisId || `EXT-${Date.now()}`,
    emailSubject: data.subject || 'Suspicious Reported Message',
    sender: data.sender || 'unknown@sender.com',
    relatedIocs: (data.emailData?.links || []).map(l => typeof l === 'string' ? l : l.href),
    relatedDomains: data.emailData?.sender ? [data.emailData.sender] : [],
    relatedIps: [],
    evidenceCount: 1,
    notes: [
      {
        id: `note-${Date.now()}`,
        author: reporter,
        timestamp: new Date().toISOString(),
        text: `Reported via MailTrace AI Chrome Extension. Reason: ${reason}`
      }
    ],
    timeline: [
      {
        id: `t-${Date.now()}`,
        timestamp: new Date().toISOString(),
        action: 'INBOX_REPORT_RECEIVED',
        actor: reporter,
        details: `Incident escalated from browser extension by ${reporter}`
      }
    ]
  };

  socStore.cases.set(newCase.id, newCase);

  socStore.logAudit(
    'CHROME_EXTENSION',
    reporter,
    'REPORT_EMAIL',
    `Created investigation ${newCase.id} from user report for "${data.subject}"`,
    '127.0.0.1',
    'SUCCESS'
  );

  return {
    success: true,
    caseId: newCase.id,
    message: 'Email successfully reported to Security Operations Center.'
  };
}
