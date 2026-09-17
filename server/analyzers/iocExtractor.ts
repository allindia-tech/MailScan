/**
 * MailTrace AI - IOC Extraction Engine
 */

import { IOC, ThreatSeverity } from '../../src/types/forensics.js';
import { IPIntelligence } from '../../src/types/forensics.js';
import { URLAnalysis } from '../../src/types/forensics.js';
import { AttachmentAnalysis } from '../../src/types/forensics.js';

export function extractIOCs(
  ips: IPIntelligence[],
  fromDomain: string,
  fromEmail: string,
  replyTo: string,
  messageId: string,
  urls: URLAnalysis[],
  attachments: AttachmentAnalysis[]
): IOC[] {
  const iocs: IOC[] = [];
  let idCounter = 1;
  const seen = new Set<string>();

  const addIoc = (type: IOC['type'], indicator: string, risk: ThreatSeverity, source: string, confidence: number) => {
    if (!indicator || seen.has(`${type}:${indicator}`)) return;
    seen.add(`${type}:${indicator}`);
    iocs.push({
      id: `ioc-${idCounter++}`,
      type,
      indicator,
      risk,
      source,
      confidence,
      addedToCase: false
    });
  };

  // Sender Domain & Email
  if (fromDomain) {
    const isSuspicious = fromDomain.includes('0') || fromDomain.includes('1') || fromDomain.includes('fake') || fromDomain.includes('top');
    addIoc('domain', fromDomain, isSuspicious ? 'HIGH' : 'LOW', 'Header: From', 95);
  }
  if (fromEmail) {
    addIoc('email', fromEmail, 'MEDIUM', 'Header: From Address', 95);
  }

  // Reply-To Email
  if (replyTo) {
    const replyMatch = replyTo.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
    if (replyMatch) {
      addIoc('email', replyMatch[0], 'HIGH', 'Header: Reply-To', 90);
      const replyDomain = replyMatch[0].split('@')[1];
      if (replyDomain && replyDomain !== fromDomain) {
        addIoc('domain', replyDomain, 'HIGH', 'Header: Reply-To Domain', 92);
      }
    }
  }

  // Message-ID
  if (messageId && messageId.includes('@')) {
    addIoc('message-id', messageId, 'LOW', 'Header: Message-ID', 80);
  }

  // IPs
  for (const ip of ips) {
    if (!ip.ip.startsWith('10.') && !ip.ip.startsWith('192.168.')) {
      addIoc('ip', ip.ip, ip.status === 'MALICIOUS' ? 'CRITICAL' : (ip.status === 'SUSPICIOUS' ? 'HIGH' : 'LOW'), `SMTP Relay (${ip.isp})`, 92);
    }
  }

  // URLs & extracted domains
  for (const u of urls) {
    addIoc('url', u.url, u.risk, `Email Body (${u.analysisNote})`, 90);
    if (u.domain && !seen.has(`domain:${u.domain}`)) {
      addIoc('domain', u.domain, u.risk, 'URL Destination Host', 88);
    }
  }

  // Attachment Hashes
  for (const att of attachments) {
    addIoc('hash', att.sha256, att.risk, `Attachment SHA-256 (${att.filename})`, 99);
    addIoc('hash', att.md5, att.risk, `Attachment MD5 (${att.filename})`, 99);
  }

  return iocs;
}
