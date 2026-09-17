/**
 * MailTrace AI - Header Anomaly & Spoofing Detection Engine
 */

import { HeaderAnomaly, ThreatSeverity } from '../../src/types/forensics.js';
import { ParsedEmailRaw } from './emailParser.js';

export function detectHeaderAnomalies(parsed: ParsedEmailRaw): {
  score: number;
  anomalies: HeaderAnomaly[];
} {
  const anomalies: HeaderAnomaly[] = [];
  let scorePenalty = 0;
  let idCounter = 1;

  // 1. From vs Reply-To mismatch
  if (parsed.replyTo) {
    const fromClean = parsed.fromDomain.toLowerCase();
    const replyMatch = parsed.replyTo.match(/[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    const replyDomain = replyMatch ? replyMatch[1].toLowerCase() : '';

    if (replyDomain && fromClean && replyDomain !== fromClean) {
      scorePenalty += 35;
      anomalies.push({
        id: `anom-${idCounter++}`,
        header: 'Reply-To vs From',
        value: `From: ${parsed.from} | Reply-To: ${parsed.replyTo}`,
        finding: 'Reply-To Domain Mismatch (Payment/Credential Diversion Vector)',
        severity: 'CRITICAL',
        explanation: `Replies will be routed to an entirely distinct domain (${replyDomain}) rather than the sender identity claimed in the From header (${fromClean}). High correlation with Business Email Compromise and credential redirection.`
      });
    }
  }

  // 2. Return-Path mismatch
  if (parsed.returnPath) {
    const returnMatch = parsed.returnPath.match(/[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    const returnDomain = returnMatch ? returnMatch[1].toLowerCase() : '';
    const fromClean = parsed.fromDomain.toLowerCase();
    const isDomainAligned = returnDomain === fromClean || 
                            returnDomain.endsWith('.' + fromClean) || 
                            fromClean.endsWith('.' + returnDomain);
    const isKnownEspBounce = returnDomain.includes('amazonses') || 
                             returnDomain.includes('sendgrid') || 
                             returnDomain.includes('mailgun') || 
                             returnDomain.includes('mcsv.net') || 
                             returnDomain.includes('mailchimp') ||
                             returnDomain.includes('sparkpost') ||
                             returnDomain.includes('braze') ||
                             returnDomain.includes('klaviyo');

    if (returnDomain && fromClean && !isDomainAligned && !isKnownEspBounce) {
      scorePenalty += 20;
      anomalies.push({
        id: `anom-${idCounter++}`,
        header: 'Return-Path',
        value: parsed.returnPath,
        finding: 'Envelope Sender / Return-Path Misalignment',
        severity: 'HIGH',
        explanation: `RFC 5321 Return-Path domain (${returnDomain}) does not match or align with RFC 5322 From header (${parsed.fromDomain}). Bounced delivery notices and authentication checks indicate cross-tenant transmission.`
      });
    }
  }

  // 3. Suspicious Message-ID
  if (!parsed.messageId) {
    scorePenalty += 15;
    anomalies.push({
      id: `anom-${idCounter++}`,
      header: 'Message-ID',
      value: '(Missing)',
      finding: 'Omitted RFC 5322 Message-ID Header',
      severity: 'MEDIUM',
      explanation: 'Legitimate enterprise MTAs generate unique Message-IDs per RFC 5322 Section 3.6.4. Omission frequently denotes rudimentary bulk-spam tools.'
    });
  } else if (!parsed.messageId.includes('@') || parsed.messageId.includes('fake') || parsed.messageId.includes('phish')) {
    scorePenalty += 25;
    anomalies.push({
      id: `anom-${idCounter++}`,
      header: 'Message-ID',
      value: parsed.messageId,
      finding: 'Non-Standard or Synthesized Message-ID Structure',
      severity: 'HIGH',
      explanation: 'Message-ID contains suspicious tokens or violates standard FQDN suffix formatting.'
    });
  }

  // 4. Scripted Mailer Client (PHPMailer, Python-urllib, etc.)
  if (parsed.xMailer) {
    const lowerMailer = parsed.xMailer.toLowerCase();
    if (lowerMailer.includes('phpmailer') || lowerMailer.includes('python') || lowerMailer.includes('curl') || lowerMailer.includes('mailer')) {
      scorePenalty += 20;
      anomalies.push({
        id: `anom-${idCounter++}`,
        header: 'X-Mailer',
        value: parsed.xMailer,
        finding: 'Scripted / Automation Mailer Engine Detected',
        severity: 'HIGH',
        explanation: `Sender utilizes ${parsed.xMailer} commonly embedded on compromised web servers or threat infrastructure to blast unsolicited mailings, rather than an interactive enterprise MUA (e.g. Outlook, Apple Mail).`
      });
    }
  }

  // 5. Received header chronological hops and forging (only evaluate if full headers with Received lines exist)
  if (parsed.receivedHeaders.length === 1 && parsed.rawHeaders.length > 500 && !['amazon.com', 'google.com', 'gmail.com'].includes(parsed.fromDomain)) {
    scorePenalty += 10;
    anomalies.push({
      id: `anom-${idCounter++}`,
      header: 'Received Chain',
      value: `${parsed.receivedHeaders.length} hop`,
      finding: 'Single Hop Transit Sequence',
      severity: 'LOW',
      explanation: 'Inbound message contains only one recorded relay hop; full perimeter routing history was not captured.'
    });
  }

  // 6. Suspicious Lookalike Homoglyph in From domain (specific to brand impersonation patterns)
  const isTargetedLookalike = (parsed.fromDomain.includes('paypa1') || 
                               parsed.fromDomain.includes('micros0ft') || 
                               parsed.fromDomain.includes('amaz0n') ||
                               parsed.fromDomain.includes('g00gle') ||
                               (parsed.fromDomain.includes('-security') && !parsed.fromDomain.includes('enterprise-defense')));
  if (isTargetedLookalike) {
    scorePenalty += 30;
    anomalies.push({
      id: `anom-${idCounter++}`,
      header: 'From Domain',
      value: parsed.fromDomain,
      finding: 'Typosquatting / Character Substitution in Sender Header',
      severity: 'CRITICAL',
      explanation: `Sender address contains deceptive homoglyphs or keywords intentionally designed to emulate brand trust.`
    });
  }

  // 7. Display Name Spoofing & Executive/IT Impersonation via Consumer Webmail
  const freemails = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'proton.me', 'mail.com'];
  const isFreemail = freemails.includes(parsed.fromDomain.toLowerCase());
  const fromDisplayName = (parsed.fromName || '').toLowerCase();
  const corporateRoleMatch = /(it\s+service|service\s+desk|it\s+support|it\s+operations|helpdesk|system\s+admin|executive|ceo|chief\s+executive|cfo|finance\s+director|board\s+of\s+directors)/i.test(fromDisplayName);
  
  if (isFreemail && corporateRoleMatch) {
    scorePenalty += 40;
    anomalies.push({
      id: `anom-${idCounter++}`,
      header: 'From',
      value: `"${parsed.fromName}" <${parsed.from}>`,
      finding: 'Display Name Spoofing / Role Impersonation via Consumer Webmail',
      severity: 'CRITICAL',
      explanation: `Sender claims corporate/executive identity ("${parsed.fromName}") while transmitting from consumer webmail provider (${parsed.fromDomain}). Strong indicator of Business Email Compromise or Credential Harvesting.`
    });
  }

  const finalAnomalyScore = Math.min(100, Math.max(0, scorePenalty));
  return {
    score: finalAnomalyScore,
    anomalies
  };
}
