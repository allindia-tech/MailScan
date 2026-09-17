/**
 * MailTrace AI - Engine A: Deterministic Email Forensics Engine (Section 3, 15, 16)
 * Authoritative source of truth for technical protocol facts.
 */

import { DetectionEngine, EngineContext, NormalizedEmail } from './engineInterface.js';
import { DetectionSignal, EngineResult, ThreatCategory } from '../../src/types/forensics.js';

export class ForensicEngine implements DetectionEngine {
  public readonly id = 'forensic-deterministic';
  public readonly name = 'Forensic Protocol Engine';
  public readonly version = '2.4.0-deterministic';
  public readonly description = 'Deterministic RFC 5322 header parser, SPF/DKIM/DMARC validator, relay graph tracer, and static artifact inspector.';

  public async analyze(email: NormalizedEmail, context?: EngineContext): Promise<EngineResult> {
    const startTime = Date.now();
    const signals: DetectionSignal[] = [];
    const limitations: string[] = [];

    // 1. Technical Authentication Analysis (SPF, DKIM, DMARC)
    const { authResults, fromDomain } = email;
    const spfPass = authResults.spf.status === 'PASS';
    const dkimPass = authResults.dkim.status === 'PASS';
    const dmarcPass = authResults.dmarc.status === 'PASS';
    const dmarcFail = authResults.dmarc.status === 'FAIL';

    if (dmarcPass) {
      signals.push({
        id: 'for-sig-dmarc-pass',
        category: 'authentication',
        severity: 'info',
        confidence: 99,
        source: 'forensic',
        evidence: `DMARC cryptographic validation PASS (policy: ${authResults.dmarc.policy}, alignment verified with ${fromDomain}).`,
        relatedIndicators: [fromDomain, authResults.dmarc.policy]
      });
    } else if (dmarcFail) {
      signals.push({
        id: 'for-sig-dmarc-fail',
        category: 'authentication',
        severity: 'critical',
        confidence: 98,
        source: 'forensic',
        evidence: `DMARC validation FAILED: Inbound message failed domain cryptographic authentication policy (${authResults.dmarc.details}).`,
        relatedIndicators: [fromDomain]
      });
    }

    if (spfPass && authResults.spf.alignment) {
      signals.push({
        id: 'for-sig-spf-pass',
        category: 'authentication',
        severity: 'info',
        confidence: 95,
        source: 'forensic',
        evidence: `SPF PASS with aligned envelope identity (${authResults.spf.domain}).`
      });
    } else if (authResults.spf.status === 'FAIL' || authResults.spf.status === 'SOFTFAIL') {
      signals.push({
        id: 'for-sig-spf-fail',
        category: 'authentication',
        severity: authResults.spf.status === 'FAIL' ? 'high' : 'medium',
        confidence: 92,
        source: 'forensic',
        evidence: `SPF returned ${authResults.spf.status} for originating host IP ${authResults.spf.clientIp}.`
      });
    }

    if (dkimPass && authResults.dkim.alignment) {
      signals.push({
        id: 'for-sig-dkim-pass',
        category: 'authentication',
        severity: 'info',
        confidence: 96,
        source: 'forensic',
        evidence: `DKIM cryptographic signature verified and aligned with ${authResults.dkim.domain} (selector: ${authResults.dkim.selector || 'default'}).`
      });
    }

    // 2. Identity Alignment (Reply-To vs From vs Return-Path)
    if (email.replyTo && email.from) {
      const replyToDomain = email.replyTo.split('@')[1]?.toLowerCase();
      if (replyToDomain && replyToDomain !== fromDomain.toLowerCase()) {
        const isLegitNewsletterESP = (
          fromDomain.includes('substack') ||
          fromDomain.includes('mailchimp') ||
          fromDomain.includes('hubspot') ||
          fromDomain.includes('sendgrid') ||
          replyToDomain.includes('substack') ||
          replyToDomain.includes('gmail.com') ||
          email.spamAnalysis?.classification === 'newsletter'
        );

        if (!isLegitNewsletterESP) {
          signals.push({
            id: 'for-sig-replyto-mismatch',
            category: 'sender-identity',
            severity: 'high',
            confidence: 94,
            source: 'forensic',
            evidence: `Reply-To domain mismatch: Header From is "${fromDomain}" but responses are routed to "${replyToDomain}".`,
            relatedIndicators: [email.replyTo, email.from]
          });
        }
      }
    }

    // 3. Domain Intelligence (Lookalike, Typosquatting, Age)
    if (email.domainIntel.lookalikePatterns.length > 0) {
      for (const p of email.domainIntel.lookalikePatterns) {
        signals.push({
          id: `for-sig-lookalike-${p.type}`,
          category: 'domain-threat',
          severity: 'critical',
          confidence: 96,
          source: 'forensic',
          evidence: `Typosquatting Lookalike: Domain "${email.fromDomain}" exhibits ${p.type} targeting brand "${p.targetBrand}" (${p.targetDomain}).`,
          relatedIndicators: [email.fromDomain, p.targetDomain]
        });
      }
    }

    if (email.domainIntel.isNewlyRegistered && email.domainIntel.domainAgeDays < 14) {
      signals.push({
        id: 'for-sig-new-domain',
        category: 'domain-threat',
        severity: email.domainIntel.domainAgeDays < 7 ? 'high' : 'medium',
        confidence: 90,
        source: 'forensic',
        evidence: `Newly registered domain: "${email.fromDomain}" was registered ${email.domainIntel.domainAgeDays} days ago via ${email.domainIntel.registrar}.`
      });
    }

    // 4. URL Extraction & Static Verification
    const maliciousUrls = email.urls.filter(u => u.status === 'MALICIOUS' || u.isIpUrl || u.isPunycode);
    const trackingUrls = email.urls.filter(u => u.urlType === 'MARKETING_TRACKING' || u.isTrackingPixel);

    if (maliciousUrls.length > 0) {
      for (const u of maliciousUrls) {
        signals.push({
          id: `for-sig-mal-url-${u.id}`,
          category: 'url-threat',
          severity: 'critical',
          confidence: 95,
          source: 'forensic',
          evidence: `Suspicious/Obfuscated URL detected: ${u.url} (${u.analysisNote || 'Direct IP / Lexical Anomaly'}).`,
          relatedIndicators: [u.url]
        });
      }
    }

    if (trackingUrls.length > 0) {
      signals.push({
        id: 'for-sig-tracking-urls',
        category: 'bulk-telemetry',
        severity: 'info',
        confidence: 92,
        source: 'forensic',
        evidence: `Observed ${trackingUrls.length} commercial click-tracking / analytics redirect URLs in message body.`
      });
    }

    // 5. Attachment Forensics
    const dangerousAttachments = email.attachments.filter(
      a => a.flags?.isMacroEnabled || a.flags?.isExecutable || a.flags?.isDoubleExtension || a.flags?.isMimeMismatch
    );
    if (dangerousAttachments.length > 0) {
      for (const a of dangerousAttachments) {
        signals.push({
          id: `for-sig-att-${a.id}`,
          category: 'attachment-threat',
          severity: 'critical',
          confidence: 96,
          source: 'forensic',
          evidence: `High-risk attachment: "${a.filename}" (${a.fileType}) flags executable/macro hazards (${a.detectionResult || a.fileType}).`,
          relatedIndicators: [a.filename, a.sha256]
        });
      }
    }

    // 6. Header Anomalies
    for (const anom of email.headerAnomalies) {
      if (anom.severity === 'CRITICAL' || anom.severity === 'HIGH') {
        signals.push({
          id: `for-sig-anom-${anom.id}`,
          category: 'header-routing',
          severity: anom.severity.toLowerCase() as any,
          confidence: 88,
          source: 'forensic',
          evidence: `Header anomaly in [${anom.header}]: ${anom.explanation}`
        });
      }
    }

    // 7. Calculate Forensic Probabilities
    let phishingProb = 0.05;
    let becProb = 0.02;
    let malwareProb = 0.01;
    let impersonationProb = 0.02;
    let spamBulkProb = 0.10;

    if (email.domainIntel.lookalikePatterns.length > 0 || dmarcFail || maliciousUrls.length > 0) {
      phishingProb = Math.max(0.85, email.domainIntel.lookalikePatterns.length > 0 ? 0.92 : 0.82);
    }
    if (dangerousAttachments.length > 0) {
      malwareProb = 0.94;
    }
    if (email.headerAnomalies.some(a => a.finding.includes('Display Name') || a.finding.includes('Spoofing'))) {
      impersonationProb = 0.85;
    }
    if (email.spamAnalysis && email.spamAnalysis.score > 50) {
      spamBulkProb = Number((email.spamAnalysis.score / 100).toFixed(2));
    }

    // Determine Forensic Classification
    let classification: ThreatCategory = 'Legitimate';
    if (malwareProb >= 0.80) {
      classification = 'Malware Delivery';
    } else if (phishingProb >= 0.80) {
      classification = email.domainIntel.lookalikePatterns.length > 0 ? 'Phishing' : (dmarcFail ? 'Domain Spoofing' : 'Phishing');
    } else if (impersonationProb >= 0.80) {
      classification = 'Executive Impersonation';
    } else if (email.spamAnalysis?.classification === 'newsletter' || (email.spamAnalysis?.breakdown?.newsletterStructureScore || 0) > 40) {
      classification = 'Newsletter';
    } else if (email.spamAnalysis && email.spamAnalysis.score >= 50) {
      classification = email.spamAnalysis.classification === 'promotional' ? 'Promotional' : 'Spam';
    } else if (dmarcPass && spfPass && dkimPass) {
      classification = 'Legitimate';
    }

    const confidence = dmarcPass || dmarcFail ? 96 : 85;

    return {
      engine: this.id,
      version: this.version,
      classification,
      probabilities: {
        phishing: Number(phishingProb.toFixed(2)),
        bec: Number(becProb.toFixed(2)),
        malware: Number(malwareProb.toFixed(2)),
        impersonation: Number(impersonationProb.toFixed(2)),
        spamBulk: Number(spamBulkProb.toFixed(2)),
        legitimate: Number((1 - Math.max(phishingProb, malwareProb, impersonationProb)).toFixed(2))
      },
      signals,
      confidence,
      limitations: limitations.length > 0 ? limitations : [
        'Deterministic protocol checks do not infer natural-language social engineering intent.'
      ],
      processingTimeMs: Date.now() - startTime,
      status: 'COMPLETED'
    };
  }
}

export const forensicEngine = new ForensicEngine();
