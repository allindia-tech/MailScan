/**
 * MailTrace AI - Engine C: Gemini AI Semantic & Social Engineering Analysis Engine (Sections 7-12)
 * Specializes in natural language understanding, psychological manipulation, deception, and semantic consistency.
 * CRITICAL DIRECTIVE: Gemini returns structured observations and probabilities; it NEVER directly computes the final score.
 */

import { GoogleGenAI } from '@google/genai';
import { DetectionEngine, EngineContext, NormalizedEmail } from './engineInterface.js';
import { DetectionSignal, EngineResult, ThreatCategory, PrivacySettings } from '../../src/types/forensics.js';

let geminiClient: GoogleGenAI | null = null;
function getGemini(): GoogleGenAI | null {
  if (!geminiClient && process.env.GEMINI_API_KEY) {
    try {
      geminiClient = new GoogleGenAI({
        apiKey: process.env.GEMINI_API_KEY,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build'
          }
        }
      });
    } catch {
      geminiClient = null;
    }
  }
  return geminiClient;
}

export class GeminiThreatEngine implements DetectionEngine {
  public readonly id = 'gemini-semantic';
  public readonly name = 'Gemini AI Semantic Engine';
  public readonly version = 'Gemini 2.5 Flash (Structured Reasoner)';
  public readonly description = 'Deep semantic understanding, intent classification, social engineering detection, and contextual deception analysis.';

  private privacySettings: PrivacySettings = {
    geminiAnalysisEnabled: true,
    sendEmailBody: 'Allowed',
    maskRecipient: true,
    maskPersonalIdentifiers: true,
    retainGeminiResponseDays: 30
  };

  public setPrivacySettings(settings: Partial<PrivacySettings>): void {
    this.privacySettings = { ...this.privacySettings, ...settings };
  }

  public getPrivacySettings(): PrivacySettings {
    return this.privacySettings;
  }

  /**
   * Evaluates whether Gemini should be called based on tiered efficiency criteria (Section 11)
   */
  public shouldInvoke(email: NormalizedEmail, mlConfidence: number, context?: EngineContext): boolean {
    if (context?.forceGemini) return true;
    if (!this.privacySettings.geminiAnalysisEnabled) return false;

    // Always invoke if API key is present for comprehensive hybrid analysis
    if (process.env.GEMINI_API_KEY) return true;

    // Trigger criteria
    const isAmbiguous = mlConfidence < 85;
    const isPotentialBEC = email.headerAnomalies.some(a => a.finding.includes('Display Name') || a.finding.includes('Spoofing'));
    const isLookalike = email.domainIntel.lookalikePatterns.length > 0;
    const hasUrgency = (email.bodyText || '').toLowerCase().includes('urgent') || (email.bodyText || '').toLowerCase().includes('immediately');

    return isAmbiguous || isPotentialBEC || isLookalike || hasUrgency;
  }

  public async analyze(email: NormalizedEmail, context?: EngineContext): Promise<EngineResult> {
    const startTime = Date.now();
    const ai = getGemini();

    // Prepare data-minimized input payload
    const safeTo = this.privacySettings.maskRecipient
      ? email.to.map(t => t.replace(/([^@]{2})[^@]+(@.*)/, '$1***$2'))
      : email.to;

    let safeBody = email.bodyText || '';
    if (this.privacySettings.sendEmailBody === 'Masked' || this.privacySettings.maskPersonalIdentifiers) {
      safeBody = safeBody
        .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[EMAIL_REDACTED]')
        .replace(/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g, '[PHONE_REDACTED]')
        .replace(/\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g, '[CARD_REDACTED]');
    }
    if (safeBody.length > 3500) {
      safeBody = safeBody.substring(0, 3500) + '\n[TRUNCATED FOR TOKEN EFFICIENCY]';
    }

    const payload = {
      subject: email.subject,
      from: email.from,
      fromDomain: email.fromDomain,
      to: safeTo,
      replyTo: email.replyTo,
      date: email.date,
      authentication: {
        spf: email.authResults.spf.status,
        dkim: email.authResults.dkim.status,
        dmarc: email.authResults.dmarc.status,
        dmarcPolicy: email.authResults.dmarc.policy
      },
      urls: email.urls.map(u => ({
        url: u.url,
        isTracking: u.urlType === 'MARKETING_TRACKING' || u.isTrackingPixel,
        hasCredentialPath: u.hasCredentialPath
      })),
      attachments: email.attachments.map(a => ({
        filename: a.filename,
        type: a.fileType,
        hasMacros: a.flags?.isMacroEnabled || false
      })),
      headerAnomalies: email.headerAnomalies.map(a => `${a.header}: ${a.finding}`),
      bodySample: safeBody
    };

    if (ai && !context?.skipExternalAI) {
      try {
        const prompt = `You are the Gemini Semantic Analysis Engine in MailTrace AI's Hybrid Threat Detection Platform.
Your task is to analyze the semantic context, social engineering lures, intent, and deceptive inconsistencies in the provided email.

CRITICAL DIRECTIVES:
1. Do NOT compute or return an overall numerical threat score like "Threat Score = 87". The Evidence Fusion Engine computes scores.
2. Distinguish legitimate promotional / newsletter / bulk mail from malicious attacks. If an email is an authenticated newsletter or product update with unsubscribe links, classify it as promotional or newsletter with low threat probabilities.
3. If an email attempts credential phishing, executive impersonation, or wire transfer fraud, classify it as such with specific threat probabilities.
4. Output STRICT JSON conforming to the following schema:
{
  "classification": {
    "label": "legitimate" | "promotional" | "newsletter" | "bulk" | "spam" | "phishing" | "bec" | "credential_theft" | "financial_fraud" | "malware" | "impersonation" | "suspicious",
    "confidence": number between 0 and 1
  },
  "threatAssessment": {
    "phishing": number between 0 and 1,
    "bec": number between 0 and 1,
    "credentialTheft": number between 0 and 1,
    "financialFraud": number between 0 and 1,
    "malware": number between 0 and 1,
    "impersonation": number between 0 and 1
  },
  "spamAssessment": {
    "bulk": number between 0 and 1,
    "promotional": number between 0 and 1,
    "unsolicited": number between 0 and 1
  },
  "signals": [
    {
      "signal": "string name",
      "severity": "info" | "low" | "medium" | "high" | "critical",
      "confidence": number between 0 and 1,
      "evidence": "concise rationale"
    }
  ],
  "contradictions": [ "string contradiction if any" ],
  "recommendedDisposition": "allow" | "allow_with_spam_label" | "quarantine" | "block" | "analyst_review"
}

EMAIL PAYLOAD:
${JSON.stringify(payload, null, 2)}`;

        let timeoutId: NodeJS.Timeout;
        const timeoutPromise = new Promise((_, reject) => {
          timeoutId = setTimeout(() => reject(new Error('Gemini API timeout (15000ms exceeded)')), 15000);
        });

        const generatePromise = ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
          config: {
            responseMimeType: 'application/json',
            temperature: 0.1
          }
        }).finally(() => {
          clearTimeout(timeoutId);
        });

        const response = await Promise.race([generatePromise, timeoutPromise]) as any;

        const rawText = response.text?.trim() || '{}';
        const parsed = JSON.parse(rawText);

        const signals: DetectionSignal[] = (parsed.signals || []).map((s: any, idx: number) => ({
          id: `gem-sig-${idx + 1}`,
          category: 'gemini-semantic',
          severity: s.severity || 'info',
          confidence: Math.round((s.confidence || 0.85) * 100),
          source: 'gemini',
          evidence: `[Gemini Semantic Observation] ${s.signal}: ${s.evidence}`
        }));

        // Map classification label to ThreatCategory
        const label = (parsed.classification?.label || '').toLowerCase();
        let mappedCat: ThreatCategory = 'Legitimate';
        if (label === 'newsletter') mappedCat = 'Newsletter';
        else if (label === 'promotional') mappedCat = 'Promotional';
        else if (label === 'bulk') mappedCat = 'Bulk / Unsolicited';
        else if (label === 'spam') mappedCat = 'Spam';
        else if (label === 'phishing') mappedCat = 'Phishing';
        else if (label === 'credential_theft') mappedCat = 'Credential Theft';
        else if (label === 'bec') mappedCat = 'Business Email Compromise';
        else if (label === 'impersonation') mappedCat = 'Executive Impersonation';
        else if (label === 'malware') mappedCat = 'Malware Delivery';
        else if (label === 'suspicious') mappedCat = 'Suspicious';

        return {
          engine: this.id,
          version: this.version,
          classification: mappedCat,
          probabilities: {
            phishing: parsed.threatAssessment?.phishing ?? 0.05,
            bec: parsed.threatAssessment?.bec ?? 0.02,
            credentialTheft: parsed.threatAssessment?.credentialTheft ?? 0.02,
            financialFraud: parsed.threatAssessment?.financialFraud ?? 0.01,
            malware: parsed.threatAssessment?.malware ?? 0.01,
            impersonation: parsed.threatAssessment?.impersonation ?? 0.03,
            bulk: parsed.spamAssessment?.bulk ?? 0.10,
            promotional: parsed.spamAssessment?.promotional ?? 0.10
          },
          signals,
          confidence: Math.round((parsed.classification?.confidence || 0.88) * 100),
          limitations: [
            'Evaluates semantic reasoning and intent context; does not override deterministic protocol authentication.'
          ],
          processingTimeMs: Date.now() - startTime,
          status: 'COMPLETED',
          details: {
            contradictions: parsed.contradictions || [],
            recommendedDisposition: parsed.recommendedDisposition
          }
        };
      } catch (err: any) {
        const errMsg = err?.message || String(err);
        if (errMsg.includes('429') || errMsg.includes('quota') || errMsg.includes('RESOURCE_EXHAUSTED')) {
          console.warn('[GeminiThreatEngine] Free-tier quota exceeded / rate-limited. Activating deterministic fallback engine.');
        } else {
          console.warn('[GeminiThreatEngine] API call failed, generating deterministic fallback:', errMsg);
        }
      }
    }

    // Deterministic Offline / Keyless Fallback Engine
    return this.generateDeterministicSemanticAnalysis(email, startTime);
  }

  /**
   * Reliable semantic reasoning fallback when Gemini API key is absent or offline
   */
  private generateDeterministicSemanticAnalysis(email: NormalizedEmail, startTime: number): EngineResult {
    const text = (email.bodyText || '').toLowerCase();
    const isNewsletter = email.spamAnalysis?.classification === 'newsletter' ||
      (email.spamAnalysis?.breakdown?.newsletterStructureScore || 0) > 40 ||
      text.includes('unsubscribe') ||
      email.subject.toLowerCase().includes('updates');
    const isPromo = email.spamAnalysis?.classification === 'promotional' || text.includes('deal') || text.includes('save 20%') || text.includes('special offer');
    const hasUrgency = text.includes('urgent') || text.includes('immediately') || text.includes('within 24 hours') || text.includes('required by');
    const hasWire = text.includes('wire transfer') || text.includes('bank details') || text.includes('swift code');
    const hasCreds = text.includes('password') || text.includes('log in to verify') || text.includes('passphrase') || text.includes('network token') || email.urls.some(u => u.hasCredentialPath);
    const hasLookalike = email.domainIntel.lookalikePatterns.length > 0;
    const freemails = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
    const isFreemailSender = freemails.includes(email.fromDomain.toLowerCase());
    const fromDisplayName = (email.fromName || '').toLowerCase();
    const hasCorporateSpoof = isFreemailSender && /(it\s+service|service\s+desk|it\s+support|it\s+operations|helpdesk|system\s+admin|executive|ceo|cfo)/i.test(fromDisplayName);

    let mappedCat: ThreatCategory = 'Legitimate';
    let phishingProb = 0.02;
    let becProb = 0.01;
    let malwareProb = email.attachments.some(a => a.flags?.isMacroEnabled) ? 0.90 : 0.01;
    let impersonationProb = hasLookalike ? 0.85 : (hasCorporateSpoof ? 0.92 : 0.02);
    let bulkProb = isNewsletter ? 0.92 : (isPromo ? 0.85 : 0.15);
    let promoProb = isPromo ? 0.90 : (isNewsletter ? 0.88 : 0.10);

    const signals: DetectionSignal[] = [];

    if (hasCorporateSpoof) {
      mappedCat = 'Executive Impersonation';
      impersonationProb = 0.94;
      if (hasCreds) {
        phishingProb = 0.90;
      }
      signals.push({
        id: 'gem-fallback-spoof',
        category: 'gemini-semantic',
        severity: 'critical',
        confidence: 96,
        source: 'gemini',
        evidence: `Deceptive identity lure: Sender persona claims internal corporate role ("${email.fromName}") transmitted via consumer webmail (${email.fromDomain}).`
      });
    } else if (isNewsletter || isPromo) {
      mappedCat = isNewsletter ? 'Newsletter' : 'Promotional';
      signals.push({
        id: 'gem-fallback-promo',
        category: 'gemini-semantic',
        severity: 'info',
        confidence: 94,
        source: 'gemini',
        evidence: `Semantic analysis identified commercial broadcast / newsletter template structure with opt-out mechanisms.`
      });
    } else if (hasCreds || hasLookalike) {
      mappedCat = 'Phishing';
      phishingProb = 0.88;
      signals.push({
        id: 'gem-fallback-phish',
        category: 'gemini-semantic',
        severity: 'critical',
        confidence: 90,
        source: 'gemini',
        evidence: `Linguistic intent aims to induce credential entry or account authentication under false pretenses.`
      });
    } else if (hasWire || (hasUrgency && email.headerAnomalies.some(a => a.finding.includes('Display Name')))) {
      mappedCat = 'Business Email Compromise';
      becProb = 0.84;
      signals.push({
        id: 'gem-fallback-bec',
        category: 'gemini-semantic',
        severity: 'critical',
        confidence: 88,
        source: 'gemini',
        evidence: `High-urgency pretext detected requesting sensitive financial action or exception to standard procedure.`
      });
    } else {
      signals.push({
        id: 'gem-fallback-benign',
        category: 'gemini-semantic',
        severity: 'info',
        confidence: 92,
        source: 'gemini',
        evidence: `No manipulative linguistic triggers, coercion patterns, or deceptive pretexts identified.`
      });
    }

    return {
      engine: this.id,
      version: `${this.version} (Deterministic Semantic Mode)`,
      classification: mappedCat,
      probabilities: {
        phishing: phishingProb,
        bec: becProb,
        credentialTheft: hasCreds ? 0.85 : 0.02,
        financialFraud: hasWire ? 0.80 : 0.01,
        malware: malwareProb,
        impersonation: impersonationProb,
        bulk: bulkProb,
        promotional: promoProb
      },
      signals,
      confidence: 88,
      limitations: [
        'Local deterministic semantic reasoner used. Set GEMINI_API_KEY to activate cloud-hosted Gemini 2.5 Flash model.'
      ],
      processingTimeMs: Date.now() - startTime,
      status: 'COMPLETED',
      details: {
        mode: 'LOCAL_SEMANTIC_REASONING',
        recommendedDisposition: (isNewsletter || isPromo) ? 'allow_with_spam_label' : (phishingProb > 0.7 ? 'quarantine' : 'allow')
      }
    };
  }
}

export const geminiThreatEngine = new GeminiThreatEngine();
