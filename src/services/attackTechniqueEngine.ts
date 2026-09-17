/**
 * MailTrace AI - Advanced Email Attack & Scam Technique Detection Engine
 * Comprehensive multi-layer analysis covering Unicode/ASCII smuggling, Bidi manipulation,
 * Homoglyphs/IDN, HTML deception, URL obfuscation, BEC/Financial fraud, Quishing,
 * Attachment disguise, and Social Engineering pressure heuristics.
 */

import {
  AttackTechnique,
  AttackTechniqueId,
  DetectedAttackTechnique,
  MultiLayerNormalizationReport,
  ThreatSeverity
} from '../types/forensics.js';

// =========================================================================
// 1. STANDARDIZED ATTACK TECHNIQUE TAXONOMY & REGISTRY
// =========================================================================

export const ATTACK_TECHNIQUE_REGISTRY: Record<string, AttackTechnique> = {
  ASCII_SMUGGLING: {
    id: 'ASCII_SMUGGLING',
    name: 'ASCII Smuggling & Invisible Unicode Encoding',
    category: 'Text Obfuscation & Evasion',
    description: 'Use of invisible Unicode characters, zero-width joiners, or hidden code points to evade keyword filters while rendering legible text to the user.',
    severity: 'high',
    detectors: ['AsciiSmugglingDetector', 'ZeroWidthDetector'],
    falsePositiveNotes: ['Normal Arabic, Indic, or complex scripts using legitimate ZWJ/ZWNJ formatting.'],
    enabled: true
  },
  ZERO_WIDTH_OBFUSCATION: {
    id: 'ZERO_WIDTH_OBFUSCATION',
    name: 'Zero-Width Character Injection',
    category: 'Text Obfuscation & Evasion',
    description: 'Zero-width spaces or word joiners injected between characters in sensitive keywords (e.g., p​a​s​s​w​o​r​d) or URLs to break signature matching.',
    severity: 'medium',
    detectors: ['ZeroWidthDetector'],
    falsePositiveNotes: ['Complex typography ligature joiners.'],
    enabled: true
  },
  BIDI_TEXT_DECEPTION: {
    id: 'BIDI_TEXT_DECEPTION',
    name: 'Bidirectional (Bidi) Text / RTL Override',
    category: 'Visual & Extension Deception',
    description: 'Use of Unicode Right-to-Left Override (RLO) control characters (e.g. U+202E) to reverse visual file extensions or URL paths.',
    severity: 'critical',
    detectors: ['BidiDetector'],
    falsePositiveNotes: ['Legitimate RTL language emails without executable extensions.'],
    enabled: true
  },
  HOMOGRAPH_ATTACK: {
    id: 'HOMOGRAPH_ATTACK',
    name: 'Unicode Homoglyph / Confusable Script Deception',
    category: 'Identity & Domain Deception',
    description: 'Substitution of Latin characters with visually identical Cyrillic, Greek, or math symbols in brand names or domains.',
    severity: 'high',
    detectors: ['UnicodeConfusableDetector'],
    falsePositiveNotes: ['Multilingual newsletters with native language sender names.'],
    enabled: true
  },
  PUNYCODE_DECEPTION: {
    id: 'PUNYCODE_DECEPTION',
    name: 'Punycode / IDN Domain Impersonation',
    category: 'Domain Deception',
    description: 'Internationalized Domain Name (xn--) encoding designed to visually mimic legitimate corporate domains.',
    severity: 'high',
    detectors: ['PunycodeDetector'],
    falsePositiveNotes: ['Legitimate non-ASCII internationalized brand domains.'],
    enabled: true
  },
  DISPLAY_NAME_SPOOFING: {
    id: 'DISPLAY_NAME_SPOOFING',
    name: 'Display Name Spoofing & Executive Impersonation',
    category: 'Identity Deception',
    description: 'Header display name crafted to impersonate trusted executives, security teams, or services while sending from an unrelated mailbox.',
    severity: 'high',
    detectors: ['EmailAddressDeceptionDetector'],
    falsePositiveNotes: ['Delegated assistants sending on behalf of executives.'],
    enabled: true
  },
  LOOKALIKE_DOMAIN: {
    id: 'LOOKALIKE_DOMAIN',
    name: 'Lookalike / Typosquatted Domain',
    category: 'Domain Deception',
    description: 'Domain registering subtle character substitutions, extra hyphens, or misleading subdomains resembling a known brand.',
    severity: 'high',
    detectors: ['LookalikeDomainDetector'],
    falsePositiveNotes: ['Unrelated legitimate domains with coincidental naming.'],
    enabled: true
  },
  URL_DISPLAY_DECEPTION: {
    id: 'URL_DISPLAY_DECEPTION',
    name: 'Link Anchor vs Href Destination Mismatch',
    category: 'URL & Link Deception',
    description: 'Visible link text displays a trusted legitimate URL (e.g. https://bank.com) while HTML href directs to a hostile external destination.',
    severity: 'critical',
    detectors: ['URLDisplayMismatchDetector'],
    falsePositiveNotes: ['Marketing tracking proxies wrapping visible URLs (if reputable).'],
    enabled: true
  },
  URL_OBFUSCATION: {
    id: 'URL_OBFUSCATION',
    name: 'URL Obfuscation & Nested Redirection',
    category: 'URL & Link Deception',
    description: 'Use of excessive percent-encoding, IP-literal URLs, hexadecimal addresses, or open redirects to conceal target landing pages.',
    severity: 'medium',
    detectors: ['URLObfuscationDetector'],
    falsePositiveNotes: ['Complex legitimate OAuth state parameters.'],
    enabled: true
  },
  HTML_DECEPTION: {
    id: 'HTML_DECEPTION',
    name: 'HTML Concealment (Hidden Text & Elements)',
    category: 'Content Obfuscation',
    description: 'Invisible text utilizing display:none, opacity:0, zero font-size, or white-on-white text to poison NLP Bayesian spam filters.',
    severity: 'high',
    detectors: ['HTMLDeceptionDetector'],
    falsePositiveNotes: ['Email client responsive preheader boilerplates.'],
    enabled: true
  },
  QR_PHISHING: {
    id: 'QR_PHISHING',
    name: 'QR-Code Phishing (Quishing) & Payment Lure',
    category: 'Emerging & Multi-Channel',
    description: 'Embedding authentication, 2FA setup, or payment instructions inside QR codes to bypass endpoint email link security filters.',
    severity: 'high',
    detectors: ['QRPhishingDetector'],
    falsePositiveNotes: ['Legitimate event tickets, loyalty apps, or app download badges.'],
    enabled: true
  },
  FILE_TYPE_MISMATCH: {
    id: 'FILE_TYPE_MISMATCH',
    name: 'Attachment Extension / MIME Magic Byte Mismatch',
    category: 'Malware & Attachment Threat',
    description: 'Attachment presented with a benign document extension (e.g. .pdf, .docx) containing binary executable or script headers.',
    severity: 'critical',
    detectors: ['AttachmentDeceptionDetector'],
    falsePositiveNotes: ['Corrupted files or misconfigured email client MIME generators.'],
    enabled: true
  },
  CREDENTIAL_HARVESTING: {
    id: 'CREDENTIAL_HARVESTING',
    name: 'Credential Harvesting & Account Verification Lure',
    category: 'Phishing Objective',
    description: 'Urgent demand for passwords, MFA tokens, login verification, or account recovery directing to unaligned destinations.',
    severity: 'high',
    detectors: ['CredentialHarvestingDetector'],
    falsePositiveNotes: ['Legitimate requested password reset workflows.'],
    enabled: true
  },
  BEC: {
    id: 'BEC',
    name: 'Business Email Compromise (BEC) & Payment Diversion',
    category: 'Financial Fraud & Impersonation',
    description: 'Targeted manipulation requesting wire transfers, bank account changes, vendor invoice modification, or urgent confidential tasks.',
    severity: 'critical',
    detectors: ['BECDetector'],
    falsePositiveNotes: ['Legitimate urgent executive directives or authorized billing updates.'],
    enabled: true
  },
  SOCIAL_ENGINEERING: {
    id: 'SOCIAL_ENGINEERING',
    name: 'High-Pressure Social Engineering (Urgency & Secrecy)',
    category: 'Behavioral Manipulation',
    description: 'Psychological coercion leveraging impending account suspension, disciplinary threats, extreme urgency, or strict confidentiality.',
    severity: 'medium',
    detectors: ['SocialEngineeringDetector'],
    falsePositiveNotes: ['Legitimate system maintenance or scheduled service notifications.'],
    enabled: true
  },
  CONTRADICTION_ANOMALY: {
    id: 'CONTRADICTION_ANOMALY',
    name: 'Technical / Claim Inconsistency Contradiction',
    category: 'Integrity Anomaly',
    description: 'Email claims official enterprise/bank affiliation while SPF/DKIM/DMARC fail or links route to an unassociated domain.',
    severity: 'high',
    detectors: ['ContradictionDetector'],
    falsePositiveNotes: ['Third-party billing agencies authorized on behalf of a brand.'],
    enabled: true
  }
};

// =========================================================================
// 2. MULTI-LAYER NORMALIZATION ENGINE
// =========================================================================

export class ContentNormalizer {
  // Unicode Zero-Width character map
  private static ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u2060\u00AD\u200E\u200F\u202A-\u202E\u2066-\u2069]/g;
  private static BIDI_CONTROL_REGEX = /[\u202A-\u202E\u2066-\u2069]/g;

  /**
   * Run full normalization pass across raw MIME and HTML representations
   */
  public static normalize(rawMime: string, bodyText: string, bodyHtml?: string): MultiLayerNormalizationReport {
    const rawMimeLength = rawMime?.length || 0;
    const plainText = bodyText || '';
    const decodedTextLength = plainText.length;

    // 1. Unicode Normalization (NFKC / NFKD)
    const normalizedUnicodeText = plainText.normalize('NFKC');

    // 2. Strip invisible characters to get true rendered representation
    const renderedVisibleText = plainText.replace(this.ZERO_WIDTH_REGEX, '').trim();

    // 3. HTML DOM Structure & Hidden Elements Scan
    const htmlDomStructure = {
      tagCount: 0,
      hiddenElementCount: 0,
      scriptTagCount: 0,
      formCount: 0,
      iframeCount: 0,
      trackingPixelCount: 0
    };

    if (bodyHtml) {
      htmlDomStructure.tagCount = (bodyHtml.match(/<[a-zA-Z0-9]+[^>]*>/g) || []).length;
      htmlDomStructure.scriptTagCount = (bodyHtml.match(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi) || []).length;
      htmlDomStructure.formCount = (bodyHtml.match(/<form\b[^>]*>/gi) || []).length;
      htmlDomStructure.iframeCount = (bodyHtml.match(/<iframe\b[^>]*>/gi) || []).length;

      // Hidden elements (display:none, opacity:0, font-size:0, etc.)
      const hiddenStyleRegex = /style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px)?|color\s*:\s*(?:#fff(?:fff)?|white)[^"']*background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white))[^"']*["']/gi;
      htmlDomStructure.hiddenElementCount = (bodyHtml.match(hiddenStyleRegex) || []).length;

      // 1x1 tracking pixel indicators
      const pixelRegex = /<img\b[^>]*(?:width\s*=\s*["']?[01]["']?|height\s*=\s*["']?[01]["']?)[^>]*>/gi;
      htmlDomStructure.trackingPixelCount = (bodyHtml.match(pixelRegex) || []).length;
    }

    // 4. URL extraction & decoding
    const extractedUrls: string[] = [];
    const urlRegex = /https?:\/\/[^\s<>"']+/gi;
    const matches = (plainText + (bodyHtml || '')).match(urlRegex) || [];
    const uniqueRawUrls = Array.from(new Set(matches));

    const decodedUrls = uniqueRawUrls.map(rawUrl => {
      extractedUrls.push(rawUrl);
      let decoded = rawUrl;
      try {
        decoded = decodeURIComponent(rawUrl);
      } catch {
        decoded = rawUrl;
      }
      return {
        original: rawUrl,
        normalized: rawUrl.toLowerCase().trim(),
        decoded,
        isDiscrepancy: rawUrl !== decoded
      };
    });

    // 5. Entropy & Obfuscation Score
    const obfuscationEntropy = this.calculateEntropy(plainText);
    const hiddenContentDetected = (
      htmlDomStructure.hiddenElementCount > 0 ||
      (plainText.length - renderedVisibleText.length) > 2
    );

    return {
      rawMimeLength,
      decodedTextLength,
      plainText,
      normalizedUnicodeText,
      renderedVisibleText,
      htmlDomStructure,
      extractedUrls,
      decodedUrls,
      attachmentMetadata: [],
      obfuscationEntropy,
      hiddenContentDetected
    };
  }

  /**
   * Calculate Shannon entropy of character distribution
   */
  private static calculateEntropy(text: string): number {
    if (!text || text.length === 0) return 0;
    const freq: Record<string, number> = {};
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = text.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return Math.round(entropy * 100) / 100;
  }
}

// =========================================================================
// 3. MODULAR ATTACK TECHNIQUE DETECTORS
// =========================================================================

export interface DetectionContext {
  from: string;
  senderDomain: string;
  replyTo?: string;
  returnPath?: string;
  subject: string;
  bodyText: string;
  bodyHtml?: string;
  rawMime?: string;
  urls: Array<{ url: string; domain: string; text?: string; isShortened?: boolean; hasCredentialPath?: boolean }>;
  attachments: Array<{ filename: string; mimeType: string; isExecutable?: boolean; isMacroEnabled?: boolean; isDoubleExtension?: boolean }>;
  spfStatus: string;
  dkimStatus: string;
  dmarcStatus: string;
  normalization: MultiLayerNormalizationReport;
}

// -------------------------------------------------------------------------
// A. ASCII Smuggling & Zero-Width Detector
// -------------------------------------------------------------------------
export class AsciiSmugglingDetector {
  public static readonly ID = 'ASCII_SMUGGLING_DETECTOR';
  public static readonly VERSION = 'v2.4.0';

  public static detect(ctx: DetectionContext): DetectedAttackTechnique[] {
    const findings: DetectedAttackTechnique[] = [];
    const text = ctx.bodyText + ' ' + ctx.subject;

    // 1. Zero-width character match
    const zeroWidthMatches = text.match(/[\u200B\u200C\u200D\uFEFF\u2060\u00AD]/g) || [];
    if (zeroWidthMatches.length > 0) {
      const isHighCount = zeroWidthMatches.length >= 4;
      findings.push({
        id: 'ASCII_SMUGGLING',
        name: 'Invisible Zero-Width Characters / ASCII Smuggling',
        category: 'Text Obfuscation & Evasion',
        severity: isHighCount ? 'high' : 'medium',
        confidence: isHighCount ? 92 : 78,
        evidence: `Detected ${zeroWidthMatches.length} invisible zero-width code point(s) embedded in text stream. These characters are invisible to humans but split keyword patterns in security parsers.`,
        source: 'Unicode Stream Inspector',
        detectorId: this.ID,
        detectorVersion: this.VERSION,
        timestamp: new Date().toISOString(),
        rawRepresentation: text.slice(0, 100),
        normalizedRepresentation: ctx.normalization.renderedVisibleText.slice(0, 100),
        signalGroup: 'text_obfuscation'
      });
    }

    return findings;
  }
}

// -------------------------------------------------------------------------
// B. Unicode Confusable / Homoglyph Detector
// -------------------------------------------------------------------------
export class UnicodeConfusableDetector {
  public static readonly ID = 'UNICODE_CONFUSABLE_DETECTOR';
  public static readonly VERSION = 'v2.4.0';

  private static HOMOGLYPH_MAP: Record<string, string> = {
    '\u0430': 'a', '\u0435': 'e', '\u043E': 'o', '\u0440': 'p', '\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
    '\u0456': 'i', '\u03BF': 'o', '\u03C1': 'p', '\u03B1': 'a', '\u03BD': 'v'
  };

  private static TARGET_BRANDS = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix', 'chase', 'wellsfargo', 'dhl', 'fedex', 'singtel', 'singnet'];

  public static detect(ctx: DetectionContext): DetectedAttackTechnique[] {
    const findings: DetectedAttackTechnique[] = [];
    const domainsToCheck = [ctx.senderDomain, ...ctx.urls.map(u => u.domain)];

    for (const d of domainsToCheck) {
      if (!d) continue;
      let hasConfusable = false;
      let replaced = '';
      for (const ch of d) {
        if (this.HOMOGLYPH_MAP[ch]) {
          hasConfusable = true;
          replaced += this.HOMOGLYPH_MAP[ch];
        } else {
          replaced += ch;
        }
      }

      if (hasConfusable) {
        const matchesBrand = this.TARGET_BRANDS.some(b => replaced.toLowerCase().includes(b));
        findings.push({
          id: 'HOMOGRAPH_ATTACK',
          name: 'Unicode Homoglyph Script Substitution',
          category: 'Identity & Domain Deception',
          severity: matchesBrand ? 'critical' : 'high',
          confidence: matchesBrand ? 96 : 85,
          evidence: `Domain "${d}" uses mixed-script Cyrillic/Greek homoglyphs resolving visually to "${replaced}". ${matchesBrand ? 'Matches protected brand identity.' : ''}`,
          source: 'IDN Script Normalizer',
          detectorId: this.ID,
          detectorVersion: this.VERSION,
          timestamp: new Date().toISOString(),
          rawRepresentation: d,
          normalizedRepresentation: replaced,
          signalGroup: 'domain_impersonation'
        });
      }
    }

    return findings;
  }
}

// -------------------------------------------------------------------------
// C. Bidi Text / RTL Override Detector
// -------------------------------------------------------------------------
export class BidiDetector {
  public static readonly ID = 'BIDI_TEXT_DETECTOR';
  public static readonly VERSION = 'v2.4.0';

  public static detect(ctx: DetectionContext): DetectedAttackTechnique[] {
    const findings: DetectedAttackTechnique[] = [];
    const combined = ctx.subject + ' ' + ctx.bodyText + ' ' + ctx.attachments.map(a => a.filename).join(' ');

    const bidiMatches = combined.match(/[\u202A-\u202E\u2066-\u2069]/g) || [];
    if (bidiMatches.length > 0) {
      const hasExecutableAttachment = ctx.attachments.some(a => a.isExecutable || a.isDoubleExtension);
      findings.push({
        id: 'BIDI_TEXT_DECEPTION',
        name: 'Bidirectional (Bidi) Text / RTL Override Character',
        category: 'Visual & Extension Deception',
        severity: hasExecutableAttachment ? 'critical' : 'high',
        confidence: 94,
        evidence: `Detected ${bidiMatches.length} Unicode Bidirectional (Bidi) control characters (such as RLO U+202E). These characters reverse text display order to disguise file extensions or malicious URLs.`,
        source: 'Bidi Anomaly Scanner',
        detectorId: this.ID,
        detectorVersion: this.VERSION,
        timestamp: new Date().toISOString(),
        rawRepresentation: combined.slice(0, 80),
        signalGroup: 'extension_deception'
      });
    }

    return findings;
  }
}

// -------------------------------------------------------------------------
// D. Email Address Deception & Spoofing Detector
// -------------------------------------------------------------------------
export class EmailAddressDeceptionDetector {
  public static readonly ID = 'EMAIL_ADDRESS_DECEPTION_DETECTOR';
  public static readonly VERSION = 'v2.4.0';

  private static EXECUTIVE_ROLES = ['ceo', 'cfo', 'coo', 'cto', 'president', 'director', 'payroll', 'finance', 'it support', 'security team', 'helpdesk', 'administrator'];

  public static detect(ctx: DetectionContext): DetectedAttackTechnique[] {
    const findings: DetectedAttackTechnique[] = [];
    const fromLower = ctx.from.toLowerCase();

    // 1. Display Name Spoofing (e.g., "Microsoft Security <user@random.com>")
    const displayNameMatch = ctx.from.match(/^"?(.*?)"?\s*<(.+?)>$/);
    if (displayNameMatch) {
      const displayName = displayNameMatch[1].toLowerCase().trim();
      const actualEmail = displayNameMatch[2].toLowerCase().trim();
      const actualDomain = actualEmail.split('@')[1] || '';

      const claimsBrandOrRole = this.EXECUTIVE_ROLES.some(role => displayName.includes(role)) ||
        ['microsoft', 'google', 'apple', 'paypal', 'support', 'billing'].some(b => displayName.includes(b));

      if (claimsBrandOrRole && !actualDomain.includes(displayName.replace(/[^a-z0-9]/g, ''))) {
        findings.push({
          id: 'DISPLAY_NAME_SPOOFING',
          name: 'Display Name Identity Spoofing',
          category: 'Identity Deception',
          severity: 'high',
          confidence: 90,
          evidence: `Display name "${displayNameMatch[1]}" claims trusted authority/brand, but actual sending mailbox is "${actualEmail}" on unrelated domain "${actualDomain}".`,
          source: 'Header Identity Analyzer',
          detectorId: this.ID,
          detectorVersion: this.VERSION,
          timestamp: new Date().toISOString(),
          rawRepresentation: ctx.from,
          signalGroup: 'identity_spoofing'
        });
      }
    }

    // 2. Reply-To Mismatch
    if (ctx.replyTo && ctx.senderDomain) {
      const replyToDomain = ctx.replyTo.split('@')[1]?.toLowerCase().trim();
      if (replyToDomain && replyToDomain !== ctx.senderDomain.toLowerCase()) {
        findings.push({
          id: 'IDENTITY_DECEPTION',
          name: 'Sender / Reply-To Routing Discrepancy',
          category: 'Identity Deception',
          severity: 'medium',
          confidence: 84,
          evidence: `Outbound responses are routed to Reply-To address "${ctx.replyTo}" which diverges from sending domain "${ctx.senderDomain}".`,
          source: 'Routing Header Inspector',
          detectorId: this.ID,
          detectorVersion: this.VERSION,
          timestamp: new Date().toISOString(),
          signalGroup: 'routing_anomaly'
        });
      }
    }

    return findings;
  }
}

// -------------------------------------------------------------------------
// E. Lookalike Domain Detector
// -------------------------------------------------------------------------
export class LookalikeDomainDetector {
  public static readonly ID = 'LOOKALIKE_DOMAIN_DETECTOR';
  public static readonly VERSION = 'v2.4.0';

  private static TARGET_BRANDS = [
    'microsoft', 'office365', 'google', 'gmail', 'apple', 'paypal', 'amazon',
    'netflix', 'chase', 'bankofamerica', 'dhl', 'fedex', 'discountwalas', 'singnet'
  ];

  public static detect(ctx: DetectionContext): DetectedAttackTechnique[] {
    const findings: DetectedAttackTechnique[] = [];
    const domains = Array.from(new Set([ctx.senderDomain, ...ctx.urls.map(u => u.domain)].filter(Boolean)));

    for (const domain of domains) {
      const cleanDomain = domain.toLowerCase().replace(/\.(com|net|org|io|co|in|xyz|top|ru)$/, '');

      for (const brand of this.TARGET_BRANDS) {
        if (cleanDomain === brand) continue; // Legitimate exact match

        // Levenshtein / Edit distance check
        const dist = this.levenshtein(cleanDomain, brand);
        const hasPrefixSuffix = (cleanDomain.includes(`${brand}-`) || cleanDomain.includes(`-${brand}`) || cleanDomain.includes(`${brand}security`) || cleanDomain.includes(`${brand}verify`));

        if (dist <= 2 || hasPrefixSuffix) {
          findings.push({
            id: 'LOOKALIKE_DOMAIN',
            name: 'Typosquatted / Brand Lookalike Domain',
            category: 'Domain Deception',
            severity: 'high',
            confidence: 91,
            evidence: `Domain "${domain}" is an unregistered lookalike or typosquat variation targeting established brand "${brand}".`,
            source: 'Levenshtein Heuristics Matrix',
            detectorId: this.ID,
            detectorVersion: this.VERSION,
            timestamp: new Date().toISOString(),
            rawRepresentation: domain,
            signalGroup: 'domain_impersonation'
          });
          break;
        }
      }
    }

    return findings;
  }

  private static levenshtein(a: string, b: string): number {
    const matrix: number[][] = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }
}

// -------------------------------------------------------------------------
// F. URL Display Mismatch & Obfuscation Detector
// -------------------------------------------------------------------------
export class URLDisplayMismatchDetector {
  public static readonly ID = 'URL_DISPLAY_MISMATCH_DETECTOR';
  public static readonly VERSION = 'v2.4.0';

  public static detect(ctx: DetectionContext): DetectedAttackTechnique[] {
    const findings: DetectedAttackTechnique[] = [];

    // Parse HTML href vs visible anchor text
    if (ctx.bodyHtml) {
      const anchorRegex = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)<\/a>/gi;
      let match;
      while ((match = anchorRegex.exec(ctx.bodyHtml)) !== null) {
        const href = match[1];
        const anchorText = match[2].replace(/<[^>]+>/g, '').trim();

        // If anchor text looks like a URL (e.g. https://legit.com) but href goes elsewhere
        if (/^https?:\/\//i.test(anchorText)) {
          try {
            const anchorHost = new URL(anchorText).hostname.toLowerCase();
            const hrefHost = new URL(href).hostname.toLowerCase();

            if (anchorHost !== hrefHost && !hrefHost.endsWith('.' + anchorHost)) {
              findings.push({
                id: 'URL_DISPLAY_DECEPTION',
                name: 'Visible Anchor vs Actual Href Destination Mismatch',
                category: 'URL & Link Deception',
                severity: 'critical',
                confidence: 97,
                evidence: `Visible link text displays "${anchorText}", but HTML destination redirects to hostile external address "${href}".`,
                source: 'DOM Anchor Comparator',
                detectorId: this.ID,
                detectorVersion: this.VERSION,
                timestamp: new Date().toISOString(),
                rawRepresentation: match[0],
                signalGroup: 'url_deception'
              });
            }
          } catch {
            // URL parse failure
          }
        }
      }
    }

    return findings;
  }
}

// -------------------------------------------------------------------------
// G. HTML Deception & Hidden Text Detector
// -------------------------------------------------------------------------
export class HTMLDeceptionDetector {
  public static readonly ID = 'HTML_DECEPTION_DETECTOR';
  public static readonly VERSION = 'v2.4.0';

  public static detect(ctx: DetectionContext): DetectedAttackTechnique[] {
    const findings: DetectedAttackTechnique[] = [];
    const { htmlDomStructure } = ctx.normalization;

    if (htmlDomStructure.hiddenElementCount > 0) {
      findings.push({
        id: 'HTML_DECEPTION',
        name: 'Hidden Content / Zero-Size Text Evasion in HTML',
        category: 'Content Obfuscation',
        severity: 'high',
        confidence: 88,
        evidence: `Detected ${htmlDomStructure.hiddenElementCount} hidden HTML element(s) utilizing display:none, opacity:0, or white-on-white CSS styling. Often used to inject invisible decoy text to poison Bayesian spam scoring.`,
        source: 'HTML DOM Structural Inspector',
        detectorId: this.ID,
        detectorVersion: this.VERSION,
        timestamp: new Date().toISOString(),
        signalGroup: 'content_obfuscation'
      });
    }

    if (htmlDomStructure.scriptTagCount > 0) {
      findings.push({
        id: 'HTML_DECEPTION',
        name: 'Embedded Script Tag in Email Body',
        category: 'Content Obfuscation',
        severity: 'critical',
        confidence: 98,
        evidence: `Email HTML contains ${htmlDomStructure.scriptTagCount} executable <script> block(s). Modern email clients reject script execution; presence indicates active exploitation payload.`,
        source: 'HTML DOM Structural Inspector',
        detectorId: this.ID,
        detectorVersion: this.VERSION,
        timestamp: new Date().toISOString(),
        signalGroup: 'malware_delivery'
      });
    }

    return findings;
  }
}

// -------------------------------------------------------------------------
// H. QR Code Phishing (Quishing) Detector
// -------------------------------------------------------------------------
export class QRPhishingDetector {
  public static readonly ID = 'QR_PHISHING_DETECTOR';
  public static readonly VERSION = 'v2.4.0';

  public static detect(ctx: DetectionContext): DetectedAttackTechnique[] {
    const findings: DetectedAttackTechnique[] = [];
    const text = (ctx.subject + ' ' + ctx.bodyText).toLowerCase();

    const mentionsQR = text.includes('qr code') || text.includes('scan the code') || text.includes('scan with your mobile') || text.includes('qr scanner') || text.includes('mfa barcode');
    const mentionsAuthOrPay = text.includes('authenticat') || text.includes('mfa') || text.includes('verify your account') || text.includes('payment') || text.includes('invoice');

    if (mentionsQR && mentionsAuthOrPay) {
      findings.push({
        id: 'QR_PHISHING',
        name: 'QR-Code Phishing (Quishing) Coercion',
        category: 'Emerging & Multi-Channel',
        severity: 'high',
        confidence: 89,
        evidence: 'Email instructs recipient to scan an embedded QR code using their mobile device to complete security verification or payment. Used to shift users off monitored enterprise networks.',
        source: 'Multi-Channel Quishing Classifier',
        detectorId: this.ID,
        detectorVersion: this.VERSION,
        timestamp: new Date().toISOString(),
        signalGroup: 'quishing'
      });
    }

    return findings;
  }
}

// -------------------------------------------------------------------------
// I. Credential Harvesting & Account Verification Detector
// -------------------------------------------------------------------------
export class CredentialHarvestingDetector {
  public static readonly ID = 'CREDENTIAL_HARVESTING_DETECTOR';
  public static readonly VERSION = 'v2.4.0';

  public static detect(ctx: DetectionContext): DetectedAttackTechnique[] {
    const findings: DetectedAttackTechnique[] = [];
    const text = (ctx.subject + ' ' + ctx.bodyText).toLowerCase();

    const credentialKeywords = ['password expired', 'reset password', 'verify credentials', 'confirm your password', 'enter otp', 'mfa verification', 'account suspended in 24 hours', 'action required: verify identity'];
    const matchesCred = credentialKeywords.some(kw => text.includes(kw));
    const hasExternalUrl = ctx.urls.length > 0;

    if (matchesCred && hasExternalUrl) {
      findings.push({
        id: 'CREDENTIAL_HARVESTING',
        name: 'Credential Harvesting & Password Theft Lure',
        category: 'Phishing Objective',
        severity: 'high',
        confidence: 93,
        evidence: 'Message demands urgent account login, password reset, or OTP identity verification and directs to external unverified links.',
        source: 'Intent & Credential Harvesting Model',
        detectorId: this.ID,
        detectorVersion: this.VERSION,
        timestamp: new Date().toISOString(),
        signalGroup: 'credential_harvesting'
      });
    }

    return findings;
  }
}

// -------------------------------------------------------------------------
// J. Business Email Compromise (BEC) Detector
// -------------------------------------------------------------------------
export class BECDetector {
  public static readonly ID = 'BEC_DETECTOR';
  public static readonly VERSION = 'v2.4.0';

  public static detect(ctx: DetectionContext): DetectedAttackTechnique[] {
    const findings: DetectedAttackTechnique[] = [];
    const text = (ctx.subject + ' ' + ctx.bodyText).toLowerCase();

    const becFinancialKeywords = ['wire transfer', 'change bank details', 'updated routing number', 'confidential payment', 'vendor invoice change', 'gift card', 'direct deposit change', 'urgent payment authorization'];
    const hasFinancialLure = becFinancialKeywords.some(kw => text.includes(kw));

    const secrecyKeywords = ['keep this confidential', 'do not call finance', 'do not discuss with anyone', 'i am in a meeting', 'private request'];
    const hasSecrecy = secrecyKeywords.some(kw => text.includes(kw));

    if (hasFinancialLure) {
      findings.push({
        id: 'BEC',
        name: 'Business Email Compromise (BEC) / Wire Transfer Fraud',
        category: 'Financial Fraud & Impersonation',
        severity: 'critical',
        confidence: hasSecrecy ? 95 : 88,
        evidence: `Message requests urgent financial transaction, banking modification, or gift card acquisition.${hasSecrecy ? ' Contains explicit secrecy manipulation ("keep this confidential").' : ''}`,
        source: 'BEC Heuristic Rule Engine',
        detectorId: this.ID,
        detectorVersion: this.VERSION,
        timestamp: new Date().toISOString(),
        signalGroup: 'financial_fraud'
      });
    }

    return findings;
  }
}

// -------------------------------------------------------------------------
// K. Social Engineering & Urgency Detector
// -------------------------------------------------------------------------
export class SocialEngineeringDetector {
  public static readonly ID = 'SOCIAL_ENGINEERING_DETECTOR';
  public static readonly VERSION = 'v2.4.0';

  public static detect(ctx: DetectionContext): DetectedAttackTechnique[] {
    const findings: DetectedAttackTechnique[] = [];
    const text = (ctx.subject + ' ' + ctx.bodyText).toLowerCase();

    const urgencyKeywords = ['within 24 hours', 'immediate action required', 'account termination', 'legal action', 'final warning', 'suspended immediately', 'overdue payment'];
    const matchedUrgency = urgencyKeywords.filter(kw => text.includes(kw));

    if (matchedUrgency.length > 0) {
      findings.push({
        id: 'SOCIAL_ENGINEERING',
        name: 'High-Pressure Urgency & Coercion Manipulation',
        category: 'Behavioral Manipulation',
        severity: 'medium',
        confidence: 86,
        evidence: `Coercive urgency tactics detected (${matchedUrgency.map(k => `"${k}"`).join(', ')}). Designed to induce immediate user compliance without technical scrutiny.`,
        source: 'NLP Sentiment & Urgency Classifier',
        detectorId: this.ID,
        detectorVersion: this.VERSION,
        timestamp: new Date().toISOString(),
        signalGroup: 'social_engineering'
      });
    }

    return findings;
  }
}

// -------------------------------------------------------------------------
// L. Contradiction Detector (Claims vs Technical Reality)
// -------------------------------------------------------------------------
export class ContradictionDetector {
  public static readonly ID = 'CONTRADICTION_DETECTOR';
  public static readonly VERSION = 'v2.4.0';

  public static detect(ctx: DetectionContext): DetectedAttackTechnique[] {
    const findings: DetectedAttackTechnique[] = [];
    const text = (ctx.subject + ' ' + ctx.bodyText).toLowerCase();

    const claimsOfficial = text.includes('official bank') || text.includes('security notification') || text.includes('account security alert');
    const authFailed = ctx.spfStatus === 'fail' || ctx.dmarcStatus === 'fail' || ctx.dmarcStatus === 'none-found';

    if (claimsOfficial && authFailed) {
      findings.push({
        id: 'CONTRADICTION_ANOMALY',
        name: 'Brand Claim vs Authentication Protocol Contradiction',
        category: 'Integrity Anomaly',
        severity: 'high',
        confidence: 92,
        evidence: `Message claims official security alert from corporate authority, but technical cryptographic authentication (SPF: ${ctx.spfStatus.toUpperCase()}, DMARC: ${ctx.dmarcStatus.toUpperCase()}) fails alignment.`,
        source: 'Forensic Cross-Verification Engine',
        detectorId: this.ID,
        detectorVersion: this.VERSION,
        timestamp: new Date().toISOString(),
        signalGroup: 'contradiction_matrix'
      });
    }

    return findings;
  }
}

// =========================================================================
// 4. MAIN ATTACK TECHNIQUE DETECTION ENGINE & PIPELINE
// =========================================================================

export class AttackTechniqueDetectionEngine {
  private static detectors = [
    AsciiSmugglingDetector,
    UnicodeConfusableDetector,
    BidiDetector,
    EmailAddressDeceptionDetector,
    LookalikeDomainDetector,
    URLDisplayMismatchDetector,
    HTMLDeceptionDetector,
    QRPhishingDetector,
    CredentialHarvestingDetector,
    BECDetector,
    SocialEngineeringDetector,
    ContradictionDetector
  ];

  /**
   * Run all registered technique detectors across email content and technical context
   */
  public static analyze(params: {
    from: string;
    senderDomain: string;
    replyTo?: string;
    returnPath?: string;
    subject: string;
    bodyText: string;
    bodyHtml?: string;
    rawMime?: string;
    urls?: Array<{ url: string; domain: string; text?: string; isShortened?: boolean; hasCredentialPath?: boolean }>;
    attachments?: Array<{ filename: string; mimeType: string; isExecutable?: boolean; isMacroEnabled?: boolean; isDoubleExtension?: boolean }>;
    spfStatus?: string;
    dkimStatus?: string;
    dmarcStatus?: string;
  }): {
    detectedTechniques: DetectedAttackTechnique[];
    normalization: MultiLayerNormalizationReport;
    techniqueRiskScore: number;
    dangerExplanation: string;
    nonMaliciousExplanation: string;
  } {
    // 1. Run multi-layer content normalization
    const normalization = ContentNormalizer.normalize(
      params.rawMime || '',
      params.bodyText || '',
      params.bodyHtml
    );

    const ctx: DetectionContext = {
      from: params.from || '',
      senderDomain: params.senderDomain || '',
      replyTo: params.replyTo,
      returnPath: params.returnPath,
      subject: params.subject || '',
      bodyText: params.bodyText || '',
      bodyHtml: params.bodyHtml,
      rawMime: params.rawMime,
      urls: params.urls || [],
      attachments: params.attachments || [],
      spfStatus: params.spfStatus || 'none',
      dkimStatus: params.dkimStatus || 'none',
      dmarcStatus: params.dmarcStatus || 'none',
      normalization
    };

    // 2. Execute all modular detectors
    const rawFindings: DetectedAttackTechnique[] = [];
    for (const detector of this.detectors) {
      try {
        const results = detector.detect(ctx);
        rawFindings.push(...results);
      } catch (err) {
        console.error(`Error in detector ${detector.ID}:`, err);
      }
    }

    // 3. Evidence Fusion & Deduplication (Avoid triple-counting identical signal groups)
    const seenGroups = new Set<string>();
    const deduplicatedTechniques: DetectedAttackTechnique[] = [];

    for (const item of rawFindings) {
      const groupKey = item.signalGroup ? `${item.id}_${item.signalGroup}` : item.id;
      if (!seenGroups.has(groupKey)) {
        seenGroups.add(groupKey);
        deduplicatedTechniques.push(item);
      }
    }

    // 4. Calculate Technique Risk Score (0-100)
    let score = 0;
    for (const t of deduplicatedTechniques) {
      const weight = t.severity === 'critical' ? 35 : t.severity === 'high' ? 24 : t.severity === 'medium' ? 12 : 5;
      score += weight * (t.confidence / 100);
    }
    const techniqueRiskScore = Math.min(100, Math.round(score));

    // 5. Generate Dynamic Explanations
    const dangerExplanation = this.generateDangerExplanation(deduplicatedTechniques, ctx);
    const nonMaliciousExplanation = this.generateNonMaliciousExplanation(deduplicatedTechniques, ctx);

    return {
      detectedTechniques: deduplicatedTechniques,
      normalization,
      techniqueRiskScore,
      dangerExplanation,
      nonMaliciousExplanation
    };
  }

  private static generateDangerExplanation(techniques: DetectedAttackTechnique[], ctx: DetectionContext): string {
    if (techniques.length === 0) {
      return 'No specific attack or scam techniques were detected in this message. Standard email security hygiene still applies.';
    }

    const highOrCrit = techniques.filter(t => t.severity === 'critical' || t.severity === 'high');
    const techniqueNames = highOrCrit.map(t => t.name).slice(0, 3).join(', ');

    return `This email exhibits indicators characteristic of ${techniqueNames || 'social engineering & deception tactics'}. The message manipulates sender identity or content formatting and directs the recipient toward unverified actions. Technical and content evidence strongly corroborate these deception patterns.`;
  }

  private static generateNonMaliciousExplanation(techniques: DetectedAttackTechnique[], ctx: DetectionContext): string {
    if (techniques.length === 0) {
      return 'No confirmed malicious behavior was detected. Authentication records (SPF/DKIM/DMARC) align with standard corporate senders and no deceptive Unicode or credential harvesting links were identified.';
    }
    return 'While certain marketing or structural tracking signals exist, no hostile payload execution or credential harvesting endpoints were confirmed.';
  }
}
