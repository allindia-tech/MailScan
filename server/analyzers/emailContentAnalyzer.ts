/**
 * MailTrace AI - Complete Email Content & Threat Analysis Engine
 * Analyzes Subject, Text Body, HTML Body, Requested Action, Intent,
 * Social Engineering Patterns, Fraud, BEC, HTML Obfuscation, and QR/OCR Indicators.
 */

import {
  EmailContentAnalysis,
  EmailIntentCategory,
  EmailIntentDisposition,
  RequestedActionType,
  SocialEngineeringFinding
} from '../../src/types/forensics.js';
import { ParsedEmailRaw } from './emailParser.js';
import { URLAnalysis } from '../../src/types/forensics.js';

export function analyzeEmailContent(
  parsed: ParsedEmailRaw,
  urls: URLAnalysis[]
): EmailContentAnalysis {
  const subject = parsed.subject || '';
  const bodyText = parsed.bodyText || '';
  const bodyHtml = parsed.bodyHtml || '';
  const combinedText = `${subject}\n${bodyText}`;
  const lowerCombined = combinedText.toLowerCase();
  const lowerSubject = subject.toLowerCase();

  // -------------------------------------------------------------------------
  // 1. SUBJECT ANALYSIS
  // -------------------------------------------------------------------------
  const subjectFlags: string[] = [];
  let subjectSentiment: 'neutral' | 'urgent' | 'alarming' | 'promotional' = 'neutral';
  let subjectSuspicious = false;

  const urgentSubjectPatterns = [
    /urgent/i, /immediate/i, /action required/i, /expires/i, /24 hours/i,
    /suspended/i, /unauthorized/i, /breach/i, /verify now/i, /security alert/i,
    /critical/i, /payment failed/i, /password expires/i
  ];
  const promotionalSubjectPatterns = [
    /off\b/i, /discount/i, /newsletter/i, /weekly/i, /monthly/i, /digest/i,
    /update/i, /features/i, /sale\b/i, /deal/i, /exclusive/i, /webinar/i
  ];
  const fraudSubjectPatterns = [
    /winner/i, /won\b/i, /prize/i, /reward/i, /wire transfer/i, /invoice/i,
    /overdue/i, /inheritance/i, /confidential request/i, /gift card/i
  ];

  for (const p of urgentSubjectPatterns) {
    if (p.test(lowerSubject)) {
      subjectFlags.push(`Urgent prompt: "${lowerSubject.match(p)?.[0]}"`);
      subjectSentiment = 'urgent';
      subjectSuspicious = true;
    }
  }

  for (const p of promotionalSubjectPatterns) {
    if (p.test(lowerSubject)) {
      subjectFlags.push(`Commercial indicator: "${lowerSubject.match(p)?.[0]}"`);
      if (subjectSentiment !== 'urgent') subjectSentiment = 'promotional';
    }
  }

  for (const p of fraudSubjectPatterns) {
    if (p.test(lowerSubject)) {
      subjectFlags.push(`Financial/Fraud prompt: "${lowerSubject.match(p)?.[0]}"`);
      subjectSuspicious = true;
    }
  }

  // -------------------------------------------------------------------------
  // 2. SOCIAL ENGINEERING ANALYSIS (With Indian Context & Transliteration)
  // -------------------------------------------------------------------------
  const socialEngineering: SocialEngineeringFinding[] = [];

  // Urgency & Coercive Pressure (English + Hinglish/Hindi transliterated)
  const urgencyMatches = combinedText.match(/(?:within\s+(?:24|48|12)\s*hours|immediately|right\s+away|asap|urgent\s+action|expires\s+today|act\s+now|prompt\s+response|account\s+band\s+ho\s+jayega|turant\s+(?:verify|action)|jaldi\s+kare)/i);
  if (urgencyMatches) {
    socialEngineering.push({
      signal: 'Urgency',
      evidence: `Explicit artificial deadline / urgency pressure: "${urgencyMatches[0]}"`,
      severity: 'high',
      confidence: 94
    });
  }

  // Fear & Consequence Manipulation
  const fearMatches = combinedText.match(/(?:account\s+(?:will\s+be\s+)?suspended|permanently\s+disabled|legal\s+action|access\s+revoked|law\s+enforcement|security\s+compromise|terminated|frozen|sim\s+block|service\s+stop)/i);
  if (fearMatches) {
    socialEngineering.push({
      signal: 'Fear',
      evidence: `Consequence threat: "${fearMatches[0]}"`,
      severity: 'high',
      confidence: 92
    });
  }

  // Authority Impersonation (Global & Indian Government / Statutory Bodies)
  const authorityMatches = combinedText.match(/(?:chief\s+executive|ceo|cfo|director|board\s+of\s+directors|security\s+operations\s+center|it\s+support\s+desk|compliance\s+officer|internal\s+audit|income\s+tax\s+department|epfo|uidai|rbi|sebi|npci|digilocker|customs\s+department|cyber\s+crime\s+cell)/i);
  if (authorityMatches) {
    socialEngineering.push({
      signal: 'Authority',
      evidence: `Executive / Statutory Authority claim: "${authorityMatches[0]}"`,
      severity: 'medium',
      confidence: 88
    });
  }

  // Trust Manipulation
  const trustMatches = combinedText.match(/(?:official\s+(?:security|verification|notice)|trusted\s+partner|verified\s+by|authorized\s+vendor|regulatory\s+mandate|sarkari\s+yojana|govt\s+approved)/i);
  if (trustMatches) {
    socialEngineering.push({
      signal: 'Trust manipulation',
      evidence: `Artificial trust anchor: "${trustMatches[0]}"`,
      severity: 'medium',
      confidence: 85
    });
  }

  // Secrecy
  const secrecyMatches = combinedText.match(/(?:keep\s+this\s+(?:confidential|between\s+us|strictly\s+private)|do\s+not\s+(?:tell|discuss|disclose)|private\s+assignment|kisi\s+ko\s+mat\s+batao)/i);
  if (secrecyMatches) {
    socialEngineering.push({
      signal: 'Secrecy',
      evidence: `Isolation tactic: "${secrecyMatches[0]}"`,
      severity: 'high',
      confidence: 96
    });
  }

  // Credential & OTP Harvesting Pressure (Including Hinglish phrases)
  const credMatches = combinedText.match(/(?:enter\s+your\s+(?:password|credentials|passcode|otp|pin)|verify\s+your\s+(?:login|identity|password)|confirm\s+your\s+account|otp\s+share\s+kare|apka\s+account\s+verify\s+kare|kyc\s+update\s+kare|pan\s+update\s+kare|aadhaar\s+verify)/i);
  if (credMatches) {
    socialEngineering.push({
      signal: 'Credential pressure',
      evidence: `Authentication data / OTP / KYC request: "${credMatches[0]}"`,
      severity: 'critical',
      confidence: 97
    });
  }

  // Financial Pressure (Global + Indian Banking/UPI terminology)
  const finMatches = combinedText.match(/(?:wire\s+transfer|remit\s+payment|update\s+banking\s+details|overdue\s+invoice|settle\s+balance|direct\s+deposit|gift\s+cards?|upi\s+collect|qr\s+code\s+scan|neft|rtgs|imps|payment\s+pending\s+hai|refund\s+lene\s+ke\s+liye)/i);
  if (finMatches) {
    socialEngineering.push({
      signal: 'Financial pressure',
      evidence: `Monetary transaction prompt / UPI lure: "${finMatches[0]}"`,
      severity: 'high',
      confidence: 91
    });
  }

  // -------------------------------------------------------------------------
  // 3. FRAUD DETECTION (With Indian Context)
  // -------------------------------------------------------------------------
  let fraudDetected = false;
  let fraudType: 'Payment' | 'Investment' | 'Prize' | 'Employment' | 'None' = 'None';
  let fraudEvidence = '';

  if (/(?:congratulations.*(?:won|winner|lottery|prize|reward)|claim\s+(?:your\s+)?(?:cash|prize|reward|cashback)|processing\s+fee\s+to\s+claim|kbc\s+lottery|draw\s+winner)/i.test(combinedText)) {
    fraudDetected = true;
    fraudType = 'Prize';
    fraudEvidence = 'Prize / cashback / lottery winner lure with advance-fee claim condition detected.';
  } else if (/(?:guaranteed\s+returns?|crypto\s+investment|100%\s+profit|high\s+yield\s+investment|bitcoin\s+transfer|guaranteed\s+stock\s+tips|unrealistic\s+ipo\s+allocation|double\s+your\s+money)/i.test(combinedText)) {
    fraudDetected = true;
    fraudType = 'Investment';
    fraudEvidence = 'Unrealistic financial returns / fraudulent investment / stock tip solicitation pattern.';
  } else if (/(?:job\s+offer.*(?:registration\s+fee|security\s+deposit)|work\s+from\s+home.*send\s+money|training\s+materials\s+deposit|guaranteed\s+placement.*pay\s+fee)/i.test(combinedText)) {
    fraudDetected = true;
    fraudType = 'Employment';
    fraudEvidence = 'Employment / recruitment opportunity requiring upfront fee, security deposit, or banking disclosure.';
  } else if (/(?:new\s+bank\s+(?:account|details)|wire\s+instructions\s+have\s+changed|invoice\s+payment\s+diversion|change\s+upi\s+id|new\s+upi\s+vpa|new\s+beneficiary\s+account)/i.test(combinedText)) {
    fraudDetected = true;
    fraudType = 'Payment';
    fraudEvidence = 'Bank account modification / UPI VPA modification / invoice redirection pattern.';
  }

  // -------------------------------------------------------------------------
  // 4. BEC DETECTION (With Indian Corporate / Vendor Context)
  // -------------------------------------------------------------------------
  let becDetected = false;
  let becType: 'Executive Impersonation' | 'Vendor Impersonation' | 'Payment Diversion' | 'Bank Detail Change' | 'Confidential Request' | 'Gift Card Request' | undefined;
  let becEvidence: string | undefined;

  const hasGiftCard = /gift\s*cards?|itunes|apple\s+gift|google\s+play|steam\s+card/i.test(combinedText);
  const hasWireUrgency = /wire\s+(?:transfer|funds)|same-?day\s+ach|transfer\s+immediately|urgent\s+(?:neft|rtgs|imps)|urgent\s+upi\s+transfer/i.test(combinedText);
  const hasExecutiveRole = /(?:ceo|chief\s+executive|director|managing\s+director|president|founder|chairman)/i.test(parsed.fromName || '') ||
                           /(?:ceo|director|managing\s+director|chairman)/i.test(subject);

  if (hasExecutiveRole && hasGiftCard) {
    becDetected = true;
    becType = 'Gift Card Request';
    becEvidence = `Executive identity claiming "${parsed.fromName}" requesting urgent acquisition of gift cards.`;
  } else if (hasExecutiveRole && (hasWireUrgency || /confidential/i.test(combinedText))) {
    becDetected = true;
    becType = 'Payment Diversion';
    becEvidence = `Executive persona requesting confidential financial transfer (NEFT/RTGS/Wire) outside standard procurement channels.`;
  } else if (/invoice\s+(?:payment|revised)|routing\s+number\s+updated|remit\s+to\s+new\s+account|gst\s+invoice\s+replacement|vendor\s+bank\s+account\s+change/i.test(combinedText)) {
    becDetected = true;
    becType = 'Bank Detail Change';
    becEvidence = 'Vendor payment modification request with altered banking or UPI coordinates.';
  }

  // -------------------------------------------------------------------------
  // 5. HTML STRUCTURE & OBFUSCATION ANALYSIS
  // -------------------------------------------------------------------------
  const htmlFindingsList: string[] = [];
  let hasHiddenElements = false;
  let hasInvisibleText = false;
  let hasSuspiciousForms = false;
  let trackingPixelsCount = 0;
  let mismatchedAnchorsCount = 0;

  if (bodyHtml) {
    // Hidden / zero font / off-screen
    if (/font-size:\s*0|display:\s*none|visibility:\s*hidden|opacity:\s*0|text-indent:\s*-\d{3,}/i.test(bodyHtml)) {
      hasHiddenElements = true;
      htmlFindingsList.push('Zero-font or display:none CSS styling identified (evasion technique).');
    }

    // Color contrast evasion (e.g. white text on white background)
    if (/color:\s*(?:#fff(?:fff)?|white)\s*;.*background(?:-color)?:\s*(?:#fff(?:fff)?|white)/i.test(bodyHtml)) {
      hasInvisibleText = true;
      htmlFindingsList.push('Invisible text evasion: white text rendered on white background.');
    }

    // Forms inside email body
    if (/<form[\s>]/i.test(bodyHtml)) {
      hasSuspiciousForms = true;
      htmlFindingsList.push('Embedded HTML <form> detected in email body (high credential theft hazard).');
    }

    // Tracking pixels (1x1 images)
    const imgMatches = bodyHtml.match(/<img[^>]+(?:width=['"]?1['"]?|height=['"]?1['"]?)[^>]*>/gi);
    if (imgMatches) {
      trackingPixelsCount = imgMatches.length;
      htmlFindingsList.push(`${trackingPixelsCount} single-pixel open-tracking elements detected.`);
    }

    // Mismatched Anchor text vs href
    const anchorMatches = bodyHtml.matchAll(/<a\s+[^>]*href=["']([^"']+)["'][^>]*>(.*?)<\/a>/gi);
    for (const match of anchorMatches) {
      const href = match[1];
      const linkText = match[2].replace(/<[^>]+>/g, '').trim();
      if (/https?:\/\/[a-zA-Z0-9.-]+/i.test(linkText)) {
        try {
          const textUrl = new URL(linkText.startsWith('http') ? linkText : `https://${linkText}`);
          const hrefUrl = new URL(href);
          if (textUrl.hostname.toLowerCase() !== hrefUrl.hostname.toLowerCase()) {
            mismatchedAnchorsCount++;
            htmlFindingsList.push(`Visual anchor spoofing: Displays "${textUrl.hostname}" but routes to "${hrefUrl.hostname}".`);
          }
        } catch {
          // parse error
        }
      }
    }
  }

  // -------------------------------------------------------------------------
  // 6. REQUESTED ACTION ("What is the email trying to make the user do?")
  // -------------------------------------------------------------------------
  let requestedAction: RequestedActionType = 'None / informational';
  let actionEvidence = 'Informational notice or communication with no immediate coercive call-to-action.';
  let actionRiskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical' = 'safe';

  if (credMatches || lowerCombined.includes('verify your password') || lowerCombined.includes('reset your password')) {
    requestedAction = 'Enter password';
    actionEvidence = 'Direct call-to-action urging the recipient to submit passwords or secret credentials.';
    actionRiskLevel = 'critical';
  } else if (lowerCombined.includes('enter otp') || lowerCombined.includes('two-factor') || lowerCombined.includes('authentication code')) {
    requestedAction = 'Enter OTP';
    actionEvidence = 'Prompting the user to reveal out-of-band one-time authentication codes.';
    actionRiskLevel = 'critical';
  } else if (hasWireUrgency || /transfer\s+(?:funds|money|\$|€|£|₹)/i.test(lowerCombined)) {
    requestedAction = 'Transfer money';
    actionEvidence = 'Requesting an urgent wire transfer or electronic funds movement.';
    actionRiskLevel = 'high';
  } else if (lowerCombined.includes('change bank details') || lowerCombined.includes('update banking')) {
    requestedAction = 'Change bank details';
    actionEvidence = 'Requesting alterations to payee accounts or financial routing numbers.';
    actionRiskLevel = 'high';
  } else if (lowerCombined.includes('download attachment') || /attached\s+(?:invoice|receipt|document|file)/i.test(lowerCombined)) {
    requestedAction = 'Download attachment';
    actionEvidence = 'Soliciting the recipient to open or execute an incoming attachment document.';
    actionRiskLevel = 'medium';
  } else if (lowerCombined.includes('login') || lowerCombined.includes('sign in') || lowerCombined.includes('log in')) {
    requestedAction = 'Log in';
    actionEvidence = 'Urging the user to follow an external link to authenticate an enterprise session.';
    actionRiskLevel = 'medium';
  } else if (lowerCombined.includes('unsubscribe') || parsed.headers['list-unsubscribe']) {
    if (lowerCombined.includes('deals') || lowerCombined.includes('newsletter') || lowerCombined.includes('updates')) {
      requestedAction = 'Read newsletter / browse articles';
      actionEvidence = 'Commercial marketing communication presenting product updates or newsletter content.';
      actionRiskLevel = 'safe';
    } else {
      requestedAction = 'Unsubscribe';
      actionEvidence = 'Communication providing standard opt-out or subscription management instructions.';
      actionRiskLevel = 'safe';
    }
  } else if (urls.length > 0) {
    requestedAction = 'Click a link';
    actionEvidence = `Directs recipient to visit external URL (${urls[0]?.domain || 'external link'}).`;
    actionRiskLevel = 'low';
  }

  // -------------------------------------------------------------------------
  // 7. EMAIL INTENT CLASSIFICATION
  // -------------------------------------------------------------------------
  let intentCategory: EmailIntentCategory = 'Unknown';
  let intentDisposition: EmailIntentDisposition = 'Benign';
  let intentConfidence = 85;
  let intentDescription = 'Standard correspondence.';

  if (credMatches || (requestedAction === 'Enter password' || requestedAction === 'Enter OTP')) {
    intentCategory = 'Credential Collection';
    intentDisposition = 'Malicious';
    intentConfidence = 96;
    intentDescription = 'High-risk intent to harvest user login credentials and session tokens.';
  } else if (becDetected) {
    intentCategory = becType === 'Gift Card Request' ? 'Executive Request' : 'Payment Request';
    intentDisposition = 'Malicious';
    intentConfidence = 94;
    intentDescription = 'Business Email Compromise impersonating leadership to manipulate financial transfers.';
  } else if (fraudDetected) {
    intentCategory = fraudType === 'Prize' ? 'Prize/Reward' : 'Finance';
    intentDisposition = 'Malicious';
    intentConfidence = 92;
    intentDescription = `Fraudulent solicitation exploiting ${fraudType.toLowerCase()} deception.`;
  } else if (/security\s+alert|unauthorized\s+access|password\s+reset|verify\s+your\s+identity/i.test(combinedText)) {
    intentCategory = 'Account Security';
    intentDisposition = 'Suspicious';
    intentConfidence = 88;
    intentDescription = 'Security notification or identity verification notice with potential spoofing risk.';
  } else if (parsed.headers['list-unsubscribe'] || /newsletter|weekly\s+digest|tech\s+insights/i.test(combinedText)) {
    intentCategory = 'Newsletter';
    intentDisposition = 'Benign';
    intentConfidence = 98;
    intentDescription = 'Standard periodic informational newsletter or curated content digest.';
  } else if (/discount|save\s+\d+%|special\s+offer|promo\b|coupon/i.test(combinedText)) {
    intentCategory = 'Marketing';
    intentDisposition = 'Benign';
    intentConfidence = 95;
    intentDescription = 'Commercial marketing or sales promotion campaign.';
  } else if (/invoice\b|receipt|payment\s+confirmation|order\s+#\d+/i.test(combinedText)) {
    intentCategory = 'Transaction';
    intentDisposition = 'Benign';
    intentConfidence = 90;
    intentDescription = 'Transactional notification regarding an order, payment, or service billing.';
  } else {
    intentCategory = 'Notification';
    intentDisposition = 'Benign';
    intentConfidence = 80;
    intentDescription = 'General system notification or standard correspondence.';
  }

  return {
    intent: {
      category: intentCategory,
      disposition: intentDisposition,
      confidence: intentConfidence,
      description: intentDescription
    },
    requestedAction: {
      action: requestedAction,
      evidence: actionEvidence,
      riskLevel: actionRiskLevel
    },
    subjectAnalysis: {
      flags: subjectFlags,
      sentiment: subjectSentiment,
      isSuspicious: subjectSuspicious
    },
    socialEngineering,
    fraudIndicators: {
      type: fraudType,
      detected: fraudDetected,
      evidence: fraudEvidence || undefined
    },
    becIndicators: {
      detected: becDetected,
      type: becType,
      evidence: becEvidence
    },
    htmlFindings: {
      hasHiddenElements,
      hasInvisibleText,
      hasSuspiciousForms,
      trackingPixelsCount,
      mismatchedAnchorsCount,
      findings: htmlFindingsList
    }
  };
}
