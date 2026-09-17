/**
 * MailTrace AI - Evidence-Based Spam & Bulk Mail Forensic Analyzer
 * Separates spam/bulk likelihood from malicious threat indicators
 * Purely deterministic: No Math.random(), no arbitrary score floors
 */

import { SpamAnalysis, SpamSignal, URLAnalysis, SpamClassificationType } from '../../src/types/forensics.js';
import { ParsedEmailRaw } from './emailParser.js';

export interface SpamWeights {
  senderSignals: number;
  promotionalContent: number;
  newsletterStructure: number;
  bulkMailIndicators: number;
  trackingInfrastructure: number;
  marketingCta: number;
  unsubscribe: number;
  deliverySignals: number;
  otherSpamIndicators: number;
}

export const DEFAULT_SPAM_WEIGHTS: SpamWeights = {
  senderSignals: 0.15,
  promotionalContent: 0.20,
  newsletterStructure: 0.15,
  bulkMailIndicators: 0.15,
  trackingInfrastructure: 0.10,
  marketingCta: 0.10,
  unsubscribe: 0.05,
  deliverySignals: 0.05,
  otherSpamIndicators: 0.05
};

export function analyzeSpamAndBulk(
  parsed: ParsedEmailRaw,
  urls: URLAnalysis[],
  weights: SpamWeights = DEFAULT_SPAM_WEIGHTS
): SpamAnalysis {
  const signals: SpamSignal[] = [];
  let sigId = 1;

  const addSignal = (sig: Omit<SpamSignal, 'id'>) => {
    signals.push({
      id: `spam-sig-${sigId++}`,
      ...sig
    });
  };

  const headers = parsed.headers;
  const rawHeaders = parsed.rawHeaders.toLowerCase();
  const subject = (parsed.subject || '').toLowerCase();
  const fromEmail = (parsed.from || '').toLowerCase();
  const fromDomain = (parsed.fromDomain || '').toLowerCase();
  const replyTo = (parsed.replyTo || '').toLowerCase();
  const returnPath = (parsed.returnPath || '').toLowerCase();
  const bodyText = (parsed.bodyText || '').toLowerCase();
  const bodyHtml = (parsed.bodyHtml || '').toLowerCase();
  const combinedBody = `${bodyText} ${bodyHtml}`;

  // =========================================================================
  // 1. SENDER & MAILING LIST SIGNALS (Weight: 15%)
  // =========================================================================
  let senderScore = 0;
  const senderEvidence: string[] = [];

  // Local part patterns
  const newsletterSenderPatterns = ['newsletter@', 'news@', 'updates@', 'digest@', 'bulletin@'];
  const marketingSenderPatterns = ['marketing@', 'promo@', 'promotions@', 'deals@', 'offers@', 'sales@', 'specials@', 'discount@', 'shop@'];
  const notificationSenderPatterns = ['no-reply@', 'noreply@', 'donotreply@', 'notifications@', 'mailer@', 'bounce@', 'bounces@'];

  const isNewsletterSender = newsletterSenderPatterns.some(p => fromEmail.includes(p));
  const isMarketingSender = marketingSenderPatterns.some(p => fromEmail.includes(p));
  const isNotificationSender = notificationSenderPatterns.some(p => fromEmail.includes(p));

  // Subdomain patterns (e.g. em.discountwalas.com, mail.company.com, mktg.brand.com)
  const isMarketingSubdomain = /(?:^|\.)(?:em|mail|mktg|campaign|news|updates|delivery|email|e|promo|msg|bounce)\.[a-z0-9.-]+\.[a-z]{2,}$/i.test(fromDomain);

  // Return-Path / Bounces pattern
  const isBouncesReturnPath = returnPath.includes('bounce') || returnPath.includes('mailer-daemon') || returnPath.includes('postmaster');

  // Major bulk ESP infrastructure headers
  const isSendGrid = rawHeaders.includes('sendgrid.net') || rawHeaders.includes('x-sg-') || rawHeaders.includes('x-sendgrid');
  const isMailgun = rawHeaders.includes('mailgun.org') || rawHeaders.includes('x-mailgun-');
  const isAmazonSES = rawHeaders.includes('amazonses.com') || rawHeaders.includes('x-ses-');
  const isMailchimp = rawHeaders.includes('mailchimpapp.net') || rawHeaders.includes('mcsv.net') || rawHeaders.includes('x-mc-user');
  const isBraze = rawHeaders.includes('braze') || rawHeaders.includes('x-braze');
  const isKlaviyo = rawHeaders.includes('klaviyo');
  const isConstantContact = rawHeaders.includes('constantcontact');
  const isKnownEsp = isSendGrid || isMailgun || isAmazonSES || isMailchimp || isBraze || isKlaviyo || isConstantContact;

  if (isNewsletterSender) {
    senderScore += 50;
    senderEvidence.push('Newsletter mailbox prefix (e.g. newsletter@)');
  }
  if (isMarketingSender) {
    senderScore += 55;
    senderEvidence.push('Marketing / promotional mailbox prefix');
  }
  if (isNotificationSender && !isNewsletterSender && !isMarketingSender) {
    senderScore += 30;
    senderEvidence.push('Automated notification / no-reply mailbox prefix');
  }
  if (isMarketingSubdomain) {
    senderScore += 30;
    senderEvidence.push(`Dedicated marketing / campaign transmission subdomain (${fromDomain})`);
  }
  if (isBouncesReturnPath) {
    senderScore += 25;
    senderEvidence.push(`Automated bounce-handler return path (${returnPath})`);
  }
  if (isKnownEsp) {
    senderScore += 30;
    senderEvidence.push('Commercial Email Service Provider (ESP) relay infrastructure');
  }

  senderScore = Math.min(100, senderScore);

  if (senderScore > 0) {
    addSignal({
      category: 'sender-signals',
      name: 'Bulk / Marketing Sender Profile',
      value: senderScore,
      weight: weights.senderSignals,
      evidence: senderEvidence.join('; '),
      pointsContribution: Number((senderScore * weights.senderSignals).toFixed(1))
    });
  }

  // =========================================================================
  // 2. PROMOTIONAL CONTENT (Weight: 20%)
  // =========================================================================
  let promoScore = 0;
  const promoEvidence: string[] = [];

  const promotionalPhrases = [
    'deal', 'deals', 'offer', 'offers', 'discount', 'discounts', '50% off', '20% off', '30% off', '40% off', '60% off', '70% off', '% off',
    'shop now', 'explore deals', 'limited offer', 'limited time offer', 'subscribe', 'newsletter',
    'daily deals', 'recommendations', 'coupon', 'promo', 'promo code', 'voucher', 'sale', 'clearance',
    'free shipping', 'bestsellers', 'exclusive', 'weekend specials', 'special offer', 'save up to',
    'order now', 'buy now', 'hurry', 'exclusive deals', 'flash sale', 'new arrivals', 'catalog', 'best price',
    'leads', 'b2b', 'pipeline', 'outbound', 'half price', 'database access', 'claim discount', 'opt out', 'opt-out'
  ];

  let matchedPromoTerms: string[] = [];
  for (const term of promotionalPhrases) {
    if (combinedBody.includes(term) || subject.includes(term)) {
      matchedPromoTerms.push(term);
    }
  }

  // Deduplicate
  matchedPromoTerms = Array.from(new Set(matchedPromoTerms));

  if (matchedPromoTerms.length >= 8) {
    promoScore = 95;
    promoEvidence.push(`High density of commercial terms (${matchedPromoTerms.slice(0, 6).join(', ')}, +${matchedPromoTerms.length - 6} more)`);
  } else if (matchedPromoTerms.length >= 5) {
    promoScore = 80;
    promoEvidence.push(`Multiple promotional discount keywords detected (${matchedPromoTerms.join(', ')})`);
  } else if (matchedPromoTerms.length >= 3) {
    promoScore = 55;
    promoEvidence.push(`Promotional offer keywords detected (${matchedPromoTerms.join(', ')})`);
  } else if (matchedPromoTerms.length >= 1) {
    promoScore = 25;
    promoEvidence.push(`Single commercial reference detected (${matchedPromoTerms[0]})`);
  }

  // Subject line promotional inspection
  if (/(\d+%\s*off|deal|discount|sale|exclusive|special|offer|save|weekend)/i.test(subject)) {
    promoScore = Math.min(100, promoScore + 20);
    promoEvidence.push('Subject line contains commercial promotion keywords');
  }

  promoScore = Math.min(100, promoScore);

  if (promoScore > 0) {
    addSignal({
      category: 'promotional-content',
      name: 'Commercial & Promotional Terminology',
      value: promoScore,
      weight: weights.promotionalContent,
      evidence: promoEvidence.join('; '),
      pointsContribution: Number((promoScore * weights.promotionalContent).toFixed(1))
    });
  }

  // =========================================================================
  // 3. NEWSLETTER STRUCTURE (Weight: 15%)
  // =========================================================================
  let structScore = 0;
  const structEvidence: string[] = [];

  const hasMultipleArticles = (bodyHtml.match(/<table/gi) || []).length >= 3 || 
                             (bodyHtml.match(/<h[2-4]/gi) || []).length >= 3 ||
                             (combinedBody.match(/(?:update|story|article|feature|item|deal)\s*#?\d+/gi) || []).length >= 2 ||
                             /5\s+new\s+updates|weekly\s+digest|newsletter\s+edition|issue\s+#\d+/i.test(combinedBody);

  const hasViewInBrowser = combinedBody.includes('view in browser') || 
                           combinedBody.includes('view online') || 
                           combinedBody.includes('web version') || 
                           combinedBody.includes('having trouble viewing');

  const hasDigestHeadings = /top stories|featured updates|what's new|in this issue|recommended for you|this week's picks/i.test(combinedBody);

  const hasMarketingNav = /shop\s*\|\s*deals|men\s*\|\s*women|view catalog|browse categories/i.test(combinedBody);

  if (hasMultipleArticles) {
    structScore += 50;
    structEvidence.push('Multi-section article/item digest layout format');
  }
  if (hasViewInBrowser) {
    structScore += 30;
    structEvidence.push('"View in browser / online version" web mirroring link');
  }
  if (hasDigestHeadings) {
    structScore += 25;
    structEvidence.push('Curated digest topical section headings');
  }
  if (hasMarketingNav) {
    structScore += 20;
    structEvidence.push('Top navigation department bar structure');
  }

  structScore = Math.min(100, structScore);

  if (structScore > 0) {
    addSignal({
      category: 'newsletter-structure',
      name: 'Newsletter Digest Structure',
      value: structScore,
      weight: weights.newsletterStructure,
      evidence: structEvidence.join('; '),
      pointsContribution: Number((structScore * weights.newsletterStructure).toFixed(1))
    });
  }

  // =========================================================================
  // 4. BULK-MAIL INDICATORS (Weight: 15%)
  // =========================================================================
  let bulkScore = 0;
  const bulkEvidence: string[] = [];

  const listUnsubHeader = headers['list-unsubscribe'] || headers['list-unsubscribe-post'];
  const listIdHeader = headers['list-id'];
  const listHelpHeader = headers['list-help'] || headers['list-owner'] || headers['list-post'];
  const precedence = (headers['precedence'] || '').toLowerCase();
  const feedbackId = headers['feedback-id'] || headers['x-feedback-id'];
  const campaignHeaders = headers['x-campaign'] || headers['x-campaign-id'] || headers['x-mpt-campaign'] || headers['x-mailgun-campaign-id'];

  if (listUnsubHeader) {
    bulkScore += 45;
    bulkEvidence.push('RFC 2369 List-Unsubscribe header present');
  }
  if (listIdHeader) {
    bulkScore += 35;
    bulkEvidence.push(`RFC 2919 List-ID header present (${listIdHeader})`);
  }
  if (precedence === 'bulk' || precedence === 'list') {
    bulkScore += 55;
    bulkEvidence.push(`Precedence header set to "${precedence}"`);
  }
  if (feedbackId) {
    bulkScore += 25;
    bulkEvidence.push('FBL (Feedback Loop) ID header present');
  }
  if (campaignHeaders) {
    bulkScore += 30;
    bulkEvidence.push('Mailing campaign tracking identifier header present');
  }
  if (listHelpHeader) {
    bulkScore += 15;
    bulkEvidence.push('Mailing list control headers present (RFC 2369)');
  }

  bulkScore = Math.min(100, bulkScore);

  if (bulkScore > 0) {
    addSignal({
      category: 'bulk-indicators',
      name: 'Mailing List & ESP Headers',
      value: bulkScore,
      weight: weights.bulkMailIndicators,
      evidence: bulkEvidence.join('; '),
      pointsContribution: Number((bulkScore * weights.bulkMailIndicators).toFixed(1))
    });
  }

  // =========================================================================
  // 5. TRACKING INFRASTRUCTURE (Weight: 10%)
  // =========================================================================
  let trackingScore = 0;
  const trackingEvidence: string[] = [];

  const marketingUrls = urls.filter(u => u.urlType === 'MARKETING_TRACKING' || u.url.includes('/campaigns/') || u.url.includes('/track-url/') || u.url.includes('/track/') || u.url.includes('utm_'));
  const trackingPixels = urls.filter(u => u.isTrackingPixel);

  const hasTrackingPixel = trackingPixels.length > 0 || 
                          combinedBody.includes('pixel.gif') || 
                          /width\s*=\s*["']?1["']?\s+height\s*=\s*["']?1["']?/i.test(bodyHtml);

  if (hasTrackingPixel) {
    trackingScore += 50;
    trackingEvidence.push('1x1 transparent tracking pixel detected (open telemetry)');
  }
  if (marketingUrls.length >= 4) {
    trackingScore += 50;
    trackingEvidence.push(`Extensive campaign redirect click-tracking URLs (${marketingUrls.length} links)`);
  } else if (marketingUrls.length >= 1) {
    trackingScore += 30;
    trackingEvidence.push(`Campaign click-tracking redirect URL identified (${marketingUrls[0].domain})`);
  }

  trackingScore = Math.min(100, trackingScore);

  if (trackingScore > 0) {
    addSignal({
      category: 'tracking-infrastructure',
      name: 'Campaign Telemetry & Tracking Infrastructure',
      value: trackingScore,
      weight: weights.trackingInfrastructure,
      evidence: trackingEvidence.join('; '),
      pointsContribution: Number((trackingScore * weights.trackingInfrastructure).toFixed(1))
    });
  }

  // =========================================================================
  // 6. MARKETING CTA / COMMERCIAL INTENT (Weight: 10%)
  // =========================================================================
  let ctaScore = 0;
  const ctaEvidence: string[] = [];

  const ctaPatterns = [
    'shop now', 'claim offer', 'explore deals', 'view collection', 'subscribe now',
    'buy now', 'order today', 'get started', 'learn more', 'redeem coupon', 'see details',
    'view deals', 'start saving', 'browse deals', 'read more', 'check it out'
  ];

  let matchedCtas: string[] = [];
  for (const cta of ctaPatterns) {
    if (combinedBody.includes(cta)) {
      matchedCtas.push(cta);
    }
  }

  if (matchedCtas.length >= 3) {
    ctaScore = 90;
    ctaEvidence.push(`Multiple commercial Call-to-Action phrases ("${matchedCtas.slice(0, 3).join('", "')}")`);
  } else if (matchedCtas.length >= 1) {
    ctaScore = 50;
    ctaEvidence.push(`Commercial Call-to-Action button / link ("${matchedCtas[0]}")`);
  }

  ctaScore = Math.min(100, ctaScore);

  if (ctaScore > 0) {
    addSignal({
      category: 'marketing-cta',
      name: 'Commercial Call-to-Action (CTA)',
      value: ctaScore,
      weight: weights.marketingCta,
      evidence: ctaEvidence.join('; '),
      pointsContribution: Number((ctaScore * weights.marketingCta).toFixed(1))
    });
  }

  // =========================================================================
  // 7. UNSUBSCRIBE / LIST MANAGEMENT (Weight: 5%)
  // Section 22: Unsubscribe is NOT a threat signal!
  // =========================================================================
  let unsubScore = 0;
  const unsubEvidence: string[] = [];

  const hasUnsubscribeText = /unsubscribe|opt-out|optout|manage\s+preferences|email\s+preferences|change\s+subscription/i.test(combinedBody);
  const hasUnsubscribeHeader = !!listUnsubHeader;
  const hasUnsubscribe = hasUnsubscribeText || hasUnsubscribeHeader;

  if (hasUnsubscribeHeader && hasUnsubscribeText) {
    unsubScore = 95;
    unsubEvidence.push('RFC 2369 List-Unsubscribe header and in-body unsubscribe link verified');
  } else if (hasUnsubscribeHeader) {
    unsubScore = 80;
    unsubEvidence.push('RFC 2369 List-Unsubscribe header verified');
  } else if (hasUnsubscribeText) {
    unsubScore = 75;
    unsubEvidence.push('In-body opt-out / unsubscribe mechanism identified');
  }

  unsubScore = Math.min(100, unsubScore);

  if (unsubScore > 0) {
    addSignal({
      category: 'unsubscribe',
      name: 'Unsubscribe / Opt-Out Mechanism',
      value: unsubScore,
      weight: weights.unsubscribe,
      evidence: unsubEvidence.join('; '),
      pointsContribution: Number((unsubScore * weights.unsubscribe).toFixed(1))
    });
  }

  // =========================================================================
  // 8. DELIVERY SIGNALS & LEGAL COMPLIANCE (Weight: 5%)
  // =========================================================================
  let deliveryScore = 0;
  const deliveryEvidence: string[] = [];

  const hasPhysicalAddress = /\b\d{1,5}\s+[a-zA-Z0-9\s.,#-]+(?:street|st|avenue|ave|road|rd|blvd|boulevard|suite|ste|floor|fl|box|p\.?o\.?\s*box|india|usa|us|uk)\b/i.test(combinedBody) ||
                            /registered\s+office|postal\s+address|headquarters/i.test(combinedBody);

  const hasPrivacyLink = /privacy\s+policy|terms\s+(?:of\s+service|and\s+conditions)/i.test(combinedBody);
  const hasCopyrightNotice = /(?:©|copyright|\(c\))\s*(?:20\d\d|19\d\d)?/i.test(combinedBody);

  if (hasPhysicalAddress) {
    deliveryScore += 45;
    deliveryEvidence.push('CAN-SPAM compliant physical mailing address detected in footer');
  }
  if (hasPrivacyLink) {
    deliveryScore += 35;
    deliveryEvidence.push('Privacy policy and terms of service links detected');
  }
  if (hasCopyrightNotice) {
    deliveryScore += 25;
    deliveryEvidence.push('Commercial corporate copyright notice identified');
  }

  deliveryScore = Math.min(100, deliveryScore);

  if (deliveryScore > 0) {
    addSignal({
      category: 'delivery-signals',
      name: 'Commercial Legal & Compliance Disclosures',
      value: deliveryScore,
      weight: weights.deliverySignals,
      evidence: deliveryEvidence.join('; '),
      pointsContribution: Number((deliveryScore * weights.deliverySignals).toFixed(1))
    });
  }

  // =========================================================================
  // 9. OTHER SPAM / FREQUENCY INDICATORS (Weight: 5%)
  // =========================================================================
  let otherScore = 0;
  if (/free|gift|bonus|winner|claim|act now|limited offer/i.test(subject)) {
    otherScore += 40;
  }
  if (combinedBody.includes('to ensure delivery to your inbox') || combinedBody.includes('add us to your address book')) {
    otherScore += 35;
  }
  otherScore = Math.min(100, otherScore);

  if (otherScore > 0) {
    addSignal({
      category: 'other',
      name: 'Deliverability Whitelist Instructions',
      value: otherScore,
      weight: weights.otherSpamIndicators,
      evidence: 'Contains sender inbox-whitelisting instructions standard in automated mass mailers.',
      pointsContribution: Number((otherScore * weights.otherSpamIndicators).toFixed(1))
    });
  }

  // =========================================================================
  // CALCULATE WEIGHTED SPAM / BULK SCORE
  // =========================================================================
  const weightedScore = Number((
    (senderScore * weights.senderSignals) +
    (promoScore * weights.promotionalContent) +
    (structScore * weights.newsletterStructure) +
    (bulkScore * weights.bulkMailIndicators) +
    (trackingScore * weights.trackingInfrastructure) +
    (ctaScore * weights.marketingCta) +
    (unsubScore * weights.unsubscribe) +
    (deliveryScore * weights.deliverySignals) +
    (otherScore * weights.otherSpamIndicators)
  ).toFixed(2));

  // High alignment bonus: If multiple commercial categories are triggered together
  const triggeredCategoriesCount = [
    senderScore >= 30,
    promoScore >= 30,
    structScore >= 30,
    bulkScore >= 30,
    trackingScore >= 30,
    ctaScore >= 30,
    unsubScore >= 30
  ].filter(Boolean).length;

  let bulkSynergyBonus = 0;
  if (triggeredCategoriesCount >= 5) {
    bulkSynergyBonus = 8;
  } else if (triggeredCategoriesCount >= 4) {
    bulkSynergyBonus = 5;
  } else if (triggeredCategoriesCount >= 3) {
    bulkSynergyBonus = 3;
  }

  const finalSpamScore = Math.min(100, Math.max(0, Math.round(weightedScore + bulkSynergyBonus)));

  // Spam/Bulk Likelihood Scale
  // 0–19 None, 20–39 Low, 40–59 Possible, 60–79 Likely, 80–100 Strong
  let level: 'None' | 'Low' | 'Possible' | 'Likely' | 'Strong' = 'None';
  if (finalSpamScore >= 80) level = 'Strong';
  else if (finalSpamScore >= 60) level = 'Likely';
  else if (finalSpamScore >= 40) level = 'Possible';
  else if (finalSpamScore >= 20) level = 'Low';
  else level = 'None';

  // Classification logic
  let classification: SpamClassificationType = 'none';
  let classificationLabel = 'Non-Bulk Communication';

  if (finalSpamScore < 20) {
    classification = 'none';
    classificationLabel = 'Direct / Personal Message';
  } else if (structScore >= 50 && (hasUnsubscribe || senderScore >= 40)) {
    classification = 'newsletter';
    classificationLabel = 'Promotional Newsletter';
  } else if (promoScore >= 50 || ctaScore >= 50) {
    classification = 'promotional';
    classificationLabel = 'Promotional Marketing Offer';
  } else if (bulkScore >= 40 || hasUnsubscribe) {
    classification = 'bulk';
    classificationLabel = 'Bulk Commercial Communication';
  } else {
    classification = 'spam';
    classificationLabel = 'Unsolicited Marketing / Spam';
  }

  // Confidence in spam classification
  let confidence = 85;
  if (triggeredCategoriesCount >= 4) confidence = 95;
  else if (triggeredCategoriesCount >= 2) confidence = 88;
  else confidence = 75;

  return {
    score: finalSpamScore,
    classification,
    classificationLabel,
    confidence,
    level,
    signals,
    breakdown: {
      senderSignalsScore: senderScore,
      promotionalContentScore: promoScore,
      newsletterStructureScore: structScore,
      bulkMailIndicatorsScore: bulkScore,
      trackingInfrastructureScore: trackingScore,
      marketingCtaScore: ctaScore,
      unsubscribeScore: unsubScore,
      deliverySignalsScore: deliveryScore
    },
    hasUnsubscribe,
    hasTrackingPixel,
    trackingPixelDetails: hasTrackingPixel ? '1x1 engagement pixel present in HTML body.' : undefined,
    marketingUrlsCount: marketingUrls.length
  };
}
