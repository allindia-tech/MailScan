/**
 * MailTrace AI - URL Analysis & Security Sandbox Simulation
 * Extracts and inspects URLs without executing or requesting them in the browser
 */

import { URLAnalysis, ThreatSeverity } from '../../src/types/forensics.js';

export function analyzeURLs(bodyText: string, bodyHtml: string): URLAnalysis[] {
  const combined = `${bodyText} ${bodyHtml}`;
  
  // 1. Extract 1x1 tracking pixels from HTML
  const trackingPixelUrls = new Set<string>();
  const pixelTagRegex = /<img[^>]+(?:width\s*=\s*["']?1["']?\s+height\s*=\s*["']?1["']?|height\s*=\s*["']?1["']?\s+width\s*=\s*["']?1["']?|style\s*=\s*["'][^"']*(?:width:\s*1px|display:\s*none)[^"']*)[^>]*src\s*=\s*["']([^"']+)["']/gi;
  let pixelMatch: RegExpExecArray | null;
  while ((pixelMatch = pixelTagRegex.exec(bodyHtml)) !== null) {
    if (pixelMatch[1]) {
      trackingPixelUrls.add(pixelMatch[1].trim());
    }
  }

  // Also check for common pixel path patterns
  const pixelPathRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`[\]]+(?:\/open\/|\/track-open|\/pixel|\/beacon|pixel\.gif|\/tr\?)[^\s<>"'{}|\\^`[\]]*/gi;
  const pixelMatches = combined.match(pixelPathRegex) || [];
  for (const pm of pixelMatches) {
    trackingPixelUrls.add(pm.trim());
  }

  // 2. Extract standard URLs
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`[\]]+/gi;
  const matches = Array.from(new Set(combined.match(urlRegex) || []));
  
  // Ensure pixel URLs are in matches set
  for (const px of trackingPixelUrls) {
    if (!matches.includes(px)) {
      matches.push(px);
    }
  }

  const results: URLAnalysis[] = [];
  let idCounter = 1;

  for (const rawUrl of matches) {
    let cleanUrl = rawUrl;
    if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
      cleanUrl = 'http://' + cleanUrl;
    }

    let urlObj: URL;
    try {
      urlObj = new URL(cleanUrl);
    } catch {
      continue;
    }

    const hostname = urlObj.hostname.toLowerCase();
    const pathname = urlObj.pathname.toLowerCase();
    const search = urlObj.search.toLowerCase();
    const isHttps = urlObj.protocol === 'https:';

    // Tracking pixel check
    const isTrackingPixel = trackingPixelUrls.has(rawUrl) || 
      pathname.includes('/pixel') || 
      pathname.includes('/open/') || 
      pathname.includes('/track-open') || 
      pathname.endsWith('.gif') && (pathname.includes('pixel') || pathname.includes('track'));

    // Forensic features
    const isIpUrl = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const isPunycode = hostname.startsWith('xn--');
    const isShortened = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'cutt.ly'].includes(hostname);

    // Marketing tracking characteristics
    const isMarketingTracking = 
      pathname.includes('/campaigns/') || 
      pathname.includes('/track-url/') || 
      pathname.includes('/track/') || 
      pathname.includes('/click') || 
      pathname.includes('/clk/') || 
      pathname.includes('/trk/') || 
      search.includes('utm_') || 
      hostname.startsWith('m.mc.') || 
      hostname.startsWith('click.') || 
      hostname.startsWith('track.') || 
      hostname.startsWith('trk.') || 
      hostname.startsWith('em.');

    // Unsubscribe link characteristics
    const isUnsubscribe = pathname.includes('unsubscribe') || 
      pathname.includes('opt-out') || 
      pathname.includes('optout') || 
      pathname.includes('preferences') || 
      search.includes('unsubscribe');
    
    // Credential path signatures (excluding unsubscribe or legitimate marketing paths)
    const credentialKeywords = ['login', 'signin', 'auth', 'verify', 'security', 'password', 'portal', 'webapps/mpp', 'cancel-wire'];
    const hasCredentialPath = !isUnsubscribe && credentialKeywords.some(kw => pathname.includes(kw) || (search.includes(kw) && !search.includes('token=')));

    // Suspicious parameters - discriminate between marketing tokens and exploit tokens
    const suspiciousParams: string[] = [];
    if (search.includes('redirect=') && !isMarketingTracking) {
      suspiciousParams.push('open_redirect_potential');
    }
    if (search.includes('user=') || search.includes('email=')) {
      suspiciousParams.push('prefilled_credential_param');
    }

    // Lookalike checks
    const isLookalike = hostname.includes('paypa1') || hostname.includes('micros0ft') || hostname.includes('office365-session');
    const suspiciousTld = ['.top', '.cc', '.ru', '.biz', '.icu', '.xyz', '.click'].some(t => hostname.endsWith(t));

    // Determine URL classification
    let urlType: 'MARKETING_TRACKING' | 'SUSPICIOUS_REDIRECT' | 'MALICIOUS' | 'BENIGN' = 'BENIGN';
    if (isLookalike || (isIpUrl && hasCredentialPath)) {
      urlType = 'MALICIOUS';
    } else if (suspiciousParams.includes('open_redirect_potential') && !isMarketingTracking) {
      urlType = 'SUSPICIOUS_REDIRECT';
    } else if (isMarketingTracking || isTrackingPixel) {
      urlType = 'MARKETING_TRACKING';
    } else {
      urlType = 'BENIGN';
    }

    // Compute URL risk score (evidence-based Threat Risk only)
    let riskScore = 0;
    if (isIpUrl) riskScore += 50;
    if (!isHttps && !isMarketingTracking) riskScore += 10;
    if (isLookalike) riskScore += 50;
    if (hasCredentialPath) riskScore += 35;
    if (suspiciousTld) riskScore += 25;
    if (suspiciousParams.length > 0) riskScore += 15;
    if (isShortened) riskScore += 20;

    // Marketing tracking and tracking pixels do NOT inherently carry high threat risk
    if (isMarketingTracking && !hasCredentialPath && !isLookalike && !isIpUrl) {
      riskScore = Math.min(riskScore, 10);
    }
    if (isTrackingPixel) {
      riskScore = 0;
    }
    if (isUnsubscribe && !isLookalike) {
      riskScore = 0;
    }

    // Cap at 100
    riskScore = Math.min(100, Math.max(0, riskScore));

    let risk: ThreatSeverity = 'LOW';
    let status: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNRESOLVED' = 'CLEAN';

    if (riskScore >= 80) {
      risk = 'CRITICAL';
      status = 'MALICIOUS';
    } else if (riskScore >= 60) {
      risk = 'HIGH';
      status = 'SUSPICIOUS';
    } else if (riskScore >= 40) {
      risk = 'MEDIUM';
      status = 'SUSPICIOUS';
    }

    let analysisNote = 'Standard web resource URI.';
    if (isTrackingPixel) {
      analysisNote = 'Tracking pixel detected (1x1 read beacon utilized for campaign engagement telemetry; benign marketing signal).';
    } else if (isUnsubscribe) {
      analysisNote = 'Opt-out / Unsubscribe mechanism verified (List management link).';
    } else if (isMarketingTracking) {
      analysisNote = 'Marketing campaign tracking URL (Click engagement telemetry; contributes to spam/bulk likelihood, non-malicious).';
    } else if (isIpUrl) {
      analysisNote = 'Critical anomaly: Bare IP host address obscures domain identity and bypasses DNS reputation filters.';
    } else if (isLookalike) {
      analysisNote = 'Deceptive homoglyph domain hosting simulated authentication landing page.';
    } else if (hasCredentialPath) {
      analysisNote = 'Target path emulates enterprise single-sign-on / payment confirmation portal.';
    }

    results.push({
      id: `url-${idCounter++}`,
      url: cleanUrl,
      domain: hostname,
      riskScore,
      risk,
      redirectChain: [cleanUrl, isShortened ? `https://unmasked-target.net/final` : cleanUrl],
      status,
      https: isHttps,
      isIpUrl,
      isShortened,
      isPunycode,
      suspiciousParams,
      hasCredentialPath,
      suspiciousTld,
      analysisNote,
      urlType,
      isTrackingPixel
    });
  }

  return results;
}
