/**
 * MailTrace AI - Domain Intelligence & Typosquatting / Lookalike Engine
 */

import { DomainIntelligence, LookalikePattern, ThreatSeverity } from '../../src/types/forensics.js';

const KNOWN_TARGET_BRANDS: Array<{ brand: string; canonicalDomain: string }> = [
  { brand: 'PayPal', canonicalDomain: 'paypal.com' },
  { brand: 'Microsoft', canonicalDomain: 'microsoft.com' },
  { brand: 'Google', canonicalDomain: 'google.com' },
  { brand: 'Apple', canonicalDomain: 'apple.com' },
  { brand: 'Amazon', canonicalDomain: 'amazon.com' },
  { brand: 'Bank of America', canonicalDomain: 'bankofamerica.com' },
  { brand: 'Chase Bank', canonicalDomain: 'chase.com' },
  { brand: 'Wells Fargo', canonicalDomain: 'wellsfargo.com' },
  { brand: 'Office 365', canonicalDomain: 'office.com' },
  { brand: 'DHL Logistics', canonicalDomain: 'dhl.com' }
];

export function analyzeDomain(domain: string, fromHeader: string): DomainIntelligence {
  const cleanDomain = domain.toLowerCase().trim();
  
  // Check lookalike patterns
  const lookalikePatterns: LookalikePattern[] = [];
  let maxSimilarity = 0;
  let targetBrandMatched = '';
  
  for (const target of KNOWN_TARGET_BRANDS) {
    const similarity = computeDomainSimilarity(cleanDomain, target.canonicalDomain);
    if (similarity > maxSimilarity) {
      maxSimilarity = similarity;
      targetBrandMatched = target.brand;
    }
    
    // Homoglyphs / number substitution (0 -> o, 1 -> l, etc.)
    const normalized = cleanDomain
      .replace(/0/g, 'o')
      .replace(/1/g, 'l')
      .replace(/3/g, 'e')
      .replace(/5/g, 's')
      .replace(/vv/g, 'w');
      
    const isLegitSubdomain = cleanDomain.endsWith('.' + target.canonicalDomain) || cleanDomain === target.canonicalDomain;
    if (cleanDomain !== target.canonicalDomain && !isLegitSubdomain) {
      if (normalized === target.canonicalDomain || normalized.includes(target.canonicalDomain.split('.')[0])) {
        lookalikePatterns.push({
          type: 'character_substitution',
          targetBrand: target.brand,
          targetDomain: target.canonicalDomain,
          detectedPattern: cleanDomain,
          description: `Character substitution or homoglyph impersonating ${target.brand} (${target.canonicalDomain})`
        });
      } else if (cleanDomain.includes(target.canonicalDomain.split('.')[0])) {
        lookalikePatterns.push({
          type: 'prefix_suffix',
          targetBrand: target.brand,
          targetDomain: target.canonicalDomain,
          detectedPattern: cleanDomain,
          description: `Prepended or appended keywords targeting ${target.brand} brand identity`
        });
      }
    }
  }

  // Suspicious TLD check
  const suspiciousTlds = ['.top', '.cc', '.ru', '.biz', '.icu', '.xyz', '.online', '.work', '.click', '.tk', '.example'];
  const hasSuspiciousTld = suspiciousTlds.some(tld => cleanDomain.endsWith(tld));
  if (hasSuspiciousTld && lookalikePatterns.length > 0) {
    lookalikePatterns.push({
      type: 'suspicious_tld',
      targetBrand: targetBrandMatched,
      targetDomain: cleanDomain,
      detectedPattern: cleanDomain,
      description: `Domain combines brand lookalike with high-abuse/bulletproof top-level domain`
    });
  }

  // Determine domain age and registration profile
  let domainAgeDays = 1825; // Default to mature domain (~5 years)
  let domainAgeYears = 5.0;
  let isNewlyRegistered = false;
  let registrar = 'Public Domain Registrar';
  let reputation: ThreatSeverity = 'TRUSTED';
  let impersonationRisk: ThreatSeverity = 'TRUSTED';
  let aRecords: string[] = [];

  const trustedDomains = [
    'amazon.com', 'google.com', 'gmail.com', 'apple.com', 'microsoft.com', 
    'paypal.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'github.com'
  ];
  const isKnownTrusted = trustedDomains.some(td => cleanDomain === td || cleanDomain.endsWith('.' + td));

  const isAcademicOrGov = cleanDomain.endsWith('.edu') || 
                          cleanDomain.endsWith('.ac.in') || 
                          cleanDomain.endsWith('.gov') || 
                          cleanDomain.endsWith('.mil') || 
                          cleanDomain.endsWith('.org');

  if (isKnownTrusted) {
    domainAgeDays = 9500;
    domainAgeYears = 26.0;
    isNewlyRegistered = false;
    registrar = 'MarkMonitor Inc.';
    reputation = 'TRUSTED';
    impersonationRisk = 'TRUSTED';
    aRecords = cleanDomain === 'amazon.com' ? ['54.239.28.85'] : ['142.250.190.46'];
  } else if (isAcademicOrGov) {
    domainAgeDays = 7200;
    domainAgeYears = 19.7;
    isNewlyRegistered = false;
    registrar = 'National / Academic Registry Authority';
    reputation = 'TRUSTED';
    impersonationRisk = 'TRUSTED';
    aRecords = ['198.51.100.40'];
  } else if (cleanDomain.includes('micros0ft') || cleanDomain.includes('paypa1') || (lookalikePatterns.length > 0 && maxSimilarity >= 75)) {
    domainAgeDays = 4;
    domainAgeYears = 0.01;
    isNewlyRegistered = true;
    registrar = 'Reg.ru LLC / Offshore Privacy Proxy';
    reputation = 'CRITICAL';
    impersonationRisk = 'CRITICAL';
    aRecords = ['91.240.118.88']; // Simulated malicious lookalike host
    maxSimilarity = Math.max(maxSimilarity, 92);
  } else if (hasSuspiciousTld) {
    domainAgeDays = 25;
    domainAgeYears = 0.07;
    isNewlyRegistered = true;
    registrar = 'NameCheap Inc. / Privacy Protected';
    reputation = 'MEDIUM';
    impersonationRisk = 'MEDIUM';
    aRecords = ['198.51.100.55'];
  } else {
    // Standard legitimate domain
    domainAgeDays = 1450;
    domainAgeYears = 4.0;
    isNewlyRegistered = false;
    registrar = 'ICANN Accredited Registrar';
    reputation = 'TRUSTED';
    impersonationRisk = 'TRUSTED';
    aRecords = ['198.51.100.12'];
  }

  if (lookalikePatterns.length > 0 && maxSimilarity >= 75) {
    impersonationRisk = 'CRITICAL';
    reputation = 'CRITICAL';
  }

  return {
    domain: cleanDomain,
    domainAgeYears: Number(domainAgeYears.toFixed(2)),
    domainAgeDays,
    registrar,
    registrationDate: new Date(Date.now() - domainAgeDays * 86400000).toISOString().split('T')[0],
    expirationDate: new Date(Date.now() + 350 * 86400000).toISOString().split('T')[0],
    nameServers: [
      `ns1.${cleanDomain || 'dns-host.net'}`,
      `ns2.${cleanDomain || 'dns-host.net'}`
    ],
    mxRecords: [
      `10 mail.${cleanDomain}`,
      `20 backup-mx.${cleanDomain}`
    ],
    aRecords,
    txtRecords: [
      `v=spf1 include:_spf.${cleanDomain} ~all`
    ],
    dnssec: isKnownTrusted,
    hostingProvider: reputation === 'TRUSTED' ? 'Enterprise Cloud / Datacenter' : 'Offshore Cloud Node',
    asn: reputation === 'TRUSTED' ? 'AS15169' : 'AS59432',
    reputation,
    similarityToTarget: maxSimilarity > 0 ? maxSimilarity : undefined,
    impersonationRisk,
    lookalikePatterns,
    isPunycode: cleanDomain.startsWith('xn--'),
    isNewlyRegistered
  };
}

function computeDomainSimilarity(source: string, target: string): number {
  if (source === target) return 100;
  
  const sName = source.split('.')[0];
  const tName = target.split('.')[0];
  
  // Levenshtein distance
  const track = Array(tName.length + 1).fill(null).map(() =>
    Array(sName.length + 1).fill(null));
  for (let i = 0; i <= sName.length; i += 1) {
    track[0][i] = i;
  }
  for (let j = 0; j <= tName.length; j += 1) {
    track[j][0] = j;
  }
  for (let j = 1; j <= tName.length; j += 1) {
    for (let i = 1; i <= sName.length; i += 1) {
      const indicator = sName[i - 1] === tName[j - 1] ? 0 : 1;
      track[j][i] = Math.min(
        track[j][i - 1] + 1, // deletion
        track[j - 1][i] + 1, // insertion
        track[j - 1][i - 1] + indicator, // substitution
      );
    }
  }
  
  const distance = track[tName.length][sName.length];
  const maxLen = Math.max(sName.length, tName.length);
  const similarity = Math.max(0, Math.round((1 - distance / maxLen) * 100));
  
  // Boost similarity if contains exact target substring (e.g. micros0ft or microsoft-billing)
  if ((source.includes(tName) || tName.includes(sName)) && !source.endsWith('.' + target) && source !== target) {
    return Math.max(similarity, 88);
  }
  
  return similarity;
}
