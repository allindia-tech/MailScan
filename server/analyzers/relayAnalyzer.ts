/**
 * MailTrace AI - SMTP Relay Path Reconstructor & Forensics Engine
 * Strictly models the boundary between trusted inbound relays and upstream untrusted nodes
 */

import { RelayNode, ThreatSeverity } from '../../src/types/forensics.js';

// Geo/ASN database mapping for IPs encountered in forensic email analysis
const KNOWN_GEO_DATABASE: Record<string, {
  country: string;
  countryCode: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  isp: string;
  asn: string;
  org: string;
  reputation: ThreatSeverity;
  isBulletproof?: boolean;
  isCloud?: boolean;
}> = {
  '185.220.101.42': {
    country: 'Russia',
    countryCode: 'RU',
    region: 'Moscow',
    city: 'Moscow',
    lat: 55.7558,
    lon: 37.6173,
    isp: 'Bulletproof VPS Hosting Services Ltd',
    asn: 'AS209104',
    org: 'Offshore Fast-Flux Host',
    reputation: 'CRITICAL',
    isBulletproof: true
  },
  '91.240.118.88': {
    country: 'Netherlands',
    countryCode: 'NL',
    region: 'North Holland',
    city: 'Amsterdam',
    lat: 52.3676,
    lon: 4.9041,
    isp: 'Novogara Datacenter Network',
    asn: 'AS59432',
    org: 'Novogara Cloud Services',
    reputation: 'HIGH',
    isCloud: true
  },
  '209.85.216.54': {
    country: 'United States',
    countryCode: 'US',
    region: 'California',
    city: 'Mountain View',
    lat: 37.3861,
    lon: -122.0839,
    isp: 'Google LLC',
    asn: 'AS15169',
    org: 'Google Mail Infrastructure',
    reputation: 'TRUSTED',
    isCloud: true
  },
  '209.85.208.52': {
    country: 'United States',
    countryCode: 'US',
    region: 'California',
    city: 'Mountain View',
    lat: 37.3861,
    lon: -122.0839,
    isp: 'Google LLC',
    asn: 'AS15169',
    org: 'Google Mail Infrastructure',
    reputation: 'TRUSTED',
    isCloud: true
  },
  '102.89.34.77': {
    country: 'Nigeria',
    countryCode: 'NG',
    region: 'Lagos',
    city: 'Ikeja',
    lat: 6.5244,
    lon: 3.3792,
    isp: 'MTN Nigeria Communications',
    asn: 'AS29465',
    org: 'MTN Broadband Residential',
    reputation: 'HIGH'
  },
  '194.26.29.115': {
    country: 'Germany',
    countryCode: 'DE',
    region: 'Hesse',
    city: 'Frankfurt',
    lat: 50.1109,
    lon: 8.6821,
    isp: 'Host Europe GmbH',
    asn: 'AS34011',
    org: 'Leased Virtual Private Server',
    reputation: 'HIGH',
    isCloud: true
  },
  '118.69.182.90': {
    country: 'Vietnam',
    countryCode: 'VN',
    region: 'Ho Chi Minh',
    city: 'Ho Chi Minh City',
    lat: 10.8231,
    lon: 106.6297,
    isp: 'Viettel Telecom',
    asn: 'AS7552',
    org: 'Compromised IoT Gateway Node',
    reputation: 'CRITICAL'
  },
  '154.16.192.44': {
    country: 'Seychelles',
    countryCode: 'SC',
    region: 'Mahe',
    city: 'Victoria',
    lat: -4.6191,
    lon: 55.4513,
    isp: 'Indian Ocean Telecom & Hosting',
    asn: 'AS37559',
    org: 'Offshore Anonymous VPS',
    reputation: 'CRITICAL',
    isBulletproof: true
  },
  '54.240.27.41': {
    country: 'United States',
    countryCode: 'US',
    region: 'Washington',
    city: 'Seattle',
    lat: 47.6062,
    lon: -122.3321,
    isp: 'Amazon.com Inc.',
    asn: 'AS16509',
    org: 'Amazon Simple Email Service (SES)',
    reputation: 'TRUSTED',
    isCloud: true
  },
  '198.51.100.25': {
    country: 'United States',
    countryCode: 'US',
    region: 'Virginia',
    city: 'Ashburn',
    lat: 39.0438,
    lon: -77.4874,
    isp: 'Cloud Email Security Gateway Ltd',
    asn: 'AS13335',
    org: 'Defense Inbound Filter',
    reputation: 'TRUSTED',
    isCloud: true
  },
  '198.51.100.18': {
    country: 'United States',
    countryCode: 'US',
    region: 'Virginia',
    city: 'Ashburn',
    lat: 39.0438,
    lon: -77.4874,
    isp: 'SpamFilter Cluster Enterprise',
    asn: 'AS13335',
    org: 'Inbound Gateway Filter',
    reputation: 'TRUSTED',
    isCloud: true
  },
  '167.114.144.194': {
    country: 'Singapore',
    countryCode: 'SG',
    region: 'Singapore',
    city: 'Singapore',
    lat: 1.3521,
    lon: 103.8198,
    isp: 'SingNet Pte Ltd',
    asn: 'AS4657',
    org: 'SingNet Infrastructure',
    reputation: 'HIGH'
  }
};

export function reconstructRelayPath(receivedHeaders: string[]): {
  relayPath: RelayNode[];
  earliestReliableNode?: RelayNode;
} {
  // Received headers are ordered newest (top) to oldest (bottom) in raw email.
  // Chronological order: reverse of array.
  const rawChronological = [...receivedHeaders].reverse();
  const nodes: RelayNode[] = [];
  
  for (let i = 0; i < rawChronological.length; i++) {
    const raw = rawChronological[i];
    
    // Extract IP address from header: [x.x.x.x] or (x.x.x.x)
    const ipMatch = raw.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/) || 
                    raw.match(/\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)/) ||
                    raw.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
    const ip = ipMatch ? ipMatch[1] : 'Unknown IP';
    
    // Extract hostname from "from <hostname>"
    const fromMatch = raw.match(/from\s+([^\s;()\[\]]+)/i);
    const hostname = fromMatch ? fromMatch[1] : (ip !== 'Unknown IP' ? ip : 'Unknown Host');
    
    // Extract by "by <hostname>"
    const byMatch = raw.match(/by\s+([^\s;()\[\]]+)/i);
    const byHost = byMatch ? byMatch[1] : '';

    // Extract timestamp after semicolon
    const semiIdx = raw.lastIndexOf(';');
    let timestamp = '';
    if (semiIdx !== -1) {
      timestamp = raw.substring(semiIdx + 1).trim();
    } else {
      timestamp = new Date(Date.now() - (rawChronological.length - i) * 2000).toISOString();
    }

    // Lookup Geo intelligence or handle unknown / unverified coordinates
    const geo = KNOWN_GEO_DATABASE[ip] || synthesizeGeo(ip, hostname);
    
    // Is private RFC 1918 IP?
    const isPrivate = ip.startsWith('10.') || ip.startsWith('192.168.') || /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip);

    nodes.push({
      index: i + 1,
      hostname: hostname,
      ip: ip,
      timestamp: timestamp,
      country: geo.country,
      countryCode: geo.countryCode,
      region: geo.region,
      city: geo.city,
      lat: geo.lat,
      lon: geo.lon,
      isp: geo.isp,
      asn: geo.asn,
      organization: geo.org,
      reverseDns: hostname.includes('.') ? hostname : (ip !== 'Unknown IP' ? `${ip.replace(/\./g, '-')}.in-addr.arpa` : 'Unknown PTR'),
      confidence: isPrivate ? 40 : (geo.lat && !isNaN(geo.lat) ? 88 : 30),
      reputation: isPrivate ? 'TRUSTED' : geo.reputation,
      isEarliestReliable: false,
      isUntrustedBoundary: false,
      protocol: raw.includes('esmtpsa') ? 'ESMTPSA' : (raw.includes('esmtps') ? 'ESMTPS' : 'ESMTP'),
      rawHeader: raw
    });
  }

  // Determine "Earliest Reliable Sending Node"
  // Forensic rule: The earliest node that was logged by the organization's receiving infrastructure.
  // Traverse from the final recipient backwards until we reach the first external (non-private/trusted) server.
  let earliestReliableIndex = -1;
  for (let i = nodes.length - 1; i >= 0; i--) {
    const node = nodes[i];
    const isInternal = node.ip.startsWith('10.') || node.ip.startsWith('192.168.') || node.hostname.includes('.internal');
    if (!isInternal && node.ip !== 'Unknown IP') {
      earliestReliableIndex = i;
      break;
    }
  }

  // Fallback to node 0 if none found or all internal
  if (earliestReliableIndex === -1 && nodes.length > 0) {
    earliestReliableIndex = 0;
  }

  if (earliestReliableIndex >= 0 && nodes[earliestReliableIndex]) {
    nodes[earliestReliableIndex].isEarliestReliable = true;
    nodes[earliestReliableIndex].isUntrustedBoundary = true;
  }

  return {
    relayPath: nodes,
    earliestReliableNode: earliestReliableIndex >= 0 ? nodes[earliestReliableIndex] : undefined
  };
}

function synthesizeGeo(ip: string, host: string) {
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) {
    return {
      country: 'Private Network',
      countryCode: 'LAN',
      region: 'Internal Intranet',
      city: 'Local Enclave',
      lat: NaN,
      lon: NaN,
      isp: 'Internal Corporate Postfix Relay',
      asn: 'AS-PRIVATE',
      org: 'Local Network Node',
      reputation: 'TRUSTED' as ThreatSeverity
    };
  }
  
  // Strict forensic rule: If geolocation is unavailable for unknown IP, DO NOT invent fake coordinates
  return {
    country: 'Unknown',
    countryCode: 'XX',
    region: 'Unknown Region',
    city: 'Unknown Location',
    lat: NaN,
    lon: NaN,
    isp: 'Unresolved ISP',
    asn: 'AS-UNKNOWN',
    org: 'Unresolved Infrastructure',
    reputation: 'SUSPICIOUS' as ThreatSeverity
  };
}
