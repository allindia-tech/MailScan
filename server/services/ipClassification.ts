/**
 * MailTrace AI — IP Classification & Routability Engine
 * ======================================================
 * Strict RFC-compliant classification for IPv4 and IPv6 addresses.
 * RFC 1918 (Private), RFC 1122 (Loopback), RFC 3927 (Link-Local),
 * RFC 6598 (CGNAT), RFC 5737 / RFC 3849 (Documentation), RFC 1112 (Multicast).
 */

export type IpRoutabilityClassification = 
  | 'PUBLIC' 
  | 'LOOPBACK' 
  | 'PRIVATE' 
  | 'LINK_LOCAL' 
  | 'CARRIER_GRADE_NAT' 
  | 'MULTICAST' 
  | 'UNSPECIFIED' 
  | 'DOCUMENTATION' 
  | 'INVALID';

export interface IpClassificationResult {
  ip: string;
  normalizedIp: string;
  version: 'IPv4' | 'IPv6' | 'UNKNOWN';
  classification: IpRoutabilityClassification;
  isPublic: boolean;
  isRoutable: boolean;
  isMappable: boolean;
  isValid: boolean;
  explanation: string;
}

/**
 * Validates and normalizes IPv4 string
 */
function parseIpv4Octets(ip: string): number[] | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = parseInt(part, 10);
    if (n < 0 || n > 255) return null;
    octets.push(n);
  }
  return octets;
}

/**
 * Checks IPv6 syntax validity
 */
function isIpv6Valid(ip: string): boolean {
  const clean = ip.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/^ipv6:/i, '');
  // Basic IPv6 regex
  const ipv6Regex = /^(([0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/i;
  return ipv6Regex.test(clean);
}

/**
 * Classifies any given IP address string strictly according to Internet RFCs.
 */
export function classifyIp(rawIp: string): IpClassificationResult {
  if (!rawIp || typeof rawIp !== 'string') {
    return {
      ip: rawIp || '',
      normalizedIp: '',
      version: 'UNKNOWN',
      classification: 'INVALID',
      isPublic: false,
      isRoutable: false,
      isMappable: false,
      isValid: false,
      explanation: 'Empty or invalid IP input'
    };
  }

  // Clean brackets, leading/trailing spaces, and optional "IPv6:" prefix
  let clean = rawIp.trim().replace(/^\[|\]$/g, '');
  if (clean.toLowerCase().startsWith('ipv6:')) {
    clean = clean.substring(5).trim();
  }

  // Check IPv4
  const octets = parseIpv4Octets(clean);
  if (octets) {
    const [o1, o2, o3, o4] = octets;
    const normalized = `${o1}.${o2}.${o3}.${o4}`;

    // 0.0.0.0/8 (RFC 1122) Unspecified
    if (o1 === 0) {
      return {
        ip: rawIp,
        normalizedIp: normalized,
        version: 'IPv4',
        classification: 'UNSPECIFIED',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'Unspecified broadcast / current network address (RFC 1122)'
      };
    }

    // 127.0.0.0/8 (RFC 1122) Loopback
    if (o1 === 127) {
      return {
        ip: rawIp,
        normalizedIp: normalized,
        version: 'IPv4',
        classification: 'LOOPBACK',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'Localhost loopback interface (RFC 1122 / Non-routable)'
      };
    }

    // 10.0.0.0/8 (RFC 1918)
    if (o1 === 10) {
      return {
        ip: rawIp,
        normalizedIp: normalized,
        version: 'IPv4',
        classification: 'PRIVATE',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'Private intranet address range 10.0.0.0/8 (RFC 1918)'
      };
    }

    // 172.16.0.0/12 (RFC 1918: 172.16.0.0 - 172.31.255.255)
    if (o1 === 172 && o2 >= 16 && o2 <= 31) {
      return {
        ip: rawIp,
        normalizedIp: normalized,
        version: 'IPv4',
        classification: 'PRIVATE',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'Private intranet address range 172.16.0.0/12 (RFC 1918)'
      };
    }

    // 192.168.0.0/16 (RFC 1918)
    if (o1 === 192 && o2 === 168) {
      return {
        ip: rawIp,
        normalizedIp: normalized,
        version: 'IPv4',
        classification: 'PRIVATE',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'Private intranet address range 192.168.0.0/16 (RFC 1918)'
      };
    }

    // 169.254.0.0/16 (RFC 3927) Link-Local
    if (o1 === 169 && o2 === 254) {
      return {
        ip: rawIp,
        normalizedIp: normalized,
        version: 'IPv4',
        classification: 'LINK_LOCAL',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'Auto-configured Link-Local address (RFC 3927)'
      };
    }

    // 100.64.0.0/10 (RFC 6598) Carrier-Grade NAT
    if (o1 === 100 && o2 >= 64 && o2 <= 127) {
      return {
        ip: rawIp,
        normalizedIp: normalized,
        version: 'IPv4',
        classification: 'CARRIER_GRADE_NAT',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'Shared Address Space / Carrier-Grade NAT (RFC 6598)'
      };
    }

    // 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3) (RFC 5737)
    if ((o1 === 192 && o2 === 0 && o3 === 2) ||
        (o1 === 198 && o2 === 51 && o3 === 100) ||
        (o1 === 203 && o2 === 0 && o3 === 113) ||
        (o1 >= 240)) { // 240.0.0.0/4 Reserved
      return {
        ip: rawIp,
        normalizedIp: normalized,
        version: 'IPv4',
        classification: 'DOCUMENTATION',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'Documentation / Benchmark / Reserved network range (RFC 5737 / RFC 1112)'
      };
    }

    // 224.0.0.0/4 (RFC 1112) Multicast
    if (o1 >= 224 && o1 <= 239) {
      return {
        ip: rawIp,
        normalizedIp: normalized,
        version: 'IPv4',
        classification: 'MULTICAST',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'Multicast address range (RFC 1112)'
      };
    }

    // Standard Public Routable IPv4
    return {
      ip: rawIp,
      normalizedIp: normalized,
      version: 'IPv4',
      classification: 'PUBLIC',
      isPublic: true,
      isRoutable: true,
      isMappable: true,
      isValid: true,
      explanation: 'Public globally-routable Internet IP'
    };
  }

  // Check IPv6
  if (isIpv6Valid(clean)) {
    const lclean = clean.toLowerCase();

    // ::1 Loopback
    if (lclean === '::1' || lclean === '0:0:0:0:0:0:0:1') {
      return {
        ip: rawIp,
        normalizedIp: '::1',
        version: 'IPv6',
        classification: 'LOOPBACK',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'IPv6 Loopback interface (RFC 4291)'
      };
    }

    // :: Unspecified
    if (lclean === '::' || lclean === '0:0:0:0:0:0:0:0') {
      return {
        ip: rawIp,
        normalizedIp: '::',
        version: 'IPv6',
        classification: 'UNSPECIFIED',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'IPv6 Unspecified address (RFC 4291)'
      };
    }

    // fc00::/7 Unique Local Address (ULA / RFC 4193)
    if (lclean.startsWith('fc') || lclean.startsWith('fd')) {
      return {
        ip: rawIp,
        normalizedIp: lclean,
        version: 'IPv6',
        classification: 'PRIVATE',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'IPv6 Unique Local Address / Private Intranet (RFC 4193)'
      };
    }

    // fe80::/10 Link-Local (RFC 4291)
    if (lclean.startsWith('fe80:')) {
      return {
        ip: rawIp,
        normalizedIp: lclean,
        version: 'IPv6',
        classification: 'LINK_LOCAL',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'IPv6 Link-Local Unicast address (RFC 4291)'
      };
    }

    // 2001:db8::/32 Documentation (RFC 3849)
    if (lclean.startsWith('2001:db8:') || lclean.startsWith('2001:0db8:')) {
      return {
        ip: rawIp,
        normalizedIp: lclean,
        version: 'IPv6',
        classification: 'DOCUMENTATION',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'IPv6 Documentation prefix (RFC 3849)'
      };
    }

    // ff00::/8 Multicast
    if (lclean.startsWith('ff')) {
      return {
        ip: rawIp,
        normalizedIp: lclean,
        version: 'IPv6',
        classification: 'MULTICAST',
        isPublic: false,
        isRoutable: false,
        isMappable: false,
        isValid: true,
        explanation: 'IPv6 Multicast address (RFC 4291)'
      };
    }

    // Public IPv6
    return {
      ip: rawIp,
      normalizedIp: lclean,
      version: 'IPv6',
      classification: 'PUBLIC',
      isPublic: true,
      isRoutable: true,
      isMappable: true,
      isValid: true,
      explanation: 'Public globally-routable IPv6 address'
    };
  }

  return {
    ip: rawIp,
    normalizedIp: rawIp,
    version: 'UNKNOWN',
    classification: 'INVALID',
    isPublic: false,
    isRoutable: false,
    isMappable: false,
    isValid: false,
    explanation: 'Malformed or unrecognized IP address format'
  };
}

/**
 * Extracts and classifies all IP candidates from raw Received / SPF headers.
 */
export function extractReceivedHeaderDetails(rawHeader: string): {
  fromHost: string;
  fromIp: string;
  byHost: string;
  byIp: string;
  primaryIp: string;
  protocol: string;
  tls?: string;
  timestamp: string;
  evidenceSource: 'received-header' | 'received-spf' | 'authentication-results' | 'x-originating-ip';
} {
  const clean = rawHeader.replace(/\r\n/g, ' ').replace(/\n/g, ' ').replace(/\s+/g, ' ').trim();

  // Extract from hostname / IP
  // e.g., "from mail.domain.com (mail.domain.com [203.0.113.10])"
  // e.g., "from [192.168.1.1] (unknown [185.220.101.42])"
  let fromHost = '';
  let fromIp = '';
  let byHost = '';
  let byIp = '';
  let protocol = 'ESMTP';
  let tls: string | undefined = undefined;
  let timestamp = '';

  // Extract from host
  const fromHostMatch = clean.match(/\bfrom\s+([^\s;()\[\]]+)/i);
  if (fromHostMatch) {
    fromHost = fromHostMatch[1];
  }

  // Extract TCP peer IP (inside parenthesis/brackets associated with from)
  // Look for: (rdns [IP]) or ([IP]) or (IP)
  const peerIpMatch = clean.match(/\((?:[^()\[\]]*\s+)?\[?((?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|IPv6:[0-9a-fA-F:]+)\]?\)/i);
  if (peerIpMatch) {
    fromIp = peerIpMatch[1].replace(/^IPv6:/i, '').trim();
  } else {
    // Fallback to bracketed IP after from
    const bracketMatch = clean.match(/\bfrom\s+[^\s;]*\s*\[((?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|IPv6:[0-9a-fA-F:]+)\]/i);
    if (bracketMatch) {
      fromIp = bracketMatch[1].replace(/^IPv6:/i, '').trim();
    }
  }

  // If still no fromIp, extract first bracketed valid IP in the header
  if (!fromIp) {
    const anyBracketMatch = clean.match(/\[((?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}|IPv6:[0-9a-fA-F:]+)\]/i);
    if (anyBracketMatch) {
      fromIp = anyBracketMatch[1].replace(/^IPv6:/i, '').trim();
    }
  }

  // Extract by host
  const byHostMatch = clean.match(/\bby\s+([^\s;()\[\]]+)/i);
  if (byHostMatch) {
    byHost = byHostMatch[1];
  }

  // Extract by IP if explicitly recorded
  const byIpMatch = clean.match(/\bby\s+[^\s;()\[\]]+\s*(?:\([^)]*\)\s*)?\[((?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})\]/i);
  if (byIpMatch) {
    byIp = byIpMatch[1].trim();
  }

  // Protocol extraction
  if (/\bwith\s+ESMTPSA\b/i.test(clean)) protocol = 'ESMTPSA';
  else if (/\bwith\s+ESMTPS\b/i.test(clean)) protocol = 'ESMTPS';
  else if (/\bwith\s+ESMTPA\b/i.test(clean)) protocol = 'ESMTPA';
  else if (/\bwith\s+ESMTP\b/i.test(clean)) protocol = 'ESMTP';
  else if (/\bwith\s+SMTP\b/i.test(clean)) protocol = 'SMTP';
  else if (/\bwith\s+HTTPS?\b/i.test(clean)) protocol = 'HTTP';

  // TLS cipher extraction
  const tlsMatch = clean.match(/\b(?:using|with)?\s*(TLS[v\d._\s]+|version=TLS[^\s;]+)\b/i);
  if (tlsMatch) {
    tls = tlsMatch[0].trim();
  }

  // Timestamp extraction (everything after final semicolon)
  const semiIdx = clean.lastIndexOf(';');
  if (semiIdx !== -1) {
    const rawDate = clean.substring(semiIdx + 1).trim();
    const parsedDate = new Date(rawDate);
    if (!isNaN(parsedDate.getTime())) {
      timestamp = parsedDate.toUTCString();
    } else {
      timestamp = rawDate;
    }
  }

  const primaryIp = fromIp || (fromHost && classifyIp(fromHost).isValid ? fromHost : '');

  return {
    fromHost: fromHost || 'Unknown Host',
    fromIp: fromIp || '',
    byHost: byHost || '',
    byIp: byIp || '',
    primaryIp: primaryIp || '',
    protocol,
    tls,
    timestamp: timestamp || '',
    evidenceSource: 'received-header'
  };
}
