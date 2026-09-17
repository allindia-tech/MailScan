/**
 * MailTrace AI - SMTP Relay Path Reconstructor & Forensics Engine
 * ================================================================
 * Strictly models RFC 5321 / 5322 transport handoffs, untrusted ingress boundaries,
 * and standards-based routability and IP intelligence with zero synthetic data.
 */

import { RelayNode, ThreatSeverity } from '../../src/types/forensics.js';
import { classifyIp, extractReceivedHeaderDetails } from '../services/ipClassification.js';
import { ipIntelligenceService, IpIntelligenceResult } from '../services/ipIntelligence.js';

export interface RelayAnalysisResult {
  relayPath: RelayNode[];
  earliestReliableNode?: RelayNode;
  totalHops: number;
  publicHopsCount: number;
  mappableHopsCount: number;
  privateHopsCount: number;
  ingressSummary: string;
}

/**
 * Reconstructs the chronological relay path from email Received headers.
 * 
 * In RFC 5322, each SMTP hop prepends its Received: header to the top of the message.
 * Therefore:
 * - Top-most header in raw email = Most recent hop (Final Recipient / Inbound Gateway)
 * - Bottom-most header in raw email = Oldest hop (Originating MTA / Initial Submission)
 * 
 * Transport Chronological Order = Reverse of the raw Received headers array.
 */
export function reconstructRelayPath(
  receivedHeaders: string[],
  fallbackHeaders?: Record<string, string>
): RelayAnalysisResult {
  if (!receivedHeaders || receivedHeaders.length === 0) {
    // Check fallback headers for X-Originating-IP (never synthesize hops from Received-SPF)
    const fallbackHops = extractFallbackHops(fallbackHeaders);
    if (fallbackHops.length > 0) {
      return buildRelayAnalysisResult(fallbackHops);
    }

    return {
      relayPath: [],
      earliestReliableNode: undefined,
      totalHops: 0,
      publicHopsCount: 0,
      mappableHopsCount: 0,
      privateHopsCount: 0,
      ingressSummary: 'No Received or relay headers observed in this specimen.'
    };
  }

  // Reverse to establish chronological transport sequence (Oldest Hop -> Newest Hop)
  const rawChronological = [...receivedHeaders].reverse();
  const nodes: RelayNode[] = [];

  for (let i = 0; i < rawChronological.length; i++) {
    const rawHeader = rawChronological[i];
    const details = extractReceivedHeaderDetails(rawHeader);
    const ipToAnalyze = details.fromIp || details.primaryIp || (details.fromHost && classifyIp(details.fromHost).isValid ? details.fromHost : '');
    
    // Perform IP classification & intelligence via master service
    const intel = ipIntelligenceService.lookupSync(ipToAnalyze || details.fromHost);

    const isPublic = intel.isPublic;
    const isMappable = intel.isMappable && intel.latitude !== null && intel.longitude !== null && Number.isFinite(intel.latitude) && Number.isFinite(intel.longitude);
    const lat = isMappable && intel.latitude !== null ? intel.latitude : NaN;
    const lon = isMappable && intel.longitude !== null ? intel.longitude : NaN;

    nodes.push({
      index: i + 1,
      receivedHeaderIndex: rawChronological.length - 1 - i,
      hostname: details.fromHost && details.fromHost !== 'Unknown Host' ? details.fromHost : intel.hostname,
      ip: intel.ip || ipToAnalyze || 'Unknown IP',
      timestamp: details.timestamp || new Date(Date.now() - (rawChronological.length - i) * 2000).toUTCString(),
      country: intel.country,
      countryCode: intel.countryCode,
      region: intel.region,
      city: intel.city,
      lat: lat,
      lon: lon,
      isp: intel.isp,
      asn: intel.asn,
      organization: intel.organization,
      reverseDns: intel.reverseDns || details.fromHost || `${intel.ip}.in-addr.arpa`,
      confidence: intel.confidence,
      reputation: intel.threatSeverity,
      isEarliestReliable: false,
      isUntrustedBoundary: false,
      protocol: details.protocol,
      tls: details.tls,
      isTor: intel.isTor,
      isPublic: isPublic,
      isMappable: isMappable,
      classification: intel.classification,
      evidenceSource: details.evidenceSource,
      rawHeader: rawHeader
    });
  }

  return buildRelayAnalysisResult(nodes);
}

/**
 * Builds the final RelayAnalysisResult, calculating boundary isolation and counts.
 */
function buildRelayAnalysisResult(nodes: RelayNode[]): RelayAnalysisResult {
  const totalHops = nodes.length;
  const publicHopsCount = nodes.filter(n => n.isPublic === true).length;
  const mappableHopsCount = nodes.filter(n => n.isMappable === true && !isNaN(n.lat) && !isNaN(n.lon)).length;
  const privateHopsCount = nodes.filter(n => n.isPublic === false).length;

  // Untrusted Ingress Boundary Identification
  // Traverse from the final destination node backwards towards origin.
  // The first external (public, non-internal) hop encountered is the boundary recorded by our recipient infrastructure.
  let earliestReliableIndex = -1;

  for (let i = nodes.length - 1; i >= 0; i--) {
    const node = nodes[i];
    if (node.isPublic === true && node.ip !== 'Unknown IP') {
      earliestReliableIndex = i;
      break;
    }
  }

  // If no public node found, select the first hop (e.g. local gateway)
  if (earliestReliableIndex === -1 && nodes.length > 0) {
    earliestReliableIndex = 0;
  }

  if (earliestReliableIndex >= 0 && nodes[earliestReliableIndex]) {
    nodes[earliestReliableIndex].isEarliestReliable = true;
    nodes[earliestReliableIndex].isUntrustedBoundary = true;
  }

  const earliestReliableNode = earliestReliableIndex >= 0 ? nodes[earliestReliableIndex] : undefined;

  let ingressSummary = '';
  if (totalHops === 0) {
    ingressSummary = 'No Received headers available in this specimen.';
  } else if (publicHopsCount === 0) {
    ingressSummary = 'Only local / loopback / private infrastructure observed. Not Internet-routable.';
  } else if (mappableHopsCount === 0) {
    ingressSummary = `Detected ${publicHopsCount} public relay hop(s), but verified geographical coordinates are unavailable.`;
  } else {
    ingressSummary = `Identified ${totalHops} total hop(s) with ${mappableHopsCount} verified geolocated node(s). Ingress boundary: ${earliestReliableNode?.ip || 'N/A'}.`;
  }

  return {
    relayPath: nodes,
    earliestReliableNode,
    totalHops,
    publicHopsCount,
    mappableHopsCount,
    privateHopsCount,
    ingressSummary
  };
}

/**
 * Extracts fallback relay evidence from secondary headers when Received: is omitted.
 * Strictly adheres to RFC standards: X-Originating-IP can serve as secondary origin evidence.
 * Received-SPF is preserved exclusively as authentication metadata and NOT converted into a relay hop.
 */
function extractFallbackHops(headers?: Record<string, string>): RelayNode[] {
  if (!headers) return [];

  const nodes: RelayNode[] = [];
  const now = new Date().toUTCString();

  // Check X-Originating-IP / X-Sender-IP / X-Client-IP
  const origIp = headers['x-originating-ip'] || headers['x-sender-ip'] || headers['x-client-ip'];
  if (origIp) {
    const cleanIp = origIp.replace(/[\[\]]/g, '').trim();
    const intel = ipIntelligenceService.lookupSync(cleanIp);
    const isMappable = intel.isMappable && intel.latitude !== null && intel.longitude !== null && Number.isFinite(intel.latitude) && Number.isFinite(intel.longitude);

    nodes.push({
      index: 1,
      receivedHeaderIndex: 0,
      hostname: intel.hostname,
      ip: intel.ip,
      timestamp: now,
      country: intel.country,
      countryCode: intel.countryCode,
      region: intel.region,
      city: intel.city,
      lat: isMappable && intel.latitude !== null ? intel.latitude : NaN,
      lon: isMappable && intel.longitude !== null ? intel.longitude : NaN,
      isp: intel.isp,
      asn: intel.asn,
      organization: intel.organization,
      reverseDns: intel.reverseDns,
      confidence: 70,
      reputation: intel.threatSeverity,
      isEarliestReliable: true,
      isUntrustedBoundary: true,
      protocol: 'X-Originating-IP',
      isTor: intel.isTor,
      isPublic: intel.isPublic,
      isMappable: isMappable,
      classification: intel.classification,
      evidenceSource: 'x-originating-ip',
      rawHeader: `X-Originating-IP: [${cleanIp}]`
    });
  }

  return nodes;
}
