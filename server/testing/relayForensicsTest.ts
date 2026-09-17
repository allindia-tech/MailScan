/**
 * MailTrace AI - Comprehensive Relay Forensics & Hop Geo-Trace Test Suite
 * =======================================================================
 * Validates RFC 5321/5322 parsing, RFC 1918/1122 routability classification,
 * multi-hop transport reconstruction, ingress boundary isolation, and zero synthetic coordinates.
 */

import { classifyIp, extractReceivedHeaderDetails } from '../services/ipClassification.js';
import { ipIntelligenceService } from '../services/ipIntelligence.js';
import { reconstructRelayPath } from '../analyzers/relayAnalyzer.js';
import { SAMPLE_SCENARIOS } from '../sampleEmails.js';
import { isPlottableLocation } from '../../src/components/GlobalThreatMap.js';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  ✓ PASS: ${testName}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${testName}${detail ? ` - ${detail}` : ''}`);
    failed++;
  }
}

export async function runRelayForensicsTests() {
  console.log('\n======================================================');
  console.log('🧪 RUNNING MAILTRACE AI RELAY FORENSICS & GEO-TRACE TEST SUITE');
  console.log('======================================================\n');

  // 1. IPv4 Parsing & Classification
  console.log('--- Suite 1: IP Classification & Standards-Aware Routability ---');
  
  const pubIpv4 = classifyIp('185.220.101.42');
  assert(pubIpv4.isValid && pubIpv4.isPublic && pubIpv4.classification === 'PUBLIC', 'IPv4 Public IP (185.220.101.42) classified as PUBLIC');

  const loopbackIpv4 = classifyIp('127.0.0.1');
  assert(loopbackIpv4.isValid && !loopbackIpv4.isPublic && loopbackIpv4.classification === 'LOOPBACK', 'IPv4 Loopback (127.0.0.1) classified as LOOPBACK');

  const loopbackSubnet = classifyIp('127.255.0.1');
  assert(loopbackSubnet.isValid && !loopbackSubnet.isPublic && loopbackSubnet.classification === 'LOOPBACK', 'IPv4 Loopback 127.0.0.0/8 range classified as LOOPBACK');

  const priv10 = classifyIp('10.0.1.5');
  assert(priv10.isValid && !priv10.isPublic && priv10.classification === 'PRIVATE', 'RFC 1918 10.0.0.0/8 classified as PRIVATE');

  const priv172 = classifyIp('172.20.10.4');
  assert(priv172.isValid && !priv172.isPublic && priv172.classification === 'PRIVATE', 'RFC 1918 172.16.0.0/12 classified as PRIVATE');

  const priv192 = classifyIp('192.168.1.1');
  assert(priv192.isValid && !priv192.isPublic && priv192.classification === 'PRIVATE', 'RFC 1918 192.168.0.0/16 classified as PRIVATE');

  const cgnat = classifyIp('100.64.0.1');
  assert(cgnat.isValid && !cgnat.isPublic && cgnat.classification === 'CARRIER_GRADE_NAT', 'RFC 6598 Carrier-Grade NAT (100.64.0.1) classified as CGNAT');

  const docNet = classifyIp('198.51.100.25');
  assert(docNet.isValid && docNet.classification === 'DOCUMENTATION', 'RFC 5737 TEST-NET-2 (198.51.100.25) classified as DOCUMENTATION');

  const invalidIp = classifyIp('999.999.999.999');
  assert(!invalidIp.isValid && invalidIp.classification === 'INVALID', 'Invalid IPv4 (999.999.999.999) rejected as INVALID');

  // 2. IPv6 Parsing & Classification
  const pubIpv6 = classifyIp('2001:4860:4860::8888');
  assert(pubIpv6.isValid && pubIpv6.isPublic && pubIpv6.version === 'IPv6', 'IPv6 Public address classified as PUBLIC');

  const loopbackIpv6 = classifyIp('::1');
  assert(loopbackIpv6.isValid && !loopbackIpv6.isPublic && loopbackIpv6.classification === 'LOOPBACK', 'IPv6 Loopback (::1) classified as LOOPBACK');

  const privUlaIpv6 = classifyIp('fc00::1');
  assert(privUlaIpv6.isValid && !privUlaIpv6.isPublic && privUlaIpv6.classification === 'PRIVATE', 'IPv6 ULA (fc00::1) classified as PRIVATE');

  // 3. Received Header Extraction
  console.log('\n--- Suite 2: RFC 5322 Received Header Parsing ---');

  const header1 = 'from mail.example.com (mail.example.com [203.0.113.25]) by mx.example.net with ESMTPS id 4V9xK718; Tue, 17 Sep 2026 08:42:12 +0000';
  const extracted1 = extractReceivedHeaderDetails(header1);
  assert(extracted1.fromHost === 'mail.example.com', 'Extracted fromHost correctly');
  assert(extracted1.fromIp === '203.0.113.25', 'Extracted fromIp from TCP peer brackets');
  assert(extracted1.byHost === 'mx.example.net', 'Extracted byHost correctly');
  assert(extracted1.protocol === 'ESMTPS', 'Extracted protocol correctly');

  const headerTls = 'from vps.host.de (vps.host.de [194.26.29.115]) by mx.net with ESMTPS id 123 using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384; Tue, 17 Sep 2026 08:42:08 +0000';
  const extractedTls = extractReceivedHeaderDetails(headerTls);
  assert(extractedTls.fromIp === '194.26.29.115', 'Extracted fromIp with cipher details');
  assert(extractedTls.tls !== undefined && extractedTls.tls.includes('TLS'), 'Extracted TLS encryption metadata');

  // 4. IP Intelligence & Zero Fake Coordinates
  console.log('\n--- Suite 3: IP Intelligence & Zero Synthetic Coordinates ---');

  const googleIntel = await ipIntelligenceService.lookup('209.85.216.54');
  assert(googleIntel.isPublic && googleIntel.isMappable && googleIntel.latitude !== null, 'Google relay (209.85.216.54) returned verified coordinates');
  assert(googleIntel.isp === 'Google LLC' && googleIntel.asn === 'AS15169', 'Google relay ISP and ASN verified');

  const loopbackIntel = await ipIntelligenceService.lookup('127.0.0.1');
  assert(!loopbackIntel.isPublic && !loopbackIntel.isMappable && loopbackIntel.latitude === null && loopbackIntel.longitude === null, '127.0.0.1 strictly yields NULL coordinates (never mapped)');
  assert(loopbackIntel.asn.includes('Non-Routable') || loopbackIntel.asn.includes('None'), '127.0.0.1 does not display fake AS0 or fabricated ISP');

  const rfc1918Intel = await ipIntelligenceService.lookup('10.0.0.1');
  assert(!rfc1918Intel.isPublic && !rfc1918Intel.isMappable && rfc1918Intel.latitude === null, 'RFC 1918 strictly yields NULL coordinates');

  const unmappedPublicIntel = await ipIntelligenceService.lookup('8.8.4.4');
  assert(unmappedPublicIntel.isPublic && (!unmappedPublicIntel.isMappable || isNaN(unmappedPublicIntel.latitude as number) || unmappedPublicIntel.latitude === null), 'Unresolved public IP does NOT use fake fallback coordinates');

  // 5. Multi-Hop Transport Reconstruction & Chronological Order
  console.log('\n--- Suite 4: Multi-Hop Transport Path Reconstruction ---');

  const testHeaders = [
    'by mail-inbound.enterprise.com (Postfix) id 4V9xL; Tue, 17 Sep 2026 08:42:15 +0000', // Hop 4 (Newest)
    'from mx1.gateway.net ([198.51.100.25]) by inbound.enterprise.com; Tue, 17 Sep 2026 08:42:12 +0000', // Hop 3
    'from vps-115.host.de ([194.26.29.115]) by mx1.gateway.net; Tue, 17 Sep 2026 08:42:08 +0000', // Hop 2
    'from vps-node-91.bulletproof.ru ([185.220.101.42]) by vps-115.host.de; Tue, 17 Sep 2026 08:41:55 +0000' // Hop 1 (Oldest / Origin)
  ];

  const relayResult = reconstructRelayPath(testHeaders);
  assert(relayResult.totalHops === 4, 'Reconstructed 4 total hops from 4 Received headers');
  assert(relayResult.relayPath[0].index === 1 && relayResult.relayPath[0].ip === '185.220.101.42', 'Hop #1 is correctly the earliest originating hop (185.220.101.42)');
  assert(relayResult.relayPath[3].index === 4, 'Hop #4 is correctly the final destination inbound gateway');
  assert(relayResult.earliestReliableNode?.ip === '198.51.100.25' || relayResult.earliestReliableNode?.ip === '194.26.29.115', 'Identified Untrusted Ingress Boundary on relay path');

  // 6. Test Scenario A: Only Localhost / Private Infrastructure
  console.log('\n--- Suite 5: Edge Cases & Real Scenarios ---');

  const loopbackScenario = SAMPLE_SCENARIOS.find(s => s.id === 'scenario-6-localhost-dev-specimen')!;
  const parsedLoopbackHeaders = [
    'by mail.localdomain (Postfix) id 3x918274a; Tue, 17 Sep 2026 12:30:40 +0000',
    'from dev-workstation.internal ([192.168.1.105]) by mail.localdomain; Tue, 17 Sep 2026 12:30:35 +0000',
    'from localhost ([127.0.0.1]) by dev-workstation.internal; Tue, 17 Sep 2026 12:30:30 +0000'
  ];
  const loopbackRelay = reconstructRelayPath(parsedLoopbackHeaders);
  assert(loopbackRelay.totalHops === 3, 'Loopback specimen correctly shows 3 total timeline hops');
  assert(loopbackRelay.mappableHopsCount === 0, 'Loopback specimen has 0 mappable nodes (never plotted on world map)');
  assert(loopbackRelay.publicHopsCount === 0, 'Loopback specimen has 0 public hops');

  // 7. Test Scenario B: Authentic BEC Multi-Hop Specimen
  const becScenario = SAMPLE_SCENARIOS.find(s => s.id === 'scenario-4-fake-invoice')!;
  assert(becScenario.rawEml.includes('Received:'), 'BEC scenario contains full RFC 5322 Received headers');

  // 8. Test Geographic Filter
  const plottableCheck = isPlottableLocation({ latitude: 55.7558, longitude: 37.6173, verified: true });
  assert(plottableCheck === true, 'Valid geographic coordinates pass isPlottableLocation');

  const unplottableNan = isPlottableLocation({ latitude: NaN, longitude: NaN });
  assert(unplottableNan === false, 'NaN coordinates strictly rejected by isPlottableLocation');

  const unplottableNull = isPlottableLocation({ latitude: null, longitude: null });
  assert(unplottableNull === false, 'Null coordinates strictly rejected by isPlottableLocation');

  const unplottableOutBounds = isPlottableLocation({ latitude: 120.5, longitude: 37.6 });
  assert(unplottableOutBounds === false, 'Out-of-bounds latitude (>90) strictly rejected');

  console.log('\n======================================================');
  console.log(`🏁 TEST RESULTS: ${passed} PASSED | ${failed} FAILED`);
  console.log('======================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

// Run if called directly
runRelayForensicsTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
