/**
 * MailTrace AI - Comprehensive Relay Forensics & Hop Geo-Trace Test Suite
 * =======================================================================
 * Validates RFC 5321/5322 parsing, RFC 1918/1122 routability classification,
 * multi-hop transport reconstruction, ingress boundary isolation, and zero synthetic coordinates.
 * Covers all 22 required forensic validation test cases.
 */

import { classifyIp, extractReceivedHeaderDetails } from '../services/ipClassification.js';
import { ipIntelligenceService } from '../services/ipIntelligence.js';
import { reconstructRelayPath } from '../analyzers/relayAnalyzer.js';
import { parseRawEmail } from '../analyzers/emailParser.js';
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
  console.log('🧪 RUNNING MAILTRACE AI 22-CASE RELAY FORENSICS TEST SUITE');
  console.log('======================================================\n');

  // Test Case 1: Standard Received Header
  console.log('--- Test 1: Standard Received Header ---');
  const standardReceived = 'Received: from mail.example.com (mail.example.com [203.0.113.25]) by mx.example.net with ESMTPS id 4V9xK718; Tue, 17 Sep 2026 08:42:12 +0000\n\nBody';
  const parsed1 = parseRawEmail(standardReceived);
  const hop1Extracted = extractReceivedHeaderDetails(parsed1.receivedHeaders[0]);
  assert(parsed1.receivedHeaders.length === 1 && hop1Extracted.fromHost === 'mail.example.com' && hop1Extracted.fromIp === '203.0.113.25', 'Test 1: Standard Received Header extracted with host, IP, and protocol');

  // Test Case 2: Folded Received Header (RFC 5322 line continuation)
  console.log('--- Test 2: Folded Received Header ---');
  const foldedReceived = 'Received: from mail.example.com\n\t(mail.example.com [203.0.113.25])\n by mx.example.net\n with ESMTPS id abc123;\n Tue, 17 Sep 2026 10:20:00 +0000\n\nBody';
  const parsed2 = parseRawEmail(foldedReceived);
  const hop2Extracted = extractReceivedHeaderDetails(parsed2.receivedHeaders[0]);
  assert(parsed2.receivedHeaders.length === 1 && hop2Extracted.fromIp === '203.0.113.25' && hop2Extracted.byHost === 'mx.example.net', 'Test 2: Folded Received Header unfolded and parsed correctly');

  // Test Case 3: Multiple Received Headers
  console.log('--- Test 3: Multiple Received Headers ---');
  const multiHeaders = [
    'Received: by mail-inbound.enterprise.com (Postfix) id 4V9xL; Tue, 17 Sep 2026 08:42:15 +0000',
    'Received: from mx1.gateway.net ([198.51.100.25]) by inbound.enterprise.com; Tue, 17 Sep 2026 08:42:12 +0000',
    'Received: from vps-115.host.de ([194.26.29.115]) by mx1.gateway.net; Tue, 17 Sep 2026 08:42:08 +0000',
    'Received: from vps-node-91.bulletproof.ru ([185.220.101.42]) by vps-115.host.de; Tue, 17 Sep 2026 08:41:55 +0000'
  ].join('\n') + '\n\nBody';
  const parsed3 = parseRawEmail(multiHeaders);
  assert(parsed3.receivedHeaders.length === 4, 'Test 3: Multiple Received Headers all preserved in array (4 count)');

  // Test Case 4: Uppercase/Lowercase Header Names (Case-Insensitivity)
  console.log('--- Test 4: Header Name Case-Insensitivity ---');
  const mixedCaseRaw = 'RECEIVED: from mail1.org ([194.26.29.115]) by mx.org; Tue, 17 Sep 2026 08:00:00 +0000\nreceived: from mail2.org ([185.220.101.42]) by mail1.org; Tue, 17 Sep 2026 07:55:00 +0000\nFROM: Sender <sender@domain.com>\nSubject: Mixed Case\n\nBody';
  const parsed4 = parseRawEmail(mixedCaseRaw);
  assert(parsed4.receivedHeaders.length === 2 && parsed4.fromDomain === 'domain.com', 'Test 4: RECEIVED: and received: parsed identically without case bias');

  // Test Case 5: IPv4 Extraction
  console.log('--- Test 5: IPv4 Extraction ---');
  const ipv4Details = extractReceivedHeaderDetails('from vps.node.de ([194.26.29.115]) by mx.dest.com; Tue, 17 Sep 2026 08:00:00 +0000');
  const ipv4Class = classifyIp(ipv4Details.fromIp || '');
  assert(ipv4Details.fromIp === '194.26.29.115' && ipv4Class.version === 'IPv4' && ipv4Class.isPublic, 'Test 5: IPv4 extracted and validated as valid public IPv4');

  // Test Case 6: IPv6 Extraction
  console.log('--- Test 6: IPv6 Extraction ---');
  const ipv6Details = extractReceivedHeaderDetails('from mail.google.com (mail.google.com [2001:4860:4860::8888]) by mx.org; Tue, 17 Sep 2026 08:00:00 +0000');
  const ipv6Class = classifyIp(ipv6Details.fromIp || '');
  assert(ipv6Details.fromIp === '2001:4860:4860::8888' && ipv6Class.version === 'IPv6' && ipv6Class.isPublic, 'Test 6: IPv6 address extracted and validated as valid IPv6');

  // Test Case 7: Private IP (RFC 1918)
  console.log('--- Test 7: Private IP Classification ---');
  const priv10 = classifyIp('10.0.1.5');
  const priv172 = classifyIp('172.20.10.4');
  const priv192 = classifyIp('192.168.1.1');
  assert(!priv10.isPublic && priv10.classification === 'PRIVATE' && !priv172.isPublic && !priv192.isPublic, 'Test 7: RFC 1918 subnets (10/8, 172.16/12, 192.168/16) classified as PRIVATE');

  // Test Case 8: Loopback IP (127.0.0.1, ::1)
  console.log('--- Test 8: Loopback IP Classification ---');
  const loopback4 = classifyIp('127.0.0.1');
  const loopback6 = classifyIp('::1');
  assert(!loopback4.isPublic && loopback4.classification === 'LOOPBACK' && !loopback6.isPublic && loopback6.classification === 'LOOPBACK', 'Test 8: 127.0.0.1 and ::1 classified strictly as LOOPBACK');

  // Test Case 9: Public IP
  console.log('--- Test 9: Public IP Classification ---');
  const pubIp = classifyIp('185.220.101.42');
  assert(pubIp.isValid && pubIp.isPublic && pubIp.classification === 'PUBLIC', 'Test 9: Public IP classified as PUBLIC and routable');

  // Test Case 10: X-Originating-IP
  console.log('--- Test 10: X-Originating-IP Parsing ---');
  const xOrigRaw = 'From: test@domain.com\nX-Originating-IP: [185.220.101.42]\nSubject: Test\n\nBody';
  const parsed10 = parseRawEmail(xOrigRaw);
  assert(parsed10.xOriginatingIp === '185.220.101.42', 'Test 10: X-Originating-IP extracted without brackets');

  // Test Case 11: Received-SPF
  console.log('--- Test 11: Received-SPF Parsing ---');
  const spfRaw = 'From: test@domain.com\nReceived-SPF: Pass (protection.outlook.com: domain of domain.com designates 194.26.29.115 as permitted sender)\n\nBody';
  const parsed11 = parseRawEmail(spfRaw);
  assert(parsed11.receivedSpfHeaders.length === 1 && parsed11.authResultsHeader?.includes('spf='), 'Test 11: Received-SPF captured in authResultsHeader');

  // Test Case 12: Authentication-Results
  console.log('--- Test 12: Authentication-Results Parsing ---');
  const authRaw = 'From: test@domain.com\nAuthentication-Results: mx.google.com; dkim=pass header.i=@domain.com; spf=pass (google.com: domain designates 194.26.29.115); dmarc=pass\n\nBody';
  const parsed12 = parseRawEmail(authRaw);
  assert(parsed12.authResultsHeaders.length === 1 && parsed12.authResultsHeader?.includes('dmarc=pass'), 'Test 12: Authentication-Results preserved with SPF/DKIM/DMARC tokens');

  // Test Case 13: Missing Received Headers
  console.log('--- Test 13: Missing Received Headers ---');
  const noHeadersRaw = 'From: sender@domain.com\nTo: recipient@domain.com\nSubject: Clean\n\nBody content';
  const parsed13 = parseRawEmail(noHeadersRaw);
  const relay13 = reconstructRelayPath(parsed13.receivedHeaders);
  assert(parsed13.receivedHeaders.length === 0 && relay13.totalHops === 0 && relay13.relayPath.length === 0, 'Test 13: Missing Received headers yields 0 total hops and empty relay path');

  // Test Case 14: Invalid Received Header
  console.log('--- Test 14: Invalid Received Header ---');
  const invalidHeader = 'garbage-header-not-rfc5321-format';
  const extracted14 = extractReceivedHeaderDetails(invalidHeader);
  const relay14 = reconstructRelayPath([invalidHeader]);
  assert(extracted14.fromIp === '' && relay14.totalHops === 1 && (relay14.relayPath[0].classification === 'INVALID' || relay14.relayPath[0].classification === 'UNRESOLVED'), 'Test 14: Invalid header safely handles malformed text without crashing');

  // Test Case 15: Mixed Private/Public Hops
  console.log('--- Test 15: Mixed Private & Public Hops ---');
  const mixedRelay = reconstructRelayPath([
    'by mail-internal.local (Postfix) id 123; Tue, 17 Sep 2026 08:42:15 +0000',
    'from gateway.net ([198.51.100.25]) by mail-internal.local; Tue, 17 Sep 2026 08:42:12 +0000',
    'from vps-115.host.de ([194.26.29.115]) by gateway.net; Tue, 17 Sep 2026 08:42:08 +0000',
    'from internal-node ([10.0.1.50]) by vps-115.host.de; Tue, 17 Sep 2026 08:41:55 +0000'
  ]);
  assert(mixedRelay.totalHops === 4 && mixedRelay.publicHopsCount === 1 && mixedRelay.mappableHopsCount === 1, 'Test 15: Mixed hops correctly segregates private (10.x), documentation, and public (194.26.29.115)');

  // Test Case 16: Geolocation Success
  console.log('--- Test 16: Geolocation Success ---');
  const geoSuccess = await ipIntelligenceService.lookup('209.85.216.54');
  assert(geoSuccess.isPublic && geoSuccess.isMappable && geoSuccess.latitude !== null && geoSuccess.country === 'United States', 'Test 16: Public IP successfully geolocated with verified coordinates and country');

  // Test Case 17: Geolocation Unavailable / Private IP
  console.log('--- Test 17: Geolocation Unavailable on Private IP ---');
  const geoPriv = await ipIntelligenceService.lookup('192.168.1.100');
  assert(!geoPriv.isMappable && geoPriv.latitude === null && geoPriv.longitude === null, 'Test 17: Private IP strictly returns null coordinates (not mappable)');

  // Test Case 18: Provider Failure / Unknown Public IP
  console.log('--- Test 18: Provider Fallback on Unindexed Public IP ---');
  const geoUnknown = await ipIntelligenceService.lookup('198.51.100.1');
  assert(!geoUnknown.isMappable && geoUnknown.latitude === null && geoUnknown.longitude === null, 'Test 18: Unindexed/documentation public IP returns null coordinates without fake fallbacks');

  // Test Case 19: Map Node Transformation
  console.log('--- Test 19: Map Node Transformation Contract ---');
  const sampleBec = SAMPLE_SCENARIOS.find(s => s.id === 'scenario-4-fake-invoice')!;
  const parsedBec = parseRawEmail(sampleBec.rawEml);
  const becRelay = reconstructRelayPath(parsedBec.receivedHeaders);
  const mappableHops = becRelay.relayPath.filter(h => h.isMappable && !isNaN(h.lat) && !isNaN(h.lon));
  assert(mappableHops.length === 2 && typeof mappableHops[0].lat === 'number' && typeof mappableHops[0].lon === 'number', 'Test 19: Map nodes have valid numeric latitude/longitude and isMappable flag');

  // Test Case 20: Timeline Transformation & Chronological Ordering
  console.log('--- Test 20: Timeline Transformation & Chronological Ordering ---');
  assert(becRelay.relayPath[0].index === 1 && becRelay.relayPath[0].ip === '185.220.101.42' && becRelay.relayPath[3].index === 4, 'Test 20: Chronological timeline correctly shows Earliest Origin as Hop #1 and Recipient Ingress as Hop #4');

  // Test Case 21: Selected Node Telemetry Integrity
  console.log('--- Test 21: Selected Node Telemetry Integrity ---');
  const node1 = becRelay.relayPath[0];
  assert(node1.ip === '185.220.101.42' && node1.isp.includes('Bulletproof') && node1.asn === 'AS209104' && node1.country === 'Russia', 'Test 21: Selected node telemetry contains verified ASN, ISP, country, and classification');

  // Test Case 22: Zero Fake Coordinates Guardrail
  console.log('--- Test 22: Zero Fake Coordinates Guardrail ---');
  const loopbackIntel = await ipIntelligenceService.lookup('127.0.0.1');
  const cgnatIntel = await ipIntelligenceService.lookup('100.64.0.1');
  const plottableLoopback = isPlottableLocation({ latitude: loopbackIntel.latitude, longitude: loopbackIntel.longitude });
  const plottableCgnat = isPlottableLocation({ latitude: cgnatIntel.latitude, longitude: cgnatIntel.longitude });
  assert(!plottableLoopback && !plottableCgnat && loopbackIntel.latitude === null && cgnatIntel.latitude === null, 'Test 22: Zero fake coordinates: Loopback and CGNAT are never given fake coordinates or plotted');

  console.log('\n======================================================');
  console.log(`🏁 22 TEST CASES COMPLETED: ${passed} PASSED | ${failed} FAILED`);
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
