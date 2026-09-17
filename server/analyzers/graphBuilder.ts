/**
 * MailTrace AI - Relationship Graph Construction Engine
 */

import { GraphEdge, GraphNode, ThreatSeverity } from '../../src/types/forensics.js';
import { IPIntelligence } from '../../src/types/forensics.js';
import { DomainIntelligence } from '../../src/types/forensics.js';
import { URLAnalysis } from '../../src/types/forensics.js';
import { AttachmentAnalysis } from '../../src/types/forensics.js';

export function buildRelationshipGraph(
  subject: string,
  fromEmail: string,
  domainIntel: DomainIntelligence,
  ips: IPIntelligence[],
  urls: URLAnalysis[],
  attachments: AttachmentAnalysis[],
  campaignName?: string
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  let edgeCounter = 1;

  // Root Email Node
  const rootId = 'node-email-root';
  nodes.push({
    id: rootId,
    label: subject.length > 28 ? subject.substring(0, 25) + '...' : subject,
    type: 'email',
    risk: domainIntel.reputation === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
    subtext: 'Subject: Target Mail Item',
    x: 400,
    y: 120
  });

  // Sender Node
  const senderId = 'node-sender';
  nodes.push({
    id: senderId,
    label: fromEmail,
    type: 'sender',
    risk: domainIntel.reputation,
    subtext: 'From Address',
    x: 200,
    y: 240
  });
  edges.push({
    id: `edge-${edgeCounter++}`,
    source: rootId,
    target: senderId,
    label: 'SENT_FROM'
  });

  // Domain Node
  const domainId = 'node-domain';
  nodes.push({
    id: domainId,
    label: domainIntel.domain,
    type: 'domain',
    risk: domainIntel.reputation,
    subtext: `Age: ${domainIntel.domainAgeDays}d | ${domainIntel.registrar.split('/')[0]}`,
    x: 200,
    y: 380
  });
  edges.push({
    id: `edge-${edgeCounter++}`,
    source: senderId,
    target: domainId,
    label: 'RESOLVES_TO'
  });

  // Primary External IP Node
  const primaryIp = ips.find(ip => !ip.ip.startsWith('10.') && !ip.ip.startsWith('192.168.')) || ips[0];
  if (primaryIp) {
    const ipId = `node-ip-${primaryIp.ip.replace(/\./g, '-')}`;
    nodes.push({
      id: ipId,
      label: primaryIp.ip,
      type: 'ip',
      risk: primaryIp.threatScore >= 75 ? 'CRITICAL' : (primaryIp.threatScore >= 40 ? 'HIGH' : 'LOW'),
      subtext: `${primaryIp.city}, ${primaryIp.countryCode}`,
      x: 200,
      y: 520
    });
    edges.push({
      id: `edge-${edgeCounter++}`,
      source: domainId,
      target: ipId,
      label: 'RESOLVES_TO'
    });

    // ASN Node
    const asnId = `node-asn-${primaryIp.asn}`;
    nodes.push({
      id: asnId,
      label: primaryIp.asn,
      type: 'asn',
      risk: primaryIp.threatScore >= 75 ? 'CRITICAL' : 'MEDIUM',
      subtext: primaryIp.isp.length > 25 ? primaryIp.isp.substring(0, 22) + '...' : primaryIp.isp,
      x: 200,
      y: 660
    });
    edges.push({
      id: `edge-${edgeCounter++}`,
      source: ipId,
      target: asnId,
      label: 'HOSTED_ON'
    });
  }

  // URL Nodes
  let urlY = 240;
  for (let i = 0; i < Math.min(urls.length, 3); i++) {
    const u = urls[i];
    const uId = `node-url-${i}`;
    nodes.push({
      id: uId,
      label: u.domain,
      type: 'url',
      risk: u.risk,
      subtext: u.isIpUrl ? 'Bare IP Host' : (u.hasCredentialPath ? 'Credential Gateway' : 'Target Host'),
      x: 600,
      y: urlY
    });
    edges.push({
      id: `edge-${edgeCounter++}`,
      source: rootId,
      target: uId,
      label: 'LINKS_TO'
    });
    urlY += 120;
  }

  // Attachment Nodes
  let attY = 240;
  for (let i = 0; i < Math.min(attachments.length, 2); i++) {
    const att = attachments[i];
    const attId = `node-att-${i}`;
    nodes.push({
      id: attId,
      label: att.filename,
      type: 'attachment',
      risk: att.risk,
      subtext: `${(att.sizeBytes / 1024).toFixed(1)} KB | ${att.flags.isDoubleExtension ? 'Double Ext!' : att.fileType}`,
      x: 400,
      y: 400 + (i * 120)
    });
    edges.push({
      id: `edge-${edgeCounter++}`,
      source: rootId,
      target: attId,
      label: 'CONTAINS'
    });
  }

  // Campaign node if present
  if (campaignName) {
    const campId = 'node-campaign';
    nodes.push({
      id: campId,
      label: campaignName,
      type: 'campaign',
      risk: 'CRITICAL',
      subtext: 'Correlated Threat Group',
      x: 400,
      y: 10
    });
    edges.push({
      id: `edge-${edgeCounter++}`,
      source: rootId,
      target: campId,
      label: 'PART_OF_CAMPAIGN'
    });
  }

  return { nodes, edges };
}
