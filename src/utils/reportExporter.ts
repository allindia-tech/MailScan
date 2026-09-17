/**
 * MailTrace AI - Incident Report Exporter (Markdown, JSON, STIX 2.1)
 */

import { EmailAnalysisResult } from '../types/forensics.js';

export function generateMarkdownReport(analysis: EmailAnalysisResult): string {
  const timestamp = new Date().toISOString();
  return `# INCIDENT FORENSIC REPORT: ${analysis.id}
**Classification:** ${analysis.primaryClassification}
**Overall Threat Score:** ${analysis.overallRiskScore}/100 (${analysis.severity})
**Generated At:** ${timestamp}

---

## 1. EXECUTIVE SUMMARY
${analysis.assessment.executiveSummary}

* **Threat Confidence:** ${analysis.threatConfidence}%
* **Origin Confidence:** ${analysis.originConfidence}%
* **Attribution Confidence:** ${analysis.attributionConfidence}%

---

## 2. EMAIL IDENTITY & ENVELOPE TRIAGE
* **Subject:** "${analysis.subject}"
* **RFC 5322 From:** ${analysis.from}
* **RFC 5321 Return-Path:** ${analysis.returnPath || 'N/A'}
* **Reply-To:** ${analysis.replyTo || '(Matches From)'}
* **Message-ID:** ${analysis.messageId || 'N/A'}

---

## 3. AUTHENTICATION ALIGNMENT MATRIX
* **SPF:** ${analysis.authResults.spf.status} (Domain: ${analysis.authResults.spf.domain}, Aligned: ${analysis.authResults.spf.alignment})
  * *Details:* ${analysis.authResults.spf.details}
* **DKIM:** ${analysis.authResults.dkim.status} (Domain: ${analysis.authResults.dkim.domain}, Selector: ${analysis.authResults.dkim.selector}, Aligned: ${analysis.authResults.dkim.alignment})
  * *Details:* ${analysis.authResults.dkim.details}
* **DMARC:** ${analysis.authResults.dmarc.status} (Policy: ${analysis.authResults.dmarc.policy}, Disposition: ${analysis.authResults.dmarc.disposition})
  * *Details:* ${analysis.authResults.dmarc.details}

---

## 4. EARLIEST RELIABLE SENDING NODE (NETWORK BOUNDARY)
* **IP Address:** ${analysis.earliestReliableNode?.ip || 'N/A'}
* **Hostname / Reverse DNS:** ${analysis.earliestReliableNode?.reverseDns || 'N/A'}
* **Autonomous System:** ${analysis.earliestReliableNode?.asn || 'N/A'} (${analysis.earliestReliableNode?.isp || 'N/A'})
* **Geolocation:** ${analysis.earliestReliableNode?.city || 'N/A'}, ${analysis.earliestReliableNode?.country || 'N/A'}
* **Total Relay Hops:** ${analysis.relayPath.length}

---

## 5. INDICATORS OF COMPROMISE (IOCs)
${analysis.iocs.map(i => `- **[${i.type.toUpperCase()}]** \`${i.indicator}\` — Risk: ${i.risk} | Context: ${i.context}`).join('\n')}

---

## 6. CONTAINMENT & DEFENSIVE RECOMMENDATIONS
${analysis.assessment.containmentPlaybook.map((step, idx) => `${idx + 1}. ${step}`).join('\n')}

---

## 7. ATTRIBUTION & COMPLIANCE DISCLAIMER
> ${analysis.assessment.disclaimer}
`;
}

export function generateStixBundle(analysis: EmailAnalysisResult): any {
  const timestamp = new Date().toISOString();
  return {
    type: 'bundle',
    id: `bundle--${crypto.randomUUID ? crypto.randomUUID() : 'mailtrace-bundle'}`,
    spec_version: '2.1',
    objects: [
      {
        type: 'report',
        id: `report--${analysis.id}`,
        created: timestamp,
        modified: timestamp,
        name: `MailTrace Forensic Report: ${analysis.primaryClassification}`,
        description: analysis.assessment.executiveSummary,
        confidence: analysis.threatConfidence,
        labels: ['email-threat', analysis.severity.toLowerCase()]
      },
      ...analysis.iocs.map((ioc, idx) => ({
        type: 'indicator',
        id: `indicator--${analysis.id}-${idx}`,
        created: timestamp,
        modified: timestamp,
        name: `${ioc.type.toUpperCase()} Indicator`,
        pattern_type: 'stix',
        pattern: `[${ioc.type}-addr:value = '${ioc.indicator}']`,
        valid_from: timestamp,
        confidence: analysis.threatConfidence
      }))
    ]
  };
}

export function downloadFile(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
