/**
 * MailTrace Workstation - Header Forensics & Anomaly Matrix
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * High-density RFC header analysis table (Field, Inspected Value, Triage Finding, Why It Matters).
 */

import React, { useState } from 'react';
import {
  ShieldCheck,
  FileCode,
  Search,
  Copy,
  Check,
  AlertTriangle,
  Terminal,
  Filter
} from 'lucide-react';
import { EmailAnalysisResult } from '../types/forensics.js';

interface HeaderForensicsTabProps {
  analysis: EmailAnalysisResult;
}

export const HeaderForensicsTab: React.FC<HeaderForensicsTabProps> = ({ analysis }) => {
  const [headerSearch, setHeaderSearch] = useState('');
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [activeFindingTag, setActiveFindingTag] = useState<string>('ALL');

  const { authResults, headerAnomalies, findings } = analysis;

  const handleCopyHeaders = () => {
    navigator.clipboard.writeText(analysis.rawHeaders);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  // Structured High-Density RFC Forensics Table matching Reference
  const forensicHeaders = [
    {
      field: 'From',
      value: analysis.from,
      finding: analysis.senderDomainIntel?.isLookalike
        ? 'Impersonation'
        : 'Aligned',
      findingColor: analysis.senderDomainIntel?.isLookalike ? 'rose' : 'emerald',
      whyItMatters: analysis.senderDomainIntel?.isLookalike
        ? `Lookalike domain (${analysis.fromDomain}) mimicking legitimate ${analysis.senderDomainIntel.targetDomain || 'corporate identity'}`
        : 'Display name and origin domain align with authenticated envelope.'
    },
    {
      field: 'Reply-To',
      value: analysis.replyTo || '(Matches From)',
      finding: analysis.replyTo && analysis.replyTo !== analysis.from
        ? 'Redirected'
        : 'Consistent',
      findingColor: analysis.replyTo && analysis.replyTo !== analysis.from ? 'amber' : 'emerald',
      whyItMatters: analysis.replyTo && analysis.replyTo !== analysis.from
        ? `Replies bypass sending server and divert to ${analysis.replyTo}`
        : 'Replies route back to sender domain without detour.'
    },
    {
      field: 'Return-Path',
      value: analysis.returnPath || '(Not specified)',
      finding: analysis.authResults?.spf?.alignment === false
        ? 'Misaligned'
        : 'Aligned',
      findingColor: analysis.authResults?.spf?.alignment === false ? 'amber' : 'emerald',
      whyItMatters: analysis.authResults?.spf?.alignment === false
        ? 'Envelope bounce address differs from declared From domain.'
        : 'Matches SPF alignment validation.'
    },
    {
      field: 'Received IP',
      value: analysis.earliestReliableNode ? `${analysis.earliestReliableNode.ip} (${analysis.earliestReliableNode.country || 'Transit'})` : (analysis.authResults?.spf?.clientIp || 'Origin Gateway'),
      finding: analysis.earliestReliableNode?.isTor || analysis.iocs?.some(i => i.type === 'ip' && i.risk === 'CRITICAL')
        ? 'Tor Node / Threat IP'
        : 'Standard Relay',
      findingColor: analysis.earliestReliableNode?.isTor ? 'rose' : 'slate',
      whyItMatters: analysis.earliestReliableNode?.isTor
        ? 'Origin infrastructure masked through anonymized Tor or VPN proxy relay.'
        : 'Standard corporate MTA transport relay hop.'
    },
    {
      field: 'Authentication-Results',
      value: `spf=${authResults.spf.status} dkim=${authResults.dkim.status} dmarc=${authResults.dmarc.status}`,
      finding: authResults.dmarc.status === 'PASS' && authResults.dkim.status === 'PASS'
        ? 'Verified'
        : (authResults.dmarc.status === 'FAIL' || authResults.dkim.status === 'FAIL' ? 'Auth Failure' : 'Evaded / Neutral'),
      findingColor: authResults.dmarc.status === 'PASS' && authResults.dkim.status === 'PASS' ? 'emerald' : 'rose',
      whyItMatters: authResults.dmarc.status === 'FAIL' || authResults.dkim.status === 'FAIL'
        ? 'Cryptographic integrity failed or SPF authorization rejected by domain policy.'
        : 'All standard RFC cryptographic checks passed.'
    },
    {
      field: 'DKIM-Signature',
      value: authResults.dkim.domain ? `d=${authResults.dkim.domain} s=${authResults.dkim.selector || 'default'}` : 'Missing Signature',
      finding: authResults.dkim.status === 'PASS' ? 'Signature Valid' : (authResults.dkim.status === 'FAIL' ? 'Body Mismatch' : 'Unsigned'),
      findingColor: authResults.dkim.status === 'PASS' ? 'emerald' : 'rose',
      whyItMatters: authResults.dkim.status === 'FAIL'
        ? 'Message body content was mutated post-signing in transit.'
        : (authResults.dkim.status === 'PASS' ? 'Digital signature is cryptographically intact.' : 'No DKIM signature found on inbound message.')
    },
    {
      field: 'Message-ID',
      value: analysis.messageId || '<unspecified@missing>',
      finding: analysis.messageId ? 'Valid Syntax' : 'Missing Syntax',
      findingColor: analysis.messageId ? 'slate' : 'amber',
      whyItMatters: analysis.messageId ? 'RFC 5322 globally unique identifier structure present.' : 'Missing Message-ID is typical of automated mailer scripts.'
    },
    {
      field: 'X-Mailer / User-Agent',
      value: analysis.headers?.['x-mailer'] || analysis.headers?.['user-agent'] || '(Standard Ingress)',
      finding: analysis.headers?.['x-mailer']?.toLowerCase().includes('phpmailer') || analysis.headers?.['x-mailer']?.toLowerCase().includes('python')
        ? 'Scripted Mailer'
        : 'Client / Webmail',
      findingColor: analysis.headers?.['x-mailer']?.toLowerCase().includes('phpmailer') ? 'amber' : 'slate',
      whyItMatters: analysis.headers?.['x-mailer']?.toLowerCase().includes('phpmailer')
        ? 'Automated scripting engine used rather than interactive desktop client.'
        : 'Standard desktop or enterprise web client envelope.'
    }
  ];

  return (
    <div className="space-y-5">
      
      {/* 1. Header Forensics Table */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs overflow-hidden">
        <div className="p-4 bg-slate-50 border-b border-slate-200 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-indigo-600" />
            <div>
              <h2 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
                RFC 5322 Forensic Key-Value Inspection
              </h2>
              <span className="text-[11px] text-slate-500">
                Cryptographic authentication alignment, routing bifurcation, and origin telemetry
              </span>
            </div>
          </div>

          <button
            onClick={handleCopyHeaders}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 text-xs font-medium transition shadow-xs"
          >
            {copiedRaw ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-500" />}
            <span>{copiedRaw ? 'Copied' : 'Copy Headers'}</span>
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-200 text-slate-500 uppercase text-[10px] tracking-wider bg-slate-50 font-mono">
                <th className="py-2.5 px-4 font-semibold w-48">RFC Header Field</th>
                <th className="py-2.5 px-4 font-semibold w-64">Inspected Value</th>
                <th className="py-2.5 px-4 font-semibold w-36">Triage Finding</th>
                <th className="py-2.5 px-4 font-semibold">Why It Matters</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
              {forensicHeaders.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-50 transition-colors">
                  <td className="py-3 px-4 font-bold text-slate-800">{item.field}</td>
                  <td className="py-3 px-4 text-slate-900 break-all max-w-xs">{item.value}</td>
                  <td className="py-3 px-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-sans font-bold border ${
                      item.findingColor === 'rose'
                        ? 'bg-rose-50 text-rose-700 border-rose-200'
                        : item.findingColor === 'amber'
                        ? 'bg-amber-50 text-amber-800 border-amber-200'
                        : item.findingColor === 'emerald'
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : 'bg-slate-100 text-slate-700 border-slate-200'
                    }`}>
                      {item.finding}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-sans text-slate-600 text-xs leading-normal">
                    {item.whyItMatters}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 2. Detected Header Anomalies */}
      {headerAnomalies && headerAnomalies.length > 0 && (
        <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
          <div className="flex items-center gap-2 border-b border-slate-100 pb-2">
            <AlertTriangle className="w-4 h-4 text-amber-600" />
            <h3 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              Detected Header Anomalies ({headerAnomalies.length})
            </h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {headerAnomalies.map((anomaly, idx) => (
              <div key={idx} className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-slate-900">{anomaly.field}</span>
                  <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold uppercase border ${
                    anomaly.severity === 'CRITICAL' || anomaly.severity === 'HIGH'
                      ? 'bg-rose-50 text-rose-700 border-rose-200'
                      : 'bg-amber-50 text-amber-800 border-amber-200'
                  }`}>
                    {anomaly.severity}
                  </span>
                </div>
                <p className="text-slate-600 text-[11px] leading-relaxed">{anomaly.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

    </div>
  );
};
