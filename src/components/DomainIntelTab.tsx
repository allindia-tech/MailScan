/**
 * MailTrace Workstation - Domain Intelligence & Typosquatting Analysis
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Homoglyph sweeper, Levenshtein distance calculation, and DNS record evaluation.
 */

import React from 'react';
import {
  Globe,
  AlertTriangle,
  Server,
  CheckCircle,
  Clock,
  ShieldCheck,
  ShieldAlert
} from 'lucide-react';
import { DomainIntelligence, EmailAnalysisResult } from '../types/forensics.js';

interface DomainIntelTabProps {
  analysis: EmailAnalysisResult;
}

export const DomainIntelTab: React.FC<DomainIntelTabProps> = ({ analysis }) => {
  const domainIntel: DomainIntelligence = analysis.senderDomainIntel;

  if (!domainIntel) {
    return (
      <div className="p-6 text-center text-xs font-mono text-slate-500 bg-white rounded-xl border border-slate-200">
        No domain intelligence available for this specimen.
      </div>
    );
  }

  return (
    <div className="space-y-5">
      
      {/* 1. Top Telemetry Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        
        {/* Domain Name & Reputation */}
        <div className="p-3.5 rounded-lg bg-white border border-slate-200 shadow-xs">
          <span className="text-[10px] uppercase font-bold text-slate-400 font-mono block mb-1">
            Sender Domain
          </span>
          <div className="font-mono text-xs font-bold text-slate-900 truncate">{domainIntel.domain}</div>
          <div className="mt-2">
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
              domainIntel.reputation === 'CRITICAL'
                ? 'bg-rose-50 text-rose-700 border-rose-200'
                : 'bg-emerald-50 text-emerald-700 border-emerald-200'
            }`}>
              {domainIntel.reputation === 'CRITICAL' ? 'HIGH ABUSE RISK' : 'REPUTABLE DOMAIN'}
            </span>
          </div>
        </div>

        {/* Domain Age */}
        <div className="p-3.5 rounded-lg bg-white border border-slate-200 shadow-xs">
          <span className="text-[10px] uppercase font-bold text-slate-400 font-mono block mb-1">
            Domain Age
          </span>
          <div className="flex items-baseline gap-1.5">
            <span className={`text-xl font-mono font-bold ${domainIntel.domainAgeDays < 30 ? 'text-rose-600' : 'text-slate-900'}`}>
              {domainIntel.domainAgeDays}
            </span>
            <span className="text-xs text-slate-500 font-mono">days</span>
          </div>
          <div className="text-[10px] text-slate-500 mt-1 font-mono">
            {domainIntel.domainAgeDays < 30 ? '⚠️ Newly registered domain' : `~${domainIntel.domainAgeYears} years active`}
          </div>
        </div>

        {/* Registrar */}
        <div className="p-3.5 rounded-lg bg-white border border-slate-200 shadow-xs">
          <span className="text-[10px] uppercase font-bold text-slate-400 font-mono block mb-1">
            Registrar
          </span>
          <div className="text-xs font-mono text-slate-800 font-medium truncate">{domainIntel.registrar || 'Unknown'}</div>
          <div className="text-[10px] text-slate-500 mt-1 font-mono">
            Registered: {domainIntel.registrationDate || 'Not specified'}
          </div>
        </div>

        {/* Hosting / ASN */}
        <div className="p-3.5 rounded-lg bg-white border border-slate-200 shadow-xs">
          <span className="text-[10px] uppercase font-bold text-slate-400 font-mono block mb-1">
            Autonomous System
          </span>
          <div className="text-xs font-mono text-indigo-700 font-semibold">{domainIntel.asn || 'AS-UNASSIGNED'}</div>
          <div className="text-[10px] text-slate-500 mt-1 truncate">
            {domainIntel.hostingProvider || 'Standard Data Center'}
          </div>
        </div>

      </div>

      {/* 2. Lookalike & Typosquatting Detection */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <Globe className="w-4 h-4 text-indigo-600" />
            <h2 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              Homoglyph & Brand Impersonation Sweeper
            </h2>
          </div>
          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
            domainIntel.lookalikePatterns && domainIntel.lookalikePatterns.length > 0
              ? 'bg-rose-50 text-rose-700 border-rose-200'
              : 'bg-emerald-50 text-emerald-700 border-emerald-200'
          }`}>
            Risk: {domainIntel.impersonationRisk}
          </span>
        </div>

        {domainIntel.lookalikePatterns && domainIntel.lookalikePatterns.length > 0 ? (
          <div className="space-y-2.5">
            {domainIntel.lookalikePatterns.map((pattern, idx) => (
              <div
                key={idx}
                className="p-3.5 rounded-lg bg-rose-50/50 border border-rose-200 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 text-xs"
              >
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-700 border border-rose-300 font-mono text-[10px] uppercase font-bold">
                      {pattern.type.replace('_', ' ')}
                    </span>
                    <span className="font-semibold text-slate-900">
                      Target Identity: <span className="text-slate-900 font-bold">{pattern.targetBrand}</span> ({pattern.targetDomain})
                    </span>
                  </div>
                  <p className="text-slate-700 text-xs leading-relaxed">{pattern.description}</p>
                </div>

                {domainIntel.similarityToTarget && (
                  <div className="bg-white px-3 py-1.5 rounded border border-rose-200 text-center shrink-0 shadow-xs">
                    <span className="text-[10px] font-mono text-slate-500 block uppercase">Levenshtein Distance</span>
                    <span className="text-xs font-mono font-bold text-rose-700">{domainIntel.similarityToTarget}% Match</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="py-3 text-xs text-slate-600 flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-600 shrink-0" />
            <span>No deceptive homoglyphs or typosquatting patterns detected against monitored enterprise brand directory.</span>
          </div>
        )}
      </div>

      {/* 3. DNS Resource Records */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-indigo-600" />
            <h2 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              DNS Telemetry & Resource Records
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-500">DNSSEC: {domainIntel.dnssec ? 'Enabled' : 'Disabled'}</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
          
          {/* MX Records */}
          <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
            <span className="text-[10px] uppercase text-slate-500 font-bold block mb-1.5 font-mono">Mail Exchanger (MX) Records</span>
            <div className="space-y-1">
              {domainIntel.mxRecords && domainIntel.mxRecords.length > 0 ? (
                domainIntel.mxRecords.map((mx, i) => (
                  <div key={i} className="text-slate-800 text-[11px]">{mx}</div>
                ))
              ) : (
                <div className="text-slate-400 text-[11px]">No MX records observed</div>
              )}
            </div>
          </div>

          {/* TXT Records */}
          <div className="bg-slate-50 p-3 rounded-lg border border-slate-200">
            <span className="text-[10px] uppercase text-slate-500 font-bold block mb-1.5 font-mono">TXT / SPF Records</span>
            <div className="space-y-1">
              {domainIntel.txtRecords && domainIntel.txtRecords.length > 0 ? (
                domainIntel.txtRecords.map((txt, i) => (
                  <div key={i} className="text-slate-800 text-[11px] break-all">{txt}</div>
                ))
              ) : (
                <div className="text-slate-400 text-[11px]">No TXT records observed</div>
              )}
            </div>
          </div>

        </div>
      </div>

    </div>
  );
};
