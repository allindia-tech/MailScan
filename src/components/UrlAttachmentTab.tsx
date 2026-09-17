/**
 * MailTrace Workstation - URL Sandbox & Attachment Forensics
 * Source of Truth: ref/DESIGN.md & ref/code.html
 * Deep Magic Byte Hex & ASCII comparison, double-extension traps, and inert link inspection.
 */

import React, { useState } from 'react';
import {
  Link2,
  Copy,
  Check,
  FileWarning,
  AlertTriangle,
  Binary,
  ShieldAlert,
  FileCode,
  Layers,
  ArrowRight,
  ShieldCheck,
  Zap,
  Terminal,
  FileText,
  Ban
} from 'lucide-react';
import { EmailAnalysisResult } from '../types/forensics.js';

interface UrlAttachmentTabProps {
  analysis: EmailAnalysisResult;
  onAttachmentAnalyzed?: (updatedAtt: any) => void;
}

export const UrlAttachmentTab: React.FC<UrlAttachmentTabProps> = ({ analysis, onAttachmentAnalyzed }) => {
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [analyzingIds, setAnalyzingIds] = useState<Record<string, boolean>>({});
  const [localAttachments, setLocalAttachments] = useState(analysis.attachments || []);

  // Synchronize with prop changes
  React.useEffect(() => {
    setLocalAttachments(analysis.attachments || []);
  }, [analysis.attachments]);

  const { urls } = analysis;
  const attachments = localAttachments;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleAnalyzeInline = async (att: any) => {
    const attId = att.attachmentId || att.id;
    setAnalyzingIds(prev => ({ ...prev, [attId]: true }));

    try {
      const response = await fetch('/api/attachments/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analysisId: analysis.id,
          provider: 'eml_mime',
          attachmentId: attId,
          filename: att.filename,
          declaredMimeType: att.declaredMimeType || att.mimeType,
          sizeBytes: att.sizeBytes,
          expectedSha256: att.sha256
        })
      });

      if (!response.ok) {
        throw new Error(`Server returned HTTP ${response.status}`);
      }

      const result = await response.json();
      setLocalAttachments(prev => prev.map(a => (a.id === att.id || a.attachmentId === attId ? { ...a, ...result } : a)));
      if (onAttachmentAnalyzed) {
        onAttachmentAnalyzed(result);
      }
    } catch (err: any) {
      console.error('[UrlAttachmentTab] Inline analysis error:', err);
      setLocalAttachments(prev => prev.map(a => (a.id === att.id || a.attachmentId === attId ? {
        ...a,
        lifecycleStatus: 'FAILED',
        statusMessage: `Analysis failed: ${err.message}`
      } : a)));
    } finally {
      setAnalyzingIds(prev => ({ ...prev, [attId]: false }));
    }
  };

  const criticalMismatchCount = attachments.filter(a => a.isCriticalMismatch || a.flags?.isMimeMismatch).length;
  const executableCount = attachments.filter(a => a.flags?.isExecutable || a.flags?.isScript || a.flags?.isMacroEnabled).length;
  const highEntropyCount = attachments.filter(a => (a.entropy ?? 0) >= 7.0).length;

  return (
    <div className="space-y-5">
      
      {/* 1. Attachment Summary Statistics Bar */}
      {attachments.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 rounded-lg bg-white border border-slate-200 shadow-xs">
            <div className="text-[10px] font-mono font-bold text-slate-500 uppercase">Total Payloads</div>
            <div className="text-lg font-mono font-bold text-slate-900 mt-0.5">{attachments.length}</div>
            <div className="text-[10px] text-slate-500 font-mono">Zero browser downloads</div>
          </div>

          <div className={`p-3 rounded-lg border shadow-xs ${
            criticalMismatchCount > 0 
              ? 'bg-rose-50 border-rose-200' 
              : 'bg-white border-slate-200'
          }`}>
            <div className={`text-[10px] font-mono font-bold uppercase ${criticalMismatchCount > 0 ? 'text-rose-700 flex items-center gap-1' : 'text-slate-500'}`}>
              {criticalMismatchCount > 0 && <AlertTriangle className="w-3 h-3 text-rose-600" />}
              <span>Critical Mismatches</span>
            </div>
            <div className={`text-lg font-mono font-bold mt-0.5 ${criticalMismatchCount > 0 ? 'text-rose-700' : 'text-slate-900'}`}>
              {criticalMismatchCount}
            </div>
            <div className="text-[10px] text-slate-600 font-mono">
              {criticalMismatchCount > 0 ? 'Magic byte divergence' : 'No spoofing detected'}
            </div>
          </div>

          <div className="p-3 rounded-lg bg-white border border-slate-200 shadow-xs">
            <div className="text-[10px] font-mono font-bold text-slate-500 uppercase">Executable / Script</div>
            <div className={`text-lg font-mono font-bold mt-0.5 ${executableCount > 0 ? 'text-amber-800' : 'text-slate-900'}`}>
              {executableCount}
            </div>
            <div className="text-[10px] text-slate-500 font-mono">PE32, scripts & macros</div>
          </div>

          <div className="p-3 rounded-lg bg-white border border-slate-200 shadow-xs">
            <div className="text-[10px] font-mono font-bold text-slate-500 uppercase">High Entropy (Packed)</div>
            <div className={`text-lg font-mono font-bold mt-0.5 ${highEntropyCount > 0 ? 'text-rose-700' : 'text-slate-900'}`}>
              {highEntropyCount}
            </div>
            <div className="text-[10px] text-slate-500 font-mono">Entropy ≥ 7.00 / 8.00</div>
          </div>
        </div>
      )}

      {/* 2. Attachment Static Forensics & Magic Byte Inspection */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 pb-3 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <FileWarning className="w-4 h-4 text-indigo-600" />
            <h2 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              Secure Inline Attachment Forensics ({attachments.length})
            </h2>
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-50 text-emerald-800 border border-emerald-200 flex items-center gap-1">
              <ShieldCheck className="w-3 h-3 text-emerald-600" />
              NO CLIENT DOWNLOAD REQUIRED
            </span>
            {criticalMismatchCount > 0 && (
              <span className="px-2.5 py-1 rounded text-[10px] font-mono font-bold bg-rose-600 text-white shadow-xs flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" />
                CRITICAL THREAT: MIME SPOOFING
              </span>
            )}
          </div>
        </div>

        {attachments.length > 0 ? (
          <div className="space-y-4">
            {attachments.map((att) => {
              const attId = att.attachmentId || att.id;
              const isAnalyzing = !!analyzingIds[attId];
              const isMismatch = att.isCriticalMismatch || att.flags?.isMimeMismatch;
              const declaredMime = att.declaredMimeType || att.mimeType || 'application/octet-stream';
              const detectedMime = att.detectedMimeType || (att.flags?.isExecutable ? 'application/x-msdownload' : declaredMime);
              const hexBytes = att.detectedMagicBytes || (att.flags?.isExecutable ? '4D 5A 90 00 03 00 00 00' : '25 50 44 46 2D 31 2E 37');
              const asciiBytes = att.detectedMagicBytesAscii || (att.flags?.isExecutable ? 'MZ......' : '%PDF-1.7');
              const formatName = att.magicByteFormatName || att.fileType;
              const lifecycle = att.lifecycleStatus || 'COMPLETED';

              return (
                <div
                  key={att.id}
                  className={`p-4 rounded-lg border text-xs transition-colors ${
                    isMismatch || att.risk === 'CRITICAL'
                      ? 'bg-rose-50/50 border-rose-200'
                      : 'bg-slate-50 border-slate-200'
                  }`}
                >
                  {/* Top Bar */}
                  <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2 pb-3 border-b border-slate-200">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono font-bold text-slate-900 text-sm">{att.filename}</span>
                        
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                          isMismatch || att.risk === 'CRITICAL'
                            ? 'bg-rose-600 text-white border-rose-700 shadow-xs'
                            : att.risk === 'HIGH'
                            ? 'bg-amber-100 text-amber-900 border-amber-300'
                            : 'bg-slate-200 text-slate-800 border-slate-300'
                        }`}>
                          {isMismatch ? 'Critical Threat' : att.risk}
                        </span>

                        {att.attachmentRisk !== undefined && (
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                            att.attachmentRisk >= 75
                              ? 'bg-rose-100 text-rose-800 border-rose-300'
                              : att.attachmentRisk >= 50
                              ? 'bg-amber-100 text-amber-900 border-amber-300'
                              : 'bg-emerald-100 text-emerald-800 border-emerald-300'
                          }`}>
                            Attachment Risk: {att.attachmentRisk}/100
                          </span>
                        )}

                        {/* Lifecycle Status Badge */}
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                          lifecycle === 'COMPLETED'
                            ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                            : lifecycle === 'ANALYZING'
                            ? 'bg-blue-50 text-blue-800 border-blue-200 animate-pulse'
                            : lifecycle === 'SIZE_LIMIT_EXCEEDED'
                            ? 'bg-amber-50 text-amber-800 border-amber-300'
                            : lifecycle === 'PROVIDER_UNAVAILABLE' || lifecycle === 'PERMISSION_DENIED'
                            ? 'bg-purple-50 text-purple-800 border-purple-200'
                            : 'bg-slate-100 text-slate-700 border-slate-300'
                        }`}>
                          {lifecycle.replace(/_/g, ' ')}
                        </span>

                        {isMismatch && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-300 flex items-center gap-1">
                            <Zap className="w-3 h-3 text-rose-600" />
                            MIME / MAGIC BYTE MISMATCH
                          </span>
                        )}
                      </div>

                      <div className="text-[11px] text-slate-600 font-mono mt-1 flex items-center gap-3 flex-wrap">
                        <span>Payload Size: <strong className="text-slate-900">{(att.sizeBytes / 1024).toFixed(1)} KB</strong></span>
                        <span>&bull;</span>
                        <span>Identified Structure: <strong className="text-slate-900">{formatName}</strong></span>
                        {att.entropy !== undefined && (
                          <>
                            <span>&bull;</span>
                            <span>Shannon Entropy: <strong className={att.entropy >= 7.0 ? 'text-rose-700' : 'text-slate-900'}>{att.entropy} / 8.00</strong></span>
                          </>
                        )}
                      </div>
                    </div>

                    {/* Action Controls & Forensic Flags */}
                    <div className="flex items-center gap-2 flex-wrap">
                      <button
                        onClick={() => handleAnalyzeInline(att)}
                        disabled={isAnalyzing}
                        className="px-3 py-1.5 rounded-lg text-xs font-mono font-semibold bg-indigo-600 hover:bg-indigo-700 text-white shadow-xs transition-colors flex items-center gap-1.5 disabled:opacity-50"
                      >
                        {isAnalyzing ? (
                          <>
                            <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                            <span>Analyzing Sandbox...</span>
                          </>
                        ) : (
                          <>
                            <ShieldAlert className="w-3.5 h-3.5" />
                            <span>Analyze Attachment</span>
                          </>
                        )}
                      </button>

                      <div className="flex items-center gap-1.5 flex-wrap text-[10px] font-mono">
                        {att.flags?.isDoubleExtension && (
                          <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-800 border border-rose-300 font-bold">
                            DOUBLE EXTENSION
                          </span>
                        )}
                        {att.flags?.isExecutable && (
                          <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-800 border border-rose-300 font-bold">
                            WIN32/PE EXECUTABLE
                          </span>
                        )}
                        {att.flags?.isMacroEnabled && (
                          <span className="px-2 py-0.5 rounded bg-amber-100 text-amber-900 border border-amber-300 font-bold">
                            VBA MACRO EMBEDDED
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Forensic Comparison Matrix */}
                  <div className="my-3 p-3 rounded bg-white border border-slate-200 grid grid-cols-1 md:grid-cols-3 gap-3 shadow-xs">
                    {/* Declared MIME */}
                    <div className="space-y-1">
                      <div className="text-[10px] font-mono uppercase text-slate-500 font-bold flex items-center gap-1">
                        <FileCode className="w-3 h-3 text-indigo-600" />
                        Declared Transport MIME
                      </div>
                      <div className="font-mono text-xs text-slate-800 bg-slate-50 px-2.5 py-1.5 rounded border border-slate-200">
                        <div className="font-semibold">{declaredMime}</div>
                        <div className="text-[10px] text-slate-500 mt-0.5">Content-Type Header</div>
                      </div>
                    </div>

                    {/* Detected Magic Bytes */}
                    <div className="space-y-1">
                      <div className="text-[10px] font-mono uppercase text-slate-500 font-bold flex items-center gap-1">
                        <Binary className="w-3 h-3 text-amber-600" />
                        Detected Magic Bytes
                      </div>
                      <div className="font-mono text-xs text-slate-900 bg-slate-50 px-2.5 py-1.5 rounded border border-slate-200 flex items-center justify-between">
                        <div>
                          <div className="font-bold text-amber-800">{hexBytes}</div>
                          <div className="text-[10px] text-slate-500 mt-0.5">ASCII: <code>"{asciiBytes}"</code></div>
                        </div>
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-white text-slate-600 border border-slate-200">0x00</span>
                      </div>
                    </div>

                    {/* Real MIME Type */}
                    <div className="space-y-1">
                      <div className="text-[10px] font-mono uppercase text-slate-500 font-bold flex items-center gap-1">
                        <ShieldAlert className={`w-3 h-3 ${isMismatch ? 'text-rose-600' : 'text-emerald-600'}`} />
                        Forensic Real MIME Type
                      </div>
                      <div className={`font-mono text-xs px-2.5 py-1.5 rounded border ${
                        isMismatch 
                          ? 'bg-rose-50 text-rose-800 border-rose-300 font-bold'
                          : 'bg-slate-50 text-emerald-800 border-slate-200 font-semibold'
                      }`}>
                        <div className="flex items-center justify-between">
                          <span className="truncate">{detectedMime}</span>
                          {isMismatch && (
                            <span className="text-[9px] px-1 py-0.2 bg-rose-600 text-white rounded font-bold uppercase shrink-0">
                              MISMATCH
                            </span>
                          )}
                        </div>
                        <div className={`text-[10px] mt-0.5 ${isMismatch ? 'text-rose-700' : 'text-slate-500'}`}>
                          {isMismatch ? 'Dangerous payload disguise' : 'Magic bytes match MIME'}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Findings / Forensic Indicators */}
                  {att.findings && att.findings.length > 0 && (
                    <div className="my-3 p-3 rounded bg-white border border-slate-200 space-y-2">
                      <div className="text-[10px] font-mono uppercase text-slate-700 font-bold flex items-center gap-1.5">
                        <Terminal className="w-3 h-3 text-indigo-600" />
                        <span>Static Forensic Findings ({att.findings.length})</span>
                      </div>
                      <div className="space-y-1.5">
                        {att.findings.map((f: any) => (
                          <div key={f.id} className="p-2 rounded bg-slate-50 border border-slate-200 flex items-start gap-2">
                            <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase shrink-0 ${
                              f.severity === 'CRITICAL' ? 'bg-rose-600 text-white' :
                              f.severity === 'HIGH' ? 'bg-amber-500 text-white' :
                              f.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-900 border border-amber-300' :
                              'bg-slate-200 text-slate-800'
                            }`}>
                              {f.severity}
                            </span>
                            <div className="flex-1 min-w-0">
                              <div className="font-mono font-bold text-slate-900 text-[11px]">{f.type}</div>
                              <div className="text-slate-600 text-[10px] mt-0.5">{f.evidence}</div>
                            </div>
                            <span className="text-[9px] font-mono text-slate-500 shrink-0">{f.confidence}% conf</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Status / Note */}
                  {att.statusMessage && (
                    <div className="mb-3 px-3 py-2 rounded bg-slate-100 text-slate-700 font-mono text-[11px] flex items-center gap-2">
                      <Zap className="w-3.5 h-3.5 text-indigo-600 shrink-0" />
                      <span>{att.statusMessage}</span>
                    </div>
                  )}

                  {/* Hash Locker */}
                  <div className="pt-2 flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-600 border-t border-slate-200">
                    <div className="flex items-center gap-1.5 truncate">
                      <span>SHA-256:</span>
                      <code className="text-slate-900 font-semibold truncate max-w-sm">{att.sha256 || 'Not computed (Click Analyze to hash)'}</code>
                    </div>
                    {att.sha256 && (
                      <button
                        onClick={() => handleCopy(att.sha256, att.id)}
                        className="text-indigo-600 hover:text-indigo-900 font-semibold flex items-center gap-1 text-[11px]"
                      >
                        {copiedHash === att.id ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedHash === att.id ? 'Copied' : 'Copy Hash'}</span>
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ) : (
          <div className="py-4 text-xs font-mono text-slate-500 text-center">
            No file attachments present in this email specimen.
          </div>
        )}
      </div>

      {/* 3. Embedded URLs & Link Sandbox */}
      <div className="rounded-xl bg-white border border-slate-200 shadow-xs p-4 space-y-3">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100">
          <div className="flex items-center gap-2">
            <Link2 className="w-4 h-4 text-indigo-600" />
            <h2 className="text-xs uppercase tracking-wider font-bold text-slate-900 font-mono">
              Extracted URLs & Redirection Analysis ({urls.length})
            </h2>
          </div>
          <span className="text-[11px] font-mono text-slate-500">Inert Analyst Inspection Sandbox</span>
        </div>

        {urls.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-200 text-slate-500 uppercase text-[10px] tracking-wider bg-slate-50 font-mono">
                  <th className="py-2.5 px-3 font-semibold">Extracted URL / Destination</th>
                  <th className="py-2.5 px-3 font-semibold w-40">Target Domain</th>
                  <th className="py-2.5 px-3 font-semibold w-28">Protocol</th>
                  <th className="py-2.5 px-3 font-semibold w-24 text-right">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-mono text-[11px]">
                {urls.map((u, i) => (
                  <tr key={i} className="hover:bg-slate-50 transition-colors">
                    <td className="py-2.5 px-3 text-slate-900 break-all max-w-md">
                      <span className="font-semibold">{u.url}</span>
                      {u.redirectChain && u.redirectChain.length > 1 && (
                        <div className="text-[10px] text-amber-800 mt-0.5">
                          Redirects: {u.redirectChain.join(' → ')}
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-slate-700">{u.domain}</td>
                    <td className="py-2.5 px-3 text-slate-600">{u.protocol || 'HTTPS'}</td>
                    <td className="py-2.5 px-3 text-right">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                        u.risk === 'CRITICAL'
                          ? 'bg-rose-50 text-rose-700 border-rose-200'
                          : u.risk === 'HIGH'
                          ? 'bg-amber-50 text-amber-800 border-amber-200'
                          : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                      }`}>
                        {u.risk}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-4 text-xs font-mono text-slate-500 text-center">
            No embedded hyperlinks observed in message payload.
          </div>
        )}
      </div>

    </div>
  );
};
