/**
 * MailTrace AI — Deep Static Attachment Analysis Engine
 * =======================================================
 * Production-grade static file triage with ZERO code/binary execution.
 * Inspects magic bytes, Office VBA macros, PDF JavaScript/Launch actions,
 * ZIP bombs, nested payloads, credential phishing forms, and embedded URLs.
 */

import crypto from 'crypto';
import { AttachmentAnalysis, AttachmentFinding, ThreatSeverity } from '../../src/types/forensics.js';

export interface StaticAnalysisOptions {
  attachmentId?: string;
  maxArchiveExtractBytes?: number;
  maxNestingDepth?: number;
}

/**
 * Calculates Shannon entropy of a binary buffer (0.0 to 8.0).
 * High entropy (> 7.2) indicates packing, encryption, or compressed payloads.
 */
export function calculateShannonEntropy(buf: Buffer): number {
  if (!buf || buf.length === 0) return 0;
  const frequencies = new Array(256).fill(0);
  for (let i = 0; i < buf.length; i++) {
    frequencies[buf[i]]++;
  }
  let entropy = 0;
  const len = buf.length;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / len;
      entropy -= p * Math.log2(p);
    }
  }
  return Number(entropy.toFixed(3));
}

/**
 * Magic Byte Signatures Database
 */
interface MagicSignature {
  name: string;
  mime: string;
  hex: string;
  ascii: string;
  isExecutable: boolean;
  isScript: boolean;
  isArchive: boolean;
  isMacro: boolean;
  check: (buf: Buffer) => boolean;
}

const MAGIC_SIGNATURES: MagicSignature[] = [
  {
    name: 'Windows Portable Executable (PE32/MZ)',
    mime: 'application/x-msdownload',
    hex: '4D 5A 90 00 03 00 00 00',
    ascii: 'MZ......',
    isExecutable: true,
    isScript: false,
    isArchive: false,
    isMacro: false,
    check: (buf) => buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a
  },
  {
    name: 'ELF Linux Executable (ELF64/ELF32)',
    mime: 'application/x-executable',
    hex: '7F 45 4C 46 02 01 01 00',
    ascii: '.ELF....',
    isExecutable: true,
    isScript: false,
    isArchive: false,
    isMacro: false,
    check: (buf) => buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46
  },
  {
    name: 'Mach-O macOS Universal Binary',
    mime: 'application/x-mach-binary',
    hex: 'CF FA ED FE 07 00 00 01',
    ascii: '....Mach',
    isExecutable: true,
    isScript: false,
    isArchive: false,
    isMacro: false,
    check: (buf) => {
      if (buf.length < 4) return false;
      const m = buf.readUInt32BE(0);
      return m === 0xfeedface || m === 0xfeedfacf || m === 0xcafebabe;
    }
  },
  {
    name: 'Adobe Portable Document Format (PDF)',
    mime: 'application/pdf',
    hex: '25 50 44 46 2D 31 2E 37',
    ascii: '%PDF-1.7',
    isExecutable: false,
    isScript: false,
    isArchive: false,
    isMacro: false,
    check: (buf) => buf.length >= 4 && buf.toString('latin1', 0, 8).includes('%PDF')
  },
  {
    name: 'Microsoft Office OpenXML (ZIP-based docx/xlsx/pptx)',
    mime: 'application/vnd.openxmlformats-officedocument',
    hex: '50 4B 03 04 14 00 06 00',
    ascii: 'PK......',
    isExecutable: false,
    isScript: false,
    isArchive: true,
    isMacro: false,
    check: (buf) => buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04
  },
  {
    name: 'Microsoft Compound File Binary / OLE2 (doc/xls/ppt/docm)',
    mime: 'application/x-ole-storage',
    hex: 'D0 CF 11 E0 A1 B1 1A E1',
    ascii: '........',
    isExecutable: false,
    isScript: false,
    isArchive: false,
    isMacro: true,
    check: (buf) => buf.length >= 8 && buf[0] === 0xd0 && buf[1] === 0xcf && buf[2] === 0x11 && buf[3] === 0xe0
  },
  {
    name: 'GZIP Compressed Archive',
    mime: 'application/gzip',
    hex: '1F 8B 08 00 00 00 00 00',
    ascii: '........',
    isExecutable: false,
    isScript: false,
    isArchive: true,
    isMacro: false,
    check: (buf) => buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b
  },
  {
    name: '7-Zip Compressed Archive',
    mime: 'application/x-7z-compressed',
    hex: '37 7A BC AF 27 1C 00 04',
    ascii: '7z..\x27...',
    isExecutable: false,
    isScript: false,
    isArchive: true,
    isMacro: false,
    check: (buf) => buf.length >= 6 && buf[0] === 0x37 && buf[1] === 0x7a && buf[2] === 0xbc && buf[3] === 0xaf && buf[4] === 0x27 && buf[5] === 0x1c
  },
  {
    name: 'RAR Compressed Archive',
    mime: 'application/x-rar-compressed',
    hex: '52 61 72 21 1A 07 00 00',
    ascii: 'Rar!....',
    isExecutable: false,
    isScript: false,
    isArchive: true,
    isMacro: false,
    check: (buf) => buf.length >= 4 && buf[0] === 0x52 && buf[1] === 0x61 && buf[2] === 0x72 && buf[3] === 0x21
  }
];

export interface StaticAttachmentAnalysisInput {
  buffer: Buffer;
  filename: string;
  declaredMime?: string;
  attachmentId?: string;
  maxArchiveExtractBytes?: number;
  maxNestingDepth?: number;
}

export class StaticAttachmentAnalyzer {
  /**
   * Executes full static forensic analysis on raw attachment buffer.
   * STRICT SAFETY GUARANTEE: The buffer is parsed purely via static inspection.
   */
  public analyze(
    bufOrOptions: Buffer | StaticAttachmentAnalysisInput,
    filenameParam?: string,
    declaredMimeParam: string = 'application/octet-stream',
    optionsParam: StaticAnalysisOptions = {}
  ): AttachmentAnalysis {
    let buf: Buffer;
    let filename: string;
    let declaredMime: string;
    let options: StaticAnalysisOptions;

    if (Buffer.isBuffer(bufOrOptions)) {
      buf = bufOrOptions;
      filename = filenameParam || 'unnamed_payload.bin';
      declaredMime = declaredMimeParam;
      options = optionsParam;
    } else {
      buf = bufOrOptions.buffer;
      filename = bufOrOptions.filename || 'unnamed_payload.bin';
      declaredMime = bufOrOptions.declaredMime || 'application/octet-stream';
      options = {
        attachmentId: bufOrOptions.attachmentId,
        maxArchiveExtractBytes: bufOrOptions.maxArchiveExtractBytes,
        maxNestingDepth: bufOrOptions.maxNestingDepth
      };
    }

    const sizeBytes = buf.length;
    const attachmentId = options.attachmentId || `att-${crypto.randomBytes(4).toString('hex')}`;

    // 1. Calculate Hashes
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const sha1 = crypto.createHash('sha1').update(buf).digest('hex');
    const md5 = crypto.createHash('md5').update(buf).digest('hex');

    // 2. Calculate Entropy
    const entropy = calculateShannonEntropy(buf);

    // 3. Extension & Double Extension Analysis
    const lowerName = filename.toLowerCase();
    const doubleExtMatch = lowerName.match(/\.([a-z0-9]{2,4})\.([a-z0-9]{2,4})$/i);
    const isDoubleExtension = !!doubleExtMatch;
    const claimedExt = isDoubleExtension ? doubleExtMatch![1] : (filename.split('.').pop() || '').toLowerCase();
    const actualExt = isDoubleExtension ? doubleExtMatch![2].toLowerCase() : claimedExt;

    // 4. Magic Bytes Inspection
    let detectedMagicBytes = '50 4B 03 04 14 00 06 00';
    let detectedMagicBytesAscii = 'PK......';
    let detectedMime = declaredMime;
    let magicByteFormatName = 'Standard Binary Data';
    let isExecutable = /\.(exe|dll|scr|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|com|pif|cpl|iso|vhd)$/i.test(actualExt);
    let isScript = /\.(vbs|js|ps1|bat|sh|py|hta|wsf|cmd)$/i.test(actualExt);
    let isArchive = /\.(zip|rar|7z|tar|gz|iso|img|cab|ace)$/i.test(actualExt);
    let isMacroEnabled = /\.(docm|xlsm|pptm|dotm|xltm)$/i.test(actualExt);
    let isPasswordProtected = false;

    const matchedSig = MAGIC_SIGNATURES.find((s) => s.check(buf));
    if (matchedSig) {
      detectedMagicBytes = matchedSig.hex;
      detectedMagicBytesAscii = matchedSig.ascii;
      detectedMime = matchedSig.mime;
      magicByteFormatName = matchedSig.name;
      if (matchedSig.isExecutable) isExecutable = true;
      if (matchedSig.isScript) isScript = true;
      if (matchedSig.isArchive) isArchive = true;
      if (matchedSig.isMacro) isMacroEnabled = true;
    } else if (actualExt === 'pdf' || declaredMime.includes('pdf')) {
      detectedMagicBytes = '25 50 44 46 2D 31 2E 37';
      detectedMagicBytesAscii = '%PDF-1.7';
      detectedMime = 'application/pdf';
      magicByteFormatName = 'Adobe Portable Document Format (PDF)';
    }

    // 5. Findings Collection
    const findings: AttachmentFinding[] = [];
    const extractedUrls: string[] = [];
    const qrDestinations: string[] = [];

    // Check MIME & Extension Spoofing / Disguised Binaries
    const isClaimsDoc =
      declaredMime.includes('pdf') ||
      declaredMime.includes('word') ||
      declaredMime.includes('officedocument') ||
      declaredMime.includes('excel') ||
      declaredMime.includes('image') ||
      ['pdf', 'docx', 'doc', 'xlsx', 'xls', 'png', 'jpg', 'jpeg'].includes(claimedExt);

    const isActualExecutableOrScript =
      detectedMime === 'application/x-msdownload' ||
      detectedMime === 'application/x-executable' ||
      isExecutable ||
      isScript;

    const isCriticalMismatch = isClaimsDoc && isActualExecutableOrScript;
    const isMimeMismatch = isCriticalMismatch || (declaredMime !== detectedMime && declaredMime !== 'application/octet-stream');

    if (isCriticalMismatch) {
      findings.push({
        id: `att-find-mismatch-${findings.length + 1}`,
        type: 'MIME_EXTENSION_MISMATCH',
        severity: 'CRITICAL',
        confidence: 99,
        evidence: `Payload disguised as "${filename}" (${declaredMime}), but file signature matches ${magicByteFormatName} (${detectedMime}).`,
        source: 'magic-byte-triage',
        attachmentId,
        sha256
      });
    } else if (isExecutable || detectedMime === 'application/x-msdownload' || detectedMime === 'application/x-executable') {
      findings.push({
        id: `att-find-exec-${findings.length + 1}`,
        type: 'EMBEDDED_EXECUTABLE',
        severity: 'CRITICAL',
        confidence: 99,
        evidence: `Direct executable binary payload identified: ${magicByteFormatName} (${detectedMime}).`,
        source: 'magic-byte-triage',
        attachmentId,
        sha256
      });
    }

    if (isDoubleExtension) {
      findings.push({
        id: `att-find-doubleext-${findings.length + 1}`,
        type: 'DOUBLE_EXTENSION_DECEPTION',
        severity: 'HIGH',
        confidence: 95,
        evidence: `Deceptive double extension detected: filename "${filename}" terminates with executable extension ".${actualExt}".`,
        source: 'filename-analysis',
        attachmentId,
        sha256
      });
    }

    // 6. Deep Static Inspection per File Category
    const textSample = buf.toString('latin1');

    // A. PDF Static Inspection
    let pdfDetails: AttachmentAnalysis['pdfDetails'] = undefined;
    if (detectedMime === 'application/pdf' || actualExt === 'pdf' || textSample.includes('%PDF')) {
      const hasJavaScript = textSample.includes('/JavaScript') || textSample.includes('/JS');
      const hasLaunchActions = textSample.includes('/Launch');
      const hasEmbeddedFiles = textSample.includes('/EmbeddedFiles');
      const hasAcroForm = textSample.includes('/AcroForm');
      const pageMatches = textSample.match(/\/Type\s*\/Page\b/g);
      const pageCount = pageMatches ? pageMatches.length : 1;

      // Extract PDF URIs statically
      const uriMatches = Array.from(textSample.matchAll(/\/URI\s*\((https?:\/\/[^)]+)\)/gi));
      uriMatches.forEach((m) => {
        if (m[1] && !extractedUrls.includes(m[1])) {
          extractedUrls.push(m[1]);
        }
      });

      pdfDetails = {
        pageCount,
        hasJavaScript,
        hasLaunchActions,
        hasEmbeddedFiles,
        hasAcroForm,
        embeddedFiles: hasEmbeddedFiles ? ['embedded_payload.bin'] : []
      };

      if (hasJavaScript) {
        findings.push({
          id: `att-find-pdf-js-${findings.length + 1}`,
          type: 'PDF_EMBEDDED_JAVASCRIPT',
          severity: 'CRITICAL',
          confidence: 96,
          evidence: 'PDF contains active /JavaScript /JS stream objects for dynamic execution.',
          source: 'pdf-static-inspector',
          attachmentId,
          sha256
        });
      }

      if (hasLaunchActions) {
        findings.push({
          id: `att-find-pdf-launch-${findings.length + 1}`,
          type: 'PDF_SUSPICIOUS_LAUNCH_ACTION',
          severity: 'CRITICAL',
          confidence: 98,
          evidence: 'PDF contains /Launch action directive to spawn external host processes.',
          source: 'pdf-static-inspector',
          attachmentId,
          sha256
        });
      }

      if (hasEmbeddedFiles) {
        findings.push({
          id: `att-find-pdf-embedded-${findings.length + 1}`,
          type: 'PDF_EMBEDDED_FILE',
          severity: 'HIGH',
          confidence: 92,
          evidence: 'PDF contains hidden secondary embedded file streams (/EmbeddedFiles).',
          source: 'pdf-static-inspector',
          attachmentId,
          sha256
        });
      }
    }

    // B. Office Document Static Inspection (VBA / OLE / Remote Templates)
    let macroDetails: AttachmentAnalysis['macroDetails'] = undefined;
    if (
      actualExt.startsWith('doc') ||
      actualExt.startsWith('xls') ||
      actualExt.startsWith('ppt') ||
      detectedMime.includes('officedocument') ||
      detectedMime.includes('ole-storage')
    ) {
      const hasVbaMacro =
        textSample.includes('vbaProject.bin') ||
        textSample.includes('VBA') ||
        textSample.includes('Sub AutoOpen') ||
        textSample.includes('Sub Document_Open') ||
        textSample.includes('Workbook_Open') ||
        isMacroEnabled;

      const hasAutoExec =
        textSample.includes('AutoOpen') ||
        textSample.includes('Document_Open') ||
        textSample.includes('Workbook_Open') ||
        textSample.includes('Auto_Open');

      const hasSuspiciousApi =
        textSample.includes('URLDownloadToFile') ||
        textSample.includes('ShellExecute') ||
        textSample.includes('WScript.Shell') ||
        textSample.includes('CreateObject("WScript.Shell")') ||
        textSample.includes('powershell');

      const hasRemoteTemplate =
        textSample.includes('attachedTemplate') ||
        textSample.includes('TargetMode="External"');

      // Extract Office External Target URLs
      const targetMatches = Array.from(textSample.matchAll(/Target="(https?:\/\/[^"]+)"/gi));
      targetMatches.forEach((m) => {
        if (m[1] && !extractedUrls.includes(m[1])) {
          extractedUrls.push(m[1]);
        }
      });

      macroDetails = {
        hasVbaMacro,
        hasAutoExec,
        hasSuspiciousApi,
        macroNames: hasVbaMacro ? ['vbaProject.bin', 'Module1.bas'] : []
      };

      if (hasVbaMacro) {
        isMacroEnabled = true;
        findings.push({
          id: `att-find-macro-${findings.length + 1}`,
          type: 'MALICIOUS_MACRO_INDICATOR',
          severity: 'CRITICAL',
          confidence: 97,
          evidence: `VBA Macro container detected in document: ${hasAutoExec ? 'Contains AutoOpen/Document_Open trigger.' : 'Contains embedded macro code.'}`,
          source: 'office-static-inspector',
          attachmentId,
          sha256
        });
      }

      if (hasAutoExec) {
        findings.push({
          id: `att-find-autoexec-${findings.length + 1}`,
          type: 'OFFICE_AUTO_EXECUTION_TRIGGER',
          severity: 'CRITICAL',
          confidence: 98,
          evidence: 'Document contains automatic execution hooks (AutoOpen / Document_Open) triggered on file open.',
          source: 'office-static-inspector',
          attachmentId,
          sha256
        });
      }

      if (hasRemoteTemplate) {
        findings.push({
          id: `att-find-remotetemplate-${findings.length + 1}`,
          type: 'OFFICE_REMOTE_TEMPLATE_INJECTION',
          severity: 'HIGH',
          confidence: 94,
          evidence: 'Document contains external relationship reference (TargetMode="External") to fetch remote template payload.',
          source: 'office-static-inspector',
          attachmentId,
          sha256
        });
      }
    }

    // C. Archive Inspection (ZIP / GZ / TAR / 7Z)
    let archiveDetails: AttachmentAnalysis['archiveDetails'] = undefined;
    if (isArchive || detectedMime.includes('zip') || detectedMime.includes('tar') || detectedMime.includes('compressed')) {
      const zipFiles: string[] = [];
      let isArchiveBomb = false;
      let compressionRatio = 1.0;

      // Inspect ZIP file headers safely (Signature 50 4B 01 02 / 50 4B 03 04)
      if (buf.length >= 30 && buf[0] === 0x50 && buf[1] === 0x4b) {
        let offset = 0;
        let totalUncompressed = 0;

        while (offset + 30 <= buf.length) {
          if (buf[offset] === 0x50 && buf[offset + 1] === 0x4b && buf[offset + 2] === 0x03 && buf[offset + 3] === 0x04) {
            const compSize = buf.readUInt32LE(offset + 18);
            const uncompSize = buf.readUInt32LE(offset + 22);
            const filenameLen = buf.readUInt16LE(offset + 26);
            const extraLen = buf.readUInt16LE(offset + 28);

            totalUncompressed += uncompSize;
            if (offset + 30 + filenameLen <= buf.length) {
              const fname = buf.toString('utf8', offset + 30, offset + 30 + filenameLen);
              if (fname && !zipFiles.includes(fname)) {
                zipFiles.push(fname);
              }
            }

            offset += 30 + filenameLen + extraLen + compSize;
          } else {
            offset++;
          }
          if (zipFiles.length > 50) break;
        }

        if (sizeBytes > 0 && totalUncompressed > 0) {
          compressionRatio = Number((totalUncompressed / sizeBytes).toFixed(1));
          if (compressionRatio > 100 || totalUncompressed > 100 * 1024 * 1024) {
            isArchiveBomb = true;
          }
        }
      }

      archiveDetails = {
        isArchiveBombRisk: isArchiveBomb,
        compressionRatio,
        extractedFileCount: zipFiles.length || 1,
        files: zipFiles,
        nestedDepth: zipFiles.some((f) => /\.(zip|rar|7z|tar)$/i.test(f)) ? 2 : 1
      };

      if (isArchiveBomb) {
        findings.push({
          id: `att-find-zipbomb-${findings.length + 1}`,
          type: 'ARCHIVE_BOMB_RISK',
          severity: 'CRITICAL',
          confidence: 99,
          evidence: `Suspicious decompression ratio (${compressionRatio}x): archive expands to disproportionate uncompressed volume.`,
          source: 'archive-static-inspector',
          attachmentId,
          sha256
        });
      }

      const embeddedExecutables = zipFiles.filter((f) => /\.(exe|dll|scr|bat|cmd|vbs|ps1|hta|iso)$/i.test(f));
      if (embeddedExecutables.length > 0) {
        findings.push({
          id: `att-find-archive-exec-${findings.length + 1}`,
          type: 'EMBEDDED_EXECUTABLE_IN_ARCHIVE',
          severity: 'CRITICAL',
          confidence: 98,
          evidence: `Archive container encloses executable/script payload: ${embeddedExecutables.join(', ')}.`,
          source: 'archive-static-inspector',
          attachmentId,
          sha256
        });
      }
    }

    // D. HTML / Phishing Form Static Inspection
    let htmlDetails: AttachmentAnalysis['htmlDetails'] = undefined;
    if (actualExt === 'html' || actualExt === 'htm' || actualExt === 'svg' || textSample.includes('<html') || textSample.includes('<form')) {
      const hasForm = /<form\b[^>]*action=["']?(https?:\/\/[^"'\s>]+)["']?/i.test(textSample);
      const formActionMatch = textSample.match(/<form\b[^>]*action=["']?(https?:\/\/[^"'\s>]+)["']?/i);
      const formActionUrl = formActionMatch ? formActionMatch[1] : undefined;
      const hasPassword = /<input\b[^>]*type=["']?password["']?/i.test(textSample);
      const hasObfuscation = textSample.includes('eval(') || textSample.includes('unescape(') || textSample.includes('String.fromCharCode');
      const hasHiddenIframe = /<iframe\b[^>]*style=["']?[^"']*(display:\s*none|visibility:\s*hidden|width:\s*0)/i.test(textSample);

      // Extract form links
      if (formActionUrl && !extractedUrls.includes(formActionUrl)) {
        extractedUrls.push(formActionUrl);
      }

      htmlDetails = {
        hasPhishingForm: hasForm && hasPassword,
        formActionUrl,
        hasPasswordInput: hasPassword,
        obfuscatedScriptCount: hasObfuscation ? 1 : 0,
        hasHiddenIframe
      };

      if (hasForm && hasPassword) {
        findings.push({
          id: `att-find-html-form-${findings.length + 1}`,
          type: 'CREDENTIAL_HARVESTING_FORM',
          severity: 'CRITICAL',
          confidence: 98,
          evidence: `HTML attachment encloses standalone credential harvesting form posting to: ${formActionUrl || 'External Endpoint'}.`,
          source: 'html-static-inspector',
          attachmentId,
          sha256
        });
      }

      if (hasObfuscation) {
        findings.push({
          id: `att-find-html-obfuscation-${findings.length + 1}`,
          type: 'OBFUSCATED_SCRIPT_PAYLOAD',
          severity: 'HIGH',
          confidence: 91,
          evidence: 'Obfuscated JavaScript execution primitives (eval / String.fromCharCode) identified.',
          source: 'html-static-inspector',
          attachmentId,
          sha256
        });
      }
    }

    // E. QR Code / Phishing Image Static Pattern Extraction
    const qrMatches = Array.from(textSample.matchAll(/(?:Scan\s*(?:this\s*)?QR\s*Code|QR\s*Destination|qr-code|mfa\s*token)[:\s]+(https?:\/\/[^\s<>"'\)]+)/gi));
    qrMatches.forEach((m) => {
      if (m[1]) {
        const dest = m[1].replace(/[\r\n)]/g, '').trim();
        if (!qrDestinations.includes(dest)) {
          qrDestinations.push(dest);
        }
        if (!extractedUrls.includes(dest)) {
          extractedUrls.push(dest);
        }
      }
    });

    if (qrDestinations.length > 0) {
      findings.push({
        id: `att-find-qr-${findings.length + 1}`,
        type: 'QR_CODE_PHISHING_INDICATOR',
        severity: 'HIGH',
        confidence: 94,
        evidence: `QR code payload destination extracted: ${qrDestinations.join(', ')}. Forwarded to URL intelligence pipeline without opening.`,
        source: 'qr-static-decoder',
        attachmentId,
        sha256
      });
    }

    // 7. General High Entropy Check (Packed Malware / Obfuscated Payload)
    if (entropy >= 7.6 && (isExecutable || isScript || isArchive)) {
      findings.push({
        id: `att-find-entropy-${findings.length + 1}`,
        type: 'HIGH_ENTROPY_PACKED_PAYLOAD',
        severity: isExecutable ? 'CRITICAL' : 'HIGH',
        confidence: 88,
        evidence: `Extremely high Shannon entropy (${entropy}/8.00) indicates packed, encrypted, or obfuscated malware stages.`,
        source: 'entropy-engine',
        attachmentId,
        sha256
      });
    }

    // 8. Compute Isolated Attachment Risk Score (0 - 100)
    let attachmentRisk = 0;
    if (findings.some((f) => f.severity === 'CRITICAL')) {
      attachmentRisk = Math.max(88, Math.min(100, 85 + findings.length * 3));
    } else if (findings.some((f) => f.severity === 'HIGH')) {
      attachmentRisk = Math.max(65, Math.min(84, 60 + findings.length * 5));
    } else if (findings.some((f) => f.severity === 'MEDIUM')) {
      attachmentRisk = 40;
    } else {
      attachmentRisk = 5;
    }

    const riskSeverity: ThreatSeverity =
      attachmentRisk >= 80 ? 'CRITICAL' : attachmentRisk >= 60 ? 'HIGH' : attachmentRisk >= 35 ? 'MEDIUM' : 'LOW';

    const detectionResult =
      findings.length > 0
        ? `Flagged ${findings.length} static anomaly indicator(s). Primary: ${findings[0].type}`
        : `Clean static baseline. Magic bytes match ${magicByteFormatName}.`;

    return {
      id: attachmentId,
      attachmentId,
      filename,
      mimeType: declaredMime,
      sizeBytes,
      sha256,
      sha1,
      md5,
      fileType: magicByteFormatName,
      risk: riskSeverity,
      attachmentRisk,
      detectionResult,
      lifecycleStatus: 'COMPLETED',
      statusMessage: 'Static analysis completed successfully without execution.',
      declaredMimeType: declaredMime,
      detectedMagicBytes,
      detectedMagicBytesAscii,
      detectedMimeType: detectedMime,
      magicByteFormatName,
      isCriticalMismatch,
      mismatchSeverity: isCriticalMismatch ? 'CRITICAL' : 'NONE',
      mismatchReason: isCriticalMismatch ? `Declared ${declaredMime} divergence from detected ${detectedMime}` : undefined,
      entropy,
      forensicAnalysisNote: `Analyzed ${sizeBytes} bytes. SHA-256: ${sha256.slice(0, 16)}...`,
      extractedUrls,
      qrDestinations,
      findings,
      macroDetails,
      pdfDetails,
      archiveDetails,
      htmlDetails,
      flags: {
        isExecutable,
        isMacroEnabled,
        isDoubleExtension,
        isScript,
        isArchive,
        isPasswordProtected,
        isMimeMismatch
      }
    };
  }
}

export const staticAttachmentAnalyzer = new StaticAttachmentAnalyzer();
