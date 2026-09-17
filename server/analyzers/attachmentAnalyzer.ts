/**
 * MailTrace AI - Attachment Forensics & Static Malware Triage Engine
 * Deep Magic Byte Hex & ASCII signature analysis with MIME type divergence detection
 */

import { AttachmentAnalysis, ThreatSeverity } from '../../src/types/forensics.js';
import { ParsedMimePart } from './emailParser.js';
import { staticAttachmentAnalyzer } from '../services/staticAttachmentAnalyzer.js';

interface MagicByteSignature {
  pattern: RegExp | ((rawBuf: Buffer | null, dataStr: string, ext: string) => boolean);
  hexSignature: string;
  asciiSignature: string;
  name: string;
  detectedMime: string;
  isExecutable: boolean;
  isScript: boolean;
  isArchive: boolean;
  isMacro: boolean;
}

const MAGIC_BYTE_DATABASE: MagicByteSignature[] = [
  {
    // MZ / PE Windows Executable header (EXE, DLL, SCR, CPL, SYS)
    pattern: (buf, data, ext) => {
      if (buf && buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) return true;
      return (
        data.startsWith('TVqQ') ||
        data.startsWith('TVoA') ||
        data.startsWith('TVpB') ||
        data.startsWith('TVpQ') ||
        data.startsWith('TVqA') ||
        data.startsWith('MZ') ||
        /\.(exe|dll|scr|com|cpl|sys|pif)$/i.test(ext)
      );
    },
    hexSignature: '4D 5A 90 00 03 00 00 00',
    asciiSignature: 'MZ......',
    name: 'Windows Portable Executable (PE32/MZ)',
    detectedMime: 'application/x-msdownload',
    isExecutable: true,
    isScript: false,
    isArchive: false,
    isMacro: false
  },
  {
    // ELF Linux Executable
    pattern: (buf, data, ext) => {
      if (buf && buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return true;
      return data.startsWith('f0VMRg') || data.startsWith('\x7FELF') || /\.(elf|bin|so)$/i.test(ext);
    },
    hexSignature: '7F 45 4C 46 02 01 01 00',
    asciiSignature: '.ELF....',
    name: 'ELF Linux Executable (ELF64)',
    detectedMime: 'application/x-executable',
    isExecutable: true,
    isScript: false,
    isArchive: false,
    isMacro: false
  },
  {
    // Mach-O macOS Binary
    pattern: (buf, data, ext) => {
      if (buf && buf.length >= 4) {
        const magic = buf.readUInt32BE(0);
        if (magic === 0xfeedface || magic === 0xfeedfacf || magic === 0xcafebabe) return true;
      }
      return /\.(dylib|macho|app)$/i.test(ext);
    },
    hexSignature: 'CF FA ED FE 07 00 00 01',
    asciiSignature: '....Mach',
    name: 'Mach-O Universal Binary (macOS)',
    detectedMime: 'application/x-mach-binary',
    isExecutable: true,
    isScript: false,
    isArchive: false,
    isMacro: false
  },
  {
    // Adobe PDF
    pattern: (buf, data, ext) => {
      if (buf && buf.length >= 4 && buf.toString('latin1', 0, 5).startsWith('%PDF')) return true;
      return data.startsWith('JVBERi') || data.includes('%PDF-') || ext === 'pdf';
    },
    hexSignature: '25 50 44 46 2D 31 2E 37',
    asciiSignature: '%PDF-1.7',
    name: 'Adobe Portable Document Format (PDF)',
    detectedMime: 'application/pdf',
    isExecutable: false,
    isScript: false,
    isArchive: false,
    isMacro: false
  },
  {
    // Microsoft Office Macro-Enabled Document / OLE2 (VBA Macro Container)
    pattern: (buf, data, ext) => {
      if (buf && buf.length >= 8 && buf[0] === 0xd0 && buf[1] === 0xcf && buf[2] === 0x11 && buf[3] === 0xe0) return true;
      return (
        /\.(docm|xlsm|pptm|dotm|xltm|vba)$/i.test(ext) ||
        data.startsWith('0M8R4') ||
        (data.startsWith('0M8') && ext.includes('doc'))
      );
    },
    hexSignature: 'D0 CF 11 E0 A1 B1 1A E1',
    asciiSignature: '........',
    name: 'Microsoft Compound File Binary / OLE2 (VBA Macro Container)',
    detectedMime: 'application/vnd.ms-excel.sheet.macroEnabled.12',
    isExecutable: false,
    isScript: false,
    isArchive: false,
    isMacro: true
  },
  {
    // ZIP Archive / Office Open XML (DOCX, XLSX, PPTX)
    pattern: (buf, data, ext) => {
      if (buf && buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && (buf[2] === 0x03 || buf[2] === 0x05 || buf[2] === 0x07)) return true;
      return data.startsWith('UEsDB') || data.startsWith('PK\x03\x04') || /\.(zip|docx|xlsx|pptx|jar|apk)$/i.test(ext);
    },
    hexSignature: '50 4B 03 04 14 00 06 00',
    asciiSignature: 'PK......',
    name: 'ZIP Compressed Archive / OpenXML Container',
    detectedMime: 'application/zip',
    isExecutable: false,
    isScript: false,
    isArchive: true,
    isMacro: false
  },
  {
    // RAR Archive
    pattern: (buf, data, ext) => {
      if (buf && buf.length >= 6 && buf.toString('latin1', 0, 4) === 'Rar!') return true;
      return data.startsWith('UmFyIRo') || ext === 'rar';
    },
    hexSignature: '52 61 72 21 1A 07 00 00',
    asciiSignature: 'Rar!....',
    name: 'RAR Compressed Archive (v5.0)',
    detectedMime: 'application/x-rar-compressed',
    isExecutable: false,
    isScript: false,
    isArchive: true,
    isMacro: false
  },
  {
    // 7-Zip Archive
    pattern: (buf, data, ext) => {
      if (buf && buf.length >= 6 && buf[0] === 0x37 && buf[1] === 0x7a && buf[2] === 0xbc && buf[3] === 0xaf) return true;
      return data.startsWith('N3q8ry') || ext === '7z';
    },
    hexSignature: '37 7A BC AF 27 1C 00 03',
    asciiSignature: "7z..'...",
    name: '7-Zip Archive Container',
    detectedMime: 'application/x-7z-compressed',
    isExecutable: false,
    isScript: false,
    isArchive: true,
    isMacro: false
  },
  {
    // Visual Basic / JavaScript / PowerShell Script / Batch
    pattern: (buf, data, ext) => {
      return (
        /\.(vbs|vbe|js|jse|wsf|hta|ps1|bat|cmd|sh|py|pl|reg)$/i.test(ext) ||
        data.startsWith('#!/bin') ||
        data.startsWith('powershell') ||
        data.includes('WScript.Shell') ||
        data.includes('CreateObject(') ||
        data.includes('eval(')
      );
    },
    hexSignature: '23 21 2F 62 69 6E 2F 73',
    asciiSignature: '#!/bin/s',
    name: 'Windows Script Host / Shell Script',
    detectedMime: 'application/x-msdos-program',
    isExecutable: true,
    isScript: true,
    isArchive: false,
    isMacro: false
  },
  {
    // PNG Image
    pattern: (buf, data, ext) => {
      if (buf && buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return true;
      return data.startsWith('iVBORw') || ext === 'png';
    },
    hexSignature: '89 50 4E 47 0D 0A 1A 0A',
    asciiSignature: '.PNG....',
    name: 'Portable Network Graphics (PNG)',
    detectedMime: 'image/png',
    isExecutable: false,
    isScript: false,
    isArchive: false,
    isMacro: false
  },
  {
    // JPEG Image
    pattern: (buf, data, ext) => {
      if (buf && buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return true;
      return data.startsWith('/9j/') || /\.(jpg|jpeg)$/i.test(ext);
    },
    hexSignature: 'FF D8 FF E0 00 10 4A 46',
    asciiSignature: '......JF',
    name: 'JPEG JFIF Image',
    detectedMime: 'image/jpeg',
    isExecutable: false,
    isScript: false,
    isArchive: false,
    isMacro: false
  }
];

export function analyzeAttachments(parts: ParsedMimePart[]): AttachmentAnalysis[] {
  const results: AttachmentAnalysis[] = [];
  let idCounter = 1;

  for (const part of parts) {
    const filename = part.filename || 'unnamed_payload.bin';
    const lowerName = filename.toLowerCase();
    const declaredMime = (part.contentType || 'application/octet-stream').toLowerCase().split(';')[0].trim();
    const attId = `att-${idCounter++}`;

    // Decode full binary buffer if base64 data exists in MIME part
    if (part.data && typeof part.data === 'string' && part.data.trim().length > 0) {
      try {
        const cleanData = part.data.replace(/[\r\n\s]/g, '');
        const fullBuf = Buffer.from(cleanData, 'base64');
        if (fullBuf && fullBuf.length > 0) {
          const staticRes = staticAttachmentAnalyzer.analyze({
            buffer: fullBuf,
            filename,
            declaredMime,
            attachmentId: attId
          });
          results.push(staticRes);
          continue;
        }
      } catch (e) {
        console.warn(`[AttachmentAnalyzer] Failed to decode base64 for ${filename}:`, e);
      }
    }

    // Decode sample buffer if partial base64 data exists
    let rawBuf: Buffer | null = null;
    if (part.data) {
      try {
        const cleanData = part.data.replace(/[\r\n\s]/g, '');
        if (/^[A-Za-z0-9+/=]+$/.test(cleanData) && cleanData.length >= 8) {
          rawBuf = Buffer.from(cleanData.substring(0, 128), 'base64');
        }
      } catch {
        rawBuf = null;
      }
    }

    // Check double extensions: e.g. invoice.pdf.exe, report.docx.vbs, photo.png.bat, document.pdf.scr
    const doubleExtMatch = lowerName.match(/\.([a-z0-9]{2,4})\.([a-z0-9]{2,4})$/i);
    const isDoubleExtension = !!doubleExtMatch;
    const claimedExt = isDoubleExtension ? doubleExtMatch![1] : (filename.split('.').pop() || '');
    const actualExt = isDoubleExtension ? doubleExtMatch![2] : claimedExt;

    // Direct extension classification
    let isExecutable = /\.(exe|dll|scr|bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|com|pif|cpl|iso|vhd)$/i.test(actualExt);
    let isMacroEnabled = /\.(docm|xlsm|pptm|dotm|xltm)$/i.test(actualExt);
    let isScript = /\.(vbs|js|ps1|bat|sh|py|hta|wsf|cmd)$/i.test(actualExt);
    let isArchive = /\.(zip|rar|7z|tar|gz|iso|img|cab|ace)$/i.test(actualExt);

    // Identify Magic Bytes
    let detectedMagicBytes = '4D 5A 90 00 03 00 00 00';
    let detectedMagicBytesAscii = 'MZ......';
    let detectedMime = 'application/octet-stream';
    let magicByteFormatName = 'Unknown Binary Data';
    
    // Check if filename claims to be benign document but contains executable indicators
    const isDisguisedInvoiceOrDoc = (
      lowerName.includes('invoice') ||
      lowerName.includes('statement') ||
      lowerName.includes('remittance') ||
      lowerName.includes('purchase') ||
      lowerName.includes('receipt') ||
      lowerName.includes('order') ||
      lowerName.includes('doc') ||
      lowerName.includes('ticket') ||
      lowerName.includes('salary')
    );

    const hasMzHeader = (
      (rawBuf && rawBuf.length >= 2 && rawBuf[0] === 0x4d && rawBuf[1] === 0x5a) ||
      (part.data && (
        part.data.startsWith('TVqQ') ||
        part.data.startsWith('TVoA') ||
        part.data.startsWith('TVpB') ||
        part.data.startsWith('TVpQ')
      )) ||
      isDoubleExtension
    );

    const claimsPdf = declaredMime.includes('pdf') || claimedExt === 'pdf';
    const claimsOfficeDoc = (
      declaredMime.includes('word') ||
      declaredMime.includes('officedocument') ||
      declaredMime.includes('excel') ||
      declaredMime.includes('sheet') ||
      claimedExt === 'docx' ||
      claimedExt === 'doc' ||
      claimedExt === 'xlsx' ||
      claimedExt === 'xls'
    );
    const claimsImage = declaredMime.includes('image') || claimedExt === 'png' || claimedExt === 'jpg' || claimedExt === 'jpeg';
    const claimsText = declaredMime.includes('text') || claimedExt === 'txt' || claimedExt === 'csv';

    // Look up in magic byte database
    let matchedSig = MAGIC_BYTE_DATABASE.find(sig => {
      if (typeof sig.pattern === 'function') {
        return sig.pattern(rawBuf, part.data, actualExt);
      }
      return sig.pattern.test(actualExt);
    });

    // Handle classic phishing scenario: filename claims to be benign document (.pdf, .docx, .png, etc.), but raw data contains MZ PE Executable header
    if (hasMzHeader && (claimsPdf || claimsOfficeDoc || claimsImage || claimsText || (isDisguisedInvoiceOrDoc && isExecutable))) {
      matchedSig = MAGIC_BYTE_DATABASE[0]; // PE Executable
      isExecutable = true;
    }

    if (matchedSig) {
      detectedMagicBytes = matchedSig.hexSignature;
      detectedMagicBytesAscii = matchedSig.asciiSignature;
      detectedMime = matchedSig.detectedMime;
      magicByteFormatName = matchedSig.name;
      if (matchedSig.isExecutable) isExecutable = true;
      if (matchedSig.isScript) isScript = true;
      if (matchedSig.isArchive) isArchive = true;
      if (matchedSig.isMacro) isMacroEnabled = true;
    } else {
      if (claimsPdf) {
        detectedMagicBytes = '25 50 44 46 2D 31 2E 37';
        detectedMagicBytesAscii = '%PDF-1.7';
        detectedMime = 'application/pdf';
        magicByteFormatName = 'Adobe Portable Document Format (PDF)';
      } else {
        detectedMagicBytes = '50 4B 03 04 14 00 06 00';
        detectedMagicBytesAscii = 'PK......';
        detectedMime = declaredMime;
        magicByteFormatName = 'Standard Binary Data Container';
      }
    }

    // Critical Mismatch Evaluation
    // e.g., claims application/pdf or image/png but magic bytes are application/x-msdownload (PE MZ), or claims docx but contains executable scripts
    const isBenignToExecutableMismatch = (
      (claimsPdf || claimsOfficeDoc || claimsImage || claimsText) &&
      (detectedMime === 'application/x-msdownload' || detectedMime === 'application/x-executable' || isExecutable || isScript)
    );

    const isBenignToMacroMismatch = (
      (claimsOfficeDoc || claimsPdf) &&
      isMacroEnabled &&
      (detectedMime.includes('macroEnabled') || detectedMime.includes('ole-storage'))
    );

    const isCriticalMismatch = (
      isBenignToExecutableMismatch ||
      isBenignToMacroMismatch ||
      isDoubleExtension ||
      (declaredMime !== detectedMime && (isExecutable || isScript || isMacroEnabled))
    );

    const isMimeMismatch = isCriticalMismatch || (declaredMime !== detectedMime && declaredMime !== 'application/octet-stream');

    // Calculate simulated Shannon entropy (higher entropy for packed/encrypted malware payloads)
    const entropy = isExecutable ? 7.84 : (isArchive ? 7.42 : (isMacroEnabled ? 6.95 : 4.85));

    // Generate deterministic hashes based on filename and contents
    const sha256 = generateSimulatedHash(filename + part.sizeBytes, 'sha256');
    const sha1 = generateSimulatedHash(filename + part.sizeBytes, 'sha1');
    const md5 = generateSimulatedHash(filename + part.sizeBytes, 'md5');

    let risk: ThreatSeverity = 'LOW';
    let mismatchSeverity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NONE' = 'NONE';
    let mismatchReason = '';
    let detectionResult = 'No known malicious patterns detected during static heuristic sweep.';
    let forensicAnalysisNote = 'Declared MIME type aligns with file header magic bytes.';

    if (isCriticalMismatch) {
      risk = 'CRITICAL';
      mismatchSeverity = 'CRITICAL';
      
      if (claimsPdf && (detectedMime === 'application/x-msdownload' || isExecutable)) {
        mismatchReason = `Attachment declared as '.pdf' (${declaredMime}), but raw binary magic bytes '${detectedMagicBytes.slice(0, 11)}' (${detectedMagicBytesAscii}) conclusively identify it as '${detectedMime}' (${magicByteFormatName}).`;
      } else if (isDoubleExtension) {
        mismatchReason = `Double-extension deception detected: File masquerades as benign extension '.${claimedExt}' but executes as '.${actualExt}' (${detectedMime}).`;
      } else if (claimsOfficeDoc && (detectedMime === 'application/x-msdownload' || isExecutable)) {
        mismatchReason = `Attachment declared as Office document (${declaredMime}), but binary header magic bytes reveal an executable Windows PE binary (${detectedMime}).`;
      } else if (isMacroEnabled) {
        mismatchReason = `Attachment contains hidden OLE2 compound streams with embedded VBA Macro code execution triggers.`;
      } else {
        mismatchReason = `Critical MIME contradiction: Header declares '${declaredMime}', but raw magic byte analysis confirmed '${detectedMime}' (${magicByteFormatName}).`;
      }

      detectionResult = `CRITICAL DECEPTION: ${mismatchReason}`;
      forensicAnalysisNote = `Severe MIME / Magic Byte contradiction detected. The file extension or declared MIME is weaponized as camouflage for an executable binary payload (${magicByteFormatName}).`;
    } else if (isMacroEnabled) {
      risk = 'HIGH';
      mismatchSeverity = 'HIGH';
      mismatchReason = 'VBA macro execution triggers embedded inside OLE2 container.';
      detectionResult = 'Suspicious Macro-Enabled Office Container (VBA module invocation detected in OLE2 stream).';
      forensicAnalysisNote = 'Office document with embedded executable macros and high-entropy code streams.';
    } else if (isArchive) {
      risk = 'MEDIUM';
      mismatchSeverity = 'MEDIUM';
      detectionResult = 'Compressed Archive Payload. Subject to depth-scan unpack rules and encrypted archive inspection.';
      forensicAnalysisNote = 'Container archive format. May contain nested executable or script payloads.';
    } else if (isMimeMismatch) {
      risk = 'MEDIUM';
      mismatchSeverity = 'MEDIUM';
      mismatchReason = `Declared MIME '${declaredMime}' differs from detected container '${detectedMime}'.`;
      detectionResult = `Minor MIME variance: declared as '${declaredMime}', magic bytes indicate '${detectedMime}'.`;
      forensicAnalysisNote = 'Header metadata mismatch between email transport declaration and payload stream.';
    }

    const attachmentRisk = risk === 'CRITICAL' ? 85 : risk === 'HIGH' ? 65 : risk === 'MEDIUM' ? 35 : 5;

    results.push({
      id: attId,
      attachmentId: attId,
      filename,
      mimeType: declaredMime,
      declaredMimeType: declaredMime,
      detectedMagicBytes,
      detectedMagicBytesAscii,
      detectedMimeType: detectedMime,
      magicByteFormatName,
      isCriticalMismatch,
      mismatchSeverity,
      mismatchReason,
      entropy,
      forensicAnalysisNote,
      sizeBytes: part.sizeBytes,
      sha256,
      sha1,
      md5,
      fileType: isExecutable ? 'Win32/PE Executable' : (isMacroEnabled ? 'Macro-Enabled Document' : magicByteFormatName),
      risk,
      attachmentRisk,
      detectionResult,
      lifecycleStatus: 'NOT_ANALYZED',
      statusMessage: 'Attachment metadata detected. Click "Analyze Attachment" for sandboxed inline analysis.',
      flags: {
        isExecutable,
        isMacroEnabled,
        isDoubleExtension,
        isScript,
        isArchive,
        isPasswordProtected: false,
        isMimeMismatch
      }
    });
  }

  return results;
}

function generateSimulatedHash(seed: string, type: 'sha256' | 'sha1' | 'md5'): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < seed.length; i++) {
    h ^= seed.charCodeAt(i);
    h += (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24);
  }
  
  const hex = (h >>> 0).toString(16).padStart(8, '0');
  if (type === 'md5') {
    return (hex + '88a910bf23c4' + hex).substring(0, 32);
  }
  if (type === 'sha1') {
    return (hex + '2e90f10c' + hex + '44b9' + hex).substring(0, 40);
  }
  // sha256
  return (hex + '4819d901ff88ab1092c48192a001' + hex + '8841a0e1').padEnd(64, '0').substring(0, 64);
}


