/**
 * MailTrace AI — Attachment Retrieval & Sandboxed Analysis Coordinator
 * ======================================================================
 * Manages authorized provider retrieval (Gmail, Outlook Graph, Raw MIME),
 * ephemeral temporary storage with automatic lifecycle cleanup,
 * size limit enforcement (25 MB), duplicate caching, and static analysis.
 * 
 * ZERO BROWSER DOWNLOADS. ZERO CODE EXECUTION. NO PERMANENT STORAGE.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { AttachmentAnalysis, ThreatSeverity } from '../../src/types/forensics.js';
import { staticAttachmentAnalyzer } from './staticAttachmentAnalyzer.js';

export interface AttachmentAnalyzeRequest {
  analysisId: string;
  provider: 'gmail' | 'outlook' | 'eml_mime' | 'local_sample';
  messageId?: string;
  attachmentId: string;
  filename: string;
  declaredMimeType?: string;
  sizeBytes?: number;
  expectedSha256?: string;
  rawBase64?: string; // Provided if the server already has the MIME part in memory (e.g. from EML ingestion)
}

export class AttachmentRetrievalService {
  private readonly MAX_ATTACHMENT_ANALYSIS_BYTES = 25 * 1024 * 1024; // 25 MB
  private readonly analysisCache = new Map<string, AttachmentAnalysis>();

  /**
   * Main entry point to securely analyze an attachment inline.
   */
  public async analyzeAttachmentInline(req: AttachmentAnalyzeRequest): Promise<AttachmentAnalysis> {
    const { analysisId, provider, messageId, attachmentId, filename, declaredMimeType, sizeBytes, rawBase64 } = req;

    // 1. Check duplicate / cached analysis
    const cacheKey = `${provider}:${messageId || 'none'}:${attachmentId || filename}:${req.expectedSha256 || ''}`;
    if (this.analysisCache.has(cacheKey)) {
      const cached = this.analysisCache.get(cacheKey)!;
      return {
        ...cached,
        statusMessage: 'Retrieved from duplicate analysis cache.'
      };
    }

    // 2. Check Size Limit prior to retrieval if declared size is known
    if (sizeBytes && sizeBytes > this.MAX_ATTACHMENT_ANALYSIS_BYTES) {
      return this.createSizeLimitExceededResult(req, sizeBytes);
    }

    // 3. Ephemeral workspace path in /tmp/mailtrace-attachments/<analysis-id>/
    const randomSuffix = crypto.randomBytes(8).toString('hex');
    const ephemeralDir = path.join('/tmp', 'mailtrace-attachments', `${analysisId || 'analysis'}-${randomSuffix}`);
    const ephemeralFilePath = path.join(ephemeralDir, `specimen-${randomSuffix}.bin`);

    try {
      // 4. Retrieve attachment bytes from authorized source
      const buffer = await this.retrieveAttachmentBytes(req);

      // Verify actual byte size against threshold
      if (buffer.length > this.MAX_ATTACHMENT_ANALYSIS_BYTES) {
        return this.createSizeLimitExceededResult(req, buffer.length);
      }

      // 5. Ensure ephemeral directory exists with restrictive permissions
      await fs.promises.mkdir(ephemeralDir, { recursive: true, mode: 0o700 });
      await fs.promises.writeFile(ephemeralFilePath, buffer, { mode: 0o600 });

      // 6. Execute Deep Static Analysis on buffer & ephemeral file
      const analysisResult = await staticAttachmentAnalyzer.analyze({
        buffer,
        filename: filename || 'unnamed_attachment',
        declaredMime: declaredMimeType || 'application/octet-stream',
        attachmentId: attachmentId || `att-${Date.now()}`
      });

      // Cache result for idempotency
      this.analysisCache.set(cacheKey, analysisResult);

      return analysisResult;
    } catch (err: any) {
      const errorMsg = err?.message || String(err);

      // Handle provider authorization errors gracefully
      if (errorMsg.includes('PROVIDER_UNAVAILABLE') || errorMsg.includes('OAUTH_REQUIRED')) {
        return this.createProviderErrorResult(req, 'PROVIDER_UNAVAILABLE', errorMsg);
      }
      if (errorMsg.includes('PERMISSION_DENIED') || errorMsg.includes('UNAUTHORIZED')) {
        return this.createProviderErrorResult(req, 'PERMISSION_DENIED', errorMsg);
      }

      return {
        id: attachmentId || `att-err-${Date.now()}`,
        attachmentId,
        filename: filename || 'unknown',
        mimeType: declaredMimeType || 'application/octet-stream',
        sizeBytes: sizeBytes || 0,
        sha256: '',
        sha1: '',
        md5: '',
        fileType: 'Unknown',
        risk: 'LOW' as ThreatSeverity,
        attachmentRisk: 0,
        detectionResult: `Analysis failed: ${errorMsg}`,
        lifecycleStatus: 'FAILED',
        statusMessage: `Retrieval / Analysis error: ${errorMsg}`,
        flags: {
          isExecutable: false,
          isMacroEnabled: false,
          isDoubleExtension: false,
          isScript: false,
          isArchive: false,
          isPasswordProtected: false,
          isMimeMismatch: false
        }
      };
    } finally {
      // 7. CRITICAL: Ephemeral storage cleanup on success, error, or exception
      try {
        if (fs.existsSync(ephemeralDir)) {
          await fs.promises.rm(ephemeralDir, { recursive: true, force: true });
        }
      } catch (cleanupErr) {
        console.warn(`[AttachmentRetrievalService] Warning: Failed to clean ephemeral directory ${ephemeralDir}:`, cleanupErr);
      }
    }
  }

  /**
   * Internal retrieval handler that communicates with Mail Provider APIs or raw MIME storage
   */
  private async retrieveAttachmentBytes(req: AttachmentAnalyzeRequest): Promise<Buffer> {
    const { provider, messageId, attachmentId, rawBase64 } = req;

    // Case A: Base64 data already stored in server memory (e.g. from uploaded EML or MIME parser)
    if (rawBase64) {
      return Buffer.from(rawBase64, 'base64');
    }

    // Case B: Gmail API retrieval
    if (provider === 'gmail') {
      const gmailToken = process.env.GMAIL_API_ACCESS_TOKEN;
      if (!gmailToken) {
        throw new Error('PROVIDER_UNAVAILABLE: Gmail API access token not configured. Authorized provider access required for inline content analysis.');
      }
      if (!messageId || !attachmentId) {
        throw new Error('PERMISSION_DENIED: Both messageId and attachmentId are required for Gmail attachment retrieval.');
      }

      const response = await fetch(
        `https://gmail.googleapis.com/gmail/v1/users/me/messages/${encodeURIComponent(messageId)}/attachments/${encodeURIComponent(attachmentId)}`,
        {
          headers: {
            Authorization: `Bearer ${gmailToken}`,
            Accept: 'application/json'
          }
        }
      );

      if (response.status === 401 || response.status === 403) {
        throw new Error('PERMISSION_DENIED: Gmail OAuth scope insufficient or expired for attachment download.');
      }
      if (!response.ok) {
        throw new Error(`PROVIDER_UNAVAILABLE: Gmail API returned status ${response.status}`);
      }

      const data = (await response.json()) as { data?: string };
      if (!data.data) {
        throw new Error('PROVIDER_UNAVAILABLE: No attachment payload returned from Gmail API.');
      }

      // Gmail API returns base64url-encoded data
      const base64Standard = data.data.replace(/-/g, '+').replace(/_/g, '/');
      return Buffer.from(base64Standard, 'base64');
    }

    // Case C: Microsoft Graph (Outlook) API retrieval
    if (provider === 'outlook') {
      const graphToken = process.env.MS_GRAPH_ACCESS_TOKEN;
      if (!graphToken) {
        throw new Error('PROVIDER_UNAVAILABLE: Microsoft Graph access token not configured. Authorized Outlook provider access required for inline content analysis.');
      }
      if (!messageId || !attachmentId) {
        throw new Error('PERMISSION_DENIED: Both messageId and attachmentId are required for Outlook attachment retrieval.');
      }

      const response = await fetch(
        `https://graph.microsoft.com/v1.0/me/messages/${encodeURIComponent(messageId)}/attachments/${encodeURIComponent(attachmentId)}/$value`,
        {
          headers: {
            Authorization: `Bearer ${graphToken}`
          }
        }
      );

      if (response.status === 401 || response.status === 403) {
        throw new Error('PERMISSION_DENIED: Microsoft Graph permissions insufficient or expired.');
      }
      if (!response.ok) {
        throw new Error(`PROVIDER_UNAVAILABLE: Microsoft Graph returned status ${response.status}`);
      }

      const arrayBuffer = await response.arrayBuffer();
      return Buffer.from(arrayBuffer);
    }

    // Fallback: Check if there is an in-memory sample attachment buffer in socStore
    throw new Error(`PROVIDER_UNAVAILABLE: Provider ${provider} requires an authorized integration token or parsed MIME buffer.`);
  }

  private createSizeLimitExceededResult(req: AttachmentAnalyzeRequest, sizeBytes: number): AttachmentAnalysis {
    return {
      id: req.attachmentId || `att-${Date.now()}`,
      attachmentId: req.attachmentId,
      filename: req.filename,
      mimeType: req.declaredMimeType || 'application/octet-stream',
      sizeBytes,
      sha256: '',
      sha1: '',
      md5: '',
      fileType: 'Size Limit Exceeded',
      risk: 'HIGH' as ThreatSeverity,
      attachmentRisk: 50,
      detectionResult: `Attachment size (${(sizeBytes / (1024 * 1024)).toFixed(2)} MB) exceeds the configured 25 MB safety limit.`,
      lifecycleStatus: 'SIZE_LIMIT_EXCEEDED',
      statusMessage: 'Attachment exceeds the 25 MB analysis threshold and was safely skipped.',
      flags: {
        isExecutable: false,
        isMacroEnabled: false,
        isDoubleExtension: false,
        isScript: false,
        isArchive: false,
        isPasswordProtected: false,
        isMimeMismatch: false
      }
    };
  }

  private createProviderErrorResult(
    req: AttachmentAnalyzeRequest,
    status: 'PROVIDER_UNAVAILABLE' | 'PERMISSION_DENIED',
    errorMsg: string
  ): AttachmentAnalysis {
    return {
      id: req.attachmentId || `att-${Date.now()}`,
      attachmentId: req.attachmentId,
      filename: req.filename,
      mimeType: req.declaredMimeType || 'application/octet-stream',
      sizeBytes: req.sizeBytes || 0,
      sha256: '',
      sha1: '',
      md5: '',
      fileType: 'Provider Pending',
      risk: 'LOW' as ThreatSeverity,
      attachmentRisk: 0,
      detectionResult: errorMsg,
      lifecycleStatus: status,
      statusMessage: errorMsg,
      flags: {
        isExecutable: false,
        isMacroEnabled: false,
        isDoubleExtension: false,
        isScript: false,
        isArchive: false,
        isPasswordProtected: false,
        isMimeMismatch: false
      }
    };
  }
}

export const attachmentRetrievalService = new AttachmentRetrievalService();
