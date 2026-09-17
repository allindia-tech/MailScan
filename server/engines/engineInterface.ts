/**
 * MailTrace AI - Hybrid Multi-Engine Detection Architecture
 * Core Engine Interfaces & Contracts (Sections 48-51)
 */

import {
  AuthenticationResults,
  DetectionSignal,
  DomainIntelligence,
  EngineResult,
  ForensicFinding,
  HeaderAnomaly,
  IPIntelligence,
  RelayNode,
  SpamAnalysis,
  ThreatCategory,
  ThreatIntelCorrelationReport,
  URLAnalysis,
  AttachmentAnalysis
} from '../../src/types/forensics.js';

export interface NormalizedEmail {
  id: string;
  rawMime: string;
  subject: string;
  from: string;
  fromName: string;
  fromDomain: string;
  to: string[];
  cc: string[];
  replyTo: string;
  returnPath: string;
  messageId: string;
  date: string;
  userAgent?: string;
  xMailer?: string;
  headers: Record<string, string>;
  rawHeaders: string;
  bodyText: string;
  bodyHtml?: string;
  normalizedText: string;
  urls: URLAnalysis[];
  attachments: AttachmentAnalysis[];
  authResults: AuthenticationResults;
  relayPath: RelayNode[];
  earliestReliableNode?: RelayNode;
  domainIntel: DomainIntelligence;
  ips: IPIntelligence[];
  headerAnomalies: HeaderAnomaly[];
  spamAnalysis?: SpamAnalysis;
}

export interface EngineContext {
  scenarioId?: string;
  clientIp?: string;
  timestamp: string;
  threatIntelCorrelation?: ThreatIntelCorrelationReport;
  forceGemini?: boolean;
  scoringVersion?: string;
  skipExternalAI?: boolean;
}

export interface DetectionEngine {
  readonly id: string;
  readonly name: string;
  readonly version: string;
  readonly description: string;
  analyze(email: NormalizedEmail, context?: EngineContext): Promise<EngineResult>;
}
