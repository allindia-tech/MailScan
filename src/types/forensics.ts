/**
 * MailTrace AI - Shared Forensic & Threat Intelligence Types
 */

export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'TRUSTED';

export type ActiveTab = 'dashboard' | 'analyzer' | 'threat-intel' | 'relay-trace' | 'forensics' | 'graph' | 'cases' | 'extension';

export type ThreatCategory = 
  | 'Legitimate'
  | 'Newsletter'
  | 'Promotional'
  | 'Transactional'
  | 'Notification'
  | 'Personal / Business Communication'
  | 'Bulk / Graymail'
  | 'Bulk / Unsolicited'
  | 'Spam'
  | 'Suspicious'
  | 'Phishing'
  | 'Credential Theft'
  | 'Malware Delivery'
  | 'Business Email Compromise'
  | 'Financial Fraud'
  | 'Executive Impersonation'
  | 'Account Takeover'
  | 'Account Compromise'
  | 'Identity / Personal Information Theft'
  | 'Investment Scam'
  | 'Payment Fraud'
  | 'Invoice Fraud'
  | 'Payroll Fraud'
  | 'Delivery / Courier Scam'
  | 'Government Impersonation'
  | 'Technical Support Scam'
  | 'Job / Recruitment Scam'
  | 'Advance Fee Scam'
  | 'Extortion / Blackmail'
  | 'OAuth / Authorization Abuse'
  | 'Malicious Link Campaign'
  | 'Data Theft / Information Harvesting'
  | 'Domain Spoofing'
  | 'Other Malicious'
  | 'Unknown';

export type ForensicTag = 'FACT' | 'OBSERVATION' | 'AI ASSESSMENT' | 'INVESTIGATIVE HYPOTHESIS' | 'SIMULATED THREAT INTELLIGENCE';

export interface ForensicFinding {
  id: string;
  tag: ForensicTag;
  text: string;
  category: string;
  confidence?: number;
  severity: ThreatSeverity;
}

export type AuthStatus = 'PASS' | 'FAIL' | 'SOFTFAIL' | 'NEUTRAL' | 'NONE';

export interface AuthenticationResults {
  spf: {
    status: AuthStatus;
    domain: string;
    clientIp: string;
    alignment: boolean;
    record?: string;
    details: string;
  };
  dkim: {
    status: AuthStatus;
    domain: string;
    selector: string;
    alignment: boolean;
    signaturePresent: boolean;
    details: string;
  };
  dmarc: {
    status: AuthStatus;
    policy: 'none' | 'quarantine' | 'reject' | 'none-found';
    headerFromDomain: string;
    alignment: boolean;
    disposition: 'none' | 'quarantine' | 'reject';
    details: string;
  };
  arc?: {
    status: AuthStatus;
    details: string;
  };
}

export interface RelayNode {
  index: number;
  hostname: string;
  ip: string;
  timestamp: string;
  timeDiffSeconds?: number;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  isp: string;
  asn: string;
  organization: string;
  reverseDns: string;
  confidence: number;
  reputation: ThreatSeverity;
  isEarliestReliable: boolean;
  isUntrustedBoundary: boolean;
  protocol: string;
  rawHeader: string;
}

export interface IPIntelligence {
  ip: string;
  type: 'IPv4' | 'IPv6';
  asn: string;
  isp: string;
  organization: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  lat: number;
  lon: number;
  hostingProvider: string;
  isProxy: boolean;
  isVpn: boolean;
  isTor: boolean;
  isOpenRelay: boolean;
  reputationScore: number; // 0-100 (100 = clean, 0 = malicious)
  threatScore: number;     // 0-100 (100 = critical)
  status: 'TRUSTED' | 'UNKNOWN' | 'SUSPICIOUS' | 'MALICIOUS';
  abuseContact?: string;
  reverseDns?: string;
}

export interface LookalikePattern {
  type: 'homoglyph' | 'character_substitution' | 'extra_characters' | 'prefix_suffix' | 'suspicious_tld' | 'punycode';
  targetBrand: string;
  targetDomain: string;
  detectedPattern: string;
  description: string;
}

export interface DomainIntelligence {
  domain: string;
  domainAgeYears: number;
  domainAgeDays: number;
  registrar: string;
  registrationDate: string;
  expirationDate: string;
  nameServers: string[];
  mxRecords: string[];
  aRecords: string[];
  txtRecords: string[];
  dnssec: boolean;
  hostingProvider: string;
  asn: string;
  reputation: ThreatSeverity;
  similarityToTarget?: number; // 0-100
  impersonationRisk: ThreatSeverity;
  lookalikePatterns: LookalikePattern[];
  isPunycode: boolean;
  isNewlyRegistered: boolean;
}

export interface URLAnalysis {
  id: string;
  url: string;
  domain: string;
  riskScore: number; // 0-100
  risk: ThreatSeverity;
  redirectChain: string[];
  status: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNRESOLVED';
  https: boolean;
  isIpUrl: boolean;
  isShortened: boolean;
  isPunycode: boolean;
  suspiciousParams: string[];
  hasCredentialPath: boolean;
  suspiciousTld: boolean;
  analysisNote: string;
  urlType?: 'MARKETING_TRACKING' | 'SUSPICIOUS_REDIRECT' | 'MALICIOUS' | 'BENIGN';
  isTrackingPixel?: boolean;
}

export interface AttachmentAnalysis {
  id: string;
  filename: string;
  mimeType: string;
  sizeBytes: number;
  sha256: string;
  sha1: string;
  md5: string;
  fileType: string;
  risk: ThreatSeverity;
  detectionResult: string;
  declaredMimeType?: string;
  detectedMagicBytes?: string;
  detectedMagicBytesAscii?: string;
  detectedMimeType?: string;
  magicByteFormatName?: string;
  isCriticalMismatch?: boolean;
  mismatchSeverity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'NONE';
  mismatchReason?: string;
  entropy?: number;
  forensicAnalysisNote?: string;
  flags: {
    isExecutable: boolean;
    isMacroEnabled: boolean;
    isDoubleExtension: boolean;
    isScript: boolean;
    isArchive: boolean;
    isPasswordProtected: boolean;
    isMimeMismatch: boolean;
  };
}

export interface IOC {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'email' | 'hash' | 'hostname' | 'message-id';
  indicator: string;
  risk: ThreatSeverity;
  source: string;
  confidence: number;
  addedToCase?: boolean;
  context?: string;
}

export interface HeaderAnomaly {
  id: string;
  header: string;
  value: string;
  finding: string;
  severity: ThreatSeverity;
  explanation: string;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'email' | 'sender' | 'domain' | 'ip' | 'asn' | 'url' | 'attachment' | 'campaign' | 'case';
  risk: ThreatSeverity;
  subtext?: string;
  x?: number;
  y?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: 'SENT_FROM' | 'RESOLVES_TO' | 'HOSTED_ON' | 'LINKS_TO' | 'CONTAINS' | 'RELATED_TO' | 'PART_OF_CAMPAIGN';
}

export interface InfrastructureScenario {
  scenario: string;
  confidence: number;
  reasoning: string;
  severity: ThreatSeverity;
}

export interface InvestigativeAssessment {
  executiveSummary?: string;
  containmentPlaybook?: string[];
  probableOrigin: {
    country: string;
    countryCode: string;
    region: string;
    city: string;
    network: string;
    isp: string;
    asn: string;
    confidence: number; // 0-100
  };
  scenarios: InfrastructureScenario[];
  disclaimer: string;
}

export interface ComponentScores {
  phishingLikelihood: number;
  impersonationLikelihood: number;
  domainRisk: number;
  senderAuthenticity: number; // 100 = high authentic, 0 = totally unauthentic
  urlRisk: number;
  becLikelihood: number;
  infrastructureRisk: number;
  threatIntelRisk: number; // Correlation with simulated threat intelligence feed
}

export interface ThreatSignal {
  id: string;
  category: 'sender-authenticity' | 'authentication' | 'header-routing' | 'domain' | 'url' | 'content' | 'attachment' | 'infrastructure' | 'threat-intel' | string;
  name: string;
  value: number; // 0 - 100
  weight: number; // 0 - 1
  direction: 'risk' | 'trust';
  confidence: number; // 0 - 100
  evidence: string;
  source: 'header' | 'content' | 'domain' | 'url' | 'attachment' | 'ip' | 'threat-intel' | 'ai';
  pointsContribution?: number; // Actual points added to category/overall
}

export interface CategoryScores {
  senderAuthenticity: number; // 0-100 (Risk score: 0 = completely authentic/trusted, 100 = critical spoofing/impersonation)
  authentication: number;     // 0-100 (Risk score: 0 = SPF/DKIM/DMARC passed, 100 = total fail/forgery)
  headerRouting: number;      // 0-100 (Risk score: 0 = clean headers, 100 = critical routing/injection anomalies)
  domain: number;             // 0-100 (Risk score: 0 = established/trusted domain, 100 = newly registered lookalike/abusive TLD)
  url: number;                // 0-100 (Risk score: 0 = no URLs or verified safe links, 100 = credential harvesting/IP URL/malicious redirect)
  content: number;            // 0-100 (Risk score: 0 = normal content, 100 = aggressive urgency/coercion/financial/credential phishing)
  attachment: number;         // 0-100 (Risk score: 0 = no attachments or benign text/pdf, 100 = executable/macro/malware hash)
  infrastructure: number;     // 0-100 (Risk score: 0 = verified enterprise/public provider, 100 = confirmed bulletproof/Tor/botnet relay)
  threatIntelligence: number; // 0-100 (Risk score: 0 = no matches / clean, 100 = confirmed malicious match in threat intel feeds)
}

export interface ScoringWeights {
  senderAuthenticity: number; // 0.15
  authentication: number;     // 0.15
  headerRouting: number;      // 0.10
  domain: number;             // 0.15
  url: number;                // 0.15
  content: number;            // 0.10
  attachment: number;         // 0.05
  infrastructure: number;     // 0.10
  threatIntelligence: number; // 0.05
}

export const DEFAULT_SCORING_WEIGHTS: ScoringWeights = {
  senderAuthenticity: 0.15,
  authentication: 0.15,
  headerRouting: 0.10,
  domain: 0.15,
  url: 0.15,
  content: 0.10,
  attachment: 0.05,
  infrastructure: 0.10,
  threatIntelligence: 0.05
};

export interface ScoreExplanation {
  summary: string;
  formula: string;
  weightedBaseScore: number;
  correlationBonus: number;
  deduplicatedCount: number;
  primaryContributors: Array<{
    category: string;
    categoryScore: number;
    weightPercent: number;
    pointsContribution: number;
    summary: string;
  }>;
  riskModifiers: Array<{
    name: string;
    delta: number;
    reason: string;
  }>;
}

export type SpamClassificationType = 'none' | 'promotional' | 'newsletter' | 'bulk' | 'spam';

export interface SpamSignal {
  id: string;
  category: 'sender-signals' | 'promotional-content' | 'newsletter-structure' | 'bulk-indicators' | 'tracking-infrastructure' | 'marketing-cta' | 'unsubscribe' | 'delivery-signals' | 'other' | string;
  name: string;
  value: number; // 0 - 100
  weight: number; // 0 - 1
  evidence: string;
  pointsContribution: number;
}

export interface SpamAnalysis {
  score: number; // 0 - 100 (Spam / Bulk Likelihood)
  classification: SpamClassificationType;
  classificationLabel: string; // e.g. "Promotional Newsletter", "Bulk Commercial", "Aggressive Spam"
  confidence: number; // 0 - 100
  level: 'None' | 'Low' | 'Possible' | 'Likely' | 'Strong';
  signals: SpamSignal[];
  breakdown: {
    senderSignalsScore: number;
    promotionalContentScore: number;
    newsletterStructureScore: number;
    bulkMailIndicatorsScore: number;
    trackingInfrastructureScore: number;
    marketingCtaScore: number;
    unsubscribeScore: number;
    deliverySignalsScore: number;
  };
  hasUnsubscribe: boolean;
  hasTrackingPixel: boolean;
  trackingPixelDetails?: string;
  marketingUrlsCount: number;
}

export interface AuthenticityAnalysis {
  score: number; // 0 - 100 Authenticity Confidence
  status: 'Strong' | 'Moderate' | 'Weak' | 'Failed' | 'Unverified';
  spfStatus: AuthStatus;
  dkimStatus: AuthStatus;
  dmarcStatus: AuthStatus;
  alignment: boolean;
  senderMatchesReplyTo: boolean;
  senderMatchesReturnPath: boolean;
  trustFactors: string[];
  riskFactors: string[];
}

export interface ThreatScoreDetails {
  score: number; // 0 - 100 Threat Risk
  severity: ThreatSeverity;
  severityLabel: 'Low' | 'Guarded' | 'Suspicious' | 'High' | 'Critical';
  confidence: number;
  riskFactors: string[];
  trustFactors: string[];
}

export interface ScoringAudit {
  engineVersion: string; // e.g. "v2.1"
  signalsEvaluated: number;
  riskSignalsCount: number;
  trustSignalsCount: number;
  spamSignalsCount: number;
}

export interface SimulatedThreatIndicator {
  id: string;
  indicator: string; // IP, domain, or file hash (SHA-256 / MD5)
  type: 'ip' | 'domain' | 'hash';
  threatName: string;
  threatActor?: string;
  category: string; // e.g. C2 Server, Credential Harvester, Malware Dropper, Bulletproof Host
  severity: ThreatSeverity;
  confidence: number; // 0 - 100
  feedSource: string; // e.g. SIMULATED THREAT INTELLIGENCE - AlienVault OTX Pulse
  firstSeen: string;
  lastSeen: string;
  tlp: 'TLP:WHITE' | 'TLP:GREEN' | 'TLP:AMBER' | 'TLP:RED';
  tags: string[];
  description: string;
  recommendedMitigation: string;
  label: 'SIMULATED THREAT INTELLIGENCE';
}

export interface ThreatIntelMatch {
  id: string;
  indicator: string;
  indicatorType: 'ip' | 'domain' | 'hash';
  matchSource: string; // e.g. "SMTP Ingress IP (185.220.101.42)", "RFC 5322 From Domain", "Attachment SHA-256 (Invoice_48291_Summary.pdf.exe)"
  matchedFeedEntry: SimulatedThreatIndicator;
  severity: ThreatSeverity;
  confidence: number;
  riskScoreContribution: number; // Risk impact points added to overall score
  matchedAt: string;
  label: 'SIMULATED THREAT INTELLIGENCE';
}

export interface ThreatIntelCorrelationReport {
  engineVersion: string;
  provenance: string;
  checkedIndicatorsCount: number;
  matchedIndicatorsCount: number;
  highestSeverity: ThreatSeverity | 'NONE';
  threatIntelRiskScore: number; // 0-100
  totalRiskBoost: number; // Points added to overall risk score
  totalRiskScoreBoost?: number;
  matches: ThreatIntelMatch[];
  matchedActors: string[];
  threatActors?: string[];
  feedSourcesConsulted?: string[];
  feedSources?: string[];
  correlationSummary: string;
  disclaimer?: string;
}

export interface EmailAnalysisResult {
  id: string;
  analyzedAt: string;
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
  
  // Scoring
  overallRiskScore: number; // 0-100 (Threat Risk)
  threatRisk?: number; // Explicit Threat Risk alias (0-100)
  spamLikelihood?: number; // 0-100 (Spam / Bulk Likelihood)
  authenticityConfidence?: number; // 0-100 (Authenticity Confidence)
  severity: ThreatSeverity;
  primaryClassification: ThreatCategory;
  classificationConfidence: number; // 0-100
  
  // Dedicated Models
  spam?: SpamAnalysis;
  authenticity?: AuthenticityAnalysis;
  threatDetails?: ThreatScoreDetails;
  scoringAudit?: ScoringAudit;
  
  // Tripartite Confidence Model
  threatConfidence: number;      // How confident that it's malicious
  originConfidence: number;      // How confident in the earliest reliable infrastructure
  attributionConfidence: number; // How strong is link to specific actor/campaign
  
  // Normalized 9-Category Scoring Breakdown
  categoryScores: CategoryScores;
  componentScores: ComponentScores;
  signals: ThreatSignal[];
  correlationBonus: number;
  scoringVersion: string;
  scoreExplanation: ScoreExplanation;
  secondaryClassifications?: string[];
  recalculationVerified?: boolean;
  
  // Forensic Findings
  findings: ForensicFinding[];
  
  // Headers & Anomalies
  headers: Record<string, string>;
  rawHeaders: string;
  headerAnomalyScore: number;
  headerAnomalies: HeaderAnomaly[];
  
  // Authentication
  authResults: AuthenticationResults;
  
  // Relay Path
  relayPath: RelayNode[];
  earliestReliableNode?: RelayNode;
  
  // Intelligence
  ips: IPIntelligence[];
  senderDomainIntel: DomainIntelligence;
  urls: URLAnalysis[];
  attachments: AttachmentAnalysis[];
  iocs: IOC[];
  
  // Threat Intelligence Correlation (Simulated Feed)
  threatIntelCorrelation: ThreatIntelCorrelationReport;
  
  // Investigative
  assessment: InvestigativeAssessment;
  
  // Graph
  graph: {
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
  
  // Content Preview (sanitized)
  bodyText: string;
  bodyHtml?: string;
  rawMime?: string;
  
  // Campaign match & Fingerprinting
  matchedCampaignId?: string;
  matchedCampaignName?: string;
  campaignFingerprint?: string;

  // Hybrid Multi-Engine Assessment & Consensus
  threatAssessment?: ThreatAssessment;
  engineConsensus?: EngineConsensus;
  whyThisScore?: ThreatAssessment['whyThisScore'];
  emailContentAnalysis?: EmailContentAnalysis;

  // Advanced Attack & Scam Technique Detection
  detectedTechniques?: DetectedAttackTechnique[];
  multiLayerNormalization?: MultiLayerNormalizationReport;

  // Primary Classification Engine & Matrix
  classificationResult?: EmailClassificationResult;
  detectionMatrix?: DetectionMatrix;

  // Authoritative Canonical Analysis Verdict (Section 3)
  verdict?: AnalysisVerdict;
}

export interface AnalysisVerdict {
  analysisId: string;
  modelVersion: string;
  verdictVersion: string;

  primaryCategory: ThreatCategory;
  secondaryCategories: ThreatCategory[];

  threatRisk: number; // 0 - 100
  spamBulkProbability: number; // 0 - 100
  authenticityScore: number; // 0 - 100
  phishingProbability: number; // 0.0 - 1.0
  fraudProbability: number; // 0.0 - 1.0
  becProbability: number; // 0.0 - 1.0
  malwareProbability: number; // 0.0 - 1.0
  credentialTheftProbability: number; // 0.0 - 1.0
  impersonationProbability: number; // 0.0 - 1.0
  socialEngineeringProbability: number; // 0.0 - 1.0
  obfuscationProbability: number; // 0.0 - 1.0
  classificationConfidence: number; // 0 - 100

  severity: ThreatSeverity;

  detectedTechniques: DetectedAttackTechnique[];

  evidence: DetectionSignal[];
  benignEvidence: DetectionSignal[];

  authentication: AuthenticationResults;
  urls: URLAnalysis[];
  attachments: AttachmentAnalysis[];
  relayPath: RelayNode[];
  infrastructure: {
    originIp?: string;
    originAsn?: string;
    originIsp?: string;
    originCountry?: string;
    relayHopsCount: number;
  };
  geolocation: {
    available: boolean;
    label: string; // strictly "Infrastructure Geolocation", never "Attacker Location"
    locations: (ThreatLocation | GeoLocationEvidence)[];
  };
  threatIntel: {
    configured: boolean;
    provider?: string;
    matches: ThreatIntelMatch[];
    note: string;
  };
  campaignCorrelations: {
    matched: boolean;
    campaignId?: string;
    campaignName?: string;
    confidence?: number;
  };
  coverage: {
    headerAnalysis: boolean;
    authenticationAnalysis: boolean;
    contentAnalysis: boolean;
    urlAnalysis: boolean;
    attachmentAnalysis: boolean;
    threatIntelAnalysis: boolean;
  };
  limitations: string[];
  generatedAt: string;
}

export type EmailIntentCategory =
  | 'Marketing'
  | 'Newsletter'
  | 'Transaction'
  | 'Notification'
  | 'Account Security'
  | 'Password Reset'
  | 'Recruitment'
  | 'Education'
  | 'Finance'
  | 'Invoice'
  | 'Payment Request'
  | 'Credential Collection'
  | 'Identity Verification'
  | 'File Delivery'
  | 'Executive Request'
  | 'Customer Support'
  | 'Survey'
  | 'Charity'
  | 'Prize/Reward'
  | 'Unknown';

export type EmailIntentDisposition = 'Benign' | 'Suspicious' | 'Malicious';

export type RequestedActionType =
  | 'Click a link'
  | 'Log in'
  | 'Enter password'
  | 'Enter OTP'
  | 'Download attachment'
  | 'Open document'
  | 'Pay money'
  | 'Transfer money'
  | 'Change bank details'
  | 'Reply with sensitive information'
  | 'Call a number'
  | 'Verify identity'
  | 'Share personal data'
  | 'Purchase something'
  | 'Ignore security warnings'
  | 'Read newsletter / browse articles'
  | 'Unsubscribe'
  | 'None / informational';

export interface SocialEngineeringFinding {
  signal: 'Urgency' | 'Fear' | 'Authority' | 'Trust manipulation' | 'Emotional pressure' | 'Secrecy' | 'Financial pressure' | 'Credential pressure' | 'Consequence manipulation';
  evidence: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
}

export interface EmailContentAnalysis {
  intent: {
    category: EmailIntentCategory;
    disposition: EmailIntentDisposition;
    confidence: number;
    description: string;
  };
  requestedAction: {
    action: RequestedActionType;
    evidence: string;
    riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  };
  subjectAnalysis: {
    flags: string[];
    sentiment: 'neutral' | 'urgent' | 'alarming' | 'promotional';
    isSuspicious: boolean;
  };
  socialEngineering: SocialEngineeringFinding[];
  fraudIndicators: {
    type?: 'Payment' | 'Investment' | 'Prize' | 'Employment' | 'None';
    detected: boolean;
    evidence?: string;
  };
  becIndicators: {
    detected: boolean;
    type?: 'Executive Impersonation' | 'Vendor Impersonation' | 'Payment Diversion' | 'Bank Detail Change' | 'Confidential Request' | 'Gift Card Request';
    evidence?: string;
  };
  htmlFindings: {
    hasHiddenElements: boolean;
    hasInvisibleText: boolean;
    hasSuspiciousForms: boolean;
    trackingPixelsCount: number;
    mismatchedAnchorsCount: number;
    findings: string[];
  };
  ocrQrFindings?: {
    hasQrCode: boolean;
    extractedUrl?: string;
    ocrText?: string;
  };
}

export interface EmailClassificationResult {
  primaryCategory: {
    id: string;
    label: string;
    family: 'BENIGN' | 'SECURITY';
    confidence: number;
    probability: number;
    severity: ThreatSeverity;
    description?: string;
  };
  secondaryCategories: Array<{
    id: string;
    label: string;
    confidence: number;
    probability: number;
    evidence: string;
  }>;
  detectedTechniques: Array<{
    techniqueId: string;
    name: string;
    severity: ThreatSeverity;
    confidence: number;
    evidence: string;
    source: string;
  }>;
  threatRisk: number;
  threatSeverity: ThreatSeverity;
  spamBulkProbability: number;
  phishingProbability: number;
  credentialTheftProbability: number;
  malwareProbability: number;
  becProbability: number;
  financialFraudProbability: number;
  executiveImpersonationProbability: number;
  accountTakeoverProbability: number;
  socialEngineeringProbability: number;
  impersonationProbability: number;
  obfuscationProbability: number;
  authenticityScore: number;
  benignEvidence: string[];
  maliciousEvidence: string[];
  whyThisClassification: {
    reasons: string[];
    whyNotOtherCategories: Array<{
      category: string;
      reason: string;
    }>;
  };
  coverage: number; // 0-100%
  modelVersion: string;
  detectorVersions: Record<string, string>;
  generatedAt: string;
}

export type MatrixStatus = 'NOT_ANALYZED' | 'NOT_DETECTED' | 'POSSIBLE' | 'LIKELY' | 'DETECTED' | 'CONFIRMED';

export interface DetectionMatrixItem {
  status: MatrixStatus;
  confidence: number;
  evidence: string[];
  source: string;
}

export type DetectionMatrixDimension =
  | 'senderIdentity'
  | 'authentication'
  | 'domainReputation'
  | 'urlReputation'
  | 'urlDeception'
  | 'attachmentRisk'
  | 'contentIntent'
  | 'socialEngineering'
  | 'credentialTheft'
  | 'phishing'
  | 'bec'
  | 'financialFraud'
  | 'executiveImpersonation'
  | 'malware'
  | 'accountTakeover'
  | 'dataHarvesting'
  | 'unicodeObfuscation'
  | 'htmlDeception'
  | 'quishing'
  | 'oauthAbuse'
  | 'spamBulk'
  | 'newsletter'
  | 'promotional'
  | 'transactional'
  | 'governmentImpersonation'
  | 'jobScam'
  | 'investmentScam'
  | 'deliveryScam'
  | 'extortion';

export type DetectionMatrix = Record<DetectionMatrixDimension, DetectionMatrixItem>;

export interface CaseItem {
  id: string;
  title: string;
  description: string;
  priority: ThreatSeverity;
  analyst: string;
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
  createdAt: string;
  updatedAt: string;
  emailId?: string;
  emailSubject?: string;
  sender?: string;
  relatedIocs: string[];
  relatedDomains: string[];
  relatedIps: string[];
  campaignId?: string;
  evidenceCount: number;
  notes: Array<{ id: string; author: string; timestamp: string; text: string }>;
  timeline: Array<{ id: string; timestamp: string; action: string; actor: string; details: string }>;
}

export interface EvidenceItem {
  id: string;
  caseId?: string;
  name: string;
  type: 'RAW_EML' | 'PARSED_HEADERS' | 'ATTACHMENT' | 'IOC_EXPORT' | 'FORENSIC_REPORT' | 'ANALYST_NOTE';
  sha256: string;
  sizeBytes: number;
  uploadedBy: string;
  timestamp: string;
  description: string;
  integrityStatus: 'VERIFIED' | 'COMPROMISED' | 'PENDING';
  rawPayload?: string;
}

export interface AlertItem {
  id: string;
  severity: ThreatSeverity;
  detectionTime: string;
  emailSubject: string;
  sender: string;
  threatType: ThreatCategory;
  riskScore: number;
  status: 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE';
  assignedAnalyst: string;
  emailId: string;
}

export interface CampaignItem {
  id: string;
  name: string;
  emailCount: number;
  commonDomain: string;
  commonIp: string;
  threatType: ThreatCategory;
  confidence: number;
  firstSeen: string;
  lastSeen: string;
  description: string;
  associatedEmails: Array<{ id: string; subject: string; from: string; date: string; risk: number }>;
}

export interface AuditLogItem {
  id: string;
  timestamp: string;
  actor: string;
  role: string;
  action: string;
  target: string;
  ipAddress: string;
  status: 'SUCCESS' | 'WARNING' | 'FAILURE';
}

export type UserRole = 'ANALYST' | 'ADMIN' | 'INVESTIGATOR' | 'VIEWER';

export interface UserProfile {
  name: string;
  email: string;
  role: UserRole;
  badge: string;
}

export interface AnalyzedEmailSummary {
  id: string;
  analyzedAt: string;
  subject: string;
  from: string;
  fromDomain: string;
  overallRiskScore: number;
  threatRisk?: number;
  spamLikelihood?: number;
  authenticityConfidence?: number;
  severity: ThreatSeverity;
  primaryClassification: ThreatCategory;
  threatConfidence: number;
  originConfidence: number;
  attributionConfidence: number;
  matchedCampaignId?: string;
  matchedCampaignName?: string;
}

export interface SocStats {
  totalAnalyzed: number;
  activeAlerts: number;
  criticalAlerts: number;
  highAlerts: number;
  mediumAlerts: number;
  lowAlerts: number;
  containedCount: number;
  quarantineRate: number;
  trackedCampaigns: number;
  activeCases: number;
  evidenceItems: number;
}

// =========================================================================
// MULTI-ENGINE ARCHITECTURE & HYBRID DETECTION SCHEMAS (Sections 48-51)
// =========================================================================

export type EngineSource = 'forensic' | 'ml' | 'gemini' | 'threat_intel' | 'historical';

export interface DetectionSignal {
  id: string;
  category: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: number; // 0-100
  source: EngineSource;
  evidence: string;
  relatedIndicators?: string[];
  pointsContribution?: number;
}

export interface EngineResult {
  engine: string;
  version: string;
  classification?: ThreatCategory | string;
  probabilities: Record<string, number>; // 0 to 1
  signals: DetectionSignal[];
  confidence: number; // 0 to 100
  limitations?: string[];
  processingTimeMs: number;
  status: 'COMPLETED' | 'SKIPPED' | 'FALLBACK' | 'ERROR';
  details?: Record<string, any>;
}

export interface EngineConsensus {
  agreement: number; // e.g. 3 (out of 3) or 2 (out of 3)
  totalEngines: number;
  disagreement: boolean;
  disagreementDetails?: string;
  consensusClassification: ThreatCategory;
  calibratedConfidence: number; // capped at 98
  reviewRecommended: boolean;
  engines: {
    forensic: { classification: string; confidence: number; agreement: boolean };
    ml: { classification: string; confidence: number; agreement: boolean };
    gemini: { classification: string; confidence: number; agreement: boolean; executed: boolean };
    threatIntel: { matched: boolean; confidence: number };
  };
}

export interface ThreatAssessment {
  classification: ThreatCategory;
  classificationConfidence: number;
  threatRisk: number; // 0-100
  spamBulkLikelihood: number; // 0-100
  authenticityConfidence: number; // 0-100
  probabilities: {
    phishing: number; // 0-1
    bec: number; // 0-1
    credentialTheft: number; // 0-1
    financialFraud: number; // 0-1
    malware: number; // 0-1
    impersonation: number; // 0-1
  };
  engineConsensus: EngineConsensus;
  signals: DetectionSignal[];
  engineResults: {
    forensic: EngineResult;
    ml: EngineResult;
    gemini?: EngineResult;
    threatIntel?: EngineResult;
  };
  whyThisScore: {
    forensic: string[];
    ml: string[];
    gemini: string[];
    threatIntel: string[];
    historical: string[];
  };
  recommendedAction: 'allow' | 'label_spam' | 'quarantine' | 'block' | 'analyst_review';
  limitations: string[];
  campaignFingerprint?: string;
  recurrentCampaignObserved?: boolean;
}

// =========================================================================
// SELF-LEARNING GOVERNANCE & FEEDBACK SCHEMAS (Sections 17-21, 38-40)
// =========================================================================

export type FeedbackTrustLevel = 'verified_analyst' | 'administrator' | 'user_report' | 'automatic_inference';

export interface AnalystFeedbackItem {
  id: string;
  emailId: string;
  emailSubject: string;
  originalClassification: ThreatCategory;
  verifiedClassification: ThreatCategory;
  isCorrection: boolean;
  feedbackType?: 'classification' | 'technique' | 'both';
  incorrectTechniques?: string[];
  reason: string;
  analyst: string;
  trustLevel: FeedbackTrustLevel;
  trustWeight: number; // Level 1 = 1.0, Level 2 = 0.8, Level 3 = 0.4, Level 4 = 0 (never train)
  submittedAt: string;
  features: Record<string, any>;
  status: 'PENDING_VALIDATION' | 'QUEUED_FOR_TRAINING' | 'QUARANTINED' | 'APPLIED';
  quarantineReason?: string;
}

export interface ModelEvaluationMetrics {
  precision: number;
  recall: number;
  f1: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  rocAuc: number;
  prAuc: number;
  calibration: number;
  byCategory: Record<string, { precision: number; recall: number; f1: number; sampleCount: number }>;
}

export interface MLModelMetadata {
  modelId: string;
  version: string;
  architecture: 'XGBoost / Calibrated Ensembled Forest' | 'Interpretable Tabular Model' | 'Multimodal Deep Transformer (8 Layers, 12 Heads, 128,894,258 Parameters)' | 'Multimodal Deep Transformer (8 Layers, 12 Heads, 100M Parameters)' | string;
  trainingDatasetVersion: string;
  trainingTimestamp: string;
  featureSchemaVersion: string;
  verifiedSamplesCount: number;
  evaluationMetrics: ModelEvaluationMetrics;
  status: 'PRODUCTION_CHAMPION' | 'EVALUATING_CHALLENGER' | 'ARCHIVED';
  featuresUsed: string[];
  topImportantFeatures: Array<{ feature: string; importance: number }>;
}

export interface ModelDriftReport {
  status: 'NORMAL' | 'WARNING' | 'DRIFT_DETECTED';
  driftScore: number; // 0-1
  featureDriftDetected: boolean;
  classDistributionDriftDetected: boolean;
  lastChecked: string;
  recentAnalystCorrectionsRate: number; // %
  topMisclassifiedCategories: Array<{ from: string; to: string; count: number }>;
  recommendation: string;
}

export interface PrivacySettings {
  geminiAnalysisEnabled: boolean;
  sendEmailBody: 'Allowed' | 'Restricted' | 'Masked';
  maskRecipient: boolean;
  maskPersonalIdentifiers: boolean;
  retainGeminiResponseDays: number;
}

export interface RegressionTestCase {
  id: string;
  name: string;
  description: string;
  rawEml: string;
  expected: {
    classification: ThreatCategory[];
    threatRiskMin?: number;
    threatRiskMax?: number;
    spamLikelihoodMin?: number;
    spamLikelihoodMax?: number;
    authenticityMin?: number;
    action?: string[];
  };
}

export interface RegressionTestResult {
  caseId: string;
  name: string;
  passed: boolean;
  actualClassification: ThreatCategory;
  actualThreatRisk: number;
  actualSpamLikelihood: number;
  actualAuthenticity: number;
  actualAction: string;
  failures: string[];
  durationMs: number;
}

// =========================================================================
// REAL D3 GLOBAL THREAT MAP & INFRASTRUCTURE ROUTE MODELS
// =========================================================================

export interface GeoLocationEvidence {
  id: string;
  latitude: number;
  longitude: number;
  source: 'email-header' | 'received-header' | 'ip-geolocation' | 'threat-intelligence' | 'case-data';
  sourceId?: string;
  ip?: string;
  hostname?: string;
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  isp?: string;
  asn?: string;
  reverseDns?: string;
  confidence?: number;
  verified: boolean;
  type?: 'origin' | 'relay' | 'destination';
  precision?: 'coordinates' | 'infrastructure_estimate' | 'city' | 'country';
  hopIndex?: number;
  rawHeader?: string;
  isUntrustedBoundary?: boolean;
}

export interface InvestigationMapData {
  investigationId: string;
  relayPath: GeoLocationEvidence[];
  routes: {
    sourceId: string;
    targetId: string;
    verified: boolean;
    sourceCoords: [number, number];
    targetCoords: [number, number];
    label?: string;
    hopNumber?: number;
  }[];
  globalThreatActivity?: ThreatActivity[];
}

export interface ThreatLocation {
  id: string;
  latitude: number;
  longitude: number;
  type: 'origin' | 'relay' | 'destination';
  source?: 'email-header' | 'received-header' | 'ip-geolocation' | 'threat-intelligence' | 'case-data';
  sourceId?: string;
  verified?: boolean;
  precision?: 'coordinates' | 'infrastructure_estimate' | 'city' | 'country';
  label?: string;
  ip?: string;
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  asn?: string;
  isp?: string;
  reverseDns?: string;
  hostname?: string;
  risk?: number;
  confidence?: number;
  timestamp?: string;
  isUntrustedBoundary?: boolean;
  hopIndex?: number;
  protocol?: string;
  rawHeader?: string;
}

export interface ThreatRoute {
  sourceId: string;
  targetId: string;
  sourceCoords: [number, number]; // [lon, lat]
  targetCoords: [number, number]; // [lon, lat]
  risk?: number;
  confidence?: number;
  hopNumber?: number;
  label?: string;
}

export interface ThreatActivity {
  id: string;
  latitude: number;
  longitude: number;
  city?: string;
  country?: string;
  countryCode?: string;
  category: 'phishing' | 'malware' | 'bec' | 'credential_theft' | 'fraud' | 'spam';
  severity: 'low' | 'medium' | 'high' | 'critical';
  timestamp: string;
  source?: string;
  eventCount?: number;
  details?: string;
  ip?: string;
  isSimulated?: boolean;
}

// =========================================================================
// ADVANCED ATTACK & SCAM TECHNIQUE DETECTION MODELS
// =========================================================================

export type AttackTechniqueId =
  | 'IDENTITY_DECEPTION'
  | 'DISPLAY_NAME_SPOOFING'
  | 'DOMAIN_SPOOFING'
  | 'LOOKALIKE_DOMAIN'
  | 'HOMOGRAPH_ATTACK'
  | 'PUNYCODE_DECEPTION'
  | 'ZERO_WIDTH_OBFUSCATION'
  | 'BIDI_TEXT_DECEPTION'
  | 'ASCII_SMUGGLING'
  | 'CONTENT_OBFUSCATION'
  | 'HTML_DECEPTION'
  | 'HIDDEN_CONTENT'
  | 'URL_OBFUSCATION'
  | 'URL_DISPLAY_DECEPTION'
  | 'REDIRECT_CHAIN'
  | 'SHORT_URL'
  | 'QR_PHISHING'
  | 'IMAGE_PHISHING'
  | 'CREDENTIAL_HARVESTING'
  | 'OTP_SCAM'
  | 'MFA_MANIPULATION'
  | 'PASSWORD_RESET_ABUSE'
  | 'BEC'
  | 'PAYMENT_DIVERSION'
  | 'INVOICE_FRAUD'
  | 'FINANCIAL_FRAUD'
  | 'PRIZE_SCAM'
  | 'JOB_SCAM'
  | 'TECH_SUPPORT_SCAM'
  | 'DELIVERY_SCAM'
  | 'GOVERNMENT_IMPERSONATION'
  | 'BANK_IMPERSONATION'
  | 'CLOUD_ACCOUNT_PHISHING'
  | 'MALICIOUS_ATTACHMENT'
  | 'FILE_TYPE_MISMATCH'
  | 'ARCHIVE_THREAT'
  | 'SCRIPT_ATTACHMENT'
  | 'MACRO_DOCUMENT'
  | 'MALWARE_DELIVERY'
  | 'RANSOM_EXTORTION'
  | 'DATA_HARVESTING'
  | 'SOCIAL_ENGINEERING'
  | 'URGENCY'
  | 'FEAR'
  | 'AUTHORITY_MANIPULATION'
  | 'SECRECY'
  | 'SCARCITY'
  | 'REWARD_MANIPULATION'
  | 'TRACKING'
  | 'CAMPAIGN_REUSE'
  | 'THREAD_HIJACKING'
  | 'CONVERSATION_HIJACKING'
  | 'HEADER_ANOMALY'
  | 'ROUTING_ANOMALY'
  | 'INFRASTRUCTURE_ANOMALY';

export interface AttackTechnique {
  id: AttackTechniqueId | string;
  name: string;
  category: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detectors: string[];
  falsePositiveNotes: string[];
  enabled: boolean;
}

export interface DetectedAttackTechnique {
  id: AttackTechniqueId | string;
  name: string;
  category: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number; // 0-100
  evidence: string;
  source: string;
  detectorId: string;
  detectorVersion: string;
  timestamp: string;
  rawRepresentation?: string;
  normalizedRepresentation?: string;
  renderedRepresentation?: string;
  signalGroup?: string;
  correlationId?: string;
  verifiedStatus?: 'unreviewed' | 'confirmed' | 'false_positive';
}

export interface MultiLayerNormalizationReport {
  rawMimeLength: number;
  decodedTextLength: number;
  plainText: string;
  normalizedUnicodeText: string;
  renderedVisibleText: string;
  htmlDomStructure: {
    tagCount: number;
    hiddenElementCount: number;
    scriptTagCount: number;
    formCount: number;
    iframeCount: number;
    trackingPixelCount: number;
  };
  extractedUrls: string[];
  decodedUrls: Array<{ original: string; normalized: string; decoded: string; isDiscrepancy: boolean }>;
  attachmentMetadata: Array<{ filename: string; mimeType: string; size: number; magicBytesType?: string; isMismatch?: boolean }>;
  ocrText?: string;
  obfuscationEntropy: number;
  hiddenContentDetected: boolean;
}

