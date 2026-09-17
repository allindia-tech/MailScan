/**
 * MailTrace AI - Extensible Primary & Secondary Category Taxonomy Config
 * Version 1.0.0
 * Stores the complete 30-category taxonomy schema, priority hierarchies, and family metadata.
 */

export interface PrimaryCategoryDefinition {
  id: string;
  label: string;
  family: 'BENIGN' | 'SECURITY';
  priority: number; // Higher number = higher evaluation priority
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'TRUSTED';
  description: string;
}

export const CATEGORY_TAXONOMY_VERSION = 'MT-TAXONOMY-V1.0.0';

export const PRIMARY_CATEGORIES: Record<string, PrimaryCategoryDefinition> = {
  // BENIGN / NON-MALICIOUS (1-8)
  'Legitimate': {
    id: 'Legitimate',
    label: 'Legitimate',
    family: 'BENIGN',
    priority: 10,
    severity: 'TRUSTED',
    description: 'Normal expected enterprise or personal communication containing zero malicious or unwanted indicators.'
  },
  'Newsletter': {
    id: 'Newsletter',
    label: 'Newsletter',
    family: 'BENIGN',
    priority: 25,
    severity: 'LOW',
    description: 'Recurring informational digest, tech publication, or editorial content with list header headers.'
  },
  'Promotional': {
    id: 'Promotional',
    label: 'Promotional',
    family: 'BENIGN',
    priority: 24,
    severity: 'LOW',
    description: 'Legitimate marketing, commercial offers, discounts, or product announcements.'
  },
  'Transactional': {
    id: 'Transactional',
    label: 'Transactional',
    family: 'BENIGN',
    priority: 23,
    severity: 'LOW',
    description: 'Automated receipt, shipping notification, password reset, or account activity confirmation.'
  },
  'Notification': {
    id: 'Notification',
    label: 'Notification',
    family: 'BENIGN',
    priority: 22,
    severity: 'LOW',
    description: 'System alert, status update, automated workflow ping, or platform notification.'
  },
  'Personal / Business Communication': {
    id: 'Personal / Business Communication',
    label: 'Personal / Business Communication',
    family: 'BENIGN',
    priority: 20,
    severity: 'TRUSTED',
    description: 'Direct human-to-human correspondence between recognized business contacts or personal acquaintances.'
  },
  'Bulk / Graymail': {
    id: 'Bulk / Graymail',
    label: 'Bulk / Graymail',
    family: 'BENIGN',
    priority: 18,
    severity: 'LOW',
    description: 'Mass-distributed marketing or cold outreach mail with non-malicious commercial intent.'
  },
  'Spam': {
    id: 'Spam',
    label: 'Spam',
    family: 'BENIGN',
    priority: 15,
    severity: 'LOW',
    description: 'Unsolicited, unwanted bulk commercial communication without security threat payload.'
  },

  // MALICIOUS / SECURITY (9-30)
  'Malware Delivery': {
    id: 'Malware Delivery',
    label: 'Malware Delivery',
    family: 'SECURITY',
    priority: 100,
    severity: 'CRITICAL',
    description: 'Inbound message containing weaponized executable, macro payload, HTML smuggling, or script attachment.'
  },
  'Credential Theft': {
    id: 'Credential Theft',
    label: 'Credential Theft',
    family: 'SECURITY',
    priority: 95,
    severity: 'CRITICAL',
    description: 'Deceptive communication designed to harvest account login names, passwords, or authentication tokens.'
  },
  'Phishing': {
    id: 'Phishing',
    label: 'Phishing',
    family: 'SECURITY',
    priority: 90,
    severity: 'HIGH',
    description: 'Social engineering attack seeking to trick recipient into disclosing sensitive information or clicking malicious links.'
  },
  'Business Email Compromise': {
    id: 'Business Email Compromise',
    label: 'Business Email Compromise',
    family: 'SECURITY',
    priority: 88,
    severity: 'CRITICAL',
    description: 'Targeted scam impersonating corporate executives, vendors, or legal counsel to execute unauthorized wire transfers.'
  },
  'Financial Fraud': {
    id: 'Financial Fraud',
    label: 'Financial Fraud',
    family: 'SECURITY',
    priority: 85,
    severity: 'HIGH',
    description: 'Deceptive scheme targeting banking credentials, UPI accounts, credit cards, or financial assets.'
  },
  'Executive Impersonation': {
    id: 'Executive Impersonation',
    label: 'Executive Impersonation',
    family: 'SECURITY',
    priority: 84,
    severity: 'HIGH',
    description: 'Header display name or domain spoofing mimicking internal corporate C-level leadership.'
  },
  'Account Takeover': {
    id: 'Account Takeover',
    label: 'Account Takeover',
    family: 'SECURITY',
    priority: 82,
    severity: 'CRITICAL',
    description: 'Unauthorized access vector attempting to compromise SaaS, cloud, or enterprise single sign-on accounts.'
  },
  'Identity / Personal Information Theft': {
    id: 'Identity / Personal Information Theft',
    label: 'Identity / Personal Information Theft',
    family: 'SECURITY',
    priority: 80,
    severity: 'HIGH',
    description: 'Targeted harvesting of Aadhaar, PAN, SSN, passport numbers, or personal PII.'
  },
  'Investment Scam': {
    id: 'Investment Scam',
    label: 'Investment Scam',
    family: 'SECURITY',
    priority: 78,
    severity: 'HIGH',
    description: 'Fraudulent crypto, stock tip, pre-IPO, or high-yield investment scheme.'
  },
  'Payment Fraud': {
    id: 'Payment Fraud',
    label: 'Payment Fraud',
    family: 'SECURITY',
    priority: 76,
    severity: 'HIGH',
    description: 'Manipulated payment links, QR code quishing, or fraudulent payment gateway redirects.'
  },
  'Invoice Fraud': {
    id: 'Invoice Fraud',
    label: 'Invoice Fraud',
    family: 'SECURITY',
    priority: 75,
    severity: 'HIGH',
    description: 'Fake billing invoice or modified vendor banking details sent to accounts payable.'
  },
  'Payroll Fraud': {
    id: 'Payroll Fraud',
    label: 'Payroll Fraud',
    family: 'SECURITY',
    priority: 74,
    severity: 'HIGH',
    description: 'Impersonation of employee requesting direct deposit bank account updates.'
  },
  'Delivery / Courier Scam': {
    id: 'Delivery / Courier Scam',
    label: 'Delivery / Courier Scam',
    family: 'SECURITY',
    priority: 72,
    severity: 'MEDIUM',
    description: 'Fake India Post, FedEx, DHL, or postal parcel delivery fee payment scam.'
  },
  'Government Impersonation': {
    id: 'Government Impersonation',
    label: 'Government Impersonation',
    family: 'SECURITY',
    priority: 70,
    severity: 'HIGH',
    description: 'Fake Income Tax refund, GST penalty, EPFO, SEBI, or RBI regulatory notice.'
  },
  'Technical Support Scam': {
    id: 'Technical Support Scam',
    label: 'Technical Support Scam',
    family: 'SECURITY',
    priority: 68,
    severity: 'MEDIUM',
    description: 'Fake Microsoft, Google, or IT desk alert requesting remote desktop connection.'
  },
  'Job / Recruitment Scam': {
    id: 'Job / Recruitment Scam',
    label: 'Job / Recruitment Scam',
    family: 'SECURITY',
    priority: 66,
    severity: 'MEDIUM',
    description: 'Fraudulent employment offer demanding processing fee, security deposit, or task completion.'
  },
  'Advance Fee Scam': {
    id: 'Advance Fee Scam',
    label: 'Advance Fee Scam',
    family: 'SECURITY',
    priority: 64,
    severity: 'MEDIUM',
    description: 'Lottery, inheritance, or grant prize claim requiring upfront fee payment.'
  },
  'Extortion / Blackmail': {
    id: 'Extortion / Blackmail',
    label: 'Extortion / Blackmail',
    family: 'SECURITY',
    priority: 62,
    severity: 'HIGH',
    description: 'Sextortion, data leak threat, or coercive ransom demand.'
  },
  'OAuth / Authorization Abuse': {
    id: 'OAuth / Authorization Abuse',
    label: 'OAuth / Authorization Abuse',
    family: 'SECURITY',
    priority: 60,
    severity: 'HIGH',
    description: 'Malicious OAuth app consent prompt or token grant request.'
  },
  'Malicious Link Campaign': {
    id: 'Malicious Link Campaign',
    label: 'Malicious Link Campaign',
    family: 'SECURITY',
    priority: 58,
    severity: 'HIGH',
    description: 'Mass email distribution embedding malicious redirect chains or exploits.'
  },
  'Data Theft / Information Harvesting': {
    id: 'Data Theft / Information Harvesting',
    label: 'Data Theft / Information Harvesting',
    family: 'SECURITY',
    priority: 55,
    severity: 'HIGH',
    description: 'Probing message attempting to extract confidential corporate directory data.'
  },
  'Other Malicious': {
    id: 'Other Malicious',
    label: 'Other Malicious',
    family: 'SECURITY',
    priority: 50,
    severity: 'MEDIUM',
    description: 'Unclassified security threat exhibiting confirmed malicious indicators.'
  }
};
