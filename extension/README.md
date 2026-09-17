# MailTrace AI — Direct Email Threat Analyzer (Chrome Extension)

**Manifest V3 Production-Ready Companion Extension for Google Chrome**

The MailTrace AI Chrome Extension extends the **MailTrace AI Forensics & SOC Platform** directly into your webmail client (Gmail and Outlook Web). Analysts and end users can analyze suspicious emails in real-time with a single click, extracting threat indicators, verifying sender authenticity, scanning hyperlinks, detecting lookalike domains, and seamlessly escalating incidents into the MailTrace AI SOC investigation vault.

---

## Features

- **Direct In-Box Extraction:** Extract email sender identity, display names, subject, plain text body, hyperlinks, and attachment headers directly from Gmail or Outlook Web.
- **Provider Abstraction Architecture:** Modular extensible provider interface (`GmailProvider`, `OutlookProvider`) handling SPA dynamic re-renders, pagination, and multi-message threads.
- **In-Page Action Trigger:** Injects a subtle, native-feeling "Analyze with MailTrace AI" button into the Gmail email header toolbar.
- **7-Stage Threat Pipeline Progress:**
  1. Extracting email content
  2. Parsing MIME & headers
  3. Checking sender & lookalike typosquatting
  4. Analyzing embedded links
  5. Running AI forensic models (Gemini & deterministic heuristics)
  6. Correlating threat indicators & IOCs
  7. Generating risk assessment
- **Comprehensive Threat Result Card:**
  - Overall Risk Score (0–100) with color-coded severity (CRITICAL, HIGH, MEDIUM, LOW)
  - Primary Classification (BEC, Credential Harvesting, Financial Coercion, Domain Impersonation)
  - Heuristic risk breakdown meters (Phishing, Impersonation, Domain, URL)
  - Key Suspicious Indicators list with rule evidence
  - Extracted Hyperlinks inspector with safe Copy action (prevents inadvertent execution of malicious URLs)
  - Attachments risk inspection
- **One-Click SOC Escalation:**
  - **Open Full Investigation:** Deep-links directly to the web platform with preloaded analysis (`/?investigation=<id>`).
  - **Create Case:** Auto-files an incident into the SOC Case Vault with cryptographic evidence artifact.
  - **Report Threat:** Alerts the Security Operations Center.
- **Dual Form Factor:**
  - Interactive Action Popup (420px width)
  - Chrome Side Panel (`sidePanel` API) for persistent side-by-side analysis during mail browsing
- **Local Telemetry & Preferences:**
  - Local scan history with instant reload
  - Configurable backend server endpoint with live latency test
  - Desktop notifications for critical threats (&ge; 85 risk score)

---

## Installation Guide (Developer Mode)

1. Download or locate the `mailtrace-ai-extension.zip` package (available directly from the web platform).
2. Unpack the ZIP archive to a folder on your computer (e.g., `~/Downloads/mailtrace-ai-extension`).
3. Open Google Chrome and navigate to:
   ```text
   chrome://extensions
   ```
4. In the top right corner, enable the **Developer mode** toggle.
5. In the top left toolbar, click the **"Load unpacked"** button.
6. Select the extracted `extension` directory.
7. Pin **MailTrace AI** to your Chrome toolbar.
8. Navigate to [Gmail](https://mail.google.com) or [Outlook](https://outlook.live.com), open any email, and click the MailTrace AI icon!

---

## Permissions Transparency

| Permission | Purpose |
| :--- | :--- |
| `activeTab` | Accesses the currently active webmail tab only when the user interacts with the extension. |
| `storage` | Stores user preferences (API endpoint, notifications) and lightweight local scan history in `chrome.storage.local`. |
| `sidePanel` | Enables the side-by-side dockable forensic inspection panel in Chrome. |
| `notifications` | Displays OS desktop alerts when an analyzed email is classified as a CRITICAL threat (&ge; 85/100). |
| `host_permissions` | Allows content scripts to detect messages on `mail.google.com` and `outlook.live.com`, and allows API requests to the MailTrace backend. |

---

## Security & Privacy Architecture

- **No Passwords or Credentials:** The extension never inspects, captures, or transmits passwords, session cookies, or personal mailbox credentials.
- **No Unsolicited Background Harvesting:** Email content is extracted strictly on-demand when the user clicks the analysis action or opens the panel.
- **Client Header Limitation Notice:** Chrome extensions running in standard webmail tabs do not have access to raw SMTP transport hops (such as `Received:` relay headers) unless an EML file is exported. The extension transparently documents this limitation and synthesizes standard RFC 5322 metadata for downstream correlation.
- **Safe Link Handling:** Extracted links are displayed as non-navigable text with one-click copy buttons, preventing analysts from accidentally opening malicious domains.
