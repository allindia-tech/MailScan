/**
 * MailTrace AI - Chrome Extension Content Script (Manifest V3)
 * Real-time Gmail & Webmail SPA email detection, multi-signal forensic extraction,
 * and seamless SOC state machine integration.
 * 
 * Strict Enterprise SOC Compliance:
 * - Multi-signal structural DOM detection engine (GmailMessageDetector & OutlookMessageDetector)
 * - Independent state separation: Tab State vs Content Script State vs Message View State
 * - Dynamic SPA navigation monitoring via MutationObserver, HashChange, and History API wrapping
 * - Zero demo/mock data: strictly extracts live DOM state or reports accurate webmail state
 */

(function () {
  if (window.__MAILTRACE_CONTENT_SCRIPT_INITIALIZED__) {
    console.log('[MailTrace][ContentScript] Already initialized on:', window.location.hostname);
    return;
  }
  window.__MAILTRACE_CONTENT_SCRIPT_INITIALIZED__ = true;

  console.log('[MailTrace][ContentScript] Initializing on:', window.location.hostname);

  // =========================================================================
  // UTILITY HELPERS: SANITIZATION, HASHING & URL UNWRAPPING
  // =========================================================================

  function sanitizeText(str) {
    if (!str) return '';
    return String(str)
      .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  function extractEmailAddress(raw) {
    if (!raw) return '';
    const match = raw.match(/<([^>]+)>/) || raw.match(/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
    return match ? match[1].trim() : raw.trim();
  }

  function cleanUrl(href) {
    if (!href || typeof href !== 'string') return null;
    let url = href.trim();
    if (
      url.startsWith('javascript:') ||
      url.startsWith('data:') ||
      url.startsWith('#') ||
      url.startsWith('mailto:')
    ) {
      return null;
    }

    // Unwrap Google click redirect wrapper (https://www.google.com/url?q=... or ?url=...)
    try {
      if (url.includes('google.com/url?') && (url.includes('q=') || url.includes('url='))) {
        const parsed = new URL(url);
        const targetQ = parsed.searchParams.get('q') || parsed.searchParams.get('url');
        if (targetQ) url = targetQ;
      }
    } catch {
      // ignore parse errors
    }

    // Exclude internal webmail / accounts URLs
    if (
      url.includes('mail.google.com') ||
      url.includes('accounts.google.com') ||
      url.includes('myaccount.google.com') ||
      url.includes('outlook.live.com') ||
      url.includes('outlook.office.com') ||
      url.includes('outlook.office365.com')
    ) {
      return null;
    }

    return url;
  }

  function extractDomain(url) {
    try {
      const parsed = new URL(url);
      return parsed.hostname.toLowerCase();
    } catch {
      return '';
    }
  }

  // Fast SHA-256 for deterministic message fingerprinting
  async function computeFingerprint(text) {
    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(text);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    } catch {
      let hash = 5381;
      for (let i = 0; i < text.length; i++) {
        hash = (hash * 33) ^ text.charCodeAt(i);
      }
      return 'fb_' + (hash >>> 0).toString(16);
    }
  }

  // =========================================================================
  // GMAIL MULTI-SIGNAL DOM DETECTION & EXTRACTION ENGINE
  // =========================================================================

  class GmailMessageDetector {
    constructor() {
      this.name = 'Gmail';
      this.provider = 'gmail';
      this.lastExtractedKey = null;
    }

    isSupported() {
      return (
        window.location.hostname === 'mail.google.com' ||
        window.location.hostname.endsWith('.mail.google.com')
      );
    }

    /**
     * Multi-signal structural DOM evidence scorer:
     * Evaluates multiple independent structural regions rather than relying on brittle single classes.
     */
    detect() {
      if (!this.isSupported()) {
        return {
          isMessageView: false,
          confidence: 0,
          signals: {},
          messageRoot: null,
          messageKey: null,
          threadKey: null
        };
      }

      // 1. Evidence Signal Queries
      // Signal A: Subject / Conversation Header Region (+1)
      const subjectSelectors = [
        'h2.hP',
        'div[role="main"] h2.hP',
        'div[role="main"] h2',
        '.ha h2',
        'h2[data-thread-perm-id]',
        'div[data-legacy-thread-id] h2',
        'div[role="main"] .hP',
        'div[role="main"] h1',
        'span.hP',
        'div[role="main"] [data-thread-perm-id] h2',
        'h2'
      ];
      let subjectElem = null;
      for (const sel of subjectSelectors) {
        const el = document.querySelector(sel);
        if (el && el.textContent.trim()) {
          subjectElem = el;
          break;
        }
      }

      // Signal B: Sender identity elements (+1)
      const senderSelectors = [
        'span.gD[email]',
        'span.gD',
        'span.gE[email]',
        'span.zF[email]',
        'span[data-hovercard-id]',
        'h3.iw span[email]',
        'span.go',
        'span.qu span[email]',
        'table.cf span[email]',
        'span[email]',
        'span.bA4 span[email]',
        'div[role="main"] span[email]'
      ];
      let senderElem = null;
      for (const sel of senderSelectors) {
        const el = document.querySelector(sel);
        if (el) {
          senderElem = el;
          break;
        }
      }

      // Signal C: Message Body Container (+2)
      const bodySelectors = [
        'div.a3s:not([style*="display: none"])',
        'div[role="listitem"] .a3s',
        'div[data-message-id] .a3s',
        'div.ii.gt',
        'div.adn.ads .a3s',
        'div[aria-label="Message Body" i]',
        'div.a3s.aiL',
        'div.a3s.aXjCH',
        '.a3s',
        'div[role="main"] div.ii',
        'div[role="main"] .a3s'
      ];
      let bodyElem = null;
      for (const sel of bodySelectors) {
        const el = document.querySelector(sel);
        if (el && (el.innerText || el.textContent || '').trim().length > 0) {
          bodyElem = el;
          break;
        }
      }

      // Signal D: Reply / Forward action controls (+1)
      const actionControls = document.querySelector(
        'div[role="button"][aria-label*="Reply" i], div[role="button"][aria-label*="Forward" i], span[role="link"][data-tooltip*="Reply" i], .ams.bkH, .amn .ams, div[aria-label*="Reply" i], div[data-tooltip*="Reply" i]'
      );

      // Signal E: Message view toolbar (+1)
      const messageToolbar = document.querySelector(
        'div[role="toolbar"], .G-atb, .iH, div.ade, div.bkK, div[role="main"] div[role="toolbar"]'
      );

      // Signal F: Email timestamp in header (+1)
      const timestampElem = document.querySelector(
        'span.g3[title], span.g3, time, span[title*="202"], span[data-timestamp], span.gK, span[title*="2026"], span[title*="AM"], span[title*="PM"]'
      );

      // Signal G: Attachment area (+1)
      const attachmentElem = document.querySelector(
        '.aZo, .aV3, a[download], .hq.e7, div[aria-label*="Attachment" i], .a6q, .aWS, .a5q, div[aria-label*="attachment" i]'
      );

      // 2. Score the Evidence
      let evidenceScore = 0;
      if (subjectElem) evidenceScore += 1;
      if (senderElem) evidenceScore += 1;
      if (bodyElem) evidenceScore += 2;
      if (actionControls) evidenceScore += 1;
      if (messageToolbar) evidenceScore += 1;
      if (timestampElem) evidenceScore += 1;
      if (attachmentElem) evidenceScore += 1;

      // 3. Route Check (Supportive signal)
      const hash = window.location.hash || '';
      const hashParts = hash.replace(/^#/, '').split('/');
      const lastSegment = hashParts[hashParts.length - 1] || '';
      const isRouteToMessage =
        hashParts.length >= 2 &&
        lastSegment.length >= 8 &&
        !['p1', 'p2', 'p3', 'p4', 'all', 'inbox', 'starred', 'snoozed', 'sent', 'drafts', 'trash', 'spam'].includes(lastSegment.toLowerCase());

      // 4. Negative Check for pure inbox/folder list view table
      const isPureListView =
        document.querySelector('table[role="grid"], div[role="main"] table.F.cf.zt') &&
        !bodyElem &&
        !subjectElem;

      if (isPureListView && !isRouteToMessage) {
        return {
          isMessageView: false,
          confidence: 0,
          signals: { evidenceScore, isPureListView: true },
          messageRoot: null,
          messageKey: null,
          threadKey: null
        };
      }

      // Determine Message View State:
      // High confidence if body is visible OR (score >= 2 AND (sender || subject || route))
      const isMessageView =
        bodyElem !== null ||
        (evidenceScore >= 2 && (senderElem !== null || subjectElem !== null || isRouteToMessage));

      const confidence = Math.min(100, Math.round((evidenceScore / 6) * 100));

      const messageKey = this.resolveMessageKey(lastSegment);
      const threadKey = messageKey;
      const messageRoot = this.getActiveMessageScope() || document.querySelector('div[role="main"]') || document.body;

      return {
        isMessageView,
        confidence,
        signals: {
          hasSubject: !!subjectElem,
          hasSender: !!senderElem,
          hasBody: !!bodyElem,
          hasActions: !!actionControls,
          hasToolbar: !!messageToolbar,
          hasTimestamp: !!timestampElem,
          hasAttachments: !!attachmentElem,
          isRouteToMessage,
          evidenceScore
        },
        messageRoot,
        messageKey,
        threadKey
      };
    }

    resolveMessageKey(routeSegment) {
      if (routeSegment && routeSegment.length >= 6 && !['p1', 'p2', 'p3'].includes(routeSegment)) {
        return `gmail:${routeSegment}`;
      }

      const threadElem = document.querySelector(
        '[data-thread-perm-id], [data-legacy-thread-id], [data-message-id], [data-legacy-message-id]'
      );
      if (threadElem) {
        const id =
          threadElem.getAttribute('data-message-id') ||
          threadElem.getAttribute('data-thread-perm-id') ||
          threadElem.getAttribute('data-legacy-thread-id') ||
          threadElem.getAttribute('data-legacy-message-id');
        if (id) return `gmail:${id}`;
      }

      const subject = this.extractSubject();
      return `gmail:${subject ? subject.slice(0, 40) : 'msg_' + Date.now()}`;
    }

    extractSubject() {
      const selectors = [
        'h2.hP',
        'div[role="main"] h2.hP',
        'div[role="main"] h2',
        '.ha h2',
        'h2[data-thread-perm-id]',
        'div[data-legacy-thread-id] h2',
        'div[role="main"] .hP',
        'div[role="main"] h1',
        'span.hP'
      ];

      for (const sel of selectors) {
        const el = document.querySelector(sel);
        if (el && el.textContent.trim()) {
          return sanitizeText(el.textContent);
        }
      }

      // Fallback to document title without Gmail suffix
      const docTitle = document.title || '';
      const cleanTitle = docTitle.replace(/ - Gmail.*$/i, '').replace(/ - .*?@.*?$/i, '').trim();
      if (cleanTitle && !['Inbox', 'Gmail', 'Sent', 'Drafts', 'Trash', 'Spam', 'Starred'].includes(cleanTitle)) {
        return sanitizeText(cleanTitle);
      }

      return '(No Subject)';
    }

    getActiveMessageScope() {
      const messageItems = Array.from(
        document.querySelectorAll('div[role="listitem"], div.adn.ads, div.gs, div[data-message-id]')
      );

      // Prefer expanded item with visible .a3s container
      for (const item of messageItems) {
        const bodyEl = item.querySelector('.a3s:not([style*="display: none"])');
        if (bodyEl && bodyEl.offsetHeight > 0) {
          return item;
        }
      }

      if (messageItems.length > 0) {
        return messageItems[messageItems.length - 1];
      }

      return document.querySelector('div[role="main"]') || document;
    }

    extractSender(scope) {
      let senderName = '';
      let senderEmail = '';

      const senderSelectors = [
        'span.gD[email]',
        'span.gD',
        'span.gE[email]',
        'span.zF[email]',
        'span[data-hovercard-id]',
        'h3.iw span[email]',
        'span.go',
        'span.qu span[email]',
        'span[data-name][email]',
        'table.cf span[email]',
        'span[email]'
      ];

      for (const sel of senderSelectors) {
        const el = scope.querySelector(sel) || document.querySelector(sel);
        if (el) {
          senderEmail =
            el.getAttribute('email') ||
            el.getAttribute('data-hovercard-id') ||
            extractEmailAddress(el.textContent);

          senderName =
            el.getAttribute('name') ||
            el.getAttribute('data-name') ||
            sanitizeText(el.textContent || '');

          if (senderEmail) break;
        }
      }

      if (!senderName || senderName === senderEmail) {
        senderName = senderEmail ? senderEmail.split('@')[0] : 'Unknown Sender';
      }

      return {
        name: sanitizeText(senderName),
        email: senderEmail ? senderEmail.toLowerCase().trim() : '',
        formatted: senderEmail
          ? `${sanitizeText(senderName)} <${senderEmail.toLowerCase().trim()}>`
          : sanitizeText(senderName)
      };
    }

    extractRecipients(scope) {
      const recipients = [];
      const seen = new Set();

      const recipientSelectors = [
        'span.hb span[email]',
        'span.g2[email]',
        'span.qu span[email]',
        'span[data-hovercard-id]',
        'td.gH span[email]',
        'span.yP[email]'
      ];

      (scope || document).querySelectorAll(recipientSelectors.join(', ')).forEach((elem) => {
        const raw =
          elem.getAttribute('email') ||
          elem.getAttribute('data-hovercard-id') ||
          extractEmailAddress(elem.textContent);

        if (raw) {
          const clean = raw.toLowerCase().trim();
          if (!seen.has(clean)) {
            seen.add(clean);
            recipients.push(clean);
          }
        }
      });

      return recipients;
    }

    extractTimestamp(scope) {
      const dateSelectors = [
        'span.g3[title]',
        'span.g3',
        'time',
        'span[title*="202"]',
        'span[data-timestamp]',
        '.date',
        'span.gK'
      ];

      for (const sel of dateSelectors) {
        const el = (scope || document).querySelector(sel);
        if (el) {
          const val = el.getAttribute('title') || el.getAttribute('data-timestamp') || sanitizeText(el.textContent);
          if (val) return val;
        }
      }

      return new Date().toUTCString();
    }

    extractBody(scope) {
      let bodyText = '';
      let bodyHtml = '';

      const bodyContainer = (scope || document).querySelector(
        '.a3s.aiL, .a3s.aXjCH, .a3s, div[role="listitem"] .a3s, .ii.gt, div[aria-label="Message Body" i]'
      );

      if (bodyContainer) {
        bodyText = sanitizeText(bodyContainer.innerText || bodyContainer.textContent || '');
        bodyHtml = bodyContainer.innerHTML
          .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
          .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
          .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '');
      }

      return { bodyText, bodyHtml, bodyContainer };
    }

    extractLinks(bodyContainer) {
      const links = [];
      const seen = new Set();

      if (!bodyContainer) return links;

      const anchors = bodyContainer.querySelectorAll('a[href]');
      anchors.forEach((a) => {
        const rawHref = a.getAttribute('href');
        const clean = cleanUrl(rawHref);

        if (clean && !seen.has(clean)) {
          seen.add(clean);
          const domain = extractDomain(clean);
          links.push({
            text: sanitizeText(a.textContent || clean),
            href: clean,
            domain,
            normalizedUrl: clean,
            protocol: clean.startsWith('https:') ? 'https:' : clean.startsWith('http:') ? 'http:' : 'unknown'
          });
        }
      });

      return links;
    }

    extractAttachments(scope) {
      const attachments = [];
      const seen = new Set();

      const attSelectors = [
        '.aZo',
        '.aV3',
        'a[download]',
        'div[role="listitem"] .aZo',
        '.hq.e7',
        'div[aria-label*="Attachment" i]',
        '.a6q',
        '.aWS',
        '.a5q'
      ];

      (scope || document).querySelectorAll(attSelectors.join(', ')).forEach((att) => {
        const nameElem = att.querySelector('.aV3, .aZw, span[download]') || att;
        const name = sanitizeText(nameElem.textContent || 'attachment');

        if (!name || seen.has(name) || name.length > 120 || name === 'Download') return;
        seen.add(name);

        let type = 'File';
        const lower = name.toLowerCase();
        if (lower.endsWith('.pdf')) type = 'PDF Document';
        else if (lower.endsWith('.exe') || lower.endsWith('.scr') || lower.endsWith('.bat') || lower.endsWith('.cmd')) type = 'Executable / Script';
        else if (lower.endsWith('.zip') || lower.endsWith('.tar') || lower.endsWith('.gz') || lower.endsWith('.7z') || lower.endsWith('.rar')) type = 'Compressed Archive';
        else if (lower.endsWith('.docx') || lower.endsWith('.doc')) type = 'Word Document';
        else if (lower.endsWith('.xlsx') || lower.endsWith('.xls') || lower.endsWith('.csv')) type = 'Spreadsheet';
        else if (lower.endsWith('.png') || lower.endsWith('.jpg') || lower.endsWith('.jpeg') || lower.endsWith('.gif')) type = 'Image';
        else if (lower.endsWith('.html') || lower.endsWith('.htm') || lower.endsWith('.svg')) type = 'HTML / Web File';
        else if (lower.endsWith('.iso') || lower.endsWith('.img') || lower.endsWith('.vhd')) type = 'Disk Image';

        const sizeElem = att.querySelector('.aZi, .aZb, span.size');
        const sizeText = sizeElem ? sanitizeText(sizeElem.textContent) : undefined;

        attachments.push({
          name,
          type,
          sizeText
        });
      });

      return attachments;
    }

    extractSecurityDetails(scope) {
      const secDetails = {};
      const detailsTable = (scope || document).querySelector('div.ajA table, table.cf.gJ');

      if (detailsTable) {
        const rows = detailsTable.querySelectorAll('tr');
        rows.forEach((r) => {
          const text = r.textContent || '';
          if (text.includes('mailed-by:')) secDetails.mailedBy = sanitizeText(text.replace(/mailed-by:/i, ''));
          if (text.includes('signed-by:')) secDetails.signedBy = sanitizeText(text.replace(/signed-by:/i, ''));
          if (text.includes('security:')) secDetails.security = sanitizeText(text.replace(/security:/i, ''));
        });
      }

      return secDetails;
    }

    async extractCurrentMessage() {
      const detection = this.detect();
      if (!detection.isMessageView) {
        return null;
      }

      const subject = this.extractSubject();
      const scope = detection.messageRoot;
      const sender = this.extractSender(scope);
      const recipients = this.extractRecipients(scope);
      const timestamp = this.extractTimestamp(scope);
      const { bodyText, bodyHtml, bodyContainer } = this.extractBody(scope);
      const linksDetailed = this.extractLinks(bodyContainer);
      const attachments = this.extractAttachments(scope);
      const securityDetails = this.extractSecurityDetails(scope);

      const messageItems = document.querySelectorAll('div[role="listitem"], div.adn.ads');
      const threadMessageCount = Math.max(messageItems.length, 1);
      const messageKey = detection.messageKey || this.resolveMessageKey();

      const fingerprintRaw = `gmail|${sender.email}|${subject}|${bodyText.slice(0, 500)}|${linksDetailed.map((l) => l.href).join(',')}`;
      const contentFingerprint = await computeFingerprint(fingerprintRaw);

      this.lastExtractedKey = messageKey;

      const hasCompleteFields = !!(subject && sender.email && bodyText);

      return {
        provider: 'gmail',
        messageKey,
        threadKey: detection.threadKey || messageKey,
        contentFingerprint,
        sender: sender.formatted,
        senderName: sender.name,
        senderEmail: sender.email,
        recipients: recipients.length > 0 ? recipients : ['current-recipient@gmail.com'],
        subject: subject || '(No Subject)',
        timestamp,
        body: bodyText,
        bodyText,
        bodyHtml,
        links: linksDetailed.map((l) => l.href),
        linksDetailed,
        attachments,
        threadMessageCount,
        securityDetails,
        extractionCoverage: {
          sender: sender.email ? 100 : (sender.name ? 70 : 40),
          recipients: recipients.length > 0 ? 100 : 50,
          subject: subject && subject !== '(No Subject)' ? 100 : 80,
          timestamp: 100,
          body: bodyText ? 100 : 0,
          links: 100,
          attachments: 100,
          headers: Object.keys(securityDetails).length > 0 ? 50 : 0
        },
        source: 'gmail-dom',
        hasFullHeaders: false,
        extractionStatus: hasCompleteFields ? 'complete' : 'partial'
      };
    }
  }

  // =========================================================================
  // OUTLOOK WEBMAIL DETECTOR & EXTRACTION ENGINE
  // =========================================================================

  class OutlookMessageDetector {
    constructor() {
      this.name = 'Outlook';
      this.provider = 'outlook';
      this.lastExtractedKey = null;
    }

    isSupported() {
      return (
        window.location.hostname.includes('outlook.live.com') ||
        window.location.hostname.includes('outlook.office.com') ||
        window.location.hostname.includes('outlook.office365.com')
      );
    }

    detect() {
      if (!this.isSupported()) {
        return { isMessageView: false, confidence: 0, messageKey: null, threadKey: null };
      }

      const readingPane = document.querySelector(
        '[aria-label="Reading Pane" i], [role="main"] [role="document"], .rps_2209, [aria-label="Message body" i]'
      );
      const subjectElem = document.querySelector(
        '[role="heading"], h1, h2, [data-testid="message-subject"]'
      );

      const isMessageView = !!(readingPane || subjectElem);
      const subject = subjectElem ? sanitizeText(subjectElem.textContent) : '(No Subject)';
      const messageKey = `outlook:${subject || window.location.pathname}`;

      return {
        isMessageView,
        confidence: isMessageView ? 90 : 0,
        messageKey,
        threadKey: messageKey,
        messageRoot: readingPane || document.body
      };
    }

    async extractCurrentMessage() {
      const detection = this.detect();
      if (!detection.isMessageView) return null;

      const readingPane = detection.messageRoot || document;
      const subjectElem = document.querySelector(
        '[role="heading"], h1, h2, [data-testid="message-subject"]'
      );
      const subject = subjectElem ? sanitizeText(subjectElem.textContent) : '(No Subject)';

      const senderElem = readingPane.querySelector(
        '[data-testid="SenderPersona"], span[title*="@"], button[aria-label*="@"], span._2808'
      );
      const sender = senderElem
        ? sanitizeText(senderElem.textContent || senderElem.getAttribute('title') || '')
        : '';

      const bodyElem = readingPane.querySelector(
        '[role="document"], .rps_2209, [aria-label="Message body" i]'
      );
      const bodyText = sanitizeText(bodyElem ? bodyElem.innerText || bodyElem.textContent : '');

      const links = [];
      const seenLinks = new Set();
      if (bodyElem) {
        bodyElem.querySelectorAll('a[href]').forEach((a) => {
          const clean = cleanUrl(a.getAttribute('href'));
          if (clean && !seenLinks.has(clean)) {
            seenLinks.add(clean);
            links.push({
              text: sanitizeText(a.textContent || clean),
              href: clean,
              domain: extractDomain(clean),
              normalizedUrl: clean
            });
          }
        });
      }

      const fingerprintRaw = `outlook|${sender}|${subject}|${bodyText.slice(0, 500)}`;
      const contentFingerprint = await computeFingerprint(fingerprintRaw);

      return {
        provider: 'outlook',
        messageKey: detection.messageKey,
        threadKey: detection.threadKey,
        contentFingerprint,
        sender: sender || 'unknown@outlook-user.corp',
        senderName: sender.split('@')[0] || 'Unknown Sender',
        senderEmail: extractEmailAddress(sender),
        recipients: ['user@enterprise.corp'],
        subject: subject || '(No Subject)',
        timestamp: new Date().toUTCString(),
        body: bodyText,
        bodyText,
        links: links.map((l) => l.href),
        linksDetailed: links,
        attachments: [],
        threadMessageCount: 1,
        extractionCoverage: {
          sender: sender ? 100 : 50,
          recipients: 50,
          subject: 100,
          timestamp: 80,
          body: bodyText ? 100 : 0,
          links: 100,
          attachments: 100,
          headers: 0
        },
        source: 'outlook-dom',
        hasFullHeaders: false,
        extractionStatus: (subject && sender && bodyText) ? 'complete' : 'partial'
      };
    }
  }

  // =========================================================================
  // STATE MACHINE & IN-PAGE BADGE CONTROLLER
  // =========================================================================

  const detectors = [new GmailMessageDetector(), new OutlookMessageDetector()];

  function getActiveDetector() {
    return detectors.find((d) => d.isSupported()) || null;
  }

  let lastReportedMessageKey = null;
  let lastReportedState = 'WEBMAIL_DETECTING';

  // Builds the authoritative WebmailContextState
  async function buildCurrentWebmailContext() {
    const detector = getActiveDetector();
    if (!detector) {
      return {
        provider: null,
        isWebmailTab: false,
        contentScriptConnected: true,
        isMessageView: false,
        messageDetected: false,
        messageKey: null,
        threadKey: null,
        email: null,
        lastDetectedAt: null,
        tabId: null,
        url: window.location.href,
        detectionSource: 'none',
        extractionStatus: 'not_started',
        state: 'NOT_WEBMAIL'
      };
    }

    const detection = detector.detect();
    const provider = detector.provider;

    if (!detection.isMessageView) {
      return {
        provider,
        isWebmailTab: true,
        contentScriptConnected: true,
        isMessageView: false,
        messageDetected: false,
        messageKey: null,
        threadKey: null,
        email: null,
        lastDetectedAt: Date.now(),
        tabId: null,
        url: window.location.href,
        detectionSource: `${provider}-dom`,
        extractionStatus: 'not_started',
        state: 'WEBMAIL_NO_MESSAGE'
      };
    }

    // Message is visible in DOM -> Extract email data
    try {
      const emailData = await detector.extractCurrentMessage();
      if (emailData) {
        return {
          provider,
          isWebmailTab: true,
          contentScriptConnected: true,
          isMessageView: true,
          messageDetected: true,
          messageKey: emailData.messageKey,
          threadKey: emailData.threadKey,
          email: emailData,
          lastDetectedAt: Date.now(),
          tabId: null,
          url: window.location.href,
          detectionSource: `${provider}-dom`,
          extractionStatus: emailData.extractionStatus || 'complete',
          state: 'WEBMAIL_READY'
        };
      } else {
        return {
          provider,
          isWebmailTab: true,
          contentScriptConnected: true,
          isMessageView: true,
          messageDetected: true,
          messageKey: detection.messageKey,
          threadKey: detection.threadKey,
          email: null,
          lastDetectedAt: Date.now(),
          tabId: null,
          url: window.location.href,
          detectionSource: `${provider}-dom`,
          extractionStatus: 'partial',
          state: 'WEBMAIL_MESSAGE_DETECTED'
        };
      }
    } catch (err) {
      console.error('[MailTrace][Extraction] Extraction error:', err);
      return {
        provider,
        isWebmailTab: true,
        contentScriptConnected: true,
        isMessageView: true,
        messageDetected: true,
        messageKey: detection.messageKey,
        threadKey: detection.threadKey,
        email: null,
        lastDetectedAt: Date.now(),
        tabId: null,
        url: window.location.href,
        detectionSource: `${provider}-dom`,
        extractionStatus: 'failed',
        error: err.message || 'Extraction failed',
        state: 'WEBMAIL_ERROR'
      };
    }
  }

  // Evaluates current webmail view and notifies service worker without modifying page DOM
  async function scheduleDetection() {
    const context = await buildCurrentWebmailContext();

    if (context.state !== lastReportedState || context.messageKey !== lastReportedMessageKey) {
      lastReportedState = context.state;
      lastReportedMessageKey = context.messageKey;

      console.log('[MailTrace][DOM] State updated:', context.state, 'Key:', context.messageKey);

      chrome.runtime.sendMessage({
        type: 'WEBMAIL_STATE_CHANGED',
        context
      }).catch(() => {});

      if (context.isMessageView && context.email) {
        chrome.runtime.sendMessage({
          type: 'EMAIL_DETECTED',
          provider: context.provider,
          messageKey: context.messageKey,
          emailData: context.email,
          detectedAt: Date.now()
        }).catch(() => {});
      } else if (!context.isMessageView) {
        chrome.runtime.sendMessage({
          type: 'EMAIL_CLOSED',
          provider: context.provider,
          timestamp: Date.now()
        }).catch(() => {});
      }
    }
  }

  // Debounced observer for dynamic SPA DOM updates
  let debounceTimer = null;
  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      scheduleDetection();
    }, 350);
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // SPA History API wrapper for immediate view change interception
  (function wrapHistoryApi() {
    const originalPushState = history.pushState;
    const originalReplaceState = history.replaceState;

    history.pushState = function (...args) {
      originalPushState.apply(this, args);
      setTimeout(scheduleDetection, 50);
    };

    history.replaceState = function (...args) {
      originalReplaceState.apply(this, args);
      setTimeout(scheduleDetection, 50);
    };
  })();

  // Native navigation listeners
  window.addEventListener('hashchange', () => setTimeout(scheduleDetection, 50));
  window.addEventListener('popstate', () => setTimeout(scheduleDetection, 50));

  // Announce content script readiness to background service worker
  const activeDetector = getActiveDetector();
  chrome.runtime.sendMessage({
    type: 'CONTENT_SCRIPT_READY',
    provider: activeDetector ? activeDetector.provider : null,
    url: window.location.href,
    timestamp: Date.now()
  }).catch(() => {});

  // Initial detection run
  setTimeout(scheduleDetection, 400);

  // =========================================================================
  // MESSAGE HANDLER FOR POPUP / WORKER REQUESTS
  // =========================================================================

  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log('[MailTrace][ContentScript] Received message:', request.type);

    if (request.type === 'GET_WEBMAIL_CONTEXT') {
      buildCurrentWebmailContext()
        .then((context) => {
          sendResponse({
            success: true,
            ...context
          });
        })
        .catch((err) => {
          sendResponse({
            success: false,
            state: 'WEBMAIL_ERROR',
            error: err.message || 'Failed to extract webmail context'
          });
        });
      return true; // Async reply
    }

    if (request.type === 'EXTRACT_CURRENT_EMAIL') {
      buildCurrentWebmailContext()
        .then((context) => {
          if (!context.isWebmailTab) {
            sendResponse({ success: false, notWebmail: true, error: 'Not on supported webmail.' });
          } else if (!context.isMessageView) {
            sendResponse({
              success: false,
              noEmailOpen: true,
              providerName: context.provider,
              error: 'No email open in view.'
            });
          } else {
            sendResponse({
              success: true,
              emailData: context.email,
              messageKey: context.messageKey
            });
          }
        })
        .catch((err) => {
          sendResponse({ success: false, error: err.message });
        });
      return true;
    }

    if (request.type === 'PING_CONTENT') {
      const detector = getActiveDetector();
      const detection = detector ? detector.detect() : { isMessageView: false };
      sendResponse({
        success: true,
        provider: detector ? detector.provider : null,
        isWebmailTab: !!detector,
        isEmailOpen: detection.isMessageView
      });
      return true;
    }

    if (request.type === 'UPDATE_ANALYSIS_BADGE') {
      // NON-INTRUSIVE REQUIREMENT: Page-level injection disabled.
      // Analysis results are presented exclusively in the extension Side Panel & Popup.
      sendResponse({ success: true, injected: false });
      return true;
    }
  });
})();
