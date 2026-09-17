/**
 * MailTrace AI - Chrome Extension Background Service Worker (Manifest V3)
 * Central routing, per-tab session isolation, content-script recovery,
 * authoritative WebmailContextState management, and EvidenceFusionEngine integration.
 */

const DEFAULT_SETTINGS = {
  apiBaseUrl: 'http://localhost:3000',
  autoAnalyze: false,
  saveHistory: true,
  enableNotifications: true,
  maxHistoryItems: 50
};

// Isolated per-tab WebmailContextState store: tabId -> WebmailContextState
const tabContexts = new Map();

// Analysis cache: fingerprint -> { analysis, analysisId, deepLinkPath, cachedAt }
const analysisCache = new Map();

// ==========================================
// DEVICE IDENTITY & SHARED STATE (PART A)
// ==========================================

async function getOrCreateDeviceId() {
  const data = await chrome.storage.local.get('deviceId');
  if (data.deviceId && typeof data.deviceId === 'string') {
    return data.deviceId;
  }

  // Generate cryptographically random 24-char hex device ID
  const randomBytes = new Uint8Array(16);
  crypto.getRandomValues(randomBytes);
  const randomHex = Array.from(randomBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  const deviceId = `mt_dev_${randomHex}`;

  await chrome.storage.local.set({ deviceId });
  console.log('[MailTrace][Identity] Generated persistent device ID:', deviceId);
  return deviceId;
}

async function registerDeviceWithBackend(deviceId) {
  try {
    const apiBase = await getApiBaseUrl();
    const resolvedId = deviceId || (await getOrCreateDeviceId());
    const res = await fetch(`${apiBase}/api/device/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        deviceId: resolvedId,
        clientType: 'extension',
        browser: 'Chrome / Chromium (Manifest V3)',
        os: navigator?.platform || 'Unknown OS',
        userAgent: navigator?.userAgent,
        extensionVersion: chrome.runtime.getManifest()?.version || '2.4.0'
      })
    });
    if (res.ok) {
      console.log('[MailTrace][Identity] Device registered with backend:', resolvedId);
    }
  } catch (err) {
    console.warn('[MailTrace][Identity] Device registration offline retry pending:', err.message);
  }
}

// ==========================================
// LIFECYCLE & INSTALLATION
// ==========================================

chrome.runtime.onInstalled.addListener(async (details) => {
  console.log('[MailTrace][ServiceWorker] Extension installed/updated:', details.reason);

  const existing = await chrome.storage.local.get('settings');
  if (!existing.settings) {
    await chrome.storage.local.set({
      settings: DEFAULT_SETTINGS,
      scanHistory: []
    });
  }

  // Initialize and register Device Identity
  const deviceId = await getOrCreateDeviceId();
  await registerDeviceWithBackend(deviceId);

  // Configure Side Panel if API is available
  if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
    try {
      await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
      console.log('[MailTrace][ServiceWorker] Side panel behavior set to openPanelOnActionClick: true');
    } catch (e) {
      console.error('[MailTrace][ServiceWorker] Failed to configure Side Panel behavior:', e);
    }
  }

  // Create context menu for quick email analysis
  if (chrome.contextMenus) {
    chrome.contextMenus.removeAll(() => {
      chrome.contextMenus.create({
        id: 'mailtrace-analyze-selection',
        title: 'Analyze Email with MailTrace AI',
        contexts: ['page', 'selection'],
        documentUrlPatterns: [
          'https://mail.google.com/*',
          'https://outlook.live.com/*',
          'https://outlook.office.com/*',
          'https://outlook.office365.com/*'
        ]
      });
    });
  }
});

// Clean up tab state on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  console.log('[MailTrace][Tab] Tab closed:', tabId);
  tabContexts.delete(tabId);
});

// Handle Context Menu Click
if (chrome.contextMenus && chrome.contextMenus.onClicked) {
  chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === 'mailtrace-analyze-selection' && tab?.id) {
      try {
        if (chrome.sidePanel && chrome.sidePanel.open) {
          await chrome.sidePanel.open({ tabId: tab.id });
        } else {
          chrome.tabs.sendMessage(tab.id, { type: 'GET_WEBMAIL_CONTEXT' });
        }
      } catch (err) {
        console.error('[MailTrace][ServiceWorker] Context menu action failed:', err);
      }
    }
  });
}

// ==========================================
// TAB URL & WEBMAIL RECOGNITION HELPERS
// ==========================================

function isGmailUrl(url = '') {
  return url.startsWith('https://mail.google.com/');
}

function isOutlookUrl(url = '') {
  return (
    url.startsWith('https://outlook.live.com/') ||
    url.startsWith('https://outlook.office.com/') ||
    url.startsWith('https://outlook.office365.com/')
  );
}

function isSupportedWebmailUrl(url = '') {
  return isGmailUrl(url) || isOutlookUrl(url);
}

function getProviderFromUrl(url = '') {
  if (isGmailUrl(url)) return 'gmail';
  if (isOutlookUrl(url)) return 'outlook';
  return null;
}

// ==========================================
// CONTENT SCRIPT RECOVERY
// ==========================================

async function recoverContentScript(tabId, url) {
  if (!isSupportedWebmailUrl(url)) return false;

  console.log(`[MailTrace][ContentScript] Attempting recovery injection on tab ${tabId} (${url})`);
  try {
    if (chrome.scripting) {
      await chrome.scripting.executeScript({
        target: { tabId },
        files: ['content/content.js']
      });
      await chrome.scripting.insertCSS({
        target: { tabId },
        files: ['content/content.css']
      }).catch(() => {});
      console.log(`[MailTrace][ContentScript] Recovery injection succeeded on tab ${tabId}`);
      return true;
    }
  } catch (err) {
    console.error(`[MailTrace][ContentScript] Recovery injection failed on tab ${tabId}:`, err);
  }
  return false;
}

// ==========================================
// CORE WEBMAIL CONTEXT RESOLUTION
// ==========================================

async function resolveActiveWebmailContext() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const activeTab = tabs[0];

  if (!activeTab || !activeTab.id) {
    return {
      success: false,
      state: 'NOT_WEBMAIL',
      provider: null,
      isWebmailTab: false,
      contentScriptConnected: false,
      isMessageView: false,
      messageDetected: false,
      messageKey: null,
      threadKey: null,
      email: null,
      lastDetectedAt: null,
      tabId: null,
      url: null,
      detectionSource: 'none',
      extractionStatus: 'not_started',
      error: 'No active browser tab found.'
    };
  }

  const url = activeTab.url || '';
  const isWebmail = isSupportedWebmailUrl(url);
  const provider = getProviderFromUrl(url);

  console.log(`[MailTrace][Tab] Active tab ${activeTab.id} url: ${url} (isWebmail: ${isWebmail})`);

  if (!isWebmail) {
    return {
      success: false,
      state: 'NOT_WEBMAIL',
      provider: null,
      isWebmailTab: false,
      contentScriptConnected: false,
      isMessageView: false,
      messageDetected: false,
      messageKey: null,
      threadKey: null,
      email: null,
      lastDetectedAt: null,
      tabId: activeTab.id,
      url,
      detectionSource: 'none',
      extractionStatus: 'not_started',
      error: 'Active tab is not a supported webmail interface (Gmail or Outlook).'
    };
  }

  // Active tab IS Webmail: Query live state from content script
  try {
    const response = await chrome.tabs.sendMessage(activeTab.id, { type: 'GET_WEBMAIL_CONTEXT' });
    if (response && response.success) {
      const stateObj = {
        ...response,
        tabId: activeTab.id,
        url,
        provider: response.provider || provider,
        isWebmailTab: true,
        contentScriptConnected: true
      };

      tabContexts.set(activeTab.id, stateObj);
      return stateObj;
    }
  } catch (err) {
    console.warn(`[MailTrace][ContentScript] Direct communication failed with tab ${activeTab.id}:`, err.message);

    // Attempt recovery once
    const recovered = await recoverContentScript(activeTab.id, url);
    if (recovered) {
      try {
        // Wait 150ms for initialization
        await new Promise((r) => setTimeout(r, 150));
        const retryResponse = await chrome.tabs.sendMessage(activeTab.id, { type: 'GET_WEBMAIL_CONTEXT' });
        if (retryResponse && retryResponse.success) {
          const stateObj = {
            ...retryResponse,
            tabId: activeTab.id,
            url,
            provider: retryResponse.provider || provider,
            isWebmailTab: true,
            contentScriptConnected: true
          };
          tabContexts.set(activeTab.id, stateObj);
          return stateObj;
        }
      } catch (retryErr) {
        console.error(`[MailTrace][ContentScript] Post-recovery retry failed:`, retryErr);
      }
    }

    // Return WEBMAIL_ERROR (NOT Not on Webmail)
    return {
      success: false,
      state: 'WEBMAIL_ERROR',
      provider,
      isWebmailTab: true,
      contentScriptConnected: false,
      isMessageView: false,
      messageDetected: false,
      messageKey: null,
      threadKey: null,
      email: null,
      lastDetectedAt: Date.now(),
      tabId: activeTab.id,
      url,
      detectionSource: `${provider}-route`,
      extractionStatus: 'failed',
      error: 'MailTrace could not connect to webmail content script. Please refresh the page.'
    };
  }

  // Fallback if response was empty but no exception
  return {
    success: false,
    state: 'WEBMAIL_DETECTING',
    provider,
    isWebmailTab: true,
    contentScriptConnected: true,
    isMessageView: false,
    messageDetected: false,
    messageKey: null,
    threadKey: null,
    email: null,
    lastDetectedAt: Date.now(),
    tabId: activeTab.id,
    url,
    detectionSource: `${provider}-route`,
    extractionStatus: 'not_started'
  };
}

// ==========================================
// CENTRAL INTERNAL MESSAGE DISPATCHER
// ==========================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const tabId = sender.tab?.id;
  handleInternalMessage(message, sender, tabId)
    .then(sendResponse)
    .catch((err) => {
      console.error('[MailTrace][ServiceWorker] Internal message error:', err);
      sendResponse({ success: false, error: err.message || 'Worker processing error' });
    });
  return true; // Async reply
});

async function getApiBaseUrl() {
  const { settings } = await chrome.storage.local.get('settings');
  return (settings?.apiBaseUrl || DEFAULT_SETTINGS.apiBaseUrl).replace(/\/$/, '');
}

async function handleInternalMessage(message, sender, senderTabId) {
  const { type, payload } = message;

  switch (type) {
    case 'PING_WORKER':
      return { success: true, timestamp: Date.now(), version: '2.4.0' };

    case 'CONTENT_SCRIPT_READY': {
      const tabId = senderTabId || message.tabId;
      if (tabId) {
        console.log(`[MailTrace][ContentScript] Announced ready on tab ${tabId} (${message.url})`);
        const existing = tabContexts.get(tabId) || {};
        tabContexts.set(tabId, {
          ...existing,
          provider: message.provider || 'gmail',
          isWebmailTab: true,
          contentScriptConnected: true,
          url: message.url,
          lastDetectedAt: Date.now()
        });
      }
      return { success: true };
    }

    case 'WEBMAIL_STATE_CHANGED': {
      const tabId = senderTabId || message.tabId;
      if (tabId && message.context) {
        tabContexts.set(tabId, {
          ...message.context,
          tabId
        });
      }
      return { success: true };
    }

    case 'EMAIL_DETECTED': {
      const tabId = senderTabId || message.tabId;
      if (tabId && message.emailData) {
        const existing = tabContexts.get(tabId) || {};
        tabContexts.set(tabId, {
          ...existing,
          provider: message.provider || 'gmail',
          isWebmailTab: true,
          contentScriptConnected: true,
          isMessageView: true,
          messageDetected: true,
          messageKey: message.messageKey,
          threadKey: message.emailData.threadKey || message.messageKey,
          email: message.emailData,
          extractionStatus: message.emailData.extractionStatus || 'complete',
          state: 'WEBMAIL_READY',
          lastDetectedAt: Date.now()
        });

        // Check if auto-analysis is enabled
        const { settings } = await chrome.storage.local.get('settings');
        if (settings?.autoAnalyze) {
          executeEmailAnalysis(message.emailData, tabId).catch(() => {});
        }
      }
      return { success: true };
    }

    case 'EMAIL_CLOSED': {
      const tabId = senderTabId || message.tabId;
      if (tabId) {
        const existing = tabContexts.get(tabId) || {};
        tabContexts.set(tabId, {
          ...existing,
          isMessageView: false,
          messageDetected: false,
          messageKey: null,
          threadKey: null,
          email: null,
          state: 'WEBMAIL_NO_MESSAGE',
          lastDetectedAt: Date.now()
        });
      }
      return { success: true };
    }

    case 'GET_CURRENT_WEBMAIL_CONTEXT': {
      const context = await resolveActiveWebmailContext();
      return context;
    }

    case 'GET_ACTIVE_EMAIL_DATA': {
      const context = await resolveActiveWebmailContext();
      if (!context.isWebmailTab) {
        return {
          success: false,
          notWebmail: true,
          state: 'NOT_WEBMAIL',
          error: context.error || 'Active tab is not a supported webmail interface.'
        };
      }

      if (!context.isMessageView || !context.email) {
        return {
          success: false,
          noEmailOpen: true,
          state: context.state,
          providerName: context.provider,
          error: 'No email currently open in view.'
        };
      }

      // Check if this email already has a cached analysis
      const fingerprint = context.email.contentFingerprint || context.messageKey;
      const cached = fingerprint ? analysisCache.get(fingerprint) : null;

      return {
        success: true,
        state: 'WEBMAIL_READY',
        emailData: context.email,
        cachedAnalysis: cached?.analysis || null,
        messageKey: context.messageKey,
        threadKey: context.threadKey
      };
    }

    case 'ANALYZE_EMAIL': {
      const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
      const targetTabId = activeTab?.id || senderTabId;
      return await executeEmailAnalysis(payload?.emailData, targetTabId, payload?.rawEmail);
    }

    case 'TEST_BACKEND_CONNECTION': {
      const apiBase = (payload?.url || await getApiBaseUrl()).replace(/\/$/, '');
      const startTime = Date.now();
      const endpoints = ['/api/health', '/health', '/api/extension/ping'];
      let lastErr = null;

      for (const ep of endpoints) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 4000);
          const res = await fetch(`${apiBase}${ep}`, { method: 'GET', signal: controller.signal });
          clearTimeout(timeoutId);

          const latencyMs = Date.now() - startTime;
          if (res.ok) {
            const data = await res.json().catch(() => ({ status: 'ok' }));
            return { success: true, latencyMs, data, resolvedUrl: apiBase };
          }
        } catch (err) {
          lastErr = err;
        }
      }

      return {
        success: false,
        latencyMs: Date.now() - startTime,
        error: lastErr?.name === 'AbortError' ? 'Connection timed out (4000ms exceeded)' : (lastErr?.message || 'Server unreachable')
      };
    }

    case 'CREATE_CASE': {
      const apiBase = await getApiBaseUrl();
      const response = await fetch(`${apiBase}/api/cases`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...payload,
          analyst: 'MailTrace Chrome Extension'
        })
      });

      if (!response.ok) {
        throw new Error(`Failed to create case: HTTP ${response.status}`);
      }

      const caseData = await response.json();
      return { success: true, caseData };
    }

    case 'REPORT_EMAIL': {
      const apiBase = await getApiBaseUrl();
      const response = await fetch(`${apiBase}/api/extension/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        throw new Error(`Failed to report email: HTTP ${response.status}`);
      }

      const reportData = await response.json();
      return { success: true, reportData };
    }

    case 'OPEN_FULL_INVESTIGATION': {
      const apiBase = await getApiBaseUrl();
      const path = payload.deepLinkPath || `/?investigation=${payload.analysisId}`;
      const fullUrl = `${apiBase}${path.startsWith('/') ? path : `/${path}`}`;
      await chrome.tabs.create({ url: fullUrl });
      return { success: true };
    }

    case 'GET_DEVICE_IDENTITY': {
      const deviceId = await getOrCreateDeviceId();
      return { success: true, deviceId, clientType: 'extension' };
    }

    case 'OPEN_SIDE_PANEL': {
      return await openMailTraceSidePanel(sender);
    }

    default:
      return { success: false, error: `Unrecognized internal message type: ${type}` };
  }
}

async function openMailTraceSidePanel(sender) {
  if (!chrome.sidePanel) {
    console.error('[MailTrace][SidePanel][ERROR] Chrome Side Panel API is unavailable.');
    return { success: false, error: 'Chrome Side Panel API is unavailable in this browser.' };
  }

  let tabId = sender?.tab?.id;
  if (!tabId) {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    tabId = tabs?.[0]?.id;
  }

  if (!tabId) {
    console.error('[MailTrace][SidePanel][ERROR] Unable to determine active tab.');
    return { success: false, error: 'Unable to determine the active browser tab.' };
  }

  try {
    console.log('[MailTrace][SidePanel] Configuring side panel options for tab:', tabId);
    if (chrome.sidePanel.setOptions) {
      await chrome.sidePanel.setOptions({
        tabId,
        path: 'sidepanel/index.html',
        enabled: true
      });
    }

    console.log('[MailTrace][SidePanel] Opening native Chrome Side Panel for tab:', tabId);
    await chrome.sidePanel.open({ tabId });
    console.log('[MailTrace][SidePanel] Native Chrome Side Panel opened successfully for tab:', tabId);
    return { success: true };
  } catch (error) {
    console.error('[MailTrace][SidePanel][ERROR] Failed to open Chrome Side Panel:', error);
    return {
      success: false,
      error: error?.message || String(error)
    };
  }
}

// ==========================================
// CORE ANALYSIS WORKFLOW WITH CACHING
// ==========================================

async function executeEmailAnalysis(emailData, tabId, rawEmail) {
  if (!emailData && !rawEmail) {
    return { success: false, error: 'No email data provided for analysis.' };
  }

  const fingerprint = emailData?.contentFingerprint || emailData?.messageKey;

  // 1. Check in-memory deduplication cache
  if (fingerprint && analysisCache.has(fingerprint)) {
    const cached = analysisCache.get(fingerprint);
    console.log('[MailTrace][Cache] Reusing cached analysis for fingerprint:', fingerprint);

    if (tabId) {
      chrome.tabs.sendMessage(tabId, {
        type: 'UPDATE_ANALYSIS_BADGE',
        analysis: cached.analysis
      }).catch(() => {});
    }

    return {
      success: true,
      data: cached,
      fromCache: true
    };
  }

  // 2. Transmit to backend EvidenceFusionEngine with persistent device identity
  const apiBase = await getApiBaseUrl();
  const deviceId = await getOrCreateDeviceId();
  const { settings } = await chrome.storage.local.get('settings');

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 28000);

    const response = await fetch(`${apiBase}/api/extension/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ emailData, rawEmail, deviceId, source: 'extension' }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.error || `Server responded with HTTP ${response.status}`);
    }

    const data = await response.json();
    const analysis = data.analysis;

    const resultPayload = {
      analysis,
      analysisId: data.analysisId || analysis.id,
      deepLinkPath: data.deepLinkPath || `/?investigation=${analysis.id}`,
      webAppBase: apiBase
    };

    if (fingerprint) {
      analysisCache.set(fingerprint, { ...resultPayload, cachedAt: Date.now() });
    }

    if (tabId) {
      chrome.tabs.sendMessage(tabId, {
        type: 'UPDATE_ANALYSIS_BADGE',
        analysis
      }).catch(() => {});
    }

    if (settings?.saveHistory !== false && analysis) {
      await recordScanHistory({
        id: analysis.id,
        timestamp: analysis.analyzedAt || new Date().toISOString(),
        subject: analysis.subject,
        sender: analysis.from,
        senderDomain: analysis.fromDomain,
        riskScore: analysis.overallRiskScore,
        severity: analysis.severity,
        classification: analysis.primaryClassification,
        deepLinkPath: resultPayload.deepLinkPath
      });
    }

    if (settings?.enableNotifications !== false && analysis.overallRiskScore >= 80) {
      if (chrome.notifications) {
        chrome.notifications.create(`threat-${analysis.id}`, {
          type: 'basic',
          iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
          title: `MailTrace AI Alert: ${analysis.severity} Risk (${analysis.overallRiskScore}/100)`,
          message: `${analysis.primaryClassification} detected from ${analysis.fromDomain || analysis.from}`,
          priority: 2
        });
      }
    }

    return {
      success: true,
      data: resultPayload
    };
  } catch (err) {
    console.error('[MailTrace][Backend] Analysis network/pipeline error:', err);
    return {
      success: false,
      error: err.name === 'AbortError'
        ? 'Analysis timed out (28s). Please check server connectivity.'
        : (err.message || 'Unable to communicate with MailTrace AI backend.')
    };
  }
}

async function recordScanHistory(entry) {
  const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
  const updated = [entry, ...scanHistory.filter((h) => h.id !== entry.id)].slice(0, 50);
  await chrome.storage.local.set({ scanHistory: updated });
}

// ==========================================
// EXTERNAL WEBSITE ↔ EXTENSION COMMUNICATION
// ==========================================

chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
  const origin = sender.origin || sender.url || '';
  console.log('[MailTrace][Website] External message received from origin:', origin, request);

  if (request.type === 'GET_EXTENSION_STATUS' || request.type === 'GET_DEVICE_IDENTITY') {
    getOrCreateDeviceId().then((deviceId) => {
      sendResponse({
        connected: true,
        version: '2.4.0',
        deviceId,
        activeTabSupported: true,
        timestamp: Date.now()
      });
    });
    return true;
  }

  if (request.type === 'SYNC_DEVICE_IDENTITY' && request.deviceId) {
    chrome.storage.local.set({ deviceId: request.deviceId }).then(() => {
      sendResponse({ success: true, deviceId: request.deviceId });
    });
    return true;
  }

  if (request.type === 'GET_CURRENT_WEBMAIL_CONTEXT' || request.type === 'GET_CURRENT_EMAIL') {
    resolveActiveWebmailContext()
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
          error: err.message || 'Failed to query webmail context'
        });
      });
    return true;
  }

  if (request.type === 'ANALYZE_CURRENT_EMAIL') {
    handleInternalMessage({ type: 'ANALYZE_EMAIL', payload: request.payload }, sender, undefined)
      .then(sendResponse)
      .catch((err) => sendResponse({ success: false, error: err.message }));
    return true;
  }

  sendResponse({ success: false, error: 'Unknown external message type' });
  return true;
});
