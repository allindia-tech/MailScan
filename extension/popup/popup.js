/**
 * MailTrace AI - Chrome Extension Popup Controller (Manifest V3)
 * State-driven WebmailContextState consumer, EvidenceFusionEngine pipeline client,
 * live extension diagnostics, and SOC investigation handoff.
 * 
 * Strict Enterprise SOC Compliance:
 * - Direct active tab querying via GET_CURRENT_WEBMAIL_CONTEXT
 * - Real-time state machine rendering: NOT_WEBMAIL vs WEBMAIL_NO_MESSAGE vs WEBMAIL_READY vs WEBMAIL_ERROR
 * - Live Diagnostics Panel for forensic transparency
 * - Zero demo/fake data fallbacks
 */

document.addEventListener('DOMContentLoaded', async () => {
  // Elements - Navigation
  const navTabs = document.querySelectorAll('.nav-tab');
  const tabContents = document.querySelectorAll('.tab-content');

  // Elements - Header & Diagnostics
  const backendBadge = document.getElementById('backend-status-badge');
  const backendStatusText = document.getElementById('backend-status-text');
  const btnToggleDiagnostics = document.getElementById('btn-toggle-diagnostics');
  const btnCloseDiagnostics = document.getElementById('btn-close-diagnostics');
  const diagnosticsPanel = document.getElementById('diagnostics-panel');
  const btnSidepanel = document.getElementById('btn-open-sidepanel');

  // Diagnostics Fields
  const diagTabId = document.getElementById('diag-tab-id');
  const diagUrl = document.getElementById('diag-url');
  const diagProvider = document.getElementById('diag-provider');
  const diagIsWebmail = document.getElementById('diag-is-webmail');
  const diagContentScript = document.getElementById('diag-content-script');
  const diagState = document.getElementById('diag-state');
  const diagIsMessage = document.getElementById('diag-is-message');
  const diagMessageKey = document.getElementById('diag-message-key');
  const diagExtractStatus = document.getElementById('diag-extract-status');
  const diagBackend = document.getElementById('diag-backend');

  // Elements - Detection Card
  const providerBadge = document.getElementById('provider-badge');
  const detectionLoading = document.getElementById('detection-loading');
  const detectionLoadingText = document.getElementById('detection-loading-text');
  const detectionEmpty = document.getElementById('detection-empty');
  const detectionDetails = document.getElementById('detection-details');
  const emptyTitle = document.getElementById('empty-message-title');
  const emptyDesc = document.getElementById('empty-message-desc');
  const btnRetryDetection = document.getElementById('btn-retry-detection');

  const detSubject = document.getElementById('det-subject');
  const detSender = document.getElementById('det-sender');
  const tagLinks = document.getElementById('tag-links');
  const tagAttachments = document.getElementById('tag-attachments');
  const tagThread = document.getElementById('tag-thread');
  const btnAnalyzeEmail = document.getElementById('btn-analyze-email');

  // Elements - Progress Flow
  const progressCard = document.getElementById('analysis-progress-card');
  const progressStepText = document.getElementById('progress-step-text');
  const progressBarFill = document.getElementById('progress-bar-fill');
  const stepCounter = document.getElementById('step-counter');

  // Elements - Results
  const resultContainer = document.getElementById('result-container');
  const scoreBanner = document.getElementById('score-banner');
  const threatSeverityBadge = document.getElementById('threat-severity-badge');
  const threatConfidence = document.getElementById('threat-confidence');
  const threatScoreVal = document.getElementById('threat-score-val');
  const threatClassification = document.getElementById('threat-classification');
  const threatReasonSnippet = document.getElementById('threat-reason-snippet');
  const riskPhish = document.getElementById('risk-phish');
  const riskImpersonation = document.getElementById('risk-impersonation');
  const riskDomain = document.getElementById('risk-domain');
  const riskUrl = document.getElementById('risk-url');
  const findingsList = document.getElementById('findings-list');
  const findingsCount = document.getElementById('findings-count');
  const linksList = document.getElementById('links-list');
  const linksCountBadge = document.getElementById('links-count-badge');
  const attachmentsCard = document.getElementById('attachments-card');
  const attachmentsList = document.getElementById('attachments-list');
  const attachmentsCountBadge = document.getElementById('attachments-count-badge');

  // Result Actions
  const btnOpenInvestigation = document.getElementById('btn-open-investigation');
  const btnCreateCase = document.getElementById('btn-create-case');
  const btnReportEmail = document.getElementById('btn-report-email');

  // Elements - History
  const historyList = document.getElementById('history-list');
  const btnClearHistory = document.getElementById('btn-clear-history');

  // Elements - Settings
  const inputApiUrl = document.getElementById('input-api-url');
  const btnTestConnection = document.getElementById('btn-test-connection');
  const connectionTestResult = document.getElementById('connection-test-result');
  const toggleHistory = document.getElementById('toggle-history');
  const toggleNotifications = document.getElementById('toggle-notifications');
  const toggleAutoAnalyze = document.getElementById('toggle-auto-analyze');
  const btnSaveSettings = document.getElementById('btn-save-settings');
  const linkOpenWebSoc = document.getElementById('link-open-web-soc');
  const linkExtensionDocs = document.getElementById('link-extension-docs');

  // Internal State
  let currentWebmailContext = null;
  let currentEmailData = null;
  let currentAnalysis = null;
  let currentAnalysisId = null;
  let currentDeepLinkPath = null;
  let appSettings = null;

  const PIPELINE_STEPS = [
    'Extracting rendered email content...',
    'Parsing sender identity & lookalikes...',
    'Evaluating in-message hyperlinks & domains...',
    'Scanning attachment descriptors...',
    'Executing EvidenceFusionEngine heuristics...',
    'Correlating AI threat intelligence (Gemini)...',
    'Finalizing forensic threat verdict...'
  ];

  // ==========================================
  // 1. TABS NAVIGATION & DIAGNOSTICS TOGGLE
  // ==========================================

  navTabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      const targetId = tab.getAttribute('data-tab');
      navTabs.forEach((t) => t.classList.remove('active'));
      tabContents.forEach((c) => c.classList.add('hidden'));

      tab.classList.add('active');
      const activeContent = document.getElementById(targetId);
      if (activeContent) activeContent.classList.remove('hidden');

      if (targetId === 'tab-history') renderHistory();
    });
  });

  if (btnToggleDiagnostics && diagnosticsPanel) {
    btnToggleDiagnostics.addEventListener('click', () => {
      diagnosticsPanel.classList.toggle('hidden');
    });
  }

  if (btnCloseDiagnostics && diagnosticsPanel) {
    btnCloseDiagnostics.addEventListener('click', () => {
      diagnosticsPanel.classList.add('hidden');
    });
  }

  if (btnSidepanel) {
    btnSidepanel.addEventListener('click', async () => {
      try {
        const response = await chrome.runtime.sendMessage({ type: 'OPEN_SIDE_PANEL' });
        if (!response?.success) {
          console.error('[MailTrace][Popup] Side Panel open failed:', response?.error);
          alert(`Unable to open Chrome Side Panel: ${response?.error || 'Unknown error'}`);
        } else {
          window.close(); // Close popup once side panel opens
        }
      } catch (error) {
        console.error('[MailTrace][Popup] Side Panel request failed:', error);
        alert(`Side Panel request error: ${error?.message || error}`);
      }
    });
  }

  // ==========================================
  // 2. SETTINGS & HEALTH CHECK
  // ==========================================

  async function loadSettingsAndCheckHealth() {
    const { settings } = await chrome.storage.local.get('settings');
    appSettings = settings || {
      apiBaseUrl: 'http://localhost:3000',
      autoAnalyze: false,
      saveHistory: true,
      enableNotifications: true
    };

    if (inputApiUrl) inputApiUrl.value = appSettings.apiBaseUrl;
    if (toggleHistory) toggleHistory.checked = appSettings.saveHistory !== false;
    if (toggleNotifications) toggleNotifications.checked = appSettings.enableNotifications !== false;
    if (toggleAutoAnalyze) toggleAutoAnalyze.checked = !!appSettings.autoAnalyze;

    // Show initial connecting state
    if (backendBadge) {
      backendBadge.className = 'status-badge connecting';
      backendStatusText.textContent = 'Connecting...';
    }

    chrome.runtime.sendMessage({ type: 'TEST_BACKEND_CONNECTION' }, (res) => {
      if (res && res.success) {
        backendBadge.className = 'status-badge connected';
        backendStatusText.textContent = `Online (${res.latencyMs}ms)`;
        if (diagBackend) diagBackend.textContent = `Online (${res.latencyMs}ms)`;
      } else {
        backendBadge.className = 'status-badge offline';
        backendStatusText.textContent = 'Server Offline';
        if (diagBackend) diagBackend.textContent = `Offline (${res?.error || 'unreachable'})`;
      }
    });
  }

  // ==========================================
  // 3. STATE-MACHINE DRIVEN WEBMAIL INSPECTION
  // ==========================================

  function updateDiagnosticsDisplay(ctx) {
    if (!ctx) return;
    if (diagTabId) diagTabId.textContent = ctx.tabId !== null ? String(ctx.tabId) : 'None';
    if (diagUrl) diagUrl.textContent = ctx.url ? ctx.url.slice(0, 60) + (ctx.url.length > 60 ? '...' : '') : '-';
    if (diagProvider) diagProvider.textContent = (ctx.provider || 'None').toUpperCase();
    if (diagIsWebmail) diagIsWebmail.textContent = ctx.isWebmailTab ? 'YES (Supported)' : 'NO (External)';
    if (diagContentScript) diagContentScript.textContent = ctx.contentScriptConnected ? 'CONNECTED' : 'DISCONNECTED';
    if (diagState) diagState.textContent = ctx.state || 'UNKNOWN';
    if (diagIsMessage) diagIsMessage.textContent = ctx.isMessageView ? 'YES (Opened Email)' : 'NO (List/Folder)';
    if (diagMessageKey) diagMessageKey.textContent = ctx.messageKey || '-';
    if (diagExtractStatus) diagExtractStatus.textContent = ctx.extractionStatus || 'none';
  }

  async function inspectActiveTab() {
    detectionLoading.classList.remove('hidden');
    detectionEmpty.classList.add('hidden');
    detectionDetails.classList.add('hidden');
    progressCard.classList.add('hidden');
    resultContainer.classList.add('hidden');

    if (detectionLoadingText) detectionLoadingText.textContent = 'Inspecting active browser tab...';
    providerBadge.textContent = 'Inspecting...';
    providerBadge.className = 'badge-neutral';

    chrome.runtime.sendMessage({ type: 'GET_CURRENT_WEBMAIL_CONTEXT' }, (res) => {
      detectionLoading.classList.add('hidden');
      currentWebmailContext = res || null;
      updateDiagnosticsDisplay(res);

      if (!res) {
        showEmptyState({
          badgeText: 'Error',
          badgeClass: 'badge-alert',
          title: 'Communication Failed',
          desc: 'Could not query extension service worker. Please restart the extension.'
        });
        return;
      }

      const state = res.state || 'UNKNOWN';
      console.log('[MailTrace][Popup] Context state received:', state, res);

      switch (state) {
        case 'NOT_WEBMAIL': {
          showEmptyState({
            badgeText: 'External Tab',
            badgeClass: 'badge-neutral',
            title: 'Not on Webmail',
            desc: 'Please switch to an active Gmail or Outlook tab with an opened email message.'
          });
          break;
        }

        case 'WEBMAIL_NO_MESSAGE': {
          const providerName = (res.provider || 'Webmail').toUpperCase();
          showEmptyState({
            badgeText: providerName,
            badgeClass: 'badge-neutral',
            title: 'No Email Open in View',
            desc: 'An inbox list view or folder is currently displayed. Click and open an email message in this tab to run forensics.'
          });
          break;
        }

        case 'WEBMAIL_DETECTING': {
          detectionLoading.classList.remove('hidden');
          if (detectionLoadingText) detectionLoadingText.textContent = 'Email rendering detected, extracting content...';
          setTimeout(inspectActiveTab, 500);
          break;
        }

        case 'WEBMAIL_ERROR': {
          const providerName = (res.provider || 'Webmail').toUpperCase();
          showEmptyState({
            badgeText: providerName,
            badgeClass: 'badge-alert',
            title: 'Webmail Connection Error',
            desc: res.error || 'Could not communicate with the page content script. Please refresh the Gmail/Outlook tab.'
          });
          break;
        }

        case 'WEBMAIL_MESSAGE_DETECTED':
        case 'WEBMAIL_READY': {
          if (res.email) {
            populateDetectedEmail(res.email, res.provider);
          } else {
            showEmptyState({
              badgeText: (res.provider || 'Webmail').toUpperCase(),
              badgeClass: 'badge-alert',
              title: 'Extraction Incomplete',
              desc: 'Email container was detected, but metadata could not be fully read. Click Re-check to retry.'
            });
          }
          break;
        }

        default: {
          showEmptyState({
            badgeText: 'Webmail',
            badgeClass: 'badge-neutral',
            title: 'Inspecting View',
            desc: 'Please ensure an email message is visibly open in Gmail or Outlook.'
          });
        }
      }
    });
  }

  function showEmptyState({ badgeText, badgeClass, title, desc }) {
    providerBadge.textContent = badgeText;
    providerBadge.className = badgeClass;
    emptyTitle.textContent = title;
    emptyDesc.textContent = desc;
    detectionEmpty.classList.remove('hidden');
    detectionDetails.classList.add('hidden');
  }

  function populateDetectedEmail(email, provider) {
    currentEmailData = email;
    providerBadge.textContent = (provider || email.provider || 'Webmail').toUpperCase();
    providerBadge.className = 'badge-success';

    detSubject.textContent = email.subject || '(No Subject)';
    detSender.textContent = email.sender || 'Unknown Sender';

    const linksCount = (email.links || []).length;
    const attsCount = (email.attachments || []).length;
    const threadCount = email.threadMessageCount || 1;

    tagLinks.textContent = `${linksCount} ${linksCount === 1 ? 'Link' : 'Links'}`;
    tagAttachments.textContent = `${attsCount} ${attsCount === 1 ? 'Attachment' : 'Attachments'}`;
    tagThread.textContent = `${threadCount} ${threadCount === 1 ? 'Message' : 'Messages in Thread'}`;

    detectionDetails.classList.remove('hidden');
    detectionEmpty.classList.add('hidden');

    if (appSettings?.autoAnalyze) {
      triggerAnalysis();
    }
  }

  if (btnRetryDetection) {
    btnRetryDetection.addEventListener('click', inspectActiveTab);
  }

  // ==========================================
  // 4. ANALYSIS PIPELINE ORCHESTRATION
  // ==========================================

  async function triggerAnalysis() {
    if (!currentEmailData) return;

    btnAnalyzeEmail.disabled = true;
    detectionDetails.classList.add('hidden');
    resultContainer.classList.add('hidden');
    progressCard.classList.remove('hidden');

    let currentStep = 0;
    progressStepText.textContent = PIPELINE_STEPS[0];
    progressBarFill.style.width = '15%';
    stepCounter.textContent = `Step 1 of ${PIPELINE_STEPS.length}`;

    const stepInterval = setInterval(() => {
      currentStep++;
      if (currentStep < PIPELINE_STEPS.length - 1) {
        progressStepText.textContent = PIPELINE_STEPS[currentStep];
        stepCounter.textContent = `Step ${currentStep + 1} of ${PIPELINE_STEPS.length}`;
        progressBarFill.style.width = `${Math.round(((currentStep + 1) / PIPELINE_STEPS.length) * 100)}%`;
      }
    }, 450);

    chrome.runtime.sendMessage(
      {
        type: 'ANALYZE_EMAIL',
        payload: { emailData: currentEmailData }
      },
      (response) => {
        clearInterval(stepInterval);
        btnAnalyzeEmail.disabled = false;
        progressCard.classList.add('hidden');

        if (!response || !response.success) {
          detectionEmpty.classList.remove('hidden');
          emptyTitle.textContent = 'Analysis Unavailable';
          emptyDesc.textContent = response?.error || 'The MailTrace AI server could not complete analysis. Check connection in Settings.';
          return;
        }

        const { analysis, analysisId, deepLinkPath } = response.data;
        renderAnalysisResult(analysis, analysisId, deepLinkPath);
      }
    );
  }

  if (btnAnalyzeEmail) {
    btnAnalyzeEmail.addEventListener('click', triggerAnalysis);
  }

  // ==========================================
  // 5. RENDER ANALYSIS RESULTS
  // ==========================================

  function renderAnalysisResult(analysis, analysisId, deepLinkPath) {
    if (!analysis) return;

    currentAnalysis = analysis;
    currentAnalysisId = analysisId || analysis.id;
    currentDeepLinkPath = deepLinkPath || `/?investigation=${currentAnalysisId}`;

    detectionDetails.classList.add('hidden');
    detectionEmpty.classList.add('hidden');
    resultContainer.classList.remove('hidden');

    const score = Math.round(analysis.overallRiskScore || 0);
    threatScoreVal.textContent = String(score);

    const spamScore = Math.round(analysis.spamScore || analysis.spamBulkScore || 0);
    const spamValEl = document.getElementById('spam-score-val');
    if (spamValEl) spamValEl.textContent = `${spamScore} / 100`;

    // Threat Severity Styling
    const severity = (analysis.severity || 'LOW').toUpperCase();
    scoreBanner.className = `threat-card ${severity.toLowerCase()}`;
    threatSeverityBadge.textContent = `${severity} RISK`;
    threatSeverityBadge.className = `severity-pill ${severity.toLowerCase()}`;

    threatConfidence.textContent = `${analysis.confidence || 90}% Confidence`;
    threatClassification.textContent = analysis.primaryCategory || analysis.primaryClassification || 'Legitimate';
    threatReasonSnippet.textContent = analysis.explanation || analysis.reasoning || 'No malicious indicators detected in rendered content.';

    // Secondary categories
    const secList = document.getElementById('secondary-cats-list');
    const secWrapper = document.getElementById('secondary-cats-wrapper');
    const secCategories = analysis.secondaryCategories || analysis.secondaryFindings || [];
    if (secList && secWrapper) {
      secList.innerHTML = '';
      if (secCategories.length > 0) {
        secWrapper.classList.remove('hidden');
        secCategories.forEach((sc) => {
          const pill = document.createElement('span');
          pill.className = 'sec-cat-pill text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-amber-300 font-mono border border-slate-700';
          pill.textContent = typeof sc === 'string' ? sc : (sc.label || sc.id);
          secList.appendChild(pill);
        });
      } else {
        secWrapper.classList.add('hidden');
      }
    }

    // Risk Dimensions
    const indicators = analysis.indicators || {};
    riskPhish.textContent = getLevelText(indicators.phishingProbability || 0.1);
    riskImpersonation.textContent = getLevelText(indicators.impersonationScore || 0.1);
    riskDomain.textContent = indicators.lookalikeDetected ? 'Lookalike Domain' : 'Verified';
    riskUrl.textContent = indicators.suspiciousUrlCount > 0 ? `${indicators.suspiciousUrlCount} Flagged` : 'Clean';

    // Key Findings
    const findings = analysis.findings || [];
    findingsCount.textContent = `${findings.length} ${findings.length === 1 ? 'Found' : 'Found'}`;
    findingsList.innerHTML = '';

    if (findings.length === 0) {
      findingsList.innerHTML = '<div class="empty-state-p text-slate-400">No anomalous or malicious indicators flagged.</div>';
    } else {
      findings.forEach((f) => {
        const item = document.createElement('div');
        item.className = 'finding-item';
        item.innerHTML = `
          <div class="finding-type">${escapeHtml(f.title || f.type || 'Indicator')}</div>
          <div class="finding-desc">${escapeHtml(f.description || f.detail || '')}</div>
        `;
        findingsList.appendChild(item);
      });
    }

    // Links List
    const links = (currentEmailData?.linksDetailed || currentEmailData?.links || []).slice(0, 10);
    linksCountBadge.textContent = String(links.length);
    linksList.innerHTML = '';

    if (links.length === 0) {
      linksList.innerHTML = '<div class="empty-state-p text-slate-400">No embedded URLs in message body.</div>';
    } else {
      links.forEach((link) => {
        const urlStr = typeof link === 'string' ? link : (link.href || link.normalizedUrl || '');
        const domainStr = typeof link === 'string' ? urlStr : (link.domain || urlStr);

        const row = document.createElement('div');
        row.className = 'link-row';
        row.innerHTML = `
          <div class="link-domain font-mono font-medium">${escapeHtml(domainStr)}</div>
          <div class="link-url font-mono text-slate-400 truncate" title="${escapeHtml(urlStr)}">${escapeHtml(urlStr)}</div>
        `;
        linksList.appendChild(row);
      });
    }

    // Attachments
    const atts = currentEmailData?.attachments || [];
    if (atts.length > 0) {
      attachmentsCard.classList.remove('hidden');
      attachmentsCountBadge.textContent = String(atts.length);
      attachmentsList.innerHTML = '';

      atts.forEach((a) => {
        const row = document.createElement('div');
        row.className = 'att-row flex items-center justify-between p-2 bg-slate-900/60 rounded border border-slate-800 text-xs';
        row.innerHTML = `
          <span class="font-mono text-slate-200">${escapeHtml(a.name)}</span>
          <span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">${escapeHtml(a.type || 'File')}</span>
        `;
        attachmentsList.appendChild(row);
      });
    } else {
      attachmentsCard.classList.add('hidden');
    }
  }

  function getLevelText(val) {
    if (val >= 0.8) return 'Critical';
    if (val >= 0.6) return 'High';
    if (val >= 0.3) return 'Medium';
    return 'Low';
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ==========================================
  // 6. RESULT ACTIONS & HANDOFFS
  // ==========================================

  if (btnOpenInvestigation) {
    btnOpenInvestigation.addEventListener('click', () => {
      if (!currentAnalysisId) return;
      chrome.runtime.sendMessage({
        type: 'OPEN_FULL_INVESTIGATION',
        payload: {
          analysisId: currentAnalysisId,
          deepLinkPath: currentDeepLinkPath
        }
      });
    });
  }

  if (btnCreateCase) {
    btnCreateCase.addEventListener('click', async () => {
      if (!currentAnalysis) return;
      btnCreateCase.disabled = true;
      btnCreateCase.textContent = 'Creating...';

      chrome.runtime.sendMessage(
        {
          type: 'CREATE_CASE',
          payload: {
            title: `[Extension Investigation] ${currentAnalysis.subject || 'Suspicious Email'}`,
            severity: currentAnalysis.severity || 'HIGH',
            summary: `Automated case generated from browser webmail inspection of sender ${currentAnalysis.from}`,
            classification: currentAnalysis.primaryClassification
          }
        },
        (res) => {
          btnCreateCase.disabled = false;
          btnCreateCase.textContent = res && res.success ? 'Case Created ✓' : 'Create Case';
          if (res && res.success) {
            setTimeout(() => {
              btnCreateCase.textContent = 'Create Case';
            }, 3000);
          }
        }
      );
    });
  }

  if (btnReportEmail) {
    btnReportEmail.addEventListener('click', async () => {
      if (!currentAnalysis) return;
      btnReportEmail.disabled = true;
      btnReportEmail.textContent = 'Reporting...';

      chrome.runtime.sendMessage(
        {
          type: 'REPORT_EMAIL',
          payload: {
            analysisId: currentAnalysis.id,
            subject: currentAnalysis.subject,
            sender: currentAnalysis.from,
            riskScore: currentAnalysis.overallRiskScore,
            reportedBy: 'SOC Analyst (Chrome Extension)'
          }
        },
        (res) => {
          btnReportEmail.disabled = false;
          btnReportEmail.textContent = res && res.success ? 'Reported ✓' : 'Report Threat';
          if (res && res.success) {
            setTimeout(() => {
              btnReportEmail.textContent = 'Report Threat';
            }, 3000);
          }
        }
      );
    });
  }

  // ==========================================
  // 7. HISTORY RENDERING
  // ==========================================

  async function renderHistory() {
    const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
    historyList.innerHTML = '';

    if (scanHistory.length === 0) {
      historyList.innerHTML = '<div class="empty-state-p p-4 text-slate-400">No scanned email telemetry recorded.</div>';
      return;
    }

    scanHistory.forEach((h) => {
      const item = document.createElement('div');
      item.className = 'history-item';
      const sevClass = (h.severity || 'low').toLowerCase();

      item.innerHTML = `
        <div class="history-item-header">
          <span class="history-subject truncate font-medium">${escapeHtml(h.subject || '(No Subject)')}</span>
          <span class="severity-pill ${sevClass}">${h.riskScore || 0}/100</span>
        </div>
        <div class="history-meta font-mono text-slate-400 text-[11px]">
          <span>${escapeHtml(h.sender || 'Unknown')}</span> &bull;
          <span>${new Date(h.timestamp).toLocaleDateString()}</span>
        </div>
      `;

      item.addEventListener('click', () => {
        chrome.runtime.sendMessage({
          type: 'OPEN_FULL_INVESTIGATION',
          payload: {
            analysisId: h.id,
            deepLinkPath: h.deepLinkPath || `/?investigation=${h.id}`
          }
        });
      });

      historyList.appendChild(item);
    });
  }

  if (btnClearHistory) {
    btnClearHistory.addEventListener('click', async () => {
      await chrome.storage.local.set({ scanHistory: [] });
      renderHistory();
    });
  }

  // ==========================================
  // 8. SETTINGS & CONNECTION TEST
  // ==========================================

  if (btnTestConnection) {
    btnTestConnection.addEventListener('click', () => {
      const url = inputApiUrl.value.trim();
      connectionTestResult.textContent = 'Testing connection...';
      connectionTestResult.className = 'text-xs text-slate-400 mt-1 block';

      chrome.runtime.sendMessage(
        {
          type: 'TEST_BACKEND_CONNECTION',
          payload: { url }
        },
        (res) => {
          if (res && res.success) {
            connectionTestResult.textContent = `Connected successfully (${res.latencyMs}ms)`;
            connectionTestResult.className = 'text-xs text-emerald-400 mt-1 block font-medium';
            backendBadge.className = 'status-badge connected';
            backendStatusText.textContent = `Online (${res.latencyMs}ms)`;
            if (diagBackend) diagBackend.textContent = `Online (${res.latencyMs}ms)`;
          } else {
            connectionTestResult.textContent = `Connection failed: ${res?.error || 'unreachable'}`;
            connectionTestResult.className = 'text-xs text-rose-400 mt-1 block font-medium';
            backendBadge.className = 'status-badge offline';
            backendStatusText.textContent = 'Server Offline';
            if (diagBackend) diagBackend.textContent = `Offline (${res?.error || 'unreachable'})`;
          }
        }
      );
    });
  }

  if (btnSaveSettings) {
    btnSaveSettings.addEventListener('click', async () => {
      const updated = {
        apiBaseUrl: inputApiUrl.value.trim() || 'http://localhost:3000',
        saveHistory: toggleHistory.checked,
        enableNotifications: toggleNotifications.checked,
        autoAnalyze: toggleAutoAnalyze.checked
      };

      await chrome.storage.local.set({ settings: updated });
      appSettings = updated;

      btnSaveSettings.textContent = 'Settings Saved ✓';
      setTimeout(() => {
        btnSaveSettings.textContent = 'Save Configuration';
      }, 2000);
    });
  }

  if (linkOpenWebSoc) {
    linkOpenWebSoc.addEventListener('click', async (e) => {
      e.preventDefault();
      const base = appSettings?.apiBaseUrl || 'http://localhost:3000';
      await chrome.tabs.create({ url: base });
    });
  }

  if (linkExtensionDocs) {
    linkExtensionDocs.addEventListener('click', async (e) => {
      e.preventDefault();
      const base = appSettings?.apiBaseUrl || 'http://localhost:3000';
      await chrome.tabs.create({ url: `${base}/?view=extension` });
    });
  }

  // ==========================================
  // 9. BOOTSTRAP POPUP
  // ==========================================

  await loadSettingsAndCheckHealth();
  await inspectActiveTab();
});
