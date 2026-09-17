/**
 * MailTrace AI - Sidepanel Controller (Manifest V3)
 * Real-time companion view for SOC analysts inspecting active webmail sessions.
 * Zero demo/mock data: strictly consumes real DOM extraction & backend engine results.
 */

document.addEventListener('DOMContentLoaded', async () => {
  const backendBadge = document.getElementById('backend-status-badge');
  const backendStatusText = document.getElementById('backend-status-text');
  const btnRefresh = document.getElementById('btn-refresh-detection');
  const btnRefreshEmpty = document.getElementById('btn-refresh-empty');

  const detectionLoading = document.getElementById('detection-loading');
  const detectionEmpty = document.getElementById('detection-empty');
  const detectionDetails = document.getElementById('detection-details');
  const emptyTitle = document.getElementById('empty-message-title');
  const emptyDesc = document.getElementById('empty-message-desc');

  const detSubject = document.getElementById('det-subject');
  const detSender = document.getElementById('det-sender');
  const tagLinks = document.getElementById('tag-links');
  const tagAttachments = document.getElementById('tag-attachments');
  const tagThread = document.getElementById('tag-thread');
  const btnAnalyzeEmail = document.getElementById('btn-analyze-email');

  const progressCard = document.getElementById('analysis-progress-card');
  const progressStepText = document.getElementById('progress-step-text');
  const progressBarFill = document.getElementById('progress-bar-fill');
  const stepCounter = document.getElementById('step-counter');

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

  const btnOpenInvestigation = document.getElementById('btn-open-investigation');
  const btnCreateCase = document.getElementById('btn-create-case');
  const btnReportEmail = document.getElementById('btn-report-email');

  let currentEmailData = null;
  let currentAnalysis = null;
  let currentAnalysisId = null;
  let currentDeepLinkPath = null;

  async function checkBackend() {
    if (backendBadge) {
      backendBadge.className = 'status-badge connecting';
      backendStatusText.textContent = 'Connecting...';
    }

    chrome.runtime.sendMessage({ type: 'TEST_BACKEND_CONNECTION' }, (res) => {
      if (res && res.success) {
        backendBadge.className = 'status-badge connected';
        backendStatusText.textContent = `Online (${res.latencyMs}ms)`;
      } else {
        backendBadge.className = 'status-badge offline';
        backendStatusText.textContent = 'Server Offline';
      }
    });
  }

  async function inspectTab() {
    detectionLoading.classList.remove('hidden');
    detectionEmpty.classList.add('hidden');
    detectionDetails.classList.add('hidden');
    resultContainer.classList.add('hidden');

    chrome.runtime.sendMessage({ type: 'GET_CURRENT_WEBMAIL_CONTEXT' }, (res) => {
      detectionLoading.classList.add('hidden');

      if (!res || !res.isWebmailTab) {
        detectionEmpty.classList.remove('hidden');
        emptyTitle.textContent = 'Not in Webmail';
        emptyDesc.textContent = 'Please navigate to an open email message inside Gmail or Outlook.';
        return;
      }

      if (!res.isMessageView || !res.email) {
        detectionEmpty.classList.remove('hidden');
        emptyTitle.textContent = 'No Email Open in View';
        emptyDesc.textContent = 'An inbox or folder list view is active. Open an email message to inspect forensic indicators.';
        return;
      }

      currentEmailData = res.email;
      detSubject.textContent = currentEmailData.subject || '(No Subject)';
      detSender.textContent = currentEmailData.sender || 'Unknown Sender';
      tagLinks.textContent = `${(currentEmailData.links || []).length} Links`;
      tagAttachments.textContent = `${(currentEmailData.attachments || []).length} Attachments`;
      tagThread.textContent = `${currentEmailData.threadMessageCount || 1} Message(s)`;

      detectionDetails.classList.remove('hidden');
    });
  }

  if (btnRefresh) btnRefresh.addEventListener('click', inspectTab);
  if (btnRefreshEmpty) btnRefreshEmpty.addEventListener('click', inspectTab);

  const ANALYSIS_STEPS = [
    { text: 'Extracting email content...', pct: 15 },
    { text: 'Parsing MIME & headers...', pct: 30 },
    { text: 'Checking sender & lookalikes...', pct: 45 },
    { text: 'Analyzing embedded links...', pct: 60 },
    { text: 'Running AI forensic models (Gemini)...', pct: 75 },
    { text: 'Correlating threat indicators...', pct: 90 },
    { text: 'Generating risk assessment...', pct: 100 }
  ];

  if (btnAnalyzeEmail) {
    btnAnalyzeEmail.addEventListener('click', () => {
      if (!currentEmailData) return;

      btnAnalyzeEmail.disabled = true;
      detectionDetails.classList.add('hidden');
      resultContainer.classList.add('hidden');
      progressCard.classList.remove('hidden');

      let stepIndex = 0;
      const stepInterval = setInterval(() => {
        if (stepIndex < ANALYSIS_STEPS.length) {
          const s = ANALYSIS_STEPS[stepIndex];
          progressStepText.textContent = s.text;
          progressBarFill.style.width = `${s.pct}%`;
          stepCounter.textContent = `Step ${stepIndex + 1} of ${ANALYSIS_STEPS.length}`;
          stepIndex++;
        }
      }, 300);

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
            emptyTitle.textContent = 'Analysis Failed';
            emptyDesc.textContent = response?.error || 'MailTrace AI backend could not process email.';
            return;
          }

          const { analysis, analysisId, deepLinkPath } = response.data;
          renderAnalysis(analysis, analysisId, deepLinkPath);
        }
      );
    });
  }

  function renderAnalysis(analysis, analysisId, deepLinkPath) {
    currentAnalysis = analysis;
    currentAnalysisId = analysisId;
    currentDeepLinkPath = deepLinkPath;
    resultContainer.classList.remove('hidden');

    const score = Math.round(analysis.overallRiskScore || 0);
    threatScoreVal.textContent = String(score);

    const spamScore = Math.round(analysis.spamScore || analysis.spamBulkScore || 0);
    const spamValEl = document.getElementById('spam-score-val');
    if (spamValEl) spamValEl.textContent = `${spamScore} / 100`;

    const sev = (analysis.severity || 'LOW').toUpperCase();
    threatSeverityBadge.textContent = `${sev} RISK`;
    scoreBanner.className = `threat-card ${sev.toLowerCase()}`;

    const confidence = analysis.confidence || 90;
    threatConfidence.textContent = `${confidence}% Confidence`;

    threatClassification.textContent = analysis.primaryCategory || analysis.primaryClassification || 'Legitimate';
    threatReasonSnippet.textContent = analysis.explanation || analysis.reasoning || 'No high-risk malicious characteristics detected.';

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

    const ind = analysis.indicators || {};
    riskPhish.textContent = (ind.phishingProbability || 0) >= 0.7 ? 'High' : (ind.phishingProbability || 0) >= 0.3 ? 'Moderate' : 'Low';
    riskImpersonation.textContent = (ind.impersonationScore || 0) >= 0.7 ? 'Critical' : (ind.impersonationScore || 0) >= 0.3 ? 'Suspicious' : 'Clean';
    riskDomain.textContent = ind.lookalikeDetected ? 'Lookalike' : 'Clean';
    riskUrl.textContent = (ind.suspiciousUrlCount || 0) > 0 ? 'Flagged' : 'Clean';

    // Findings
    findingsList.innerHTML = '';
    const findings = analysis.findings || [];
    findingsCount.textContent = `${findings.length} Found`;

    if (findings.length === 0) {
      findingsList.innerHTML = '<div class="empty-state-p text-slate-400">No anomalous indicators flagged.</div>';
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

    // Links
    const links = (currentEmailData?.linksDetailed || currentEmailData?.links || []).slice(0, 10);
    linksCountBadge.textContent = String(links.length);
    linksList.innerHTML = '';

    if (links.length === 0) {
      linksList.innerHTML = '<div class="empty-state-p text-slate-400">No embedded URLs in message.</div>';
    } else {
      links.forEach((l) => {
        const urlStr = typeof l === 'string' ? l : (l.href || l.normalizedUrl || '');
        const domainStr = typeof l === 'string' ? urlStr : (l.domain || urlStr);

        const row = document.createElement('div');
        row.className = 'link-row';
        row.innerHTML = `
          <div class="link-domain font-mono font-medium">${escapeHtml(domainStr)}</div>
          <div class="link-url font-mono text-slate-400 truncate">${escapeHtml(urlStr)}</div>
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

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

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
    btnCreateCase.addEventListener('click', () => {
      if (!currentAnalysis) return;
      btnCreateCase.disabled = true;
      btnCreateCase.textContent = 'Creating...';
      chrome.runtime.sendMessage(
        {
          type: 'CREATE_CASE',
          payload: {
            title: `[Sidepanel] ${currentAnalysis.subject || 'Suspicious Email'}`,
            severity: currentAnalysis.severity || 'HIGH',
            summary: `Case created from sidepanel for sender ${currentAnalysis.from}`,
            classification: currentAnalysis.primaryClassification
          }
        },
        () => {
          btnCreateCase.disabled = false;
          btnCreateCase.textContent = 'Case Created ✓';
          setTimeout(() => { btnCreateCase.textContent = 'Create Case'; }, 3000);
        }
      );
    });
  }

  if (btnReportEmail) {
    btnReportEmail.addEventListener('click', () => {
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
            reportedBy: 'SOC Analyst (Sidepanel)'
          }
        },
        () => {
          btnReportEmail.disabled = false;
          btnReportEmail.textContent = 'Reported ✓';
          setTimeout(() => { btnReportEmail.textContent = 'Report Threat'; }, 3000);
        }
      );
    });
  }

  await checkBackend();
  await inspectTab();
});
