document.addEventListener('DOMContentLoaded', async () => {
  const inputUrl = document.getElementById('input-backend-url');
  const btnTest = document.getElementById('btn-test');
  const testFeedback = document.getElementById('test-feedback');
  const optAutoAnalyze = document.getElementById('opt-auto-analyze');
  const optSaveHistory = document.getElementById('opt-save-history');
  const optNotifications = document.getElementById('opt-notifications');
  const btnSave = document.getElementById('btn-save-options');

  // Load existing settings
  const { settings } = await chrome.storage.local.get('settings');
  const current = settings || {
    apiBaseUrl: 'http://localhost:3000',
    autoAnalyze: false,
    saveHistory: true,
    enableNotifications: true
  };

  inputUrl.value = current.apiBaseUrl;
  optAutoAnalyze.checked = !!current.autoAnalyze;
  optSaveHistory.checked = current.saveHistory !== false;
  optNotifications.checked = current.enableNotifications !== false;

  btnTest.addEventListener('click', () => {
    testFeedback.textContent = 'Testing connection...';
    testFeedback.className = 'text-xs text-amber-400 mt-1 block';

    chrome.runtime.sendMessage(
      { type: 'TEST_BACKEND_CONNECTION', payload: { url: inputUrl.value.trim() } },
      (res) => {
        if (res && res.success) {
          testFeedback.textContent = `Success! Response in ${res.latencyMs}ms.`;
          testFeedback.className = 'text-xs text-emerald-400 mt-1 block';
        } else {
          testFeedback.textContent = `Connection failed: ${res?.error || 'Unreachable'}`;
          testFeedback.className = 'text-xs text-rose-400 mt-1 block';
        }
      }
    );
  });

  btnSave.addEventListener('click', async () => {
    const updated = {
      apiBaseUrl: inputUrl.value.trim() || 'http://localhost:3000',
      autoAnalyze: optAutoAnalyze.checked,
      saveHistory: optSaveHistory.checked,
      enableNotifications: optNotifications.checked
    };

    await chrome.storage.local.set({ settings: updated });
    alert('Settings saved successfully.');
  });
});
