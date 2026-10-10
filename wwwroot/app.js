const logInput = document.getElementById('logInput');
const analyzeBtn = document.getElementById('analyzeBtn');
const sampleBtn = document.getElementById('sampleBtn');
const clearBtn = document.getElementById('clearBtn');
const copyBtn = document.getElementById('copyBtn');
const downloadBtn = document.getElementById('downloadBtn');
const fileInput = document.getElementById('fileInput');
const resultContent = document.getElementById('resultContent');
const severityBadge = document.getElementById('severityBadge');
const fileNameMeta = document.getElementById('fileNameMeta');
const confidenceMeta = document.getElementById('confidenceMeta');
const actionStatus = document.getElementById('actionStatus');
const recentList = document.getElementById('recentList');
const historySearch = document.getElementById('historySearch');
const historySeverity = document.getElementById('historySeverity');
const historyCount = document.getElementById('historyCount');
const historyPrevious = document.getElementById('historyPrevious');
const historyNext = document.getElementById('historyNext');
const logoutBtn = document.getElementById('logoutBtn');

let currentAnalysis = null;
let recentAnalyses = [];
let historyPage = 1;
let totalHistoryPages = 0;
let totalHistoryCount = 0;
let historyRequestId = 0;
let historySearchTimeout;
let csrfToken = null;

const sampleLog = `2026-10-06 12:18:01 ERROR Failed to connect to database
2026-10-06 12:18:03 WARN Retrying request to API gateway
2026-10-06 12:18:09 ERROR Timeout while waiting for upstream service
2026-10-06 12:18:11 Exception: System.InvalidOperationException: service unavailable
2026-10-06 12:18:15 FATAL Resource exhaustion detected after 5000 requests`;

recentList.addEventListener('click', (event) => {
  const button = event.target.closest('button[data-analysis-id]');
  if (!button) return;

  if (button.dataset.action === 'delete') {
    deleteAnalysis(button.dataset.analysisId);
    return;
  }

  openAnalysis(button.dataset.analysisId);
});

historySearch.addEventListener('input', () => {
  clearTimeout(historySearchTimeout);
  historySearchTimeout = setTimeout(() => {
    historyPage = 1;
    loadRecentAnalyses();
  }, 250);
});
historySeverity.addEventListener('change', () => {
  historyPage = 1;
  loadRecentAnalyses();
});
historyPrevious.addEventListener('click', () => {
  if (historyPage > 1) {
    historyPage--;
    loadRecentAnalyses();
  }
});
historyNext.addEventListener('click', () => {
  if (historyPage < totalHistoryPages) {
    historyPage++;
    loadRecentAnalyses();
  }
});
logoutBtn.addEventListener('click', async () => {
  try {
    await requireSuccessfulResponse(await fetch('/api/auth/logout', {
      method: 'POST',
      headers: await getCsrfHeaders()
    }));
    window.location.assign('/login.html');
  } catch (error) {
    actionStatus.textContent = error instanceof Error ? error.message : 'Could not sign out.';
  }
});

sampleBtn.addEventListener('click', () => {
  logInput.value = sampleLog;
  fileNameMeta.textContent = 'Sample log';
  analyzeLog(sampleLog, 'sample.log');
});

clearBtn.addEventListener('click', () => {
  logInput.value = '';
  fileInput.value = '';
  currentAnalysis = null;
  severityBadge.textContent = 'Awaiting analysis';
  severityBadge.className = 'badge';
  fileNameMeta.textContent = 'No file selected';
  confidenceMeta.textContent = 'Confidence: --';
  actionStatus.textContent = '';
  resultContent.innerHTML = '<div class="status">Paste a log and click “Analyze Log” to begin.</div>';
});

copyBtn.addEventListener('click', async () => {
  if (!currentAnalysis) {
    actionStatus.textContent = 'There is no analysis result to copy yet.';
    return;
  }

  const summary = `${currentAnalysis.summary}\n\nSeverity: ${currentAnalysis.severity}\nConfidence: ${currentAnalysis.confidence}%\nFile: ${currentAnalysis.fileName || 'manual-entry.log'}`;

  try {
    await navigator.clipboard.writeText(summary);
    actionStatus.textContent = 'Summary copied to the clipboard.';
  } catch {
    actionStatus.textContent = 'Clipboard access is blocked in this browser.';
  }
});

downloadBtn.addEventListener('click', () => {
  if (!currentAnalysis) {
    actionStatus.textContent = 'There is no analysis result to download yet.';
    return;
  }

  const blob = new Blob([JSON.stringify(currentAnalysis, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${(currentAnalysis.fileName || 'log-analysis').replace(/\.[^.]+$/, '') || 'log-analysis'}.json`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  actionStatus.textContent = 'Analysis JSON downloaded.';
});

analyzeBtn.addEventListener('click', async () => {
  const text = logInput.value;
  if (!text.trim()) {
    resultContent.innerHTML = '<div class="status">Please paste log content first.</div>';
    return;
  }

  await analyzeLog(text, 'manual-entry.log');
});

fileInput.addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (!file) return;

  if (file.size > 2 * 1024 * 1024) {
    actionStatus.textContent = 'Uploaded files must be no larger than 2 MB.';
    fileInput.value = '';
    return;
  }

  actionStatus.textContent = '';
  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await fetch('/api/analyze-file', {
      method: 'POST',
      headers: await getCsrfHeaders(),
      body: formData
    });

    await requireSuccessfulResponse(response);

    const data = await response.json();
    fileNameMeta.textContent = file.name;
    renderResult(data, file.name);
    historyPage = 1;
    await loadRecentAnalyses();
    logInput.value = await file.text();
  } catch (error) {
    showError(error);
  }
});

async function analyzeLog(logText, fileName) {
  resultContent.innerHTML = '<div class="status">Analyzing log...</div>';

  try {
    const response = await fetch('/api/analyze', {
      method: 'POST',
      headers: await getCsrfHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ logText, fileName })
    });

    await requireSuccessfulResponse(response);

    const data = await response.json();
    renderResult(data, fileName);
    historyPage = 1;
    await loadRecentAnalyses();
  } catch (error) {
    showError(error);
  }
}

async function getResponseError(response) {
  try {
    const body = await response.json();
    return body.detail || body.title || body.error || `Request failed (${response.status}).`;
  } catch {
    return `Request failed (${response.status}).`;
  }
}

async function getCsrfHeaders(headers = {}) {
  if (!csrfToken) {
    const response = await fetch('/api/auth/csrf');
    if (!response.ok) {
      throw new Error(await getResponseError(response));
    }

    const result = await response.json();
    csrfToken = result.token;
  }

  return { ...headers, 'X-CSRF-TOKEN': csrfToken };
}

async function requireSuccessfulResponse(response) {
  if (response.status === 401) {
    window.location.assign('/login.html');
  }
  if (!response.ok) {
    throw new Error(await getResponseError(response));
  }
}

function showError(error) {
  const message = error instanceof Error ? error.message : 'An unexpected error occurred.';
  resultContent.innerHTML = `<div class="status">${escapeHtml(message)}</div>`;
}

async function loadRecentAnalyses() {
  const requestId = ++historyRequestId;
  try {
    const params = new URLSearchParams({
      page: String(historyPage),
      pageSize: '20'
    });
    if (historySearch.value.trim()) params.set('search', historySearch.value.trim());
    if (historySeverity.value) params.set('severity', historySeverity.value);

    const response = await fetch(`/api/history?${params}`);
    await requireSuccessfulResponse(response);

    const history = await response.json();
    if (requestId !== historyRequestId) return;
    recentAnalyses = history.items || [];
    historyPage = history.page;
    totalHistoryPages = history.totalPages;
    totalHistoryCount = history.totalCount;
    renderRecentAnalyses();
  } catch (error) {
    if (requestId !== historyRequestId) return;
    historyCount.textContent = '';
    recentList.innerHTML = '<div class="status">Recent analyses are unavailable right now.</div>';
    historyPrevious.disabled = true;
    historyNext.disabled = true;
  }
}

async function openAnalysis(id) {
  try {
    const response = await fetch(`/api/recent/${encodeURIComponent(id)}`);
    await requireSuccessfulResponse(response);

    const analysis = await response.json();
    renderResult(analysis, analysis.fileName);
    document.getElementById('resultPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    recentList.innerHTML = `<div class="status">${escapeHtml(error instanceof Error ? error.message : 'Could not load this analysis.')}</div>`;
  }
}

async function deleteAnalysis(id) {
  if (!window.confirm('Delete this saved analysis? This cannot be undone.')) {
    return;
  }

  try {
    const response = await fetch(`/api/recent/${encodeURIComponent(id)}`, {
      method: 'DELETE',
      headers: await getCsrfHeaders()
    });
    await requireSuccessfulResponse(response);

    if (currentAnalysis?.id === id) {
      currentAnalysis = null;
      severityBadge.textContent = 'Awaiting analysis';
      severityBadge.className = 'badge';
      fileNameMeta.textContent = 'No file selected';
      confidenceMeta.textContent = 'Confidence: --';
      resultContent.innerHTML = '<div class="status">This saved analysis was deleted.</div>';
    }

    await loadRecentAnalyses();
  } catch (error) {
    recentList.innerHTML = `<div class="status">${escapeHtml(error instanceof Error ? error.message : 'Could not delete this analysis.')}</div>`;
  }
}

function renderRecentAnalyses() {
  historyPrevious.disabled = historyPage <= 1;
  historyNext.disabled = historyPage >= totalHistoryPages;
  if (recentAnalyses.length === 0) {
    historyCount.textContent = 'Showing 0 of 0 saved analyses';
    recentList.innerHTML = '<div class="status">No analyses match the selected filters.</div>';
    return;
  }

  const firstItem = (historyPage - 1) * 20 + 1;
  const lastItem = firstItem + recentAnalyses.length - 1;
  historyCount.textContent = `Showing ${firstItem}-${lastItem} of ${totalHistoryCount} matching analyses · Page ${historyPage} of ${totalHistoryPages}`;

  recentList.innerHTML = recentAnalyses.map(item => `
      <div class="finding">
        <h4>
          <span>${escapeHtml(item.fileName || 'manual-entry.log')}</span>
          <span class="tag ${getSeverityClass(item.severity)}">${escapeHtml(item.severity || 'INFO')}</span>
        </h4>
        <div class="status">${escapeHtml(item.summary || 'No summary')}</div>
        <div class="status">Confidence: ${Number(item.confidence ?? 0)}% · ${new Date(item.analyzedAt).toLocaleString()}</div>
        <div class="history-item-actions">
          <button class="secondary" type="button" data-analysis-id="${escapeHtml(item.id)}">View analysis</button>
          <button class="danger" type="button" data-action="delete" data-analysis-id="${escapeHtml(item.id)}">Delete</button>
        </div>
      </div>
    `).join('');
}

function renderResult(data, fileName) {
  currentAnalysis = data;
  currentAnalysis.fileName = fileName || currentAnalysis.fileName || 'manual-entry.log';

  severityBadge.textContent = data.severity || 'INFO';
  severityBadge.className = 'badge';
  severityBadge.classList.add(getSeverityClass(data.severity));
  fileNameMeta.textContent = fileName || 'Uploaded log';
  confidenceMeta.textContent = `Confidence: ${data.confidence ?? 0}%`;

  const findingsHtml = (data.findings || []).map(find => `
    <div class="finding">
      <h4>
        <span>${find.endLineNumber > find.lineNumber ? `Lines ${find.lineNumber}-${find.endLineNumber}` : `Line ${find.lineNumber}`}</span>
        <span class="tag ${getSeverityClass(find.severity)}">${find.severity}</span>
      </h4>
      ${find.timestamp ? `<div class="status">${escapeHtml(find.timestamp)}</div>` : ''}
      <div><strong>${find.category}</strong></div>
      <div>${escapeHtml(find.message)}</div>
      <div class="status">Evidence: ${escapeHtml(find.evidence)}</div>
      <div class="status">Suggestion: ${escapeHtml(find.suggestion)}</div>
    </div>
  `).join('') || '<div class="status">No error signatures found.</div>';

  const recommendationsHtml = (data.recommendations || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');
  const truncationNotice = data.findingsTruncated
    ? `<div class="status" role="status">Showing the first ${data.findings.length} findings. Overall severity includes all detected lines.</div>`
    : '';

  resultContent.innerHTML = `
    <div class="summary">${escapeHtml(data.summary || 'No summary available.')}</div>
    ${truncationNotice}
    <div class="meta">
      <span>Lines: ${data.statistics?.totalLines ?? 0}</span>
      <span>Error-like: ${data.statistics?.errorLikeLines ?? 0}</span>
      <span>Top category: ${escapeHtml(data.statistics?.topCategory || 'General')}</span>
    </div>
    <div><strong>Recommendations</strong><ul>${recommendationsHtml}</ul></div>
    <div><strong>Findings</strong>${findingsHtml}</div>
  `;
}

function getSeverityClass(severity) {
  const normalized = (severity || 'INFO').toLowerCase();
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  return 'info';
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

loadRecentAnalyses();
