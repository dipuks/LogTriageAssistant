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
const recentList = document.getElementById('recentList');
const historySearch = document.getElementById('historySearch');
const historySeverity = document.getElementById('historySeverity');
const historyCount = document.getElementById('historyCount');

let currentAnalysis = null;
let recentAnalyses = [];

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

  const analysis = recentAnalyses.find(item => item.id === button.dataset.analysisId);
  if (!analysis) return;

  renderResult(analysis, analysis.fileName);
  document.getElementById('resultPanel').scrollIntoView({ behavior: 'smooth', block: 'start' });
});

historySearch.addEventListener('input', renderRecentAnalyses);
historySeverity.addEventListener('change', renderRecentAnalyses);

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
  resultContent.innerHTML = '<div class="status">Paste a log and click “Analyze Log” to begin.</div>';
});

copyBtn.addEventListener('click', async () => {
  if (!currentAnalysis) {
    resultContent.innerHTML = '<div class="status">There is no analysis result to copy yet.</div>';
    return;
  }

  const summary = `${currentAnalysis.summary}\n\nSeverity: ${currentAnalysis.severity}\nConfidence: ${currentAnalysis.confidence}%\nFile: ${currentAnalysis.fileName || 'manual-entry.log'}`;

  try {
    await navigator.clipboard.writeText(summary);
    resultContent.innerHTML = '<div class="status">Summary copied to the clipboard.</div>';
  } catch {
    resultContent.innerHTML = '<div class="status">Clipboard access is blocked in this browser.</div>';
  }
});

downloadBtn.addEventListener('click', () => {
  if (!currentAnalysis) {
    resultContent.innerHTML = '<div class="status">There is no analysis result to download yet.</div>';
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
  URL.revokeObjectURL(url);
});

analyzeBtn.addEventListener('click', async () => {
  const text = logInput.value.trim();
  if (!text) {
    resultContent.innerHTML = '<div class="status">Please paste log content first.</div>';
    return;
  }

  await analyzeLog(text, 'manual-entry.log');
});

fileInput.addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (!file) return;

  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await fetch('/api/analyze-file', {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      throw new Error(await getResponseError(response));
    }

    const data = await response.json();
    fileNameMeta.textContent = file.name;
    renderResult(data, file.name);
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
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ logText, fileName })
    });

    if (!response.ok) {
      throw new Error(await getResponseError(response));
    }

    const data = await response.json();
    renderResult(data, fileName);
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

function showError(error) {
  const message = error instanceof Error ? error.message : 'An unexpected error occurred.';
  resultContent.innerHTML = `<div class="status">${escapeHtml(message)}</div>`;
}

async function loadRecentAnalyses() {
  try {
    const response = await fetch('/api/recent?limit=100');
    if (!response.ok) {
      throw new Error('Recent analyses request failed');
    }

    const list = await response.json();
    recentAnalyses = Array.isArray(list) ? list : [];
    renderRecentAnalyses();
  } catch (error) {
    historyCount.textContent = '';
    recentList.innerHTML = '<div class="status">Recent analyses are unavailable right now.</div>';
  }
}

async function deleteAnalysis(id) {
  if (!window.confirm('Delete this saved analysis? This cannot be undone.')) {
    return;
  }

  try {
    const response = await fetch(`/api/recent/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (!response.ok) {
      throw new Error(await getResponseError(response));
    }

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
  if (recentAnalyses.length === 0) {
    historyCount.textContent = '';
    recentList.innerHTML = '<div class="status">No previous analyses yet.</div>';
    return;
  }

  const query = historySearch.value.trim().toLocaleLowerCase();
  const severity = historySeverity.value;
  const filtered = recentAnalyses.filter(item => {
    if (severity && (item.severity || 'INFO').toUpperCase() !== severity) {
      return false;
    }

    if (!query) {
      return true;
    }

    const findingText = (item.findings || [])
      .map(finding => `${finding.category} ${finding.message} ${finding.evidence}`)
      .join(' ');
    const searchableText = `${item.fileName || ''} ${item.summary || ''} ${item.statistics?.topCategory || ''} ${findingText}`;
    return searchableText.toLocaleLowerCase().includes(query);
  });

  historyCount.textContent = `Showing ${filtered.length} of the latest ${recentAnalyses.length} saved analyses`;
  if (filtered.length === 0) {
    recentList.innerHTML = '<div class="status">No analyses match the selected filters.</div>';
    return;
  }

  recentList.innerHTML = filtered.map(item => `
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
        <span>Line ${find.lineNumber}</span>
        <span class="tag ${getSeverityClass(find.severity)}">${find.severity}</span>
      </h4>
      <div><strong>${find.category}</strong></div>
      <div>${escapeHtml(find.message)}</div>
      <div class="status">Evidence: ${escapeHtml(find.evidence)}</div>
      <div class="status">Suggestion: ${escapeHtml(find.suggestion)}</div>
    </div>
  `).join('') || '<div class="status">No error signatures found.</div>';

  const recommendationsHtml = (data.recommendations || []).map(item => `<li>${escapeHtml(item)}</li>`).join('');

  resultContent.innerHTML = `
    <div class="summary">${escapeHtml(data.summary || 'No summary available.')}</div>
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
