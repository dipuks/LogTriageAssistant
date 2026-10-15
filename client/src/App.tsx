import { useCallback, useEffect, useRef, useState } from 'react';
import type { ChangeEvent, DragEvent, FormEvent, KeyboardEvent } from 'react';
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  ArrowUp,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  Clock3,
  FileCode2,
  FileInput,
  FileText,
  Flame,
  Gauge,
  History,
  LoaderCircle,
  LogOut,
  Search,
  ShieldCheck,
  Sparkles,
  Trash2,
  Upload,
  WandSparkles,
  X
} from 'lucide-react';

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'INFO';
type Finding = {
  lineNumber: number;
  endLineNumber: number;
  timestamp?: string | null;
  message: string;
  severity: Severity;
  category: string;
  evidence: string;
  suggestion: string;
};
type Analysis = {
  id: string;
  fileName?: string | null;
  analyzedAt: string;
  summary: string;
  severity: Severity;
  confidence: number;
  findingsTruncated: boolean;
  statistics: {
    totalLines: number;
    errorLikeLines: number;
    uniqueCategories: number;
    topCategory: string;
  };
  findings: Finding[];
  recommendations: string[];
};
type HistoryItem = Pick<Analysis, 'id' | 'analyzedAt' | 'fileName' | 'severity' | 'summary' | 'confidence'>;
type HistoryPage = {
  items: HistoryItem[];
  totalCount: number;
  page: number;
  pageSize: number;
  totalPages: number;
};
type Provider = { id: string; name: string; configured: boolean; privacy: string };
type AiBrief = {
  provider: string;
  model: string;
  summary: string;
  likelyCause: string;
  impact: string;
  evidence: string[];
  nextSteps: string[];
  caveat: string;
};

const sampleLog = `2026-10-06 12:18:01 ERROR Failed to connect to database
2026-10-06 12:18:03 WARN Retrying request to API gateway
2026-10-06 12:18:09 ERROR Timeout while waiting for upstream service
2026-10-06 12:18:11 Exception: System.InvalidOperationException: service unavailable
2026-10-06 12:18:15 FATAL Resource exhaustion detected after 5000 requests`;

let csrfToken: string | null = null;

async function requestError(response: Response): Promise<string> {
  try {
    const body = await response.json();
    return body.detail || body.title || body.error || `Request failed (${response.status}).`;
  } catch {
    return `Request failed (${response.status}).`;
  }
}

async function csrfHeaders(headers: HeadersInit = {}): Promise<Headers> {
  if (!csrfToken) {
    const response = await fetch('/api/auth/csrf');
    if (!response.ok) throw new Error(await requestError(response));
    csrfToken = (await response.json()).token;
  }
  const result = new Headers(headers);
  result.set('X-CSRF-TOKEN', csrfToken!);
  return result;
}

async function ensureOk(response: Response): Promise<void> {
  if (response.status === 401) {
    window.location.assign('/login.html');
    throw new Error('Your session expired. Sign in again.');
  }
  if (!response.ok) throw new Error(await requestError(response));
}

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <a className={`brand ${compact ? 'brand-compact' : ''}`} href="/" aria-label="LogTriage home">
      <span className="brand-symbol" aria-hidden="true">
        <FileText size={22} strokeWidth={2.2} />
        <Activity className="brand-signal" size={13} strokeWidth={2.8} />
      </span>
      <span className="brand-wordmark">logtriage<span className="brand-period text-orange-500">.</span></span>
    </a>
  );
}

function AuthScreen({ register }: { register: boolean }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    document.title = `${register ? 'Create account' : 'Sign in'} · LogTriage`;
  }, [register]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError('');
    const form = new FormData(event.currentTarget);
    const username = String(form.get('username') || '');
    const password = String(form.get('password') || '');
    const confirmPassword = String(form.get('confirmPassword') || '');
    if (register && password !== confirmPassword) {
      setError('Passwords do not match.');
      setBusy(false);
      return;
    }

    try {
      const headers = await csrfHeaders({ 'Content-Type': 'application/json' });
      const response = await fetch(register ? '/api/auth/register' : '/api/auth/login', {
        method: 'POST',
        headers,
        body: JSON.stringify(register
          ? { username, password, confirmPassword }
          : { username, password })
      });
      if (!response.ok) {
        if (response.status === 429) {
          setError(register
            ? 'Too many account attempts. Wait a minute and try again.'
            : 'Too many sign-in attempts. Wait a minute and try again.');
        } else {
          setError(await requestError(response));
        }
        return;
      }
      window.location.assign('/');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'The request could not be completed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-page">
      <div className="auth-orb auth-orb-one" />
      <div className="auth-orb auth-orb-two" />
      <div className="auth-shell">
        <section className="auth-art">
          <div className="auth-art-top"><Brand compact /><span className="art-stars"><Sparkles size={16} /></span></div>
          <div className="auth-art-copy">
            <span className="auth-overline">{register ? 'A BETTER WAY TO DEBUG' : 'INCIDENTS, IN FOCUS'}</span>
            <h1>{register ? <>Your logs.<br /><span>Your clarity.</span></> : <>Less noise.<br /><span>More signal.</span></>}</h1>
            <p>Turn application logs into clear findings and confident next steps.</p>
          </div>
          <div className="art-bottom">
            <div className="art-wave"><span /><span /><span /><span /><span /><span /><span /><span /><span /><span /></div>
            <span>Private workspace <ShieldCheck size={14} /></span>
          </div>
          <div className="art-deco art-deco-one" /><div className="art-deco art-deco-two" />
        </section>
        <section className="auth-form-panel">
          <div className="auth-form-inner">
            <span className="auth-chip"><span /> {register ? 'GET STARTED' : 'WELCOME BACK'}</span>
            <h2>{register ? 'Create your account' : 'Sign in to LogTriage'}</h2>
            <p className="auth-description">
              {register ? 'Your private space for calmer incident response.' : 'Pick up where you left off in your workspace.'}
            </p>
            <form className="auth-form" onSubmit={submit}>
              <label htmlFor="username">Username
                <input
                  id="username"
                  name="username"
                  autoComplete="username"
                  required
                  minLength={register ? 3 : undefined}
                  maxLength={register ? 32 : 100}
                  pattern={register ? '[A-Za-z0-9][A-Za-z0-9._-]*' : undefined}
                  aria-describedby={register ? 'usernameHint' : undefined}
                  autoFocus
                />
                {register && <small id="usernameHint">3–32 characters · letters, numbers, . _ -</small>}
              </label>
              <label htmlFor="password">Password
                <input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete={register ? 'new-password' : 'current-password'}
                  required
                  minLength={register ? 12 : undefined}
                  maxLength={1024}
                  aria-describedby={register ? 'passwordHint' : undefined}
                />
                {register && <small id="passwordHint">Use at least 12 characters.</small>}
              </label>
              {register && (
                <label htmlFor="confirmPassword">Confirm password
                  <input id="confirmPassword" name="confirmPassword" type="password" autoComplete="new-password" required minLength={12} maxLength={1024} />
                </label>
              )}
              <button id={register ? 'registerButton' : 'loginButton'} className="auth-submit" type="submit" disabled={busy}>
                {busy ? <LoaderCircle className="spin" size={17} /> : register ? <Sparkles size={16} /> : <ArrowRight size={16} />}
                {busy ? (register ? 'Creating your account…' : 'Signing in…') : register ? 'Create your account' : 'Sign in'}
              </button>
              <p className="form-error" role="status" aria-live="polite">{error}</p>
            </form>
            <div className="auth-foot">
              {register
                ? <>Already have an account? <a href="/login.html">Sign in</a></>
                : <>New to LogTriage? <a href="/register.html">Create an account</a></>}
            </div>
            <div className="auth-privacy"><ShieldCheck size={15} /> Your saved analyses are private to your account.</div>
          </div>
        </section>
      </div>
      <span className="auth-copyright">LOGTRIAGE · MADE FOR THE MOMENTS THAT MATTER</span>
    </main>
  );
}

function SeverityPill({ severity }: { severity: string }) {
  const kind = severity.toLowerCase();
  const Icon = kind === 'critical' ? Flame : kind === 'high' ? CircleAlert : kind === 'medium' ? Activity : Check;
  return <span className={`severity-pill severity-${kind}`}><Icon size={12} /> {severity}</span>;
}

function EmptyState({ title, detail, icon = true }: { title: string; detail: string; icon?: boolean }) {
  return (
    <div className="empty-state">
      {icon && <span className="empty-art"><FileInput size={22} /></span>}
      <strong>{title}</strong><span>{detail}</span>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  return (
    <article className={`finding-card finding-${finding.severity.toLowerCase()}`}>
      <div className="finding-topline">
        <span className="line-marker">LINES {finding.endLineNumber > finding.lineNumber
          ? `${finding.lineNumber}–${finding.endLineNumber}` : finding.lineNumber}</span>
        <SeverityPill severity={finding.severity} />
      </div>
      {finding.timestamp && <div className="finding-timestamp"><Clock3 size={12} /> {finding.timestamp}</div>}
      <div className="finding-category">{finding.category}</div>
      <p className="finding-message">{finding.message}</p>
      <div className="finding-detail"><span>Evidence</span>{finding.evidence}</div>
      <div className="finding-detail"><span>Try this</span>{finding.suggestion}</div>
    </article>
  );
}

function Dashboard() {
  const [logText, setLogText] = useState('');
  const [fileName, setFileName] = useState('');
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [history, setHistory] = useState<HistoryPage | null>(null);
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [providers, setProviders] = useState<Provider[]>([]);
  const [provider, setProvider] = useState('ollama');
  const [brief, setBrief] = useState<AiBrief | null>(null);
  const [busy, setBusy] = useState(false);
  const [aiBusy, setAiBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [notice, setNotice] = useState('');
  const [aiError, setAiError] = useState('');
  const [username, setUsername] = useState('');
  const [copied, setCopied] = useState(false);
  const searchTimer = useRef<number | undefined>(undefined);
  const requestId = useRef(0);
  const fileRef = useRef<HTMLInputElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const availableProvider = providers.find(item => item.id === provider);
  const canAskAi = Boolean(logText.trim() && availableProvider?.configured && !aiBusy);

  const loadHistory = useCallback(async (targetPage: number, query: string, filter: string) => {
    const id = ++requestId.current;
    try {
      const params = new URLSearchParams({ page: String(targetPage), pageSize: '20' });
      if (query.trim()) params.set('search', query.trim());
      if (filter) params.set('severity', filter);
      const response = await fetch(`/api/history?${params}`);
      await ensureOk(response);
      const data: HistoryPage = await response.json();
      if (requestId.current === id) {
        setHistory(data);
        setPage(data.page);
      }
    } catch {
      if (requestId.current === id) setHistory(null);
    }
  }, []);

  useEffect(() => {
    document.title = 'Incident workspace · LogTriage';
    void loadHistory(1, '', '');
    void (async () => {
      try {
        const [providerResponse, statusResponse] = await Promise.all([
          fetch('/api/ai/providers'),
          fetch('/api/auth/status')
        ]);
        await ensureOk(providerResponse);
        const configured: Provider[] = await providerResponse.json();
        setProviders(configured);
        const preferred = configured.find(item => item.id === 'ollama' && item.configured)
          ?? configured.find(item => item.configured);
        if (preferred) setProvider(preferred.id);
        if (statusResponse.ok) setUsername((await statusResponse.json()).username || '');
      } catch (cause) {
        setAiError(cause instanceof Error ? cause.message : 'AI provider settings are unavailable.');
      }
    })();
  }, [loadHistory]);

  useEffect(() => {
    window.clearTimeout(searchTimer.current);
    searchTimer.current = window.setTimeout(() => {
      setPage(1);
      void loadHistory(1, search, severity);
    }, 250);
    return () => window.clearTimeout(searchTimer.current);
  }, [search, severity, loadHistory]);

  useEffect(() => {
    function shortcut(event: globalThis.KeyboardEvent) {
      if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
        event.preventDefault();
        if (event.shiftKey) {
          if (canAskAi) void runAi();
        } else if (logText.trim() && !busy) {
          void analyze(logText, fileName || 'manual-entry.log');
        }
      }
    }
    document.addEventListener('keydown', shortcut);
    return () => document.removeEventListener('keydown', shortcut);
  });

  async function runAi() {
    if (!logText.trim() || !availableProvider?.configured || aiBusy) return;
    setAiBusy(true);
    setAiError('');
    setBrief(null);
    try {
      const headers = await csrfHeaders({ 'Content-Type': 'application/json' });
      const response = await fetch('/api/ai/analyze', {
        method: 'POST',
        headers,
        body: JSON.stringify({ logText, provider })
      });
      await ensureOk(response);
      setBrief(await response.json());
    } catch (cause) {
      setAiError(cause instanceof Error ? cause.message : 'AI analysis could not be completed.');
    } finally {
      setAiBusy(false);
    }
  }

  async function analyze(text: string, name: string) {
    if (!text.trim() || busy) return;
    setBusy(true);
    setNotice('');
    setBrief(null);
    try {
      const headers = await csrfHeaders({ 'Content-Type': 'application/json' });
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers,
        body: JSON.stringify({ logText: text, fileName: name })
      });
      await ensureOk(response);
      const result: Analysis = await response.json();
      setAnalysis(result);
      setFileName(name);
      setPage(1);
      void loadHistory(1, search, severity);
    } catch (cause) {
      setNotice(cause instanceof Error ? cause.message : 'The log could not be analyzed.');
    } finally {
      setBusy(false);
    }
  }

  async function analyzeFile(file: File) {
    if (file.size > 2 * 1024 * 1024) {
      setNotice('Uploaded files must be no larger than 2 MB.');
      return;
    }
    setBusy(true);
    setNotice('');
    setBrief(null);
    const form = new FormData();
    form.append('file', file);
    try {
      const response = await fetch('/api/analyze-file', {
        method: 'POST',
        headers: await csrfHeaders(),
        body: form
      });
      await ensureOk(response);
      const result: Analysis = await response.json();
      setAnalysis(result);
      setFileName(file.name);
      setLogText(await file.text());
      setPage(1);
      void loadHistory(1, search, severity);
    } catch (cause) {
      setNotice(cause instanceof Error ? cause.message : 'The file could not be analyzed.');
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = '';
    }
  }

  async function logout() {
    try {
      const response = await fetch('/api/auth/logout', {
        method: 'POST',
        headers: await csrfHeaders()
      });
      await ensureOk(response);
      window.location.assign('/login.html');
    } catch (cause) {
      setNotice(cause instanceof Error ? cause.message : 'Could not sign out.');
    }
  }

  async function copySummary() {
    if (!analysis) return;
    try {
      await navigator.clipboard.writeText(
        `${analysis.summary}\n\nSeverity: ${analysis.severity}\nSignal: ${analysis.confidence}%\nFile: ${analysis.fileName || fileName || 'manual-entry.log'}`
      );
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      setNotice('Clipboard access is blocked in this browser.');
    }
  }

  function exportAnalysis() {
    if (!analysis) return;
    const blob = new Blob([JSON.stringify(analysis, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${(analysis.fileName || fileName || 'log-analysis').replace(/\.[^.]+$/, '') || 'log-analysis'}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  async function openSaved(itemId: string) {
    try {
      const response = await fetch(`/api/recent/${encodeURIComponent(itemId)}`);
      await ensureOk(response);
      const saved: Analysis = await response.json();
      setAnalysis(saved);
      setFileName(saved.fileName || '');
      setBrief(null);
      document.getElementById('analysisPanel')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (cause) {
      setNotice(cause instanceof Error ? cause.message : 'Could not load this analysis.');
    }
  }

  async function deleteSaved(itemId: string) {
    if (!window.confirm('Delete this saved analysis? This cannot be undone.')) return;
    try {
      const response = await fetch(`/api/recent/${encodeURIComponent(itemId)}`, {
        method: 'DELETE',
        headers: await csrfHeaders()
      });
      await ensureOk(response);
      if (analysis?.id === itemId) setAnalysis(null);
      void loadHistory(page, search, severity);
    } catch (cause) {
      setNotice(cause instanceof Error ? cause.message : 'Could not delete this analysis.');
    }
  }

  function changeSearch(event: ChangeEvent<HTMLInputElement>) {
    setSearch(event.target.value);
  }

  function selectFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (file) void analyzeFile(file);
  }

  function dropFile(event: DragEvent<HTMLElement>) {
    event.preventDefault();
    setDragging(false);
    const file = event.dataTransfer.files[0];
    if (file) void analyzeFile(file);
  }

  function enterOnDropZone(event: DragEvent<HTMLElement>) {
    event.preventDefault();
    setDragging(true);
  }

  function leaveDropZone(event: DragEvent<HTMLElement>) {
    if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false);
  }

  function loadSample() {
    setLogText(sampleLog);
    setFileName('sample.log');
    void analyze(sampleLog, 'sample.log');
  }

  function clearWorkspace() {
    setLogText('');
    setFileName('');
    setAnalysis(null);
    setBrief(null);
    setNotice('');
    setAiError('');
    if (fileRef.current) fileRef.current.value = '';
    inputRef.current?.focus();
  }

  function handleTextareaKey(event: KeyboardEvent<HTMLTextAreaElement>) {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      void analyze(logText, fileName || 'manual-entry.log');
    }
  }

  const lineCount = logText ? logText.split(/\r\n|\r|\n/).length : 0;
  const shown = history?.items.length ?? 0;
  const firstItem = shown ? (page - 1) * 20 + 1 : 0;
  const lastItem = firstItem + shown - 1;
  const hasHistoryFilters = Boolean(search.trim() || severity);

  return (
    <div className="app-frame">
      <header className="topbar">
        <Brand />
        <div className="topbar-right">
          <div className="workspace-identity">
            <span className="online-dot" />
            <span className="workspace-label">PRIVATE WORKSPACE</span>
            {username && <span className="user-chip">{username.slice(0, 1).toUpperCase()}</span>}
          </div>
          <button className="icon-button signout-button" type="button" onClick={() => void logout()} aria-label="Sign out" title="Sign out">
            <LogOut size={16} /><span>Sign out</span>
          </button>
        </div>
      </header>
      <main className="app-main">
        <section className="hero-section">
          <div className="hero-copy">
            <span className="hero-eyebrow"><span className="eyebrow-bloom"><Sparkles size={12} /></span> INCIDENT INTELLIGENCE</span>
            <h1>Make the <span>signal</span> impossible to miss.</h1>
            <p>Turn noisy logs into a clear picture of what broke — and where to look next.</p>
          </div>
          <div className="hero-art" aria-hidden="true">
            <div className="hero-art-orbit orbit-a" /><div className="hero-art-orbit orbit-b" />
            <div className="hero-art-core"><Activity size={35} strokeWidth={1.7} /></div>
            <span className="orbit-dot dot-a" /><span className="orbit-dot dot-b" /><span className="orbit-dot dot-c" />
            <span className="hero-art-label">SIGNAL / DETECTED</span>
          </div>
        </section>

        <section className="workspace-grid" aria-label="Log analysis workspace">
          <article className={`surface input-surface ${dragging ? 'is-dragging' : ''}`} onDragOver={enterOnDropZone} onDragLeave={leaveDropZone} onDrop={dropFile}>
            <div className="surface-heading">
              <div className="heading-title">
                <span className="step-bubble bubble-violet">01</span>
                <div><span className="overline">START WITH THE EVIDENCE</span><h2>Log source</h2></div>
              </div>
              <span className="size-label"><FileCode2 size={13} /> 2 MB max</span>
            </div>
            <div className="editor-shell">
              <div className="editor-topbar"><span className="editor-lights"><i /><i /><i /></span><span>RAW LOG INPUT</span><span>{lineCount} {lineCount === 1 ? 'LINE' : 'LINES'}</span></div>
              <label className="sr-only" htmlFor="logInput">Paste or type log content</label>
              <textarea
                ref={inputRef}
                id="logInput"
                value={logText}
                onChange={event => { setLogText(event.target.value); setBrief(null); setAiError(''); }}
                onKeyDown={handleTextareaKey}
                spellCheck={false}
                placeholder={'Paste your application logs here…\n\nor drop a .log, .txt, .json, or .csv file'}
              />
              {dragging && <div className="drop-overlay"><Upload size={25} /><strong>Drop your log file</strong><span>We’ll inspect and triage it instantly</span></div>}
            </div>
            <div className="input-toolbar">
              <button id="analyzeBtn" className="button button-primary" type="button" disabled={!logText.trim() || busy} onClick={() => void analyze(logText, fileName || 'manual-entry.log')}>
                {busy ? <LoaderCircle className="spin" size={16} /> : <Activity size={16} />}
                {busy ? 'Analyzing…' : 'Analyze Log'}
                {!busy && <kbd>Ctrl ↵</kbd>}
              </button>
              <label className="button button-ghost upload-control" htmlFor="fileInput"><Upload size={15} /> Upload</label>
              <input ref={fileRef} id="fileInput" className="sr-only" type="file" accept=".txt,.log,.json,.csv" onChange={selectFile} />
              <span className="toolbar-divider" />
              <button id="sampleBtn" className="button button-soft" type="button" onClick={loadSample}>Try a sample</button>
              <button id="clearBtn" className="button button-soft button-clear" type="button" onClick={clearWorkspace}><X size={14} /><span>Clear</span></button>
            </div>
            <p className="input-footnote"><ShieldCheck size={13} /> Full logs are never saved. Matched evidence is redacted before storage.</p>
          </article>

          <article className="surface analysis-surface" id="analysisPanel">
            <div className="surface-heading">
              <div className="heading-title">
                <span className="step-bubble bubble-coral">02</span>
                <div><span className="overline">UNDERSTAND WHAT HAPPENED</span><h2>Incident triage</h2></div>
              </div>
              {analysis && <SeverityPill severity={analysis.severity} />}
            </div>
            <div className="analysis-meta">
              <span className="filename"><FileText size={13} /> {fileName || analysis?.fileName || 'Awaiting log input'}</span>
              {analysis && <span className="signal-label"><Gauge size={13} /> Signal {analysis.confidence}%</span>}
              {analysis && <div className="analysis-actions">
                <button id="copyBtn" className="mini-action" type="button" onClick={() => void copySummary()} aria-label="Copy summary" title="Copy summary">
                  {copied ? <Check size={14} /> : <FileInput size={14} />}
                </button>
                <button id="downloadBtn" className="mini-action" type="button" onClick={exportAnalysis} aria-label="Download JSON" title="Download JSON"><ArrowDownToLine size={14} /></button>
              </div>}
            </div>
            {notice && <p className="notice" role="status"><CircleAlert size={14} /> {notice}</p>}
            <div className="result-content" id="resultContent" aria-live="polite">
              {!analysis && !busy && <EmptyState title="Your incident story starts here" detail="Run a log analysis to see severity, evidence, and practical next steps." />}
              {busy && <div className="analyzing-state"><LoaderCircle className="spin" size={21} /><strong>Finding the signal…</strong><span>Grouping related events and scoring severity.</span></div>}
              {analysis && <>
                <div className="analysis-summary"><div className="summary-icon"><Sparkles size={16} /></div><div><span className="summary-overline">QUICK READ</span><p>{analysis.summary}</p></div></div>
                <div className="stat-grid">
                  <div className="stat-tile stat-purple"><span>LOG LINES</span><strong>{analysis.statistics.totalLines.toLocaleString()}</strong><FileText size={15} /></div>
                  <div className="stat-tile stat-peach"><span>SIGNAL HITS</span><strong>{analysis.statistics.errorLikeLines.toLocaleString()}</strong><Activity size={15} /></div>
                  <div className="stat-tile stat-blue"><span>TOP SIGNAL</span><strong>{analysis.statistics.topCategory}</strong><Gauge size={15} /></div>
                </div>
                {analysis.findingsTruncated && <p className="truncation-note">Showing {analysis.findings.length} findings. Severity includes every detected line.</p>}
                <div className="result-section-heading"><span>Recommended next steps</span><i /></div>
                <div className="recommendation-list">
                  {analysis.recommendations.map((item, index) => <div className="recommendation" key={`${index}-${item}`}><span>{index + 1}</span><p>{item}</p></div>)}
                </div>
                <div className="result-section-heading"><span>Detected findings</span><span className="count-chip">{analysis.findings.length}</span></div>
                {analysis.findings.length
                  ? <div className="findings-list">{analysis.findings.map((finding, index) => <FindingCard key={`${finding.lineNumber}-${index}`} finding={finding} />)}</div>
                  : <p className="no-findings">No error signatures found in this log.</p>}
              </>}
            </div>
            <section className="ai-panel" aria-labelledby="aiHeading">
              <div className="ai-panel-heading">
                <span className="ai-icon-wrap"><WandSparkles size={17} /></span>
                <div><h3 id="aiHeading">Ask AI for a second perspective</h3><p>Evidence-based incident brief, in plain language.</p></div>
                <span className="optional-label">OPTIONAL</span>
              </div>
              <div className="ai-controls">
                <label className="sr-only" htmlFor="aiProvider">AI provider</label>
                <div className="provider-select-wrap">
                  <select id="aiProvider" value={provider} onChange={event => { setProvider(event.target.value); setBrief(null); }}>
                    {providers.map(item => <option value={item.id} disabled={!item.configured} key={item.id}>{item.configured ? item.name : `${item.name} — not configured`}</option>)}
                  </select><ChevronDown size={14} />
                </div>
                <button id="aiAnalyzeBtn" className="button button-ai" type="button" disabled={!canAskAi} onClick={() => void runAi()}>
                  {aiBusy ? <LoaderCircle className="spin" size={15} /> : <Sparkles size={15} />}
                  {aiBusy ? 'Thinking…' : 'Generate brief'} {!aiBusy && <ArrowUp size={13} />}
                </button>
              </div>
              <p className="ai-privacy"><ShieldCheck size={12} /> {availableProvider?.privacy || 'Configure Ollama or a hosted API on the server to enable AI briefs.'}</p>
              {aiError && <p className="ai-error" role="status"><CircleAlert size={13} /> {aiError}</p>}
              {aiBusy && <div className="ai-loading"><LoaderCircle className="spin" size={16} /> Building your incident brief…</div>}
              {brief && <div className="ai-brief" id="aiResults">
                <div className="ai-brief-model"><Sparkles size={12} /> {brief.provider} · {brief.model}</div>
                <h4>Incident overview</h4><p>{brief.summary}</p>
                <h4>Likely cause</h4><p>{brief.likelyCause}</p>
                <h4>Potential impact</h4><p>{brief.impact}</p>
                {brief.evidence.length > 0 && <><h4>Evidence</h4><ul>{brief.evidence.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul></>}
                <h4>Suggested investigation</h4><ol>{brief.nextSteps.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ol>
                <p className="ai-caveat">{brief.caveat || 'AI-generated hypothesis; verify against system metrics and deployment context.'}</p>
              </div>}
              {!brief && !aiBusy && !aiError && <div className="ai-placeholder" id="aiResults">Analyze a log, then ask AI for an extra perspective.</div>}
            </section>
          </article>
        </section>

        <section className="surface history-surface" aria-labelledby="historyHeading">
          <div className="history-header">
            <div className="history-title">
              <span className="history-icon"><History size={18} /></span>
              <div><span className="overline">YOUR PRIVATE ARCHIVE</span><h2 id="historyHeading">Recent analyses</h2></div>
              {history && <span className="history-total">{history.totalCount}</span>}
            </div>
            <div className="history-filters">
              <label className="search-box" htmlFor="historySearch"><Search size={15} /><input id="historySearch" type="search" value={search} onChange={changeSearch} placeholder="Search your analyses…" /></label>
              <label className="sr-only" htmlFor="historySeverity">Filter by severity</label>
              <div className="filter-select-wrap"><select id="historySeverity" value={severity} onChange={event => { setSeverity(event.target.value); setPage(1); }}><option value="">All severities</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="INFO">Info</option></select><ChevronDown size={14} /></div>
            </div>
          </div>
          <p className="history-count" id="historyCount">
            {history
              ? history.totalCount
                ? `Showing ${firstItem}–${lastItem} of ${history.totalCount} ${hasHistoryFilters ? 'matching' : 'saved'} analyses · Page ${history.page} of ${history.totalPages}`
                : hasHistoryFilters ? 'No matching analyses' : 'Showing 0 of 0 saved analyses'
              : 'Your saved analyses are temporarily unavailable.'}
          </p>
          <div className="history-list" id="recentList">
            {!history && <div className="history-empty"><LoaderCircle className="spin" size={18} /> Loading your saved analyses…</div>}
            {history?.totalCount === 0 && <div className="history-empty"><History size={19} /> Nothing here yet. Your next analysis will be saved to this private archive.</div>}
            {history?.items.map((item, index) => <article className="history-item" key={item.id}>
              <span className={`history-item-index index-${index % 4}`}><FileText size={15} /></span>
              <div className="history-item-main">
                <div className="history-item-name">{item.fileName || 'manual-entry.log'}</div>
                <p>{item.summary}</p>
                <span className="history-item-time"><Clock3 size={12} /> {new Date(item.analyzedAt).toLocaleString()}</span>
              </div>
              <div className="history-item-end">
                <SeverityPill severity={item.severity} />
                <div className="history-item-actions">
                  <button className="button button-view" type="button" data-analysis-id={item.id} onClick={() => void openSaved(item.id)}>View analysis</button>
                  <button className="history-delete" type="button" data-action="delete" data-analysis-id={item.id} onClick={() => void deleteSaved(item.id)} aria-label={`Delete ${item.fileName || 'analysis'}`} title="Delete analysis"><Trash2 size={14} /></button>
                </div>
              </div>
            </article>)}
          </div>
          <div className="history-footer">
            <span>Local rules are explainable. Always validate before acting.</span>
            <div className="pagination">
              <button className="button button-page" type="button" id="historyPrevious" disabled={!history || page <= 1} onClick={() => { const next = page - 1; setPage(next); void loadHistory(next, search, severity); }}><ChevronLeft size={15} /> Previous</button>
              <span className="page-label">{history?.totalPages ? `${page} / ${history.totalPages}` : '—'}</span>
              <button className="button button-page" type="button" id="historyNext" disabled={!history || page >= history.totalPages} onClick={() => { const next = page + 1; setPage(next); void loadHistory(next, search, severity); }}>Next <ChevronRight size={15} /></button>
            </div>
          </div>
        </section>
        <footer className="app-footer"><Brand compact /><span>CALM TRIAGE FOR COMPLEX SYSTEMS</span><span>Human judgment stays in the loop <ShieldCheck size={13} /></span></footer>
      </main>
    </div>
  );
}

export default function App() {
  const path = window.location.pathname.toLowerCase();
  if (path === '/login.html' || path === '/login') return <AuthScreen register={false} />;
  if (path === '/register.html' || path === '/register') return <AuthScreen register />;
  return <Dashboard />;
}
