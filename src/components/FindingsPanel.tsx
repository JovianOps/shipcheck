import {
  memo,
  useCallback,
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from 'react';
import { SEVERITIES } from '../types';
import type { CategoryFilter, Finding, Severity, SeverityFilter } from '../types';
import { CATEGORY_LABEL, SEVERITY_LABEL, SEVERITY_RANK, copyText, formatNumber, joinPath } from '../utils';
import { VirtualList } from './VirtualList';

const FILE_ROW_HEIGHT = 40;
const FINDING_ROW_HEIGHT = 128;

type Row =
  | { kind: 'file'; key: string; file: string; count: number; worst: Severity }
  | { kind: 'finding'; key: string; finding: Finding };

const rowHeight = (row: Row): number => (row.kind === 'file' ? FILE_ROW_HEIGHT : FINDING_ROW_HEIGHT);
const rowKey = (row: Row): string => row.key;

const TABS: ReadonlyArray<{ id: CategoryFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'secrets', label: CATEGORY_LABEL.secrets },
  { id: 'pii', label: CATEGORY_LABEL.pii },
  { id: 'readiness', label: CATEGORY_LABEL.readiness },
];

const SEVERITY_OPTIONS: ReadonlyArray<{ value: SeverityFilter; label: string }> = [
  { value: 'all', label: 'All severities' },
  ...SEVERITIES.map((s) => ({ value: s as SeverityFilter, label: SEVERITY_LABEL[s] })),
];

function buildRows(list: readonly Finding[]): { rows: Row[]; fileCount: number } {
  const groups = new Map<string, Finding[]>();
  for (const finding of list) {
    const group = groups.get(finding.file);
    if (group) group.push(finding);
    else groups.set(finding.file, [finding]);
  }

  const entries = Array.from(groups.entries()).map(([file, items]) => {
    items.sort((a, b) => a.line - b.line || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
    const worst = items.reduce<Severity>(
      (acc, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[acc] ? f.severity : acc),
      'info',
    );
    return { file, items, worst };
  });
  entries.sort((a, b) => SEVERITY_RANK[b.worst] - SEVERITY_RANK[a.worst] || a.file.localeCompare(b.file));

  const rows: Row[] = [];
  for (const entry of entries) {
    rows.push({ kind: 'file', key: `file:${entry.file}`, file: entry.file, count: entry.items.length, worst: entry.worst });
    for (const finding of entry.items) rows.push({ kind: 'finding', key: `f:${finding.id}`, finding });
  }
  return { rows, fileCount: entries.length };
}

interface FindingCardProps {
  finding: Finding;
  onCopy: (finding: Finding) => void;
}

const FindingCard = memo(function FindingCard({ finding, onCopy }: FindingCardProps) {
  const location = finding.line > 0 ? `${finding.file}:${finding.line}` : finding.file;
  return (
    <article className={`finding sev-${finding.severity}`}>
      <header className="finding-head">
        <span className={`badge sev sev-${finding.severity}`}>{SEVERITY_LABEL[finding.severity]}</span>
        <span className="badge cat">{CATEGORY_LABEL[finding.category]}</span>
        <strong className="finding-type">{finding.type}</strong>
        <code className="finding-loc" title={location}>
          {location}
        </code>
        <button
          type="button"
          className="btn btn-small"
          onClick={() => onCopy(finding)}
          aria-label={`Copy path of ${finding.file}`}
        >
          Copy path
        </button>
      </header>
      <code className="finding-preview" aria-label="Redacted preview">
        {finding.preview || '(no preview)'}
      </code>
      <p className="finding-fix">
        <strong>Fix:</strong> {finding.remediation || 'No remediation guidance provided.'}
      </p>
    </article>
  );
});

interface Props {
  findings: readonly Finding[];
  repoPath: string;
}

export function FindingsPanel({ findings, repoPath }: Props) {
  const [category, setCategory] = useState<CategoryFilter>('all');
  const [severity, setSeverity] = useState<SeverityFilter>('all');
  const [query, setQuery] = useState('');
  const deferredQuery = useDeferredValue(query);
  const [notice, setNotice] = useState('');
  const noticeTimer = useRef(0);
  const tabRefs = useRef<Partial<Record<CategoryFilter, HTMLButtonElement | null>>>({});

  useEffect(() => () => window.clearTimeout(noticeTimer.current), []);

  const haystacks = useMemo(
    () =>
      findings.map((f) =>
        `${f.file}\n${f.type}\n${f.ruleId}\n${f.preview}\n${f.remediation}`.toLowerCase(),
      ),
    [findings],
  );

  const counts = useMemo(() => {
    const c: Record<CategoryFilter, number> = { all: findings.length, secrets: 0, pii: 0, readiness: 0 };
    for (const f of findings) c[f.category] += 1;
    return c;
  }, [findings]);

  const needle = deferredQuery.trim().toLowerCase();

  const filtered = useMemo(() => {
    const out: Finding[] = [];
    findings.forEach((f, i) => {
      if (category !== 'all' && f.category !== category) return;
      if (severity !== 'all' && f.severity !== severity) return;
      if (needle && !(haystacks[i] ?? '').includes(needle)) return;
      out.push(f);
    });
    return out;
  }, [findings, haystacks, category, severity, needle]);

  const { rows, fileCount } = useMemo(() => buildRows(filtered), [filtered]);

  const handleCopy = useCallback(
    async (finding: Finding): Promise<void> => {
      const target = repoPath ? joinPath(repoPath, finding.file) : finding.file;
      const ok = await copyText(target);
      setNotice(ok ? `Copied path: ${finding.file}` : 'Copy failed: clipboard unavailable.');
      window.clearTimeout(noticeTimer.current);
      noticeTimer.current = window.setTimeout(() => setNotice(''), 3000);
    },
    [repoPath],
  );

  const renderRow = useCallback(
    (row: Row): JSX.Element => {
      if (row.kind === 'file') {
        return (
          <div className="file-row">
            <code title={row.file}>{row.file}</code>
            <span className="file-meta">
              <span className={`badge sev sev-${row.worst}`}>{SEVERITY_LABEL[row.worst]}</span>
              <span className="muted">{formatNumber(row.count)} finding(s)</span>
            </span>
          </div>
        );
      }
      return <FindingCard finding={row.finding} onCopy={(f) => void handleCopy(f)} />;
    },
    [handleCopy],
  );

  const onTabKeyDown = (event: KeyboardEvent<HTMLDivElement>): void => {
    const index = TABS.findIndex((t) => t.id === category);
    let next = index;
    if (event.key === 'ArrowRight') next = (index + 1) % TABS.length;
    else if (event.key === 'ArrowLeft') next = (index - 1 + TABS.length) % TABS.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = TABS.length - 1;
    else return;
    event.preventDefault();
    const tab = TABS[next];
    if (tab) {
      setCategory(tab.id);
      tabRefs.current[tab.id]?.focus();
    }
  };

  const filtersActive = category !== 'all' || severity !== 'all' || query !== '';
  const clearFilters = (): void => {
    setCategory('all');
    setSeverity('all');
    setQuery('');
  };

  return (
    <section className="card" aria-labelledby="findings-title">
      <h2 id="findings-title">Findings</h2>

      <div role="tablist" aria-label="Finding category" className="tabs" onKeyDown={onTabKeyDown}>
        {TABS.map((tab) => (
          <button
            key={tab.id}
            ref={(el) => {
              tabRefs.current[tab.id] = el;
            }}
            type="button"
            role="tab"
            id={`tab-${tab.id}`}
            aria-selected={category === tab.id}
            aria-controls="findings-panel"
            tabIndex={category === tab.id ? 0 : -1}
            className={`tab${category === tab.id ? ' tab-active' : ''}`}
            onClick={() => setCategory(tab.id)}
          >
            {tab.label} <span className="tab-count">{formatNumber(counts[tab.id])}</span>
          </button>
        ))}
      </div>

      <div className="filters">
        <label className="field">
          <span>Search</span>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="File, type, rule, preview…"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <label className="field">
          <span>Severity</span>
          <select value={severity} onChange={(e) => setSeverity(e.target.value as SeverityFilter)}>
            {SEVERITY_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </label>
        {filtersActive ? (
          <button type="button" className="btn btn-small" onClick={clearFilters}>
            Clear filters
          </button>
        ) : null}
      </div>

      <p className="muted" aria-live="polite">
        Showing {formatNumber(filtered.length)} of {formatNumber(findings.length)} findings in{' '}
        {formatNumber(fileCount)} file(s)
      </p>

      <div id="findings-panel" role="tabpanel" aria-labelledby={`tab-${category}`}>
        {findings.length === 0 ? (
          <div className="empty">
            <strong>No findings.</strong>
            <span>The scan completed without reporting any issues.</span>
          </div>
        ) : filtered.length === 0 ? (
          <div className="empty">
            <strong>No findings match the current filters.</strong>
            <button type="button" className="btn btn-small" onClick={clearFilters}>
              Clear filters
            </button>
          </div>
        ) : (
          <VirtualList
            rows={rows}
            rowHeight={rowHeight}
            renderRow={renderRow}
            getKey={rowKey}
            resetKey={`${category}|${severity}|${needle}`}
            label="Findings grouped by file"
          />
        )}
      </div>

      <div className="toast" role="status" aria-live="polite">
        {notice}
      </div>
    </section>
  );
}
