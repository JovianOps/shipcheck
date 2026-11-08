import { useMemo } from 'react';
import type { ScanResult } from '../types';
import { formatDuration, formatNumber, riskLevel } from '../utils';

export function Summary({ result }: { result: ScanResult }) {
  const counts = useMemo(() => {
    const c = { secrets: 0, pii: 0, readiness: 0 };
    for (const finding of result.findings) c[finding.category] += 1;
    return c;
  }, [result.findings]);

  const risk = riskLevel(result.summary.riskScore);

  return (
    <section className="card" aria-labelledby="summary-title">
      <h2 id="summary-title">Summary</h2>
      <dl className="stats">
        <div className="stat stat-ok">
          <dt>Checks passed</dt>
          <dd>{formatNumber(result.summary.passed)}</dd>
        </div>
        <div className="stat stat-fail">
          <dt>Checks failed</dt>
          <dd>{formatNumber(result.summary.failed)}</dd>
        </div>
        <div className={`stat risk risk-${risk.level}`}>
          <dt>Risk score</dt>
          <dd>
            {result.summary.riskScore}
            <span className="stat-sub"> / 100 · {risk.label}</span>
          </dd>
          <div className="meter" aria-hidden="true">
            <div className="meter-fill" style={{ width: `${result.summary.riskScore}%` }} />
          </div>
        </div>
        <div className="stat">
          <dt>Files scanned</dt>
          <dd>{formatNumber(result.filesScanned)}</dd>
          <div className="stat-sub">{formatDuration(result.durationMs)}</div>
        </div>
      </dl>
      <p className="counts">
        <span>
          Secrets: <strong>{formatNumber(counts.secrets)}</strong>
        </span>
        <span>
          PII: <strong>{formatNumber(counts.pii)}</strong>
        </span>
        <span>
          Readiness: <strong>{formatNumber(counts.readiness)}</strong>
        </span>
      </p>
      {result.truncated ? (
        <p className="inline-warn" role="note">
          Results were truncated; some findings are not shown.
        </p>
      ) : null}
      {result.invalidFindings > 0 ? (
        <p className="inline-warn" role="note">
          {formatNumber(result.invalidFindings)} finding(s) were dropped because their data was malformed.
        </p>
      ) : null}
    </section>
  );
}
