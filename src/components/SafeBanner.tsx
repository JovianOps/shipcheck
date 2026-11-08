import { useMemo } from 'react';
import type { ScanOptions, ScanResult } from '../types';
import { formatNumber } from '../utils';

type VerdictKind = 'unsafe' | 'safe' | 'unknown';

interface Verdict {
  kind: VerdictKind;
  headline: string;
  detail: string;
}

function computeVerdict(result: ScanResult, options: ScanOptions | null): Verdict {
  let secrets = 0;
  let pii = 0;
  for (const finding of result.findings) {
    if (finding.category === 'secrets') secrets += 1;
    else if (finding.category === 'pii') pii += 1;
  }

  if (secrets > 0 || pii > 0) {
    return {
      kind: 'unsafe',
      headline: 'NO — secrets or PII found',
      detail: `${formatNumber(secrets)} secret and ${formatNumber(pii)} PII finding(s). Remove or rotate them before sharing this repository.`,
    };
  }

  const reasons: string[] = [];
  if (options && !options.secretsPii) reasons.push('the secrets/PII scan was disabled');
  if (result.truncated) reasons.push('results were truncated');
  if (result.invalidFindings > 0) {
    reasons.push(`${formatNumber(result.invalidFindings)} finding(s) could not be validated`);
  }
  if (reasons.length > 0) {
    return {
      kind: 'unknown',
      headline: 'UNKNOWN — cannot confirm',
      detail: `Not confirmed safe because ${reasons.join(', ')}.`,
    };
  }

  return {
    kind: 'safe',
    headline: 'YES — no secrets or PII found',
    detail: `Scanned ${formatNumber(result.filesScanned)} files. Readiness findings do not affect upload safety.`,
  };
}

interface Props {
  result: ScanResult;
  options: ScanOptions | null;
}

export function SafeBanner({ result, options }: Props) {
  const verdict = useMemo(() => computeVerdict(result, options), [result, options]);
  const icon = verdict.kind === 'unsafe' ? '✕' : verdict.kind === 'safe' ? '✓' : '!';

  return (
    <section className={`banner banner-${verdict.kind}`} role="status" aria-label="Upload safety verdict">
      <span className="banner-icon" aria-hidden="true">
        {icon}
      </span>
      <div>
        <div className="banner-eyebrow">SAFE TO UPLOAD?</div>
        <div className="banner-headline">{verdict.headline}</div>
        <p className="banner-detail">{verdict.detail}</p>
      </div>
    </section>
  );
}
