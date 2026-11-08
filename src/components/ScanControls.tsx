import type { ChangeEvent } from 'react';
import type { ScanOptions, ScanProgress, ScanStatus } from '../types';
import { formatNumber } from '../utils';

interface Props {
  options: ScanOptions;
  status: ScanStatus;
  progress: ScanProgress | null;
  canScan: boolean;
  onChange: (next: ScanOptions) => void;
  onScan: () => void;
  onCancel: () => void;
}

export function ScanControls({ options, status, progress, canScan, onChange, onScan, onCancel }: Props) {
  const busy = status === 'scanning' || status === 'cancelling';
  const nothingEnabled = !options.readiness && !options.secretsPii;

  const toggle =
    (key: keyof ScanOptions) =>
    (event: ChangeEvent<HTMLInputElement>): void => {
      onChange({ ...options, [key]: event.target.checked });
    };

  const total = progress?.total ?? 0;
  const scanned = progress?.scanned ?? 0;
  const hasTotal = total > 0;

  return (
    <section className="card" aria-labelledby="scan-title">
      <h2 id="scan-title">2. Scan</h2>
      <fieldset className="options" disabled={busy}>
        <legend>Checks</legend>
        <label className="check">
          <input type="checkbox" checked={options.readiness} onChange={toggle('readiness')} />
          <span>Readiness checks</span>
        </label>
        <label className="check">
          <input type="checkbox" checked={options.secretsPii} onChange={toggle('secretsPii')} />
          <span>Secrets / PII scan</span>
        </label>
        <label className="check">
          <input type="checkbox" checked={options.respectIgnore} onChange={toggle('respectIgnore')} />
          <span>
            Respect <code>.shipcheckignore</code>
          </span>
        </label>
      </fieldset>

      {nothingEnabled ? (
        <p className="hint" role="note">
          Enable at least one check to scan.
        </p>
      ) : null}

      <div className="actions">
        <button
          type="button"
          className="btn btn-primary"
          onClick={onScan}
          disabled={!canScan || busy || nothingEnabled}
        >
          {busy ? 'Scanning…' : 'Scan'}
        </button>
        {busy ? (
          <button type="button" className="btn" onClick={onCancel} disabled={status === 'cancelling'}>
            {status === 'cancelling' ? 'Cancelling…' : 'Cancel'}
          </button>
        ) : null}
        {!canScan && !busy ? <span className="muted">Select a repository first.</span> : null}
      </div>

      {busy ? (
        <div className="progress" aria-live="off">
          <div role="status" className="sr-only">
            {status === 'cancelling' ? 'Cancelling scan' : 'Scan in progress'}
          </div>
          <progress
            aria-label="Scan progress"
            max={hasTotal ? total : undefined}
            value={hasTotal ? scanned : undefined}
          />
          <div className="progress-text" aria-hidden="true">
            {hasTotal
              ? `${formatNumber(scanned)} / ${formatNumber(total)} files`
              : 'Preparing…'}
            {progress?.currentFile ? <code className="progress-file">{progress.currentFile}</code> : null}
          </div>
        </div>
      ) : null}
    </section>
  );
}
