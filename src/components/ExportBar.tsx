import { useState } from 'react';
import { exportReport, pickSavePath, toMessage } from '../ipc';
import type { ExportResult, ReportFormat, ScanResult } from '../types';
import { formatBytes } from '../utils';

export function ExportBar({ result }: { result: ScanResult }) {
  const [format, setFormat] = useState<ReportFormat>('json');
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<ExportResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleExport = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const stamp = new Date().toISOString().slice(0, 10);
      const ext = format === 'json' ? 'json' : format === 'markdown' ? 'md' : 'txt';
      const defaultName = `shipcheck-report-${stamp}.${ext}`;
      const destPath = await pickSavePath(format, defaultName);
      if (!destPath) return;
      setDone(await exportReport(result.scanId, format, destPath));
    } catch (e) {
      setError(toMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card" aria-labelledby="export-title">
      <h2 id="export-title">Export</h2>
      <div className="export-row">
        <fieldset className="radios" disabled={busy}>
          <legend>Format</legend>
          <label className="check">
            <input type="radio" name="format" checked={format === 'json'} onChange={() => setFormat('json')} />
            <span>JSON</span>
          </label>
          <label className="check">
            <input
              type="radio"
              name="format"
              checked={format === 'markdown'}
              onChange={() => setFormat('markdown')}
            />
            <span>Markdown</span>
          </label>
          <label className="check">
            <input type="radio" name="format" checked={format === 'txt'} onChange={() => setFormat('txt')} />
            <span>Text (.txt)</span>
          </label>
        </fieldset>
        <button type="button" className="btn btn-primary" onClick={() => void handleExport()} disabled={busy}>
          {busy ? 'Exporting…' : 'Export report (choose folder)'}
        </button>
      </div>
      <p className="muted">Reports contain redacted previews only.</p>
      <div aria-live="polite">
        {done ? (
          <p className="inline-ok">
            Saved <code>{done.path}</code> ({formatBytes(done.bytes)}).
          </p>
        ) : null}
        {error ? (
          <p className="inline-error" role="alert">
            {error}
          </p>
        ) : null}
      </div>
    </section>
  );
}
