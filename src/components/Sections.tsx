import { useState } from "react";
import type { ReportFormat, ScanOptions, ScanProgress, ScanResult } from "../types";
import { exportReport, pickFolder, pickSavePath } from "../ipc";

export function ProjectPicker({ path, onPick, disabled }: { path: string | null; onPick: (p: string) => void; disabled: boolean }) {
  const [err, setErr] = useState<string | null>(null);
  const pick = async () => {
    setErr(null);
    try { const p = await pickFolder(); if (p) onPick(p); } catch (e) { setErr(e instanceof Error ? e.message : "Could not open dialog."); }
  };
  return (
    <section className="sc-card" aria-labelledby="proj-h">
      <h2 id="proj-h">Project</h2>
      <div className="sc-row">
        <button type="button" className="sc-btn" onClick={pick} disabled={disabled}>Choose folder…</button>
        <code className="sc-path" aria-live="polite">{path ?? "No folder selected"}</code>
      </div>
      {err && <p className="sc-error" role="alert">{err}</p>}
    </section>
  );
}

function Toggle({ id, label, checked, onChange, disabled }: { id: string; label: string; checked: boolean; onChange: (v: boolean) => void; disabled: boolean }) {
  return (
    <label className="sc-toggle" htmlFor={id}>
      <input id={id} type="checkbox" role="switch" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span className="sc-toggle-track" aria-hidden="true" />
      <span>{label}</span>
    </label>
  );
}

export function ScanControls(props: {
  options: ScanOptions; setOptions: (o: ScanOptions) => void; canScan: boolean; scanning: boolean;
  progress: ScanProgress | null; onScan: () => void; onCancel: () => void;
}) {
  const { options, setOptions, canScan, scanning, progress, onScan, onCancel } = props;
  const pct = progress && progress.total > 0 ? Math.round((progress.scanned / progress.total) * 100) : 0;
  return (
    <section className="sc-card" aria-labelledby="scan-h">
      <h2 id="scan-h">Scan</h2>
      <div className="sc-row sc-wrap">
        <Toggle id="opt-ready" label="Readiness checks" checked={options.readiness} disabled={scanning} onChange={(v) => setOptions({ ...options, readiness: v })} />
        <Toggle id="opt-secrets" label="Secrets / PII scan" checked={options.secrets} disabled={scanning} onChange={(v) => setOptions({ ...options, secrets: v })} />
        <div className="sc-spacer" />
        <button type="button" className="sc-btn sc-btn-primary" onClick={onScan} disabled={!canScan || scanning}>Scan</button>
        <button type="button" className="sc-btn sc-btn-ghost" onClick={onCancel} disabled={!scanning}>Cancel</button>
      </div>
      {scanning && (
        <div className="sc-progress-wrap">
          <div className="sc-progress" role="progressbar" aria-label="Scan progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct}>
            <div className={`sc-progress-bar${progress ? "" : " sc-indeterminate"}`} style={progress ? { width: `${pct}%` } : undefined} />
          </div>
          <p className="sc-muted sc-small" aria-live="polite">
            {progress ? `${progress.scanned} / ${progress.total} files · ${progress.currentFile}` : "Starting…"}
          </p>
        </div>
      )}
    </section>
  );
}

export function Dashboard({ result }: { result: ScanResult }) {
  const { safeToUpload, riskScore, passed, failed, filesScanned } = result.summary;
  return (
    <section className="sc-card" aria-labelledby="dash-h">
      <h2 id="dash-h" className="sc-sr">Results</h2>
      <div className={`sc-banner ${safeToUpload ? "sc-safe" : "sc-unsafe"}`} role="status">
        <span className="sc-banner-label">Safe to upload?</span>
        <strong>{safeToUpload ? "YES" : "NO"}</strong>
      </div>
      <div className="sc-stats">
        <div className="sc-stat"><span className="sc-stat-v">{riskScore}<small>/100</small></span><span className="sc-stat-l">Risk score</span>
          <div className="sc-meter"><div style={{ width: `${riskScore}%` }} /></div></div>
        <div className="sc-stat"><span className="sc-stat-v sc-ok">{passed}</span><span className="sc-stat-l">Passed</span></div>
        <div className="sc-stat"><span className="sc-stat-v sc-bad">{failed}</span><span className="sc-stat-l">Failed</span></div>
        <div className="sc-stat"><span className="sc-stat-v">{filesScanned}</span><span className="sc-stat-l">Files scanned</span></div>
      </div>
    </section>
  );
}

const FORMATS: { v: ReportFormat; l: string }[] = [{ v: "json", l: "JSON" }, { v: "markdown", l: "Markdown" }, { v: "txt", l: "Text (.txt)" }];

export function ExportBar({ scanId }: { scanId: string }) {
  const [format, setFormat] = useState<ReportFormat>("json");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const run = async () => {
    setMsg(null);
    try {
      const dest = await pickSavePath(format);
      if (!dest) return;
      setBusy(true);
      const r = await exportReport(scanId, format, dest);
      setMsg({ ok: true, text: `Saved ${r.bytes.toLocaleString()} bytes to ${r.path}` });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error ? e.message : "Export failed." });
    } finally { setBusy(false); }
  };
  return (
    <section className="sc-card sc-export" aria-labelledby="exp-h">
      <h2 id="exp-h">Export</h2>
      <fieldset className="sc-radios">
        <legend className="sc-sr">Report format</legend>
        {FORMATS.map((f) => (
          <label key={f.v} className="sc-radio">
            <input type="radio" name="fmt" value={f.v} checked={format === f.v} onChange={() => setFormat(f.v)} />
            <span>{f.l}</span>
          </label>
        ))}
      </fieldset>
      <button type="button" className="sc-btn sc-btn-primary" onClick={run} disabled={busy}>{busy ? "Exporting…" : "Export report"}</button>
      {msg && <p className={msg.ok ? "sc-muted sc-small" : "sc-error"} role="status">{msg.text}</p>}
    </section>
  );
}
