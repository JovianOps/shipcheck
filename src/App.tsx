import { useState } from "react";
import type { ScanOptions } from "./types";
import { useScan } from "./hooks/useScan";
import { Dashboard, ExportBar, ProjectPicker, ScanControls } from "./components/Sections";
import { FindingsList } from "./components/FindingsList";

export default function App() {
  const [path, setPath] = useState<string | null>(null);
  const [options, setOptions] = useState<ScanOptions>({ readiness: true, secrets: true });
  const { result, progress, scanning, error, start, cancel } = useScan();
  const canScan = !!path && (options.readiness || options.secrets);

  return (
    <div className="sc-app">
      <header className="sc-header">
        <div className="sc-logo" aria-hidden="true">✓</div>
        <div>
          <h1>shipcheck</h1>
          <p className="sc-muted sc-small">Scan a folder for secrets, PII and release readiness — locally.</p>
        </div>
      </header>
      <main className="sc-main">
        <ProjectPicker path={path} onPick={setPath} disabled={scanning} />
        <ScanControls options={options} setOptions={setOptions} canScan={canScan} scanning={scanning}
          progress={progress} onScan={() => path && start(path, options)} onCancel={cancel} />
        {error && <p className="sc-error" role="alert">{error}</p>}
        {result && (
          <>
            <Dashboard result={result} />
            <FindingsList findings={result.findings} />
            <ExportBar scanId={result.scanId} />
          </>
        )}
      </main>
    </div>
  );
}
