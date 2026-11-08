import { useCallback, useState } from 'react';
import { ExportBar } from './components/ExportBar';
import { FindingsPanel } from './components/FindingsPanel';
import { ProjectPicker } from './components/ProjectPicker';
import { SafeBanner } from './components/SafeBanner';
import { ScanControls } from './components/ScanControls';
import { Summary } from './components/Summary';
import { useScan } from './hooks/useScan';
import { isTauri, pickDirectory, toMessage } from './ipc';
import type { ScanOptions } from './types';

const DEFAULT_OPTIONS: ScanOptions = { readiness: true, secretsPii: true, respectIgnore: true };

export function App() {
  const [repoPath, setRepoPath] = useState<string | null>(null);
  const [options, setOptions] = useState<ScanOptions>(DEFAULT_OPTIONS);
  const [pickError, setPickError] = useState<string | null>(null);
  const { status, progress, result, usedOptions, error, start, cancel } = useScan();

  const busy = status === 'scanning' || status === 'cancelling';

  const handlePick = useCallback(async (): Promise<void> => {
    setPickError(null);
    try {
      const picked = await pickDirectory();
      if (picked) setRepoPath(picked);
    } catch (e) {
      setPickError(toMessage(e));
    }
  }, []);

  const handleScan = useCallback((): void => {
    if (repoPath) void start(repoPath, options);
  }, [repoPath, options, start]);

  return (
    <>
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <header className="app-header">
        <div>
          <h1>shipcheck</h1>
          <p className="muted">Release readiness and secret/PII leak scanner</p>
        </div>
        <div className="header-badges">
          <span className="pill">Offline · no telemetry</span>
          {!isTauri() ? <span className="pill pill-warn">Mock data (dev)</span> : null}
        </div>
      </header>

      <main id="main" className="app-main">
        <ProjectPicker
          path={repoPath}
          disabled={busy}
          error={pickError}
          onPick={() => void handlePick()}
        />
        <ScanControls
          options={options}
          status={status}
          progress={progress}
          canScan={repoPath !== null}
          onChange={setOptions}
          onScan={handleScan}
          onCancel={cancel}
        />

        {status === 'error' && error ? (
          <div className="card card-error" role="alert">
            <h2>Scan failed</h2>
            <p>{error}</p>
          </div>
        ) : null}

        {status === 'idle' && !result ? (
          <section className="card empty" aria-label="Results">
            <strong>No results yet</strong>
            <span>Select a repository and run a scan to see findings.</span>
          </section>
        ) : null}

        {result ? (
          <>
            <SafeBanner result={result} options={usedOptions} />
            <Summary result={result} />
            <FindingsPanel findings={result.findings} repoPath={result.repoPath} />
            <ExportBar result={result} />
          </>
        ) : null}
      </main>

      <footer className="app-footer muted">
        Previews are redacted. All processing is local; shipcheck makes no network requests.
      </footer>
    </>
  );
}
