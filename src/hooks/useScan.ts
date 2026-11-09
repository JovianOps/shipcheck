import { useCallback, useEffect, useRef, useState } from "react";
import type { ScanOptions, ScanProgress, ScanResult } from "../types";
import { cancelScan, onProgress, scanRepo } from "../ipc";

export function useScan() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const runId = useRef(0);

  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let alive = true;
    onProgress((p) => setProgress(p)).then((u) => { if (alive) unlisten = u; else u(); }).catch(() => {});
    return () => { alive = false; unlisten?.(); };
  }, []);

  const start = useCallback(async (path: string, options: ScanOptions) => {
    const id = ++runId.current;
    setScanning(true); setError(null); setResult(null); setProgress(null);
    try {
      const r = await scanRepo(path, options);
      if (id === runId.current) setResult(r);
    } catch (e) {
      if (id === runId.current) setError(e instanceof Error ? e.message : "Scan failed.");
    } finally {
      if (id === runId.current) setScanning(false);
    }
  }, []);

  const cancel = useCallback(async () => {
    runId.current++;
    setScanning(false);
    setError("Scan cancelled.");
    try { await cancelScan(); } catch { /* ignore */ }
  }, []);

  return { result, progress, scanning, error, start, cancel };
}
