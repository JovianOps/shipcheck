import { useCallback, useEffect, useRef, useState } from 'react';
import { cancelScan, scanRepo, toMessage } from '../ipc';
import type { ScanOptions, ScanProgress, ScanResult, ScanStatus } from '../types';

export interface UseScan {
  status: ScanStatus;
  progress: ScanProgress | null;
  result: ScanResult | null;
  usedOptions: ScanOptions | null;
  error: string | null;
  start: (path: string, options: ScanOptions) => Promise<void>;
  cancel: () => void;
}

export function useScan(): UseScan {
  const [status, setStatus] = useState<ScanStatus>('idle');
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [usedOptions, setUsedOptions] = useState<ScanOptions | null>(null);
  const [error, setError] = useState<string | null>(null);

  const controllerRef = useRef<AbortController | null>(null);
  const pendingProgress = useRef<ScanProgress | null>(null);
  const frameRef = useRef(0);

  const flushProgress = useCallback((next: ScanProgress): void => {
    pendingProgress.current = next;
    if (frameRef.current) return;
    frameRef.current = requestAnimationFrame(() => {
      frameRef.current = 0;
      if (pendingProgress.current) setProgress(pendingProgress.current);
    });
  }, []);

  useEffect(
    () => () => {
      controllerRef.current?.abort();
      if (frameRef.current) cancelAnimationFrame(frameRef.current);
    },
    [],
  );

  const start = useCallback(
    async (path: string, options: ScanOptions): Promise<void> => {
      if (controllerRef.current) return;
      const controller = new AbortController();
      controllerRef.current = controller;
      setStatus('scanning');
      setError(null);
      setResult(null);
      setProgress({ scanned: 0, total: 0, currentFile: null });
      try {
        const next = await scanRepo(path, options, flushProgress, controller.signal);
        if (controller.signal.aborted) {
          setStatus('idle');
          return;
        }
        setResult(next);
        setUsedOptions(options);
        setStatus('done');
      } catch (e) {
        if (controller.signal.aborted) {
          setStatus('idle');
        } else {
          setError(toMessage(e));
          setStatus('error');
        }
      } finally {
        if (frameRef.current) {
          cancelAnimationFrame(frameRef.current);
          frameRef.current = 0;
        }
        pendingProgress.current = null;
        if (controllerRef.current === controller) controllerRef.current = null;
      }
    },
    [flushProgress],
  );

  const cancel = useCallback((): void => {
    const controller = controllerRef.current;
    if (!controller) return;
    setStatus('cancelling');
    controller.abort();
    void cancelScan().catch(() => undefined);
  }, []);

  return { status, progress, result, usedOptions, error, start, cancel };
}
