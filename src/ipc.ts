import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { open, save } from '@tauri-apps/plugin-dialog';
import { parseExportResult, parseProgress, parseScanResult } from './guards';
import { sanitizePreview } from './redact';
import type { ExportResult, ReportFormat, ScanOptions, ScanProgress, ScanResult } from './types';

const PROGRESS_EVENT = 'shipcheck://progress';

export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}

async function loadMock(): Promise<typeof import('./mock')> {
  if (import.meta.env.DEV) {
    return import('./mock');
  }
  throw new Error('Tauri runtime is not available.');
}

/** Converts any thrown value to a short, redacted, display-safe message. */
export function toMessage(error: unknown): string {
  let raw = '';
  if (typeof error === 'string') {
    raw = error;
  } else if (error instanceof Error) {
    raw = error.message;
  } else if (typeof error === 'object' && error !== null && 'message' in error) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === 'string') raw = message;
  }
  return sanitizePreview(raw, 300) || 'Unexpected error.';
}

export async function pickDirectory(): Promise<string | null> {
  if (!isTauri()) {
    return (await loadMock()).mockPickDirectory();
  }
  const selected = await open({ directory: true, multiple: false, title: 'Select repository folder' });
  return typeof selected === 'string' && selected.length > 0 ? selected : null;
}

export async function scanRepo(
  path: string,
  options: ScanOptions,
  onProgress: (progress: ScanProgress) => void,
  signal: AbortSignal,
): Promise<ScanResult> {
  if (!isTauri()) {
    const mock = await loadMock();
    return parseScanResult(await mock.mockScan(path, options, onProgress, signal));
  }
  let unlisten: (() => void) | undefined;
  try {
    unlisten = await listen<unknown>(PROGRESS_EVENT, (event) => {
      const progress = parseProgress(event.payload);
      if (progress) onProgress(progress);
    });
    const raw = await invoke<unknown>('scan_repo', { path, options });
    return parseScanResult(raw);
  } finally {
    unlisten?.();
  }
}

export async function cancelScan(): Promise<void> {
  if (!isTauri()) return;
  await invoke<void>('cancel_scan');
}

export async function pickSavePath(format: ReportFormat, defaultName: string): Promise<string | null> {
  if (!isTauri()) {
    return (await loadMock()).mockSavePath(format, defaultName);
  }
  const extension = format === 'json' ? 'json' : format === 'markdown' ? 'md' : 'txt';
  const name = format === 'json' ? 'JSON' : format === 'markdown' ? 'Markdown' : 'Text';
  const selected = await save({
    title: 'Export report — choose folder and file name',
    defaultPath: defaultName,
    filters: [{ name, extensions: [extension] }],
  });
  return typeof selected === 'string' && selected.length > 0 ? selected : null;
}

export async function exportReport(scanId: string, format: ReportFormat, destPath: string): Promise<ExportResult> {
  if (!isTauri()) {
    return parseExportResult(await (await loadMock()).mockExport(scanId, format, destPath));
  }
  const raw = await invoke<unknown>('export_report', { scanId, format, destPath });
  return parseExportResult(raw);
}
