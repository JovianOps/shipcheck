import type { ExportResult, ReportFormat, ScanOptions, ScanProgress, ScanResult } from "./types";
import { parseExportResult, parseProgress, parseScanResult } from "./guards";
import { mockIpc } from "./mock";

export const PROGRESS_EVENT = "shipcheck://progress";

const isTauri = () =>
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in (window as unknown as Record<string, unknown>);

function backend() {
  if (isTauri()) return null;
  if (import.meta.env.DEV) return mockIpc;
  throw new Error("Tauri runtime not available.");
}

async function invoke(cmd: string, args?: Record<string, unknown>): Promise<unknown> {
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke(cmd, args);
}

export async function scanRepo(path: string, options: ScanOptions): Promise<ScanResult> {
  const mock = backend();
  const raw = mock ? await mock.scanRepo(path, options) : await invoke("scan_repo", { path, options });
  const parsed = parseScanResult(raw);
  if (!parsed) throw new Error("Backend returned an invalid scan result.");
  return parsed;
}

export async function cancelScan(): Promise<void> {
  const mock = backend();
  if (mock) return mock.cancelScan();
  await invoke("cancel_scan");
}

export async function exportReport(scanId: string, format: ReportFormat, destPath: string): Promise<ExportResult> {
  const mock = backend();
  const raw = mock ? await mock.exportReport(scanId, format, destPath) : await invoke("export_report", { scanId, format, destPath });
  const parsed = parseExportResult(raw);
  if (!parsed) throw new Error("Backend returned an invalid export result.");
  return parsed;
}

export async function onProgress(cb: (p: ScanProgress) => void): Promise<() => void> {
  const mock = backend();
  if (mock) return mock.onProgress((raw) => { const p = parseProgress(raw); if (p) cb(p); });
  const { listen } = await import("@tauri-apps/api/event");
  return listen<unknown>(PROGRESS_EVENT, (e) => { const p = parseProgress(e.payload); if (p) cb(p); });
}

export async function pickFolder(): Promise<string | null> {
  const mock = backend();
  if (mock) return mock.pickFolder();
  const { open } = await import("@tauri-apps/plugin-dialog");
  const res = await open({ directory: true, multiple: false, title: "Select project folder" });
  return typeof res === "string" ? res : null;
}

const EXT: Record<ReportFormat, { ext: string; name: string }> = {
  json: { ext: "json", name: "JSON" },
  markdown: { ext: "md", name: "Markdown" },
  txt: { ext: "txt", name: "Text" },
};

export async function pickSavePath(format: ReportFormat): Promise<string | null> {
  const { ext, name } = EXT[format];
  const mock = backend();
  if (mock) return mock.pickSavePath(ext);
  const { save } = await import("@tauri-apps/plugin-dialog");
  const res = await save({ title: "Export report", defaultPath: `shipcheck-report.${ext}`, filters: [{ name, extensions: [ext] }] });
  return typeof res === "string" ? res : null;
}
