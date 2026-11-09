import type {
  ExportResult,
  Finding,
  FindingCategory,
  ReportFormat,
  ScanProgress,
  ScanResult,
  ScanSummary,
  Severity,
} from "./types";
import { redact } from "./redact";

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low", "info"];
const CATEGORIES: readonly FindingCategory[] = ["secrets", "pii", "readiness"];
const FORMATS: readonly ReportFormat[] = ["json", "markdown", "txt"];

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const isStr = (v: unknown): v is string => typeof v === "string";
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const isBool = (v: unknown): v is boolean => typeof v === "boolean";

export const isSeverity = (v: unknown): v is Severity => isStr(v) && (SEVERITIES as readonly string[]).includes(v);
export const isCategory = (v: unknown): v is FindingCategory => isStr(v) && (CATEGORIES as readonly string[]).includes(v);
export const isReportFormat = (v: unknown): v is ReportFormat => isStr(v) && (FORMATS as readonly string[]).includes(v);

export function parseFinding(v: unknown): Finding | null {
  if (!isObj(v)) return null;
  const { id, category, type, severity, file, line, preview, remediation } = v;
  if (!isStr(id) || !isCategory(category) || !isStr(type) || !isSeverity(severity)) return null;
  if (!isStr(file) || !isNum(line) || !isStr(preview) || !isStr(remediation)) return null;
  return { id, category, type, severity, file, line: Math.max(0, Math.floor(line)), preview: redact(preview), remediation };
}

export function parseSummary(v: unknown): ScanSummary | null {
  if (!isObj(v)) return null;
  const { safeToUpload, riskScore, passed, failed, filesScanned } = v;
  if (!isBool(safeToUpload) || !isNum(riskScore) || !isNum(passed) || !isNum(failed) || !isNum(filesScanned)) return null;
  return { safeToUpload, riskScore: Math.min(100, Math.max(0, Math.round(riskScore))), passed, failed, filesScanned };
}

export function parseScanResult(v: unknown): ScanResult | null {
  if (!isObj(v)) return null;
  const { scanId, path, findings: raw } = v;
  if (!isStr(scanId) || !isStr(path) || !Array.isArray(raw)) return null;
  const summary = parseSummary(v["summary"]);
  if (!summary) return null;
  const findings = raw.map(parseFinding).filter((f): f is Finding => f !== null);
  return { scanId, path, summary, findings };
}

export function parseProgress(v: unknown): ScanProgress | null {
  if (!isObj(v)) return null;
  const { scanned, total, currentFile } = v;
  if (!isNum(scanned) || !isNum(total) || !isStr(currentFile)) return null;
  return { scanned, total, currentFile };
}

export function parseExportResult(v: unknown): ExportResult | null {
  if (!isObj(v)) return null;
  const { path, bytes } = v;
  if (!isStr(path) || !isNum(bytes)) return null;
  return { path, bytes };
}
