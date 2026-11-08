import { CATEGORIES, SEVERITIES } from './types';
import type { ExportResult, Finding, ScanProgress, ScanResult } from './types';
import { cleanText, sanitizePreview } from './redact';

const MAX_FINDINGS = 100_000;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function text(value: unknown, max: number): string | null {
  if (typeof value !== 'string') return null;
  const bounded = value.length > max * 2 ? value.slice(0, max * 2) : value;
  const cleaned = cleanText(bounded);
  return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned;
}

function intIn(value: unknown, min: number, max: number): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return Math.min(max, Math.max(min, Math.trunc(value)));
}

function oneOf<T extends string>(list: readonly T[], value: unknown): T | null {
  if (typeof value !== 'string') return null;
  return list.find((item) => item === value) ?? null;
}

function parseFinding(raw: unknown, index: number): Finding | null {
  if (!isRecord(raw)) return null;
  const category = oneOf(CATEGORIES, raw.category);
  const severity = oneOf(SEVERITIES, raw.severity);
  const type = text(raw.type, 80);
  const fileRaw = text(raw.file, 500);
  const preview = typeof raw.preview === 'string' ? sanitizePreview(raw.preview) : null;
  if (!category || !severity || !type || !fileRaw || preview === null) return null;

  return {
    id: text(raw.id, 128) || `finding-${index}`,
    category,
    severity,
    type,
    ruleId: text(raw.ruleId, 80) || 'unknown',
    file: fileRaw.replace(/\\/g, '/'),
    line: intIn(raw.line, 0, 100_000_000) ?? 0,
    preview,
    remediation: sanitizePreview(typeof raw.remediation === 'string' ? raw.remediation : '', 500),
  };
}

export function parseScanResult(raw: unknown): ScanResult {
  if (!isRecord(raw)) throw new Error('Scan result is malformed (expected an object).');
  if (!Array.isArray(raw.findings)) throw new Error('Scan result is malformed (findings missing).');
  if (!isRecord(raw.summary)) throw new Error('Scan result is malformed (summary missing).');
  const scanId = text(raw.scanId, 128);
  if (!scanId) throw new Error('Scan result is malformed (scanId missing).');

  const source: unknown[] = raw.findings;
  const limited = source.length > MAX_FINDINGS ? source.slice(0, MAX_FINDINGS) : source;

  const seen = new Set<string>();
  const findings: Finding[] = [];
  let invalid = 0;
  limited.forEach((item, index) => {
    const parsed = parseFinding(item, index);
    if (!parsed) {
      invalid += 1;
      return;
    }
    if (seen.has(parsed.id)) parsed.id = `${parsed.id}~${index}`;
    seen.add(parsed.id);
    findings.push(parsed);
  });

  const summary = raw.summary;
  return {
    scanId,
    repoPath: text(raw.repoPath, 1024) ?? '',
    startedAt: text(raw.startedAt, 64) ?? '',
    finishedAt: text(raw.finishedAt, 64) ?? '',
    durationMs: intIn(raw.durationMs, 0, 1e12) ?? 0,
    filesScanned: intIn(raw.filesScanned, 0, 1e9) ?? 0,
    summary: {
      passed: intIn(summary.passed, 0, 1e9) ?? 0,
      failed: intIn(summary.failed, 0, 1e9) ?? 0,
      riskScore: intIn(summary.riskScore, 0, 100) ?? 0,
    },
    findings,
    truncated: raw.truncated === true || source.length > MAX_FINDINGS,
    invalidFindings: invalid,
  };
}

export function parseProgress(raw: unknown): ScanProgress | null {
  if (!isRecord(raw)) return null;
  const scanned = intIn(raw.scanned, 0, 1e12);
  const total = intIn(raw.total, 0, 1e12);
  if (scanned === null || total === null) return null;
  return {
    scanned: total > 0 ? Math.min(scanned, total) : scanned,
    total,
    currentFile: text(raw.currentFile, 500),
  };
}

export function parseExportResult(raw: unknown): ExportResult {
  if (!isRecord(raw)) throw new Error('Export result is malformed.');
  const path = text(raw.path, 1024);
  if (!path) throw new Error('Export result is malformed (path missing).');
  return { path, bytes: intIn(raw.bytes, 0, 1e12) ?? 0 };
}
