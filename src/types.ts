export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const CATEGORIES = ['secrets', 'pii', 'readiness'] as const;
export type Category = (typeof CATEGORIES)[number];

export type CategoryFilter = 'all' | Category;
export type SeverityFilter = 'all' | Severity;
export type ReportFormat = 'json' | 'markdown' | 'txt';

export interface ScanOptions {
  readiness: boolean;
  secretsPii: boolean;
  respectIgnore: boolean;
}

export interface Finding {
  id: string;
  category: Category;
  severity: Severity;
  type: string;
  ruleId: string;
  /** Repo-relative path using forward slashes. */
  file: string;
  /** 1-based line; 0 means file-level finding. */
  line: number;
  /** Redacted preview only. Never contains the full secret/PII value. */
  preview: string;
  remediation: string;
}

export interface ScanSummary {
  passed: number;
  failed: number;
  /** 0..100 */
  riskScore: number;
}

export interface ScanResult {
  scanId: string;
  repoPath: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  filesScanned: number;
  summary: ScanSummary;
  findings: Finding[];
  truncated: boolean;
  /** Findings dropped by the UI because their shape failed validation. */
  invalidFindings: number;
}

export interface ScanProgress {
  scanned: number;
  total: number;
  currentFile: string | null;
}

export interface ExportResult {
  path: string;
  bytes: number;
}

export type ScanStatus = 'idle' | 'scanning' | 'cancelling' | 'done' | 'error';
