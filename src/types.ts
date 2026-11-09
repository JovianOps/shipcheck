export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingCategory = "secrets" | "pii" | "readiness";
export type ReportFormat = "json" | "markdown" | "txt";

export interface ScanOptions {
  readiness: boolean;
  secrets: boolean;
}

export interface Finding {
  id: string;
  category: FindingCategory;
  type: string;
  severity: Severity;
  file: string;
  line: number;
  preview: string;
  remediation: string;
}

export interface ScanSummary {
  safeToUpload: boolean;
  riskScore: number;
  passed: number;
  failed: number;
  filesScanned: number;
}

export interface ScanResult {
  scanId: string;
  path: string;
  summary: ScanSummary;
  findings: Finding[];
}

export interface ScanProgress {
  scanned: number;
  total: number;
  currentFile: string;
}

export interface ExportResult {
  path: string;
  bytes: number;
}
