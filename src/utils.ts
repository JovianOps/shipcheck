import type { Category, Severity } from './types';

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

export const CATEGORY_LABEL: Record<Category, string> = {
  secrets: 'Secrets',
  pii: 'PII',
  readiness: 'Readiness',
};

export function joinPath(root: string, rel: string): string {
  const useBackslash = root.includes('\\') && !root.includes('/');
  const sep = useBackslash ? '\\' : '/';
  const trimmedRoot = root.replace(/[\\/]+$/, '');
  const normalizedRel = rel.replace(/^[\\/]+/, '').replace(/[\\/]+/g, sep);
  return `${trimmedRoot}${sep}${normalizedRel}`;
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value);
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) return `${seconds.toFixed(1)} s`;
  const minutes = Math.floor(seconds / 60);
  return `${minutes}m ${Math.round(seconds - minutes * 60)}s`;
}

export type RiskLevel = 'low' | 'moderate' | 'high' | 'critical';

export function riskLevel(score: number): { level: RiskLevel; label: string } {
  if (score >= 75) return { level: 'critical', label: 'Critical risk' };
  if (score >= 50) return { level: 'high', label: 'High risk' };
  if (score >= 25) return { level: 'moderate', label: 'Moderate risk' };
  return { level: 'low', label: 'Low risk' };
}

export async function copyText(value: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
