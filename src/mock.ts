// Dev-only IPC mock. Excluded from production builds (see ipc.ts).
import type {
  Category,
  ExportResult,
  Finding,
  ReportFormat,
  ScanOptions,
  ScanProgress,
  ScanResult,
  Severity,
} from './types';

interface Template {
  category: Category;
  severity: Severity;
  type: string;
  ruleId: string;
  preview: string;
  remediation: string;
  files?: string[];
}

const SOURCE_FILES = [
  'src/config/aws.ts',
  'src/lib/auth.ts',
  'scripts/deploy.sh',
  '.env.production',
  'docker-compose.yml',
  'src/server/db.ts',
  'tests/fixtures/users.json',
  'docs/onboarding.md',
  'infra/terraform/main.tf',
  'src/components/Profile.tsx',
  'src/utils/logger.ts',
  'config/settings.yaml',
  'data/export_2024.csv',
  'src/api/client.ts',
  'Dockerfile',
  'src/seed/seed.ts',
  'keys/deploy_key.pem',
];

const TEMPLATES: Template[] = [
  {
    category: 'secrets',
    severity: 'critical',
    type: 'AWS access key ID',
    ruleId: 'SEC-AWS-001',
    preview: 'AWS_ACCESS_KEY_ID="AKIA************MPLE"',
    remediation: 'Revoke the key in IAM, rotate it, purge it from git history, and load credentials from the environment or a secret manager.',
  },
  {
    category: 'secrets',
    severity: 'critical',
    type: 'GitHub personal access token',
    ruleId: 'SEC-GH-002',
    preview: 'token: ghp_****************************wXyZ',
    remediation: 'Revoke the token in GitHub settings and use a fine-grained token supplied via CI secrets.',
  },
  {
    category: 'secrets',
    severity: 'critical',
    type: 'Private key block',
    ruleId: 'SEC-KEY-003',
    preview: '-----BEGIN RSA PRIVATE KEY----- [REDACTED]',
    remediation: 'Remove the key file, generate a new key pair, and add the path to .gitignore and .shipcheckignore.',
    files: ['keys/deploy_key.pem', 'infra/ssh/id_rsa'],
  },
  {
    category: 'secrets',
    severity: 'high',
    type: 'Hard-coded signing secret',
    ruleId: 'SEC-GEN-004',
    preview: 'JWT_SECRET=********[REDACTED 32 chars]',
    remediation: 'Move the secret to an environment variable and rotate it; invalidate tokens signed with the old value.',
  },
  {
    category: 'secrets',
    severity: 'high',
    type: 'Database URL with password',
    ruleId: 'SEC-DB-005',
    preview: 'postgres://admin:*******@db.internal:5432/app',
    remediation: 'Rotate the database password and inject the connection string at runtime.',
  },
  {
    category: 'pii',
    severity: 'medium',
    type: 'Email address',
    ruleId: 'PII-EML-001',
    preview: 'j***@example.com',
    remediation: 'Replace real addresses with synthetic fixtures such as user@example.test.',
  },
  {
    category: 'pii',
    severity: 'medium',
    type: 'Phone number',
    ruleId: 'PII-TEL-002',
    preview: '+1 (***) ***-**42',
    remediation: 'Use reserved fictional numbers (e.g. 555-01xx) in test data.',
  },
  {
    category: 'pii',
    severity: 'high',
    type: 'Government ID number',
    ruleId: 'PII-GOV-003',
    preview: '***-**-6789',
    remediation: 'Delete the record and scrub history; never commit real identity numbers.',
  },
  {
    category: 'pii',
    severity: 'low',
    type: 'Local user path',
    ruleId: 'PII-PTH-004',
    preview: '/Users/a****/Documents/projects/…',
    remediation: 'Use relative paths or environment variables instead of absolute home paths.',
  },
  {
    category: 'readiness',
    severity: 'medium',
    type: 'Missing LICENSE file',
    ruleId: 'RDY-LIC-001',
    preview: 'No LICENSE file found at repository root',
    remediation: 'Add a LICENSE file that matches your distribution terms.',
    files: ['LICENSE'],
  },
  {
    category: 'readiness',
    severity: 'low',
    type: 'TODO/FIXME left in source',
    ruleId: 'RDY-TODO-002',
    preview: '// TODO: remove before release',
    remediation: 'Resolve or track the item in your issue tracker before tagging a release.',
  },
  {
    category: 'readiness',
    severity: 'medium',
    type: 'Debug flag enabled',
    ruleId: 'RDY-DBG-003',
    preview: 'DEBUG = true',
    remediation: 'Disable debug flags in production configuration.',
    files: ['config/settings.yaml', 'src/utils/logger.ts'],
  },
  {
    category: 'readiness',
    severity: 'medium',
    type: 'Lockfile out of date',
    ruleId: 'RDY-LCK-004',
    preview: 'package.json and pnpm-lock.yaml disagree',
    remediation: 'Run your package manager install and commit the updated lockfile.',
    files: ['package.json'],
  },
  {
    category: 'readiness',
    severity: 'info',
    type: 'No CI release workflow',
    ruleId: 'RDY-CI-005',
    preview: 'No release workflow detected',
    remediation: 'Add a CI workflow that builds and verifies release artifacts.',
    files: ['.github/workflows/release.yml'],
  },
];

function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function pick<T>(items: readonly T[], rand: () => number): T {
  const item = items[Math.floor(rand() * items.length)];
  if (item === undefined) throw new Error('Cannot pick from an empty list.');
  return item;
}

function isLarge(): boolean {
  return new URLSearchParams(window.location.search).has('large');
}

function buildFindings(count: number, large: boolean, options: ScanOptions): Finding[] {
  const rand = mulberry32(1337);
  const pool = TEMPLATES.filter((t) => (t.category === 'readiness' ? options.readiness : options.secretsPii));
  if (pool.length === 0) return [];
  const out: Finding[] = [];
  for (let i = 0; i < count; i += 1) {
    const t = pick(pool, rand);
    const file = t.files
      ? pick(t.files, rand)
      : large && rand() > 0.3
        ? `src/generated/module-${Math.floor(rand() * 300)}.ts`
        : pick(SOURCE_FILES, rand);
    out.push({
      id: `mock-${i}`,
      category: t.category,
      severity: t.severity,
      type: t.type,
      ruleId: t.ruleId,
      file,
      line: t.files && t.category === 'readiness' ? 0 : 1 + Math.floor(rand() * 600),
      preview: t.preview,
      remediation: t.remediation,
    });
  }
  return out;
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new DOMException('Cancelled', 'AbortError'));
      return;
    }
    const onAbort = (): void => {
      window.clearTimeout(timer);
      reject(new DOMException('Cancelled', 'AbortError'));
    };
    const timer = window.setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

let lastResult: ScanResult | null = null;

export async function mockPickDirectory(): Promise<string | null> {
  await sleep(120, new AbortController().signal);
  return '/home/dev/projects/sample-repo';
}

export async function mockScan(
  path: string,
  options: ScanOptions,
  onProgress: (progress: ScanProgress) => void,
  signal: AbortSignal,
): Promise<ScanResult> {
  const large = isLarge();
  const total = large ? 18_342 : 1_284;
  const steps = 20;
  const startedAt = new Date();
  for (let step = 1; step <= steps; step += 1) {
    await sleep(120, signal);
    onProgress({
      scanned: Math.round((total * step) / steps),
      total,
      currentFile: `src/generated/module-${step * 7}.ts`,
    });
  }

  const findings = buildFindings(large ? 4000 : 48, large, options);
  const weights: Record<Severity, number> = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };
  const sum = findings.reduce((acc, f) => acc + weights[f.severity], 0);
  const failedRules = new Set(findings.map((f) => f.ruleId)).size;
  const totalChecks = 42;

  const finishedAt = new Date();
  lastResult = {
    scanId: `mock-${startedAt.getTime()}`,
    repoPath: path,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    filesScanned: total,
    summary: {
      passed: Math.max(0, totalChecks - failedRules),
      failed: failedRules,
      riskScore: Math.round(100 * (1 - Math.exp(-sum / 60))),
    },
    findings,
    truncated: false,
    invalidFindings: 0,
  };
  return lastResult;
}

export async function mockSavePath(_format: ReportFormat, defaultName: string): Promise<string | null> {
  return defaultName;
}

function escapeMd(value: string): string {
  return value.replace(/`/g, "'").replace(/\|/g, '/');
}

function toMarkdown(result: ScanResult): string {
  const lines = [
    '# shipcheck report',
    '',
    `- Repository: \`${escapeMd(result.repoPath)}\``,
    `- Scan ID: \`${escapeMd(result.scanId)}\``,
    `- Risk score: ${result.summary.riskScore}/100`,
    `- Checks passed / failed: ${result.summary.passed} / ${result.summary.failed}`,
    `- Findings: ${result.findings.length}`,
    '',
    '> All secret and PII values are redacted.',
    '',
  ];
  for (const f of result.findings) {
    lines.push(
      `## [${f.severity.toUpperCase()}] ${escapeMd(f.type)}`,
      `- Category: ${f.category}`,
      `- Location: \`${escapeMd(f.file)}${f.line > 0 ? `:${f.line}` : ''}\``,
      `- Preview: \`${escapeMd(f.preview)}\``,
      `- Fix: ${escapeMd(f.remediation)}`,
      '',
    );
  }
  return lines.join('\n');
}

function download(name: string, mime: string, body: string): number {
  const blob = new Blob([body], { type: mime });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  anchor.rel = 'noopener';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  return blob.size;
}

export async function mockExport(scanId: string, format: ReportFormat, destPath: string): Promise<ExportResult> {
  if (!lastResult || lastResult.scanId !== scanId) throw new Error('No matching scan to export.');
  const body =
    format === 'json'
      ? JSON.stringify(
          {
            tool: 'shipcheck',
            generatedAt: new Date().toISOString(),
            scanId: lastResult.scanId,
            repoPath: lastResult.repoPath,
            summary: lastResult.summary,
            findings: lastResult.findings,
          },
          null,
          2,
        )
      : toMarkdown(lastResult);
  const bytes = download(destPath, format === 'json' ? 'application/json' : 'text/markdown', body);
  return { path: destPath, bytes };
}
