// Dev-only mock backend, used when the Tauri runtime is absent and import.meta.env.DEV is true.
import type { ReportFormat, ScanOptions } from "./types";

type Listener = (p: unknown) => void;
const listeners = new Set<Listener>();
let cancelled = false;

const SAMPLE = [
  { category: "secrets", type: "AWS Access Key", severity: "critical", file: "config/aws.ts", preview: "AKIA********[REDACTED]", remediation: "Revoke the key in IAM, move it to an environment variable and purge it from git history." },
  { category: "secrets", type: "Stripe Secret Key", severity: "critical", file: "server/billing.js", preview: "sk_l********[REDACTED]", remediation: "Rotate the key in the Stripe dashboard and load it from a secret store." },
  { category: "secrets", type: "Private Key (PEM)", severity: "high", file: "certs/dev.pem", preview: "----********[REDACTED]", remediation: "Remove the file and add *.pem to .gitignore." },
  { category: "pii", type: "Email address", severity: "medium", file: "fixtures/users.json", preview: "j***@*****.com", remediation: "Replace real addresses with example.com fixtures." },
  { category: "pii", type: "Phone number", severity: "low", file: "docs/contact.md", preview: "+1 *** *** **42", remediation: "Confirm this number is meant to be public." },
  { category: "readiness", type: "Missing LICENSE", severity: "medium", file: "LICENSE", preview: "file not found", remediation: "Add a LICENSE file describing usage terms." },
  { category: "readiness", type: ".env committed", severity: "high", file: ".env", preview: "tracked by git", remediation: "Remove .env from the index and add it to .gitignore." },
  { category: "readiness", type: "README present", severity: "info", file: "README.md", preview: "ok", remediation: "No action needed." },
] as const;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const mockIpc = {
  async scanRepo(path: string, options: ScanOptions): Promise<unknown> {
    cancelled = false;
    const total = 240;
    for (let i = 1; i <= total; i += 8) {
      if (cancelled) throw new Error("Scan cancelled.");
      listeners.forEach((l) => l({ scanned: Math.min(i, total), total, currentFile: `src/module_${i}.ts` }));
      await sleep(40);
    }
    const base = SAMPLE.filter((s) => (s.category === "readiness" ? options.readiness : options.secrets));
    const findings = Array.from({ length: 300 }, (_, i) => {
      const s = base[i % Math.max(1, base.length)];
      return s && { ...s, id: `f${i}`, line: 1 + ((i * 37) % 400), file: i < base.length ? s.file : `${s.file.replace(/(\.\w+)?$/, `_${i}$1`)}` };
    }).filter(Boolean).slice(0, base.length ? 300 : 0);
    const failed = findings.filter((f) => f && f.severity !== "info").length;
    const crit = findings.filter((f) => f && (f.severity === "critical" || f.severity === "high")).length;
    return {
      scanId: `mock-${Date.now()}`,
      path,
      findings,
      summary: { safeToUpload: crit === 0, riskScore: Math.min(100, crit * 2 + failed / 10), passed: 42, failed, filesScanned: total },
    };
  },
  async cancelScan() { cancelled = true; },
  async exportReport(_id: string, _f: ReportFormat, destPath: string): Promise<unknown> {
    await sleep(300);
    return { path: destPath, bytes: 18432 };
  },
  onProgress(cb: Listener) { listeners.add(cb); return () => { listeners.delete(cb); }; },
  async pickFolder() { return "/Users/dev/projects/my-app"; },
  async pickSavePath(ext: string) { return `/Users/dev/Desktop/shipcheck-report.${ext}`; },
};
