# shipcheck

Repo release-readiness + secret/PII scanner. Tauri v2 desktop app (React + TypeScript + Vite UI, Rust backend). Offline by default.

## Features
- Scan a folder for secrets/PII (common tokens/keys/credentials, emails/phones heuristics) and readiness checks (LICENSE, README, CI, `.gitignore`).
- Redacted previews only. Risk summary + safe-to-upload indicator.
- Export report: JSON / Markdown / Text (`.txt`) — choose folder and file name.

## Download & run (Windows)
- Download ZIP from GitHub → run `shipcheck.exe` (WebView2 required; debug build).

## Run (dev)
```bash
npm install
npm run tauri dev      # desktop (recommended)
npm run dev            # browser mock only
```

## Build
```bash
npm run build
npx tauri build --debug
```
Windows note: if rustc crashes on parallel builds, use `CARGO_BUILD_JOBS=1`.

## IPC (Tauri)
- `scan_repo(path, options)` → `ScanResult` (emits `shipcheck://progress`)
- `cancel_scan()` → `()`
- `export_report(scanId, format, destPath)` → `{ path, bytes }` (`format`: `json` | `markdown` | `txt`)

## Security notes
- No telemetry/network calls. Scans only the selected folder. Reports are redacted.
- Detection is heuristic — false positives/negatives possible; verify findings before acting.
- UI validates IPC payloads and treats content as untrusted (no unsafe HTML).
