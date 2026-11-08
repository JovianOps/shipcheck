# shipcheck

Repo release-readiness + secret/PII scanner (Tauri desktop app). Offline by default.

## Download & run (Windows)
1. Download ZIP: https://github.com/JovianOps/shipcheck/archive/refs/heads/main.zip
2. Extract and run `shipcheck.exe` (WebView2 required; debug build).

## What it does
- Scans a folder for secrets/PII (heuristic) and readiness checks (LICENSE, README, CI, `.gitignore`).
- Redacted previews only. Safe-to-upload indicator.
- Export: JSON / Markdown / `.txt` (choose folder and file name).

## Notes
- Detection is heuristic — false positives/negatives possible; verify findings.
- No telemetry/network calls. Scans only the selected folder.

## Develop / build
```bash
npm install
npm run tauri dev
# build: npx tauri build --debug  (use CARGO_BUILD_JOBS=1 if rustc crashes)
```
