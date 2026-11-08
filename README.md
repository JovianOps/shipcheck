# shipcheck

Repo release-readiness + secret/PII scanner (Tauri desktop app). Offline by default.

## Download & run (Windows)
1. Download ZIP: https://github.com/JovianOps/shipcheck/archive/refs/heads/main.zip
2. Extract — keep `shipcheck.exe` **and** `WebView2Loader.dll` together in the same folder.
3. Run `shipcheck.exe`. Requires the Microsoft Edge WebView2 Runtime installed on the PC.

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
# build: npx tauri build   (use CARGO_BUILD_JOBS=1 if rustc crashes)
```
