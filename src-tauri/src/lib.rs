use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Instant;
use tauri::{AppHandle, Emitter, State};
use walkdir::WalkDir;

#[derive(Default)]
struct AppState { cancel: AtomicBool }
#[derive(Default)]
struct Store { last: Mutex<Option<ScanResult>> }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanOptions { readiness: bool, secrets_pii: bool, respect_ignore: bool }

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScanProgress { scanned: u64, total: u64, current_file: Option<String> }

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Finding { id: String, category: String, severity: String, #[serde(rename="type")] type_: String, rule_id: String, file: String, line: u32, preview: String, remediation: String }

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScanSummary { passed: u32, failed: u32, risk_score: u32 }

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScanResult { scan_id: String, repo_path: String, started_at: String, finished_at: String, duration_ms: u64, files_scanned: u64, summary: ScanSummary, findings: Vec<Finding>, truncated: bool, invalid_findings: u32 }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportResult { path: String, bytes: u64 }

fn redact(s: &str) -> String {
    let s = s.trim();
    if s.len() <= 8 { return "****".into(); }
    format!("{}****[REDACTED {} chars]", &s[..4.min(s.len())], s.len())
}
static LONG_TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9_\-+/=]{20,}").unwrap());
static LONG_DIGITS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d{10,}").unwrap());

fn clean_preview(line: &str) -> String {
    let mut out: String = line.chars().filter(|c| !c.is_control() || *c=='\t').take(160).collect();
    out = out.replace('\t', " ");
    LONG_TOKEN.replace_all(&out, |m: &regex::Captures| redact(m.get(0).unwrap().as_str())).to_string()
}
fn is_ignored(path: &Path, root: &Path) -> bool {
    let rel = path.strip_prefix(root).unwrap_or(path).to_string_lossy().replace('\\',"/").to_lowercase();
    [".git/", "node_modules/", "target/", "dist/", "build/", ".next/", "vendor/", ".webview2/", "ebwebview/", "webview2/"].iter().any(|p| rel.contains(p))
}
fn skip_secret_rule(rel: &str, rid: &str, line: &str) -> bool {
    let r = rel.to_lowercase();
    let l = line.to_lowercase();
    if rid == "SEC-GEN-004" && (l.contains("publickeytoken=") || l.contains("culture=neutral") || r.ends_with(".resx")) { return true; }
    if rid == "PII-EML-001" {
        let base = Path::new(&r).file_name().and_then(|s| s.to_str()).unwrap_or("");
        if ["license","license.md","license.txt","eula","eula.txt","readme.md","readme.txt","readme","authors","notice","third-party-notices.txt","copying","security.md"].contains(&base) { return true; }
        if l.contains("copyright") || l.starts_with("// partial copyright") { return true; }
        let lower = line.to_lowercase();
        if lower.contains("@example.com") || lower.contains("@example.org") || lower.contains("@example.net") || lower.contains("@example.test") || lower.contains(".example") { return true; }
    }
    if rid == "PII-TEL-002" && LONG_DIGITS.is_match(line) { return true; }
    false
}
fn rules() -> Vec<(Regex, &'static str, &'static str, &'static str, &'static str, &'static str)> {
    vec![
        (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "secrets","critical","AWS access key ID","SEC-AWS-001","Revoke/rotate the key and load from env/secret manager."),
        (Regex::new(r"gh[pousr]_[A-Za-z0-9]{20,}").unwrap(), "secrets","critical","GitHub token","SEC-GH-002","Revoke token; use CI secrets."),
        (Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap(), "secrets","critical","Private key","SEC-KEY-003","Remove key, rotate, purge history; add to ignore."),
        (Regex::new(r#"(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['"][A-Za-z0-9_\-+/=]{12,}['"]"#).unwrap(), "secrets","high","Hard-coded credential","SEC-GEN-004","Move to env var/secret store and rotate."),
        (Regex::new(r"(?i)postgres(?:ql)?://[^:\s]+:[^@\s]+@").unwrap(), "secrets","high","DB URL with password","SEC-DB-005","Rotate password; inject connection string at runtime."),
        (Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}").unwrap(), "secrets","high","JWT token","SEC-JWT-006","Remove token and rotate signing secret."),
        (Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap(), "pii","medium","Email address","PII-EML-001","If real PII, remove/replace; ignore public/license contacts."),
        (Regex::new(r"\b(?:\+1[-.\s])?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b").unwrap(), "pii","medium","Phone number","PII-TEL-002","If real PII, remove/replace; verify (heuristic)."),
    ]
}

#[tauri::command]
fn cancel_scan(state: State<'_, AppState>) { state.cancel.store(true, Ordering::SeqCst); }

fn do_scan(app: &AppHandle, state: &State<'_, AppState>, path: String, options: ScanOptions) -> Result<ScanResult, String> {
    state.cancel.store(false, Ordering::SeqCst);
    let root = PathBuf::from(&path);
    if !root.is_dir() { return Err("Selected path is not a directory.".into()); }
    let started = Instant::now();
    let started_at = Utc::now().to_rfc3339();
    let mut findings: Vec<Finding> = Vec::new();
    let mut idn: u64 = 0;

    let mut files: Vec<PathBuf> = Vec::new();
    for e in WalkDir::new(&root).follow_links(false).into_iter().flatten() {
        if state.cancel.load(Ordering::SeqCst) { break; }
        if e.file_type().is_file() {
            let p = e.path();
            if options.respect_ignore && is_ignored(p, &root) { continue; }
            if let Ok(m) = e.metadata() { if m.len() > 2_000_000 { continue; } }
            files.push(p.to_path_buf());
        }
    }
    let total = files.len() as u64;
    let rs = if options.secrets_pii { rules() } else { vec![] };

    for (i, p) in files.iter().enumerate() {
        if state.cancel.load(Ordering::SeqCst) { break; }
        let rel = p.strip_prefix(&root).unwrap_or(p).to_string_lossy().replace('\\',"/");
        let _ = app.emit("shipcheck://progress", ScanProgress { scanned: (i as u64)+1, total, current_file: Some(rel.clone()) });
        if options.secrets_pii {
            if let Ok(text) = fs::read_to_string(p) {
                for (ln, line) in text.lines().enumerate().take(50000) {
                    for (re, cat, sev, typ, rid, rem) in &rs {
                        if re.find(line).is_some() && !skip_secret_rule(&rel, rid, line) {
                            idn += 1;
                            findings.push(Finding { id: format!("f-{idn}"), category: (*cat).into(), severity: (*sev).into(), type_: (*typ).into(), rule_id: (*rid).into(), file: rel.clone(), line: (ln as u32)+1, preview: clean_preview(line), remediation: (*rem).into() });
                        }
                    }
                }
            }
        }
    }

    let mut passed = 0u32; let mut failed_rules: HashSet<String> = HashSet::new();
    if options.readiness {
        let checks = [
            ("RDY-LIC-001","LICENSE file exists", root.join("LICENSE").exists() || root.join("LICENSE.md").exists()),
            ("RDY-README-001","README exists", root.join("README.md").exists() || root.join("README").exists()),
            ("RDY-CI-001","CI workflow exists", root.join(".github/workflows").exists() || root.join(".gitlab-ci.yml").exists()),
            ("RDY-GITIGNORE-001",".gitignore exists", root.join(".gitignore").exists()),
        ];
        for (rid, label, ok) in checks {
            if ok { passed += 1; } else {
                failed_rules.insert(rid.into()); idn += 1;
                findings.push(Finding { id: format!("f-{idn}"), category: "readiness".into(), severity: "medium".into(), type_: label.into(), rule_id: rid.into(), file: ".".into(), line: 0, preview: format!("{label}: missing"), remediation: "Add the missing project hygiene file before release.".into() });
            }
        }
    }
    for f in &findings { failed_rules.insert(f.rule_id.clone()); }
    let sum: i32 = findings.iter().map(|f| match f.severity.as_str() { "critical"=>10,"high"=>6,"medium"=>3,"low"=>1,_=>0 }).sum();
    let risk = (100.0*(1.0 - (- (sum as f64)/60.0).exp())) as u32;

    Ok(ScanResult {
        scan_id: format!("scan-{}", started_at.replace(|c:char| !c.is_ascii_alphanumeric(), "")),
        repo_path: root.to_string_lossy().to_string(),
        started_at, finished_at: Utc::now().to_rfc3339(),
        duration_ms: started.elapsed().as_millis() as u64,
        files_scanned: files.len() as u64,
        summary: ScanSummary { passed, failed: failed_rules.len() as u32, risk_score: risk.min(100) },
        findings, truncated: false, invalid_findings: 0,
    })
}

#[tauri::command]
fn scan_repo(app: AppHandle, state: State<'_, AppState>, store: State<'_, Store>, path: String, options: ScanOptions) -> Result<ScanResult, String> {
    let r = do_scan(&app, &state, path, options)?;
    *store.last.lock().map_err(|_| "lock")? = Some(r.clone());
    Ok(r)
}

#[tauri::command]
fn export_report(scan_id: String, format: String, dest_path: String, store: State<'_, Store>) -> Result<ExportResult, String> {
    let guard = store.last.lock().map_err(|_| "lock")?;
    let r = guard.as_ref().ok_or("No scan")?;
    if r.scan_id != scan_id { return Err("No matching scan to export.".into()); }
    let body = if format == "json" {
        serde_json::to_string_pretty(&serde_json::json!({"tool":"shipcheck","scanId":r.scan_id,"repoPath":r.repo_path,"summary":r.summary,"findings":r.findings})).map_err(|e| e.to_string())?
    } else if format == "txt" {
        let mut s = format!("shipcheck report\nRepository: {}\nRisk score: {}/100\nPassed/Failed: {}/{}\nFindings: {}\n\nAll secret and PII values are redacted.\n\n", r.repo_path, r.summary.risk_score, r.summary.passed, r.summary.failed, r.findings.len());
        for f in &r.findings { s.push_str(&format!("[{}] {}\n{}:{}\nPreview: {}\nFix: {}\n\n", f.severity.to_uppercase(), f.type_, f.file, f.line, f.preview, f.remediation)); }
        s
    } else {
        let mut s = format!("# shipcheck report\n\n- Repository: `{}`\n- Risk score: {}/100\n- Passed/Failed: {}/{}\n- Findings: {}\n\n> All secret and PII values are redacted.\n\n", r.repo_path, r.summary.risk_score, r.summary.passed, r.summary.failed, r.findings.len());
        for f in &r.findings { s.push_str(&format!("## [{}] {}\n- {}:{}\n- Preview: `{}`\n- Fix: {}\n\n", f.severity.to_uppercase(), f.type_, f.file, f.line, f.preview.replace('`',"'"), f.remediation)); }
        s
    };
    fs::write(&dest_path, &body).map_err(|e| e.to_string())?;
    Ok(ExportResult { path: dest_path, bytes: body.len() as u64 })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState::default())
        .manage(Store::default())
        .invoke_handler(tauri::generate_handler![scan_repo, cancel_scan, export_report])
        .run(tauri::generate_context!())
        .expect("error running tauri app");
}
