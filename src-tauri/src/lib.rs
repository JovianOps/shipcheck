use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, Mutex};
use tauri::{AppHandle, Emitter, State};
use walkdir::WalkDir;

#[derive(Default)]
struct AppState { cancel: AtomicBool }
#[derive(Default)]
struct Store { last: Mutex<Option<ScanResult>> }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScanOptions { readiness: bool, secrets: bool }

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScanProgress { scanned: u64, total: u64, current_file: String }

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Finding { id: String, category: String, severity: String, #[serde(rename="type")] type_: String, rule_id: String, file: String, line: u32, preview: String, remediation: String }

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScanSummary { safe_to_upload: bool, risk_score: u32, passed: u32, failed: u32, files_scanned: u64 }

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ScanResult { scan_id: String, path: String, summary: ScanSummary, findings: Vec<Finding> }

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportResult { path: String, bytes: u64 }

const MAX_FINDINGS: u64 = 50_000;

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
    [".git/", "node_modules/", "target/", "dist/", "build/", ".next/", "vendor/", ".webview2/",
     "ebwebview/", "webview2/", "external/", "third_party/", "thirdparty/", "3rdparty/", "deps/",
     "ext/", "submodules/", "venv/", ".venv/", "__pycache__/"]
        .iter().any(|p| rel.contains(p))
}
fn looks_like_placeholder(l: &str) -> bool {
    ["your-", "__", "<", ">", "example", "sample", "dummy", "placeholder",
     "changeme", "change_me", "fake", "notreal", "mock", "stub", "xxx", "todo"]
        .iter().any(|k| l.contains(k))
}

fn in_test_or_fixture_area(rel_lower: &str) -> bool {
    // path segment convention used by almost every language / build tool
    ["/test", "/spec/", "/fixture", "/sample", "/examples/", "/demo", "/preview", "/conformance",
     "/vectors", "/golden", "__tests__",
     ".tests/", ".test/", "_test.go", "_test.py", "_test.js", "_spec.rb", "conftest."]
        .iter().any(|p| rel_lower.contains(p))
        || rel_lower.starts_with("test/") || rel_lower.starts_with("tests/")
        || rel_lower.starts_with("spec/") || rel_lower.starts_with("fixtures/")
        || rel_lower.starts_with("samples/") || rel_lower.starts_with("examples/")
        || rel_lower.starts_with("preview/")
}

fn is_notice_like_file(rel_lower: &str) -> bool {
    let base = Path::new(rel_lower).file_name().and_then(|s| s.to_str()).unwrap_or("");
    ["license", "eula", "readme", "authors", "notice", "third-party", "copying",
     "security.md", "code_of_conduct", "contributing", "changelog", "history", "news", "manifest"]
        .iter().any(|k| base.starts_with(k))
        || base.ends_with(".patch") || base.ends_with(".diff")
        || base.ends_with(".mib") || base.ends_with(".pib") || base.ends_with(".rfc")
        || rel_lower.contains("/mib") || rel_lower.contains("/mibs/")
        || rel_lower.contains("/docs/") || rel_lower.starts_with("docs/")
}

fn skip_secret_rule(rel: &str, rid: &str, line: &str) -> bool {
    let r = rel.to_lowercase().replace('\\', "/");
    let l = line.to_lowercase();

    // generic suppressions for every rule, in any scanned folder:
    // placeholder-style content and test/fixture/sample trees are not real leaks.
    if looks_like_placeholder(&l) { return true; }
    if in_test_or_fixture_area(&r) { return true; }

    if rid == "SEC-GEN-004" {
        if l.contains("publickeytoken=") || l.contains("culture=neutral") || r.ends_with(".resx") { return true; }
        // quoted snake_case identifiers ("access_token") are enum keys, not credentials
        if SNAKE_VALUE.is_match(line) { return true; }
    }
    if rid == "SEC-DB-005" && (l.contains("user:pass@") || l.contains("username:password@") || l.contains(":username:")) { return true; }
    if rid == "PII-EML-001" {
        if is_notice_like_file(&r) { return true; }
        // hidden dirs (`.external`, `.eddy`, ...) are vendored/tooling trees, and
        // CI bot addresses are never personal PII
        if r.contains("/.") || r.starts_with(".") { return true; }
        if l.contains("noreply") || l.contains("no-reply") { return true; }
        // image/asset references like "icons/128x128@2x.png" are not emails
        if ASSET_AT.is_match(line) { return true; }
        // lockfiles and package manifests carry upstream author contacts, not repo-owned PII
        let base = Path::new(&r).file_name().and_then(|s| s.to_str()).unwrap_or("");
        if base.ends_with(".lock") || ["composer.json", "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"].contains(&base) { return true; }
        // author/owner metadata lines in package manifests are public contact info
        if ["authors =", "authors:", "maintainers =", "maintainers:", "author :", "owner :"].iter().any(|k| l.contains(k))
            || l.contains("\"author\"") || l.contains("\"maintainer") { return true; }
        // git scp-style remote URLs (git@host:repo) are not emails
        if GIT_SCP.is_match(line) { return true; }
        // "contact me at ..." documentation conventions
        if ["contact me at", "contact us at", "email the maintainer", "mail to:", "send mail to"].iter().any(|k| l.contains(k)) { return true; }
        if l.contains("copyright") { return true; }
        if l.contains("@example.com") || l.contains("@example.org") || l.contains("@example.net") || l.contains("@example.test") || l.contains(".example") || l.contains("test.com") { return true; }
        // RFC822-style "Name <a@b.c>" attribution (docs / changelogs / git history)
        if ANGLE_EMAIL.is_match(line) { return true; }
    }
    if rid == "PII-TEL-002" {
        if LONG_DIGITS.is_match(line) { return true; }
        if is_notice_like_file(&r) { return true; }
        if r.contains("/.") || r.starts_with(".") { return true; }
        let trimmed = l.trim_start();
        if ["phone", "tel:", "telephone", "fax"].iter().any(|k| trimmed.starts_with(k)) { return true; }
    }
    false
}

static ANGLE_EMAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"<[^<>,\s]+@[^<>,\s]+\.[A-Za-z]{2,}>").unwrap());
static GIT_SCP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bgit@[^\s:]+:").unwrap());
static ASSET_AT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)[A-Za-z0-9.\-/\\_"' ]*@[A-Za-z0-9.\-]+\.(png|jpg|jpeg|gif|svg|webp|ico|ttf|woff2?|mp4|mov|css|map)\b"#).unwrap());
static SNAKE_VALUE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"(?i)"[a-z][a-z0-9_]*_[a-z0-9_]+""#).unwrap());
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
    let mut findings: Vec<Finding> = Vec::new();
    let mut idn: u64 = 0;
    let mut truncated = false;

    let mut files: Vec<PathBuf> = Vec::new();
    for e in WalkDir::new(&root).follow_links(false).into_iter().flatten() {
        if state.cancel.load(Ordering::SeqCst) { break; }
        if e.file_type().is_file() {
            let p = e.path();
            if is_ignored(p, &root) { continue; }
            if let Ok(m) = e.metadata() { if m.len() > 2_000_000 { continue; } }
            files.push(p.to_path_buf());
        }
    }
    let total = files.len() as u64;
    let rs = if options.secrets { rules() } else { vec![] };

    for (i, p) in files.iter().enumerate() {
        if state.cancel.load(Ordering::SeqCst) { break; }
        let rel = p.strip_prefix(&root).unwrap_or(p).to_string_lossy().replace('\\',"/");
        let _ = app.emit("shipcheck://progress", ScanProgress { scanned: (i as u64)+1, total, current_file: rel.clone() });
        if options.secrets {
            if let Ok(text) = fs::read_to_string(p) {
                for (ln, line) in text.lines().enumerate().take(50000) {
                    for (re, cat, sev, typ, rid, rem) in &rs {
                        if re.find(line).is_some() && !skip_secret_rule(&rel, rid, line) {
                            idn += 1;
                            findings.push(Finding { id: format!("f-{idn}"), category: (*cat).into(), severity: (*sev).into(), type_: (*typ).into(), rule_id: (*rid).into(), file: rel.clone(), line: (ln as u32)+1, preview: clean_preview(line), remediation: (*rem).into() });
                        }
                    }
                    if idn >= MAX_FINDINGS { truncated = true; break; }
                }
                if truncated { break; }
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
    let safe = findings.iter().all(|f| f.severity != "critical" && f.severity != "high");

    Ok(ScanResult {
        scan_id: format!("scan-{}", Utc::now().to_rfc3339().replace(|c:char| !c.is_ascii_alphanumeric(), "")),
        path: root.to_string_lossy().to_string(),
        summary: ScanSummary { safe_to_upload: safe, risk_score: risk.min(100), passed, failed: failed_rules.len() as u32, files_scanned: files.len() as u64 },
        findings,
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
        serde_json::to_string_pretty(&serde_json::json!({"tool":"shipcheck","scanId":r.scan_id,"path":r.path,"summary":r.summary,"findings":r.findings})).map_err(|e| e.to_string())?
    } else if format == "txt" {
        let mut s = format!("shipcheck report\nPath: {}\nRisk score: {}/100\nPassed/Failed: {}/{}\nFindings: {}\n\nAll secret and PII values are redacted.\n\n", r.path, r.summary.risk_score, r.summary.passed, r.summary.failed, r.findings.len());
        for f in &r.findings { s.push_str(&format!("[{}] {}\n{}:{}\nPreview: {}\nFix: {}\n\n", f.severity.to_uppercase(), f.type_, f.file, f.line, f.preview, f.remediation)); }
        s
    } else {
        let mut s = format!("# shipcheck report\n\n- Path: `{}`\n- Risk score: {}/100\n- Passed/Failed: {}/{}\n- Findings: {}\n\n> All secret and PII values are redacted.\n\n", r.path, r.summary.risk_score, r.summary.passed, r.summary.failed, r.findings.len());
        for f in &r.findings { s.push_str(&format!("## [{}] {}\n- {}:{}\n- Preview: `{}`\n- Fix: {}\n\n", f.severity.to_uppercase(), f.type_, f.file, f.line, f.preview.replace('`',"'"), f.remediation)); }
        s
    };
    fs::write(&dest_path, &body).map_err(|e| e.to_string())?;
    Ok(ExportResult { path: dest_path, bytes: body.len() as u64 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn match_rules(line: &str) -> Vec<&'static str> {
        rules().iter()
            .filter(|(re, _, _, _, _, _)| re.find(line).is_some())
            .map(|(_, _, _, _, rid, _)| *rid)
            .collect()
    }

    #[test]
    fn detects_core_secret_rules() {
        assert!(match_rules("aws_key = AKIAIOSFODNN7EXAMPLE").contains(&"SEC-AWS-001"));
        assert!(match_rules("token: ghp_XXXXXXXXXXXXXXXXXXXX").contains(&"SEC-GH-002"));
        assert!(match_rules("-----BEGIN OPENSSH PRIVATE KEY-----").contains(&"SEC-KEY-003"));
        assert!(match_rules(r#"api_key = "supersecretvalue12""#).contains(&"SEC-GEN-004"));
        assert!(match_rules("postgres://user:pass@db.example.com:5432/app").contains(&"SEC-DB-005"));
        assert!(match_rules("jwt = eyJAABBCCDD11.eyJXXYYZZ00x1.eyJDDDEEFF22").contains(&"SEC-JWT-006"));
    }

    #[test]
    fn detects_pii_rules() {
        assert!(match_rules("contact: jane.doe@example.org").contains(&"PII-EML-001"));
        assert!(match_rules("phone: (555) 123-4567").contains(&"PII-TEL-002"));
    }

    #[test]
    fn skip_rules_suppress_false_positives() {
        // Example-domain emails are not findings
        for line in ["email: jane@example.com", "x: test@example.org"] {
            let hits = match_rules(line);
            for rid in &hits {
                if *rid == "PII-EML-001" { assert!(skip_secret_rule("notes.md", rid, line)); }
            }
        }
        // License/readme files and copyright lines are exempt
        assert!(skip_secret_rule("LICENSE", "PII-EML-001", "A. U. Thor <author@example.com>"));
        assert!(skip_secret_rule("src/main.rs", "PII-EML-001", "// Copyright (c) 2026 Acme"));
        // notice-like files (changelog, docs, ...) are exempt for PII in any folder
        assert!(skip_secret_rule("docs/overview.md", "PII-EML-001", "Email the maintainer at bob@corp.io"));
        assert!(skip_secret_rule("History.rst", "PII-EML-001", "fixed by kev@corp.io"));
        assert!(skip_secret_rule("docs/overview.md", "PII-TEL-002", "call the team at 555 123 4567"));
        // RFC822 attribution style e-mails are exempt
        assert!(skip_secret_rule("something.txt", "PII-EML-001", "Mon Dec 22 20:29:16 1997    <bk@gamers.org>"));
        // git patch / MIB files
        assert!(skip_secret_rule("0001-fix.patch", "PII-EML-001", "From: A B <a@b.io>"));
        assert!(skip_secret_rule("external/mibs/ACCESSBIND-PIB", "PII-TEL-002", "          Phone: 603-879-7364"));
        assert!(skip_secret_rule("x.snmp", "PII-TEL-002", "        Tel: +1 510-578-0158"));
        // Assembly PublicKeyToken lines in .resx are exempt
        assert!(skip_secret_rule("App.resx", "SEC-GEN-004", "...Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a..."));
        // Long digit runs (timestamps/ids) are not phone numbers
        assert!(skip_secret_rule("log.txt", "PII-TEL-002", "epoch: 1799450000000"));
        // placeholder / test fixture values are never findings
        assert!(skip_secret_rule("src/lib.rs", "SEC-GEN-004", r#"config.apiKey = "your-api-key-1234567890""#));
        assert!(skip_secret_rule("src/lib.rs", "SEC-GEN-004", r#"$repository_token = "__GITHUB_TOKEN__""#));
        assert!(skip_secret_rule("docs/demo.py", "SEC-GEN-004", r#"client(api_key="sk-ant-test123")"#));
        assert!(skip_secret_rule("src/db.rs", "SEC-DB-005", r#"'postgres://user:pass@host/db',"#));
        // test / fixture folders are exempt, in any repo
        assert!(skip_secret_rule("tests/e2e/auth.rs", "SEC-GEN-004", r#"password = "letmein123456""#));
        assert!(skip_secret_rule("tests/sample.rs", "SEC-GEN-004", r#"token = "tok_live_abcdefgh""#));
    }

    #[test]
    fn skip_rules_do_not_overmatch() {
        // Real-looking findings in real source files must NOT be suppressed
        assert!(!skip_secret_rule("src/deploy.rs", "SEC-AWS-001", "AWS_ACCESS_KEY_ID=AKIAJ2YAVLNQJB4LBTHQ"));
        assert!(!skip_secret_rule("src/db.rs", "PII-EML-001", "contact mary.jane@corp.io immediately"));
        assert!(!skip_secret_rule("src/db.rs", "SEC-DB-005", "postgres://admin:S3cr3t!Pass@db.corp:5432/prod"));
        assert!(!skip_secret_rule("src/dial.rs", "PII-TEL-002", "call jim on 650-867-5309"));
        // same secret value with a placeholder-looking *name* is still a finding
        assert!(!skip_secret_rule("config/prod.env", "SEC-GEN-004", r#"DB_PASSWORD = "V9tdafzTZprvhebw""#));
    }

    #[test]
    fn redact_never_reveals_values() {
        let r = redact("AKIAIOSFODNN7EXAMPLE");
        assert!(r.starts_with("AKIA"));
        assert!(r.ends_with("[REDACTED 20 chars]"));
        assert!(r.contains("IOSFODNN7") == false);
        assert_eq!(redact("short"), "****");
    }

    #[test]
    fn clean_preview_redacts_long_tokens() {
        let out = clean_preview("secret: AKIAIOSFODNN7EXAMPLE is bad");
        assert!(out.contains("****"), "expected redaction, got: {out}");
        assert!(out.contains("IOSFODNN7") == false);

        let t = clean_preview("key: skjfhsdkjfhskjdhfskjdhfskjhdkjfhskjdfh");
        assert!(t.contains("****"));
    }

    #[test]
    fn is_ignored_matches_expected_dirs() {
        let root = Path::new("/repo");
        assert!(is_ignored(Path::new("/repo/node_modules/pkg/index.js"), root));
        assert!(is_ignored(Path::new("/repo/.git/config"), root));
        assert!(is_ignored(Path::new("/repo/target/debug/shipcheck.exe"), root));
        assert!(is_ignored(Path::new("/repo/dist/bundle.js"), root));
        // vendored third-party trees are skipped in any repo
        assert!(is_ignored(Path::new("/repo/external/Wireshark/snmp/mibs/IF-MIB"), root));
        assert!(is_ignored(Path::new("/repo/third_party/lib/foo.c"), root));
        assert!(is_ignored(Path::new("/repo/submodules/ui/src/main.ts"), root));
        assert!(!is_ignored(Path::new("/repo/src/main.rs"), root));
    }

    #[test]
    fn readiness_rules_compile() {
        // sanity: all regexes used by the scanner are valid over a sample corpus
        let corpus = ["AKIAIOSFODNN7EXAMPLE", "grs_bogus", "-----BEGIN RSA PRIVATE KEY-----", "a@b.co"];
        for line in corpus { let _ = match_rules(line); }
    }
    #[test]
    #[ignore] // heavy: scans a real folder; run explicitly with `cargo test -- --ignored --nocapture`
    fn diagnostic_folder_hunt() {
        let dirs: Vec<PathBuf> = std::fs::read_dir("C:/Users/RDC/Desktop")
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .map(|e| e.path())
            .collect();
        let mut by_rule: std::collections::HashMap<&str, Vec<(String, u32, String)>> = std::collections::HashMap::new();
        let rs = rules();
        for root in &dirs {
            let root_name = root.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
            if root_name == "shipcheck" { continue; } // our own repo
            for e in WalkDir::new(root).follow_links(false)
                .into_iter()
                .filter_entry(|e| {
                    if e.depth() == 0 { return true; }
                    let p = e.path().to_path_buf();
                    !is_ignored(&p, root)
                })
                .flatten()
            {
                if !e.file_type().is_file() { continue; }
                if let Ok(m) = e.metadata() { if m.len() > 2_000_000 { continue; } }
                let p = e.path().to_path_buf();
                let Ok(text) = fs::read_to_string(&p) else { continue };
                for (ln, line) in text.lines().enumerate().take(50000) {
                    let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().replace('\\', "/");
                    for (re, _, _, _, rid, _) in &rs {
                        if re.find(line).is_some() && !skip_secret_rule(&rel, rid, line) {
                            let entry = by_rule.entry(rid).or_default();
                            if entry.len() < 40 {
                                entry.push((format!("{root_name}/{rel}"), (ln+1) as u32, clean_preview(line)));
                            } else if entry.len() < 400 { entry.push((String::new(), 0, String::new())); }
                        }
                    }
                }
            }
        }
        let mut rows: Vec<(&&str, &Vec<(String, u32, String)>)> = by_rule.iter().collect();
        rows.sort_by_key(|(rid, _)| **rid);
        for (rid, hits) in rows {
            eprintln!("=== {rid} : {} hits ===", hits.len());
            for (repo, ln, prev) in hits.iter().take(12) {
                if prev.is_empty() { eprintln!("  ...more in {repo}"); } else { eprintln!("  {repo} :{ln} | {prev}"); }
            }
        }
    }
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
