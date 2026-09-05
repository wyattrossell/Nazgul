//! Plugin bridge: run an external command-line tool described by a JSON manifest and turn
//! its output into findings. This is how Sherlock, holehe, Maigret and friends plug in
//! without bundling Python.
//!
//! Manifest (plugins/<name>.json):
//! {
//!   "name": "sherlock",
//!   "description": "Sherlock username search",
//!   "inputTypes": ["username"],
//!   "command": "sherlock",
//!   "args": ["{input}", "--print-found", "--no-color"],
//!   "parse": "lines",            // or "json"
//!   "foundMarker": "[+]",        // lines containing this are hits (lines mode)
//!   "timeoutSecs": 300
//! }

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;

use super::{EntityType, FindingStatus, ScanContext};

static RE_URL: Lazy<Regex> = Lazy::new(|| Regex::new(r#"https?://[^\s<>"')\]]+"#).unwrap());

fn default_parse() -> String {
    "lines".to_string()
}
fn default_timeout() -> u64 {
    300
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginManifest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub input_types: Vec<EntityType>,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default = "default_parse")]
    pub parse: String,
    #[serde(default)]
    pub found_marker: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub path: Option<String>,
}

/// Folders searched for manifests, in priority order.
pub fn plugin_dirs(app_data: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(d) = app_data {
        dirs.push(d.join("plugins"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.join("plugins"));
        }
    }
    if cfg!(debug_assertions) {
        dirs.push(Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("plugins"));
    }
    dirs
}

pub fn list(dirs: &[PathBuf]) -> Vec<PluginManifest> {
    let mut out: Vec<PluginManifest> = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else { continue };
            let Ok(mut manifest) = serde_json::from_str::<PluginManifest>(&text) else { continue };
            if out.iter().any(|m| m.name == manifest.name) {
                continue;
            }
            manifest.path = Some(path.display().to_string());
            out.push(manifest);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn manifest_from(ctx: &ScanContext) -> Result<PluginManifest, String> {
    serde_json::from_value(ctx.options.extra["manifest"].clone())
        .map_err(|_| "No plugin manifest was attached to this scan.".to_string())
}

pub async fn run(ctx: Arc<ScanContext>) -> Result<(), String> {
    let manifest = manifest_from(&ctx)?;
    let input = ctx.input.trim().to_string();
    if input.is_empty() {
        return Err("Enter an input for the plugin.".to_string());
    }
    ctx.start(1);

    let args: Vec<String> = manifest.args.iter().map(|a| a.replace("{input}", &input)).collect();
    let mut command = tokio::process::Command::new(&manifest.command);
    command
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let started = Instant::now();
    let mut child = command.spawn().map_err(|e| {
        format!(
            "Could not start `{}`: {e}. Is it installed and on PATH? (manifest: {})",
            manifest.command,
            manifest.path.clone().unwrap_or_default()
        )
    })?;

    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let mut out_buf = Vec::new();
    let mut err_buf = Vec::new();
    let timeout = Duration::from_secs(manifest.timeout_secs.clamp(5, 3600));

    let exit = tokio::select! {
        _ = ctx.cancel.cancelled() => {
            let _ = child.kill().await;
            None
        }
        _ = tokio::time::sleep(timeout) => {
            let _ = child.kill().await;
            ctx.emit(ctx.finding(&manifest.name, "plugin", "Timed out").category("plugin").error(format!("no exit after {}s", timeout.as_secs())));
            None
        }
        res = async {
            let (o, e) = tokio::join!(stdout.read_to_end(&mut out_buf), stderr.read_to_end(&mut err_buf));
            let _ = (o, e);
            child.wait().await
        } => res.ok(),
    };

    let stdout_text = String::from_utf8_lossy(&out_buf).to_string();
    let stderr_text = String::from_utf8_lossy(&err_buf).to_string();
    let mut emitted = 0usize;

    if manifest.parse == "json" {
        let parsed: Value = serde_json::from_str(stdout_text.trim()).unwrap_or(Value::Null);
        let items: Vec<Value> = match parsed {
            Value::Array(a) => a,
            Value::Object(o) => o.into_iter().map(|(k, v)| json!({ "name": k, "value": v })).collect(),
            _ => Vec::new(),
        };
        for item in items {
            let title = item["title"].as_str().or(item["name"].as_str()).or(item["site"].as_str()).unwrap_or("result").to_string();
            let url = item["url"].as_str().or(item["url_user"].as_str()).map(str::to_string);
            let exists = item["exists"].as_bool().or(item["found"].as_bool()).unwrap_or(url.is_some());
            let mut f = ctx.finding(&manifest.name, "plugin", &title).category("plugin")
                .status(if exists { FindingStatus::Found } else { FindingStatus::NotFound })
                .data(item.clone());
            if let Some(u) = url {
                f = f.url(u);
            }
            ctx.emit(f);
            emitted += 1;
        }
    } else {
        let marker = manifest.found_marker.clone().unwrap_or_else(|| "[+]".to_string());
        for line in stdout_text.lines() {
            let clean = strip_ansi(line).trim().to_string();
            if clean.is_empty() {
                continue;
            }
            let url = RE_URL.find(&clean).map(|m| m.as_str().trim_end_matches(['.', ',']).to_string());
            let found = clean.contains(&marker);
            let mut f = ctx.finding(&manifest.name, "plugin", &clean.chars().take(160).collect::<String>())
                .category("plugin")
                .status(if found { FindingStatus::Found } else { FindingStatus::Info })
                .data(json!({ "line": clean }));
            if let Some(u) = url {
                f = f.url(u);
            }
            ctx.emit(f);
            emitted += 1;
            if emitted >= 2000 {
                break;
            }
        }
    }

    let code = exit.and_then(|s| s.code());
    let summary = format!(
        "exit {} · {} line(s) parsed · {:.1}s",
        code.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
        emitted,
        started.elapsed().as_secs_f64()
    );
    let mut f = ctx.finding(&manifest.name, "plugin-run", &format!("{} finished", manifest.name)).category("plugin")
        .summary(summary)
        .data(json!({ "command": manifest.command, "args": args, "exitCode": code, "stderr": stderr_text.chars().take(4000).collect::<String>() }));
    f.status = match code {
        Some(0) => FindingStatus::Info,
        Some(_) => FindingStatus::Error,
        None => FindingStatus::Ambiguous,
    };
    if f.status == FindingStatus::Error {
        f.detail = Some(stderr_text.lines().last().unwrap_or("non-zero exit").chars().take(200).collect());
    }
    ctx.emit(f);
    Ok(())
}

fn strip_ansi(s: &str) -> String {
    static RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").unwrap());
    RE.replace_all(s, "").to_string()
}
