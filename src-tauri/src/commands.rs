//! Tauri commands exposed to the frontend.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, State};

use crate::db::{self, Case, Db, Entity, Graph, Note, ScanRow};
use crate::engine::http::{build_following_client, fetch, HttpOptions};
use crate::engine::secrets::{self, SecretStatus};
use crate::engine::ScanRegistry;
use crate::probes::plugin::{self, PluginManifest};
use crate::probes::username::CATALOG;
use crate::probes::{self, EntityType, Finding, ProbeKind, ScanDone, ScanRequest, ScanSink, ScanStarted};

pub type Shared = Arc<Db>;

// ---------------------------------------------------------------------------
// App / catalog
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub site_count: usize,
    pub data_dir: String,
}

#[tauri::command]
pub fn app_info(app: AppHandle) -> AppInfo {
    AppInfo {
        name: "Nazgul",
        version: env!("CARGO_PKG_VERSION"),
        site_count: CATALOG.sites.len(),
        data_dir: app
            .path()
            .app_data_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryCount {
    pub name: String,
    pub count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteSummary {
    pub total: usize,
    pub categories: Vec<CategoryCount>,
    pub license: String,
    pub authors: Vec<String>,
}

#[tauri::command]
pub fn list_sites() -> SiteSummary {
    let catalog = &*CATALOG;
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for site in &catalog.sites {
        *counts.entry(site.cat.as_str()).or_default() += 1;
    }
    SiteSummary {
        total: catalog.sites.len(),
        categories: counts
            .into_iter()
            .map(|(name, count)| CategoryCount {
                name: name.to_string(),
                count,
            })
            .collect(),
        license: catalog.license.clone(),
        authors: catalog.authors.clone(),
    }
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

/// Sends scan events to the window and persists them.
struct AppSink {
    app: AppHandle,
    db: Shared,
    case_id: i64,
    entity_id: i64,
}

impl ScanSink for AppSink {
    fn started(&self, event: &ScanStarted) {
        let _ = self.db.set_scan_total(&event.scan_id, event.total);
        let _ = self.app.emit("scan://started", event);
    }

    fn finding(&self, finding: &Finding) {
        let _ = self.app.emit("scan://finding", finding);
        let _ = self.db.insert_finding(self.case_id, Some(self.entity_id), finding);
        for found in &finding.discovered {
            if let Ok(target) = self.db.upsert_entity(
                self.case_id,
                found.entity_type,
                &found.value,
                found.label.as_deref(),
            ) {
                let relation = format!("{}:{}", finding.source, finding.kind);
                let _ = self
                    .db
                    .add_link(self.case_id, self.entity_id, target, &relation, Some(&finding.scan_id));
            }
        }
    }

    fn done(&self, event: &ScanDone) {
        let status = db::scan_status_label(event.cancelled, event.error.as_deref());
        let _ = self.db.finish_scan(
            &event.scan_id,
            status,
            event.checked,
            event.found,
            event.elapsed_ms,
            event.error.as_deref(),
        );
        let _ = self.app.emit("scan://done", event);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanHandle {
    pub scan_id: String,
    pub probe: ProbeKind,
    pub input: String,
    pub case_id: i64,
    pub entity_id: i64,
}

fn new_scan_id() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{:x}{:04x}", millis, rand::random::<u16>())
}

#[tauri::command]
pub async fn start_scan(
    app: AppHandle,
    registry: State<'_, ScanRegistry>,
    db: State<'_, Shared>,
    mut req: ScanRequest,
) -> Result<ScanHandle, String> {
    req.input = req.input.trim().to_string();
    if req.input.is_empty() {
        return Err("Enter something to search for.".to_string());
    }
    if req.probe == ProbeKind::Username && req.input.chars().any(char::is_whitespace) {
        return Err("Usernames cannot contain spaces.".to_string());
    }
    if req.probe == ProbeKind::Username && probes::username::matching_sites(&req.options).is_empty() {
        return Err("No sites match the selected categories.".to_string());
    }

    // Plugins: resolve the manifest now so the probe does not need filesystem access.
    let mut entity_type = req.probe.input_entity();
    if req.probe == ProbeKind::Plugin {
        let name = req.options.extra["plugin"].as_str().unwrap_or("").to_string();
        let dirs = plugin::plugin_dirs(app.path().app_data_dir().ok().as_deref());
        let manifest = plugin::list(&dirs)
            .into_iter()
            .find(|m| m.name == name)
            .ok_or_else(|| format!("No plugin named \"{name}\" was found."))?;
        if let Some(t) = manifest.input_types.first() {
            entity_type = *t;
        }
        req.options.extra = serde_json::json!({ "plugin": name, "manifest": manifest });
    }

    let case_id = if req.case_id > 0 && db.case_exists(req.case_id)? {
        req.case_id
    } else {
        db.first_case_id()?
    };
    let entity_id = db.upsert_entity(case_id, entity_type, &req.input, None)?;

    let scan_id = new_scan_id();
    let options_json = serde_json::to_value(&req.options).unwrap_or(Value::Null);
    db.insert_scan(&scan_id, case_id, Some(entity_id), req.probe, &req.input, &options_json)?;

    let token = registry.register(&scan_id);
    let handle = ScanHandle {
        scan_id: scan_id.clone(),
        probe: req.probe,
        input: req.input.clone(),
        case_id,
        entity_id,
    };

    let sink: Arc<dyn ScanSink> = Arc::new(AppSink {
        app: app.clone(),
        db: db.inner().clone(),
        case_id,
        entity_id,
    });
    let app_for_task = app.clone();
    let secrets = if req.options.airgap { Default::default() } else { secrets::load_all() };
    tauri::async_runtime::spawn(async move {
        let _ = probes::run_scan_with_secrets(sink, scan_id.clone(), req, token, secrets).await;
        app_for_task.state::<ScanRegistry>().remove(&scan_id);
    });

    Ok(handle)
}

// ---------------------------------------------------------------------------
// Secrets, route, plugins
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn secret_status() -> Vec<SecretStatus> {
    secrets::status()
}

#[tauri::command]
pub fn set_secret(name: String, value: String) -> Result<(), String> {
    secrets::set(&name, &value)
}

#[tauri::command]
pub fn delete_secret(name: String) -> Result<(), String> {
    secrets::delete(&name)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteStatus {
    pub ok: bool,
    pub ip: Option<String>,
    pub is_tor: bool,
    pub error: Option<String>,
}

/// Asks the Tor Project check service what it sees through the given proxy.
#[tauri::command]
pub async fn check_route(proxy: Option<String>) -> RouteStatus {
    let opts = HttpOptions {
        proxy,
        timeout_secs: 20,
        ..HttpOptions::default()
    };
    let client = match build_following_client(&opts) {
        Ok(c) => c,
        Err(e) => {
            return RouteStatus {
                ok: false,
                ip: None,
                is_tor: false,
                error: Some(format!("proxy configuration: {e}")),
            }
        }
    };
    match fetch(client.get("https://check.torproject.org/api/ip")).await {
        Err((e, _)) => RouteStatus {
            ok: false,
            ip: None,
            is_tor: false,
            error: Some(e),
        },
        Ok(res) => {
            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
            RouteStatus {
                ok: res.status == 200,
                ip: v["IP"].as_str().map(str::to_string),
                is_tor: v["IsTor"].as_bool().unwrap_or(false),
                error: if res.status == 200 { None } else { Some(format!("HTTP {}", res.status)) },
            }
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginList {
    pub plugins: Vec<PluginManifest>,
    pub dirs: Vec<String>,
}

#[tauri::command]
pub fn list_plugins(app: AppHandle) -> PluginList {
    let dirs = plugin::plugin_dirs(app.path().app_data_dir().ok().as_deref());
    PluginList {
        plugins: plugin::list(&dirs),
        dirs: dirs.iter().map(|d| d.display().to_string()).collect(),
    }
}

#[tauri::command]
pub fn cancel_scan(registry: State<'_, ScanRegistry>, scan_id: String) -> bool {
    registry.cancel(&scan_id)
}

#[tauri::command]
pub fn list_scans(db: State<'_, Shared>, case_id: Option<i64>, limit: Option<i64>) -> Result<Vec<ScanRow>, String> {
    db.list_scans(case_id, limit.unwrap_or(200))
}

#[tauri::command]
pub fn scan_findings(db: State<'_, Shared>, scan_id: String) -> Result<Vec<Finding>, String> {
    db.list_findings(&scan_id)
}

#[tauri::command]
pub fn delete_scan(db: State<'_, Shared>, scan_id: String) -> Result<(), String> {
    db.delete_scan(&scan_id)
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn list_cases(db: State<'_, Shared>) -> Result<Vec<Case>, String> {
    db.list_cases()
}

#[tauri::command]
pub fn create_case(db: State<'_, Shared>, name: String, description: Option<String>) -> Result<Case, String> {
    if name.trim().is_empty() {
        return Err("Give the case a name.".to_string());
    }
    db.create_case(&name, description.as_deref().unwrap_or(""))
}

#[tauri::command]
pub fn update_case(db: State<'_, Shared>, id: i64, name: String, description: Option<String>) -> Result<(), String> {
    if name.trim().is_empty() {
        return Err("Give the case a name.".to_string());
    }
    db.update_case(id, &name, description.as_deref().unwrap_or(""))
}

#[tauri::command]
pub fn delete_case(db: State<'_, Shared>, id: i64) -> Result<(), String> {
    db.delete_case(id)
}

// ---------------------------------------------------------------------------
// Entities
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn list_entities(db: State<'_, Shared>, case_id: i64) -> Result<Vec<Entity>, String> {
    db.list_entities(case_id)
}

#[tauri::command]
pub fn add_entity(
    db: State<'_, Shared>,
    case_id: i64,
    entity_type: String,
    value: String,
    label: Option<String>,
) -> Result<i64, String> {
    let kind = EntityType::parse(&entity_type).ok_or_else(|| format!("Unknown entity type {entity_type}"))?;
    if value.trim().is_empty() {
        return Err("Entity value cannot be empty.".to_string());
    }
    db.upsert_entity(case_id, kind, &value, label.as_deref())
}

#[tauri::command]
pub fn delete_entity(db: State<'_, Shared>, id: i64) -> Result<(), String> {
    db.delete_entity(id)
}

#[tauri::command]
pub fn set_entity_label(db: State<'_, Shared>, id: i64, label: Option<String>) -> Result<(), String> {
    db.set_entity_label(id, label.as_deref().map(str::trim).filter(|s| !s.is_empty()))
}

#[tauri::command]
pub fn set_entity_tags(db: State<'_, Shared>, entity_id: i64, tags: Vec<String>) -> Result<(), String> {
    db.set_tags(entity_id, &tags)
}

#[tauri::command]
pub fn entity_hits(db: State<'_, Shared>, entity_id: i64) -> Result<Vec<Finding>, String> {
    db.entity_hits(entity_id)
}

#[tauri::command]
pub fn case_hits(db: State<'_, Shared>, case_id: i64, limit: Option<i64>) -> Result<Vec<Finding>, String> {
    db.case_hits(case_id, limit.unwrap_or(5000))
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn list_notes(db: State<'_, Shared>, case_id: i64, entity_id: Option<i64>) -> Result<Vec<Note>, String> {
    db.list_notes(case_id, entity_id)
}

#[tauri::command]
pub fn add_note(db: State<'_, Shared>, case_id: i64, entity_id: Option<i64>, body: String) -> Result<Note, String> {
    if body.trim().is_empty() {
        return Err("Note is empty.".to_string());
    }
    db.add_note(case_id, entity_id, body.trim())
}

#[tauri::command]
pub fn update_note(db: State<'_, Shared>, id: i64, body: String) -> Result<(), String> {
    db.update_note(id, body.trim())
}

#[tauri::command]
pub fn delete_note(db: State<'_, Shared>, id: i64) -> Result<(), String> {
    db.delete_note(id)
}

// ---------------------------------------------------------------------------
// Graph
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn case_graph(db: State<'_, Shared>, case_id: i64) -> Result<Graph, String> {
    db.graph(case_id, 400)
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// Writes UTF-8 text to a path the user picked through the save dialog.
#[tauri::command]
pub fn write_text_file(path: String, contents: String) -> Result<(), String> {
    std::fs::write(&path, contents).map_err(|e| format!("Could not write {}: {}", path, e))
}
