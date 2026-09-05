//! Launch-time updates from GitHub Releases via the Tauri updater plugin.
//! The frontend asks for a check after boot (skipped in airgap mode), shows a banner when a
//! newer signed build exists, and calls `install_update` to download, verify, install and restart.

use std::sync::Mutex;

use serde::Serialize;
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_updater::UpdaterExt;

#[derive(Default)]
pub struct PendingUpdate(pub Mutex<Option<tauri_plugin_updater::Update>>);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub available: bool,
    pub current: String,
    pub version: Option<String>,
    pub notes: Option<String>,
    pub date: Option<String>,
    pub error: Option<String>,
}

fn base(app: &AppHandle) -> UpdateInfo {
    UpdateInfo {
        available: false,
        current: app.package_info().version.to_string(),
        version: None,
        notes: None,
        date: None,
        error: None,
    }
}

fn friendly(err: tauri_plugin_updater::Error) -> String {
    let text = err.to_string();
    if text.contains("404") {
        "Update manifest not found (HTTP 404). Releases must be public for the updater to reach them.".to_string()
    } else if text.contains("dns") || text.contains("connect") || text.contains("timed out") {
        format!("Could not reach GitHub: {text}")
    } else {
        text
    }
}

pub async fn check(app: &AppHandle) -> UpdateInfo {
    let mut info = base(app);
    let updater = match app.updater() {
        Ok(u) => u,
        Err(e) => {
            info.error = Some(format!("updater not configured: {e}"));
            return info;
        }
    };
    match updater.check().await {
        Ok(Some(update)) => {
            info.available = true;
            info.version = Some(update.version.clone());
            info.notes = update.body.clone();
            info.date = update.date.map(|d| d.to_string());
            if let Some(state) = app.try_state::<PendingUpdate>() {
                *state.0.lock().expect("pending update lock") = Some(update);
            }
        }
        Ok(None) => {}
        Err(e) => info.error = Some(friendly(e)),
    }
    info
}

#[tauri::command]
pub async fn check_update(app: AppHandle) -> UpdateInfo {
    check(&app).await
}

/// Downloads, verifies the signature, runs the installer and restarts.
#[tauri::command]
pub async fn install_update(app: AppHandle) -> Result<(), String> {
    let update = app
        .state::<PendingUpdate>()
        .0
        .lock()
        .expect("pending update lock")
        .take()
        .ok_or_else(|| "No update is pending. Run a check first.".to_string())?;

    let progress_app = app.clone();
    let mut downloaded: u64 = 0;
    update
        .download_and_install(
            move |chunk, total| {
                downloaded += chunk as u64;
                let _ = progress_app.emit("update://progress", json!({ "downloaded": downloaded, "total": total }));
            },
            || {},
        )
        .await
        .map_err(|e| e.to_string())?;

    let _ = app.emit("update://installed", json!({}));
    app.restart();
}
