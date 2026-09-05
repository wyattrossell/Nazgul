//! Nazgul core: Tauri setup and command registration.

pub mod commands;
pub mod db;
pub mod engine;
pub mod probes;

use std::sync::Arc;

use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(engine::ScanRegistry::default())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            let database = db::Db::open(&dir.join("nazgul.db")).map_err(std::io::Error::other)?;
            database.close_stale_scans().map_err(std::io::Error::other)?;
            app.manage(Arc::new(database));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::list_sites,
            commands::start_scan,
            commands::cancel_scan,
            commands::list_scans,
            commands::scan_findings,
            commands::delete_scan,
            commands::list_cases,
            commands::create_case,
            commands::update_case,
            commands::delete_case,
            commands::list_entities,
            commands::add_entity,
            commands::delete_entity,
            commands::set_entity_label,
            commands::set_entity_tags,
            commands::entity_hits,
            commands::case_hits,
            commands::list_notes,
            commands::add_note,
            commands::update_note,
            commands::delete_note,
            commands::case_graph,
            commands::write_text_file,
            commands::secret_status,
            commands::set_secret,
            commands::delete_secret,
            commands::check_route,
            commands::list_plugins,
            commands::save_flipped_image,
            commands::launcher_catalog,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
