//! SQLite persistence: cases, entities, scans, findings, links, notes, tags.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::Value;

use crate::probes::{EntityType, Finding, FindingStatus, ProbeKind};

pub type DbResult<T> = Result<T, String>;

pub struct Db {
    conn: Mutex<Connection>,
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn err(e: rusqlite::Error) -> String {
    format!("database: {e}")
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS entities (
  id INTEGER PRIMARY KEY,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  label TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE(case_id, type, value)
);
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  entity_id INTEGER REFERENCES entities(id) ON DELETE SET NULL,
  probe TEXT NOT NULL,
  input TEXT NOT NULL,
  status TEXT NOT NULL,
  total INTEGER NOT NULL DEFAULT 0,
  checked INTEGER NOT NULL DEFAULT 0,
  found INTEGER NOT NULL DEFAULT 0,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  elapsed_ms INTEGER,
  error TEXT,
  options_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  entity_id INTEGER REFERENCES entities(id) ON DELETE SET NULL,
  probe TEXT NOT NULL,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  title TEXT NOT NULL,
  url TEXT,
  status TEXT NOT NULL,
  json TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS findings_case_status ON findings(case_id, status);
CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  from_entity INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  to_entity INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  relation TEXT NOT NULL,
  scan_id TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE(case_id, from_entity, to_entity, relation)
);
CREATE TABLE IF NOT EXISTS notes (
  id INTEGER PRIMARY KEY,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  entity_id INTEGER REFERENCES entities(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tags (
  id INTEGER PRIMARY KEY,
  case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
  tag TEXT NOT NULL,
  UNIQUE(entity_id, tag)
);
"#;

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Case {
    pub id: i64,
    pub name: String,
    pub description: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub entity_count: i64,
    pub scan_count: i64,
    pub finding_count: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entity {
    pub id: i64,
    pub case_id: i64,
    #[serde(rename = "type")]
    pub entity_type: String,
    pub value: String,
    pub label: Option<String>,
    pub created_at: i64,
    pub scan_count: i64,
    pub found_count: i64,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRow {
    pub id: String,
    pub case_id: i64,
    pub case_name: String,
    pub entity_id: Option<i64>,
    pub probe: String,
    pub input: String,
    pub status: String,
    pub total: i64,
    pub checked: i64,
    pub found: i64,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub elapsed_ms: Option<i64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Note {
    pub id: i64,
    pub case_id: i64,
    pub entity_id: Option<i64>,
    pub body: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String,
    pub label: String,
    pub value: String,
    pub url: Option<String>,
    pub entity_id: Option<i64>,
    pub weight: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Graph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

// ---------------------------------------------------------------------------
// Open / migrate
// ---------------------------------------------------------------------------

impl Db {
    pub fn open(path: &Path) -> DbResult<Self> {
        let conn = Connection::open(path).map_err(err)?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> DbResult<Self> {
        let conn = Connection::open_in_memory().map_err(err)?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> DbResult<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )
        .map_err(err)?;
        conn.execute_batch(SCHEMA).map_err(err)?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.ensure_default_case()?;
        Ok(db)
    }

    fn with<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> DbResult<T> {
        let conn = self.conn.lock().map_err(|_| "database lock poisoned".to_string())?;
        f(&conn).map_err(err)
    }

    // -----------------------------------------------------------------------
    // Cases
    // -----------------------------------------------------------------------

    fn ensure_default_case(&self) -> DbResult<()> {
        let count: i64 = self.with(|c| c.query_row("SELECT COUNT(*) FROM cases", [], |r| r.get(0)))?;
        if count == 0 {
            self.create_case("scratch", "Default working case")?;
        }
        Ok(())
    }

    pub fn list_cases(&self) -> DbResult<Vec<Case>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT c.id, c.name, c.description, c.created_at, c.updated_at,
                        (SELECT COUNT(*) FROM entities e WHERE e.case_id = c.id),
                        (SELECT COUNT(*) FROM scans s WHERE s.case_id = c.id),
                        (SELECT COUNT(*) FROM findings f WHERE f.case_id = c.id AND f.status IN ('found','info'))
                 FROM cases c ORDER BY c.updated_at DESC",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(Case {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    description: r.get(2)?,
                    created_at: r.get(3)?,
                    updated_at: r.get(4)?,
                    entity_count: r.get(5)?,
                    scan_count: r.get(6)?,
                    finding_count: r.get(7)?,
                })
            })?;
            rows.collect()
        })
    }

    pub fn create_case(&self, name: &str, description: &str) -> DbResult<Case> {
        let now = now_ms();
        let id = self.with(|c| {
            c.execute(
                "INSERT INTO cases (name, description, created_at, updated_at) VALUES (?1, ?2, ?3, ?3)",
                params![name.trim(), description.trim(), now],
            )?;
            Ok(c.last_insert_rowid())
        })?;
        Ok(Case {
            id,
            name: name.trim().to_string(),
            description: description.trim().to_string(),
            created_at: now,
            updated_at: now,
            entity_count: 0,
            scan_count: 0,
            finding_count: 0,
        })
    }

    pub fn update_case(&self, id: i64, name: &str, description: &str) -> DbResult<()> {
        self.with(|c| {
            c.execute(
                "UPDATE cases SET name = ?2, description = ?3, updated_at = ?4 WHERE id = ?1",
                params![id, name.trim(), description.trim(), now_ms()],
            )?;
            Ok(())
        })
    }

    pub fn delete_case(&self, id: i64) -> DbResult<()> {
        self.with(|c| {
            c.execute("DELETE FROM cases WHERE id = ?1", params![id])?;
            Ok(())
        })?;
        self.ensure_default_case()
    }

    pub fn touch_case(&self, id: i64) -> DbResult<()> {
        self.with(|c| {
            c.execute("UPDATE cases SET updated_at = ?2 WHERE id = ?1", params![id, now_ms()])?;
            Ok(())
        })
    }

    // -----------------------------------------------------------------------
    // Entities
    // -----------------------------------------------------------------------

    pub fn upsert_entity(&self, case_id: i64, entity_type: EntityType, value: &str, label: Option<&str>) -> DbResult<i64> {
        let value = value.trim();
        self.with(|c| {
            c.execute(
                "INSERT INTO entities (case_id, type, value, label, created_at) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(case_id, type, value) DO UPDATE SET label = COALESCE(entities.label, excluded.label)",
                params![case_id, entity_type.as_str(), value, label, now_ms()],
            )?;
            c.query_row(
                "SELECT id FROM entities WHERE case_id = ?1 AND type = ?2 AND value = ?3",
                params![case_id, entity_type.as_str(), value],
                |r| r.get(0),
            )
        })
    }

    pub fn list_entities(&self, case_id: i64) -> DbResult<Vec<Entity>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT e.id, e.case_id, e.type, e.value, e.label, e.created_at,
                        (SELECT COUNT(*) FROM scans s WHERE s.entity_id = e.id),
                        (SELECT COUNT(*) FROM findings f WHERE f.entity_id = e.id AND f.status = 'found'),
                        (SELECT GROUP_CONCAT(t.tag, '\u{1f}') FROM tags t WHERE t.entity_id = e.id)
                 FROM entities e WHERE e.case_id = ?1 ORDER BY e.created_at DESC",
            )?;
            let rows = stmt.query_map(params![case_id], |r| {
                let tags: Option<String> = r.get(8)?;
                Ok(Entity {
                    id: r.get(0)?,
                    case_id: r.get(1)?,
                    entity_type: r.get(2)?,
                    value: r.get(3)?,
                    label: r.get(4)?,
                    created_at: r.get(5)?,
                    scan_count: r.get(6)?,
                    found_count: r.get(7)?,
                    tags: tags
                        .map(|t| t.split('\u{1f}').map(str::to_string).collect())
                        .unwrap_or_default(),
                })
            })?;
            rows.collect()
        })
    }

    pub fn delete_entity(&self, id: i64) -> DbResult<()> {
        self.with(|c| {
            c.execute("DELETE FROM entities WHERE id = ?1", params![id])?;
            Ok(())
        })
    }

    pub fn set_entity_label(&self, id: i64, label: Option<&str>) -> DbResult<()> {
        self.with(|c| {
            c.execute("UPDATE entities SET label = ?2 WHERE id = ?1", params![id, label])?;
            Ok(())
        })
    }

    pub fn set_tags(&self, entity_id: i64, tags: &[String]) -> DbResult<()> {
        self.with(|c| {
            let case_id: i64 = c.query_row("SELECT case_id FROM entities WHERE id = ?1", params![entity_id], |r| r.get(0))?;
            c.execute("DELETE FROM tags WHERE entity_id = ?1", params![entity_id])?;
            for tag in tags {
                let tag = tag.trim().to_lowercase();
                if tag.is_empty() {
                    continue;
                }
                c.execute(
                    "INSERT OR IGNORE INTO tags (case_id, entity_id, tag) VALUES (?1, ?2, ?3)",
                    params![case_id, entity_id, tag],
                )?;
            }
            Ok(())
        })
    }

    pub fn add_link(&self, case_id: i64, from: i64, to: i64, relation: &str, scan_id: Option<&str>) -> DbResult<()> {
        if from == to {
            return Ok(());
        }
        self.with(|c| {
            c.execute(
                "INSERT OR IGNORE INTO links (case_id, from_entity, to_entity, relation, scan_id, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![case_id, from, to, relation, scan_id, now_ms()],
            )?;
            Ok(())
        })
    }

    // -----------------------------------------------------------------------
    // Scans
    // -----------------------------------------------------------------------

    pub fn insert_scan(
        &self,
        scan_id: &str,
        case_id: i64,
        entity_id: Option<i64>,
        probe: ProbeKind,
        input: &str,
        options: &Value,
    ) -> DbResult<()> {
        self.with(|c| {
            c.execute(
                "INSERT INTO scans (id, case_id, entity_id, probe, input, status, started_at, options_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'running', ?6, ?7)",
                params![scan_id, case_id, entity_id, probe.as_str(), input, now_ms(), options.to_string()],
            )?;
            Ok(())
        })?;
        self.touch_case(case_id)
    }

    pub fn set_scan_total(&self, scan_id: &str, total: usize) -> DbResult<()> {
        self.with(|c| {
            c.execute("UPDATE scans SET total = ?2 WHERE id = ?1", params![scan_id, total as i64])?;
            Ok(())
        })
    }

    pub fn finish_scan(
        &self,
        scan_id: &str,
        status: &str,
        checked: usize,
        found: usize,
        elapsed_ms: u64,
        error: Option<&str>,
    ) -> DbResult<()> {
        self.with(|c| {
            c.execute(
                "UPDATE scans SET status = ?2, checked = ?3, found = ?4, elapsed_ms = ?5, finished_at = ?6, error = ?7
                 WHERE id = ?1",
                params![scan_id, status, checked as i64, found as i64, elapsed_ms as i64, now_ms(), error],
            )?;
            Ok(())
        })
    }

    pub fn list_scans(&self, case_id: Option<i64>, limit: i64) -> DbResult<Vec<ScanRow>> {
        self.with(|c| {
            let sql = "SELECT s.id, s.case_id, c.name, s.entity_id, s.probe, s.input, s.status, s.total, s.checked,
                              s.found, s.started_at, s.finished_at, s.elapsed_ms, s.error
                       FROM scans s JOIN cases c ON c.id = s.case_id
                       WHERE (?1 IS NULL OR s.case_id = ?1)
                       ORDER BY s.started_at DESC LIMIT ?2";
            let mut stmt = c.prepare(sql)?;
            let rows = stmt.query_map(params![case_id, limit], |r| {
                Ok(ScanRow {
                    id: r.get(0)?,
                    case_id: r.get(1)?,
                    case_name: r.get(2)?,
                    entity_id: r.get(3)?,
                    probe: r.get(4)?,
                    input: r.get(5)?,
                    status: r.get(6)?,
                    total: r.get(7)?,
                    checked: r.get(8)?,
                    found: r.get(9)?,
                    started_at: r.get(10)?,
                    finished_at: r.get(11)?,
                    elapsed_ms: r.get(12)?,
                    error: r.get(13)?,
                })
            })?;
            rows.collect()
        })
    }

    pub fn delete_scan(&self, scan_id: &str) -> DbResult<()> {
        self.with(|c| {
            c.execute("DELETE FROM scans WHERE id = ?1", params![scan_id])?;
            Ok(())
        })
    }

    /// Marks any scan still flagged as running (from a previous session) as interrupted.
    pub fn close_stale_scans(&self) -> DbResult<()> {
        self.with(|c| {
            c.execute(
                "UPDATE scans SET status = 'interrupted', finished_at = ?1 WHERE status = 'running'",
                params![now_ms()],
            )?;
            Ok(())
        })
    }

    // -----------------------------------------------------------------------
    // Findings
    // -----------------------------------------------------------------------

    pub fn insert_finding(&self, case_id: i64, entity_id: Option<i64>, finding: &Finding) -> DbResult<i64> {
        let json = serde_json::to_string(finding).map_err(|e| e.to_string())?;
        let status = serde_json::to_value(finding.status)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_else(|| "info".to_string());
        self.with(|c| {
            c.execute(
                "INSERT INTO findings (scan_id, case_id, entity_id, probe, source, kind, title, url, status, json, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    finding.scan_id,
                    case_id,
                    entity_id,
                    finding.probe.as_str(),
                    finding.source,
                    finding.kind,
                    finding.title,
                    finding.url,
                    status,
                    json,
                    now_ms()
                ],
            )?;
            Ok(c.last_insert_rowid())
        })
    }

    pub fn list_findings(&self, scan_id: &str) -> DbResult<Vec<Finding>> {
        let rows: Vec<String> = self.with(|c| {
            let mut stmt = c.prepare("SELECT json FROM findings WHERE scan_id = ?1 ORDER BY id")?;
            let rows = stmt.query_map(params![scan_id], |r| r.get::<_, String>(0))?;
            rows.collect()
        })?;
        Ok(rows
            .iter()
            .filter_map(|j| serde_json::from_str::<Finding>(j).ok())
            .collect())
    }

    /// Found findings for an entity across all its scans (newest scan first, de-duplicated by url).
    pub fn entity_hits(&self, entity_id: i64) -> DbResult<Vec<Finding>> {
        let rows: Vec<String> = self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT json FROM findings WHERE entity_id = ?1 AND status IN ('found','info') ORDER BY id DESC",
            )?;
            let rows = stmt.query_map(params![entity_id], |r| r.get::<_, String>(0))?;
            rows.collect()
        })?;
        let mut seen = std::collections::HashSet::new();
        Ok(rows
            .iter()
            .filter_map(|j| serde_json::from_str::<Finding>(j).ok())
            .filter(|f| seen.insert(format!("{}|{}|{}", f.source, f.kind, f.url.clone().unwrap_or_default())))
            .collect())
    }

    /// Every found/info finding in a case, newest first, capped.
    pub fn case_hits(&self, case_id: i64, limit: i64) -> DbResult<Vec<Finding>> {
        let rows: Vec<String> = self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT json FROM findings WHERE case_id = ?1 AND status IN ('found','info') ORDER BY id DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![case_id, limit], |r| r.get::<_, String>(0))?;
            rows.collect()
        })?;
        Ok(rows.iter().filter_map(|j| serde_json::from_str::<Finding>(j).ok()).collect())
    }

    // -----------------------------------------------------------------------
    // Notes
    // -----------------------------------------------------------------------

    pub fn list_notes(&self, case_id: i64, entity_id: Option<i64>) -> DbResult<Vec<Note>> {
        self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, case_id, entity_id, body, created_at, updated_at FROM notes
                 WHERE case_id = ?1 AND ((?2 IS NULL AND entity_id IS NULL) OR entity_id = ?2)
                 ORDER BY updated_at DESC",
            )?;
            let rows = stmt.query_map(params![case_id, entity_id], |r| {
                Ok(Note {
                    id: r.get(0)?,
                    case_id: r.get(1)?,
                    entity_id: r.get(2)?,
                    body: r.get(3)?,
                    created_at: r.get(4)?,
                    updated_at: r.get(5)?,
                })
            })?;
            rows.collect()
        })
    }

    pub fn add_note(&self, case_id: i64, entity_id: Option<i64>, body: &str) -> DbResult<Note> {
        let now = now_ms();
        let id = self.with(|c| {
            c.execute(
                "INSERT INTO notes (case_id, entity_id, body, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?4)",
                params![case_id, entity_id, body, now],
            )?;
            Ok(c.last_insert_rowid())
        })?;
        Ok(Note {
            id,
            case_id,
            entity_id,
            body: body.to_string(),
            created_at: now,
            updated_at: now,
        })
    }

    pub fn update_note(&self, id: i64, body: &str) -> DbResult<()> {
        self.with(|c| {
            c.execute(
                "UPDATE notes SET body = ?2, updated_at = ?3 WHERE id = ?1",
                params![id, body, now_ms()],
            )?;
            Ok(())
        })
    }

    pub fn delete_note(&self, id: i64) -> DbResult<()> {
        self.with(|c| {
            c.execute("DELETE FROM notes WHERE id = ?1", params![id])?;
            Ok(())
        })
    }

    // -----------------------------------------------------------------------
    // Graph
    // -----------------------------------------------------------------------

    pub fn graph(&self, case_id: i64, max_profiles: usize) -> DbResult<Graph> {
        let entities = self.list_entities(case_id)?;
        let mut nodes: Vec<GraphNode> = entities
            .iter()
            .map(|e| GraphNode {
                id: format!("e{}", e.id),
                node_type: e.entity_type.clone(),
                label: e.label.clone().unwrap_or_else(|| e.value.clone()),
                value: e.value.clone(),
                url: None,
                entity_id: Some(e.id),
                weight: e.found_count.max(1),
            })
            .collect();

        let mut edges: Vec<GraphEdge> = self.with(|c| {
            let mut stmt = c.prepare("SELECT id, from_entity, to_entity, relation FROM links WHERE case_id = ?1")?;
            let rows = stmt.query_map(params![case_id], |r| {
                let id: i64 = r.get(0)?;
                let from: i64 = r.get(1)?;
                let to: i64 = r.get(2)?;
                Ok(GraphEdge {
                    id: format!("l{id}"),
                    source: format!("e{from}"),
                    target: format!("e{to}"),
                    relation: r.get(3)?,
                })
            })?;
            rows.collect()
        })?;

        // Found profiles hang off the entity that was scanned.
        let profiles: Vec<(i64, i64, String, Option<String>, String)> = self.with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, entity_id, title, url, source FROM findings
                 WHERE case_id = ?1 AND status = 'found' AND kind = 'profile' AND entity_id IS NOT NULL
                 ORDER BY id DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![case_id, max_profiles as i64], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?;
            rows.collect()
        })?;
        let mut seen = std::collections::HashSet::new();
        for (id, entity_id, title, url, source) in profiles {
            let key = format!("{entity_id}|{}", url.clone().unwrap_or_else(|| title.clone()));
            if !seen.insert(key) {
                continue;
            }
            nodes.push(GraphNode {
                id: format!("f{id}"),
                node_type: "profile".to_string(),
                label: title.clone(),
                value: url.clone().unwrap_or(title),
                url,
                entity_id: None,
                weight: 1,
            });
            edges.push(GraphEdge {
                id: format!("fe{id}"),
                source: format!("e{entity_id}"),
                target: format!("f{id}"),
                relation: source,
            });
        }

        Ok(Graph { nodes, edges })
    }

    // -----------------------------------------------------------------------
    // Misc
    // -----------------------------------------------------------------------

    pub fn case_exists(&self, id: i64) -> DbResult<bool> {
        self.with(|c| {
            c.query_row("SELECT 1 FROM cases WHERE id = ?1", params![id], |_| Ok(()))
                .optional()
                .map(|o| o.is_some())
        })
    }

    pub fn first_case_id(&self) -> DbResult<i64> {
        self.with(|c| c.query_row("SELECT id FROM cases ORDER BY updated_at DESC LIMIT 1", [], |r| r.get(0)))
    }
}

/// Status string stored for a finished scan.
pub fn scan_status_label(cancelled: bool, error: Option<&str>) -> &'static str {
    if error.is_some() {
        "error"
    } else if cancelled {
        "cancelled"
    } else {
        "done"
    }
}

impl FindingStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingStatus::Found => "found",
            FindingStatus::NotFound => "notFound",
            FindingStatus::Ambiguous => "ambiguous",
            FindingStatus::Error => "error",
            FindingStatus::Info => "info",
        }
    }
}
