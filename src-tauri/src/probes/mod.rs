//! Probes turn one identifier into a stream of findings.
//!
//! Every probe shares the same vocabulary: a `ScanRequest` names the probe and its input,
//! the probe emits `Finding`s through a `ScanContext`, and a `ScanSink` decides where they
//! go (the Tauri window plus SQLite in the app, a Vec in tests).

pub mod crypto;
pub mod domain;
pub mod email;
pub mod geo;
pub mod image;
pub mod ip;
pub mod launchers;
pub mod org;
pub mod payments;
pub mod person;
pub mod phone;
pub mod plugin;
pub mod username;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::engine::http::{build_client, random_user_agent, HttpOptions, DEFAULT_USER_AGENT};

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProbeKind {
    Username,
    Email,
    Phone,
    Domain,
    Ip,
    Image,
    Crypto,
    /// External tool driven by a manifest in the plugins folder.
    Plugin,
    /// A person's name: handle candidates, payment apps, people search.
    Person,
    /// Coordinates or a place name.
    Geo,
    /// A company or organisation name.
    Org,
}

impl ProbeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ProbeKind::Username => "username",
            ProbeKind::Email => "email",
            ProbeKind::Phone => "phone",
            ProbeKind::Domain => "domain",
            ProbeKind::Ip => "ip",
            ProbeKind::Image => "image",
            ProbeKind::Crypto => "crypto",
            ProbeKind::Plugin => "plugin",
            ProbeKind::Person => "person",
            ProbeKind::Geo => "geo",
            ProbeKind::Org => "org",
        }
    }

    /// Probes that touch the network. Phone and image work fully offline.
    pub fn needs_network(self) -> bool {
        !matches!(self, ProbeKind::Phone | ProbeKind::Image)
    }

    pub fn parse(s: &str) -> Option<Self> {
        serde_json::from_value(Value::String(s.to_string())).ok()
    }

    /// Entity type a probe's input is recorded as.
    pub fn input_entity(self) -> EntityType {
        match self {
            ProbeKind::Username => EntityType::Username,
            ProbeKind::Email => EntityType::Email,
            ProbeKind::Phone => EntityType::Phone,
            ProbeKind::Domain => EntityType::Domain,
            ProbeKind::Ip => EntityType::Ip,
            ProbeKind::Image => EntityType::Image,
            ProbeKind::Crypto => EntityType::Wallet,
            ProbeKind::Plugin => EntityType::Url,
            ProbeKind::Person => EntityType::Person,
            ProbeKind::Geo => EntityType::Location,
            ProbeKind::Org => EntityType::Org,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntityType {
    Username,
    Email,
    Phone,
    Domain,
    Ip,
    Image,
    Wallet,
    Person,
    Org,
    Url,
    Location,
}

impl EntityType {
    pub fn as_str(self) -> &'static str {
        match self {
            EntityType::Username => "username",
            EntityType::Email => "email",
            EntityType::Phone => "phone",
            EntityType::Domain => "domain",
            EntityType::Ip => "ip",
            EntityType::Image => "image",
            EntityType::Wallet => "wallet",
            EntityType::Person => "person",
            EntityType::Org => "org",
            EntityType::Url => "url",
            EntityType::Location => "location",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        serde_json::from_value(Value::String(s.to_string())).ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FindingStatus {
    /// The thing exists (profile, record, breach...).
    Found,
    NotFound,
    /// Response matched neither the "exists" nor the "missing" signature.
    Ambiguous,
    Error,
    /// Informational result with no exists/missing semantics (a DNS record, EXIF field...).
    Info,
}

/// An identifier discovered inside a finding that can seed a new probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityRef {
    #[serde(rename = "type")]
    pub entity_type: EntityType,
    pub value: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub scan_id: String,
    pub probe: ProbeKind,
    /// Where it came from: a site name, "dns", "crt.sh", "exif"...
    pub source: String,
    /// What it is: "profile", "dns_record", "subdomain", "breach", "exif"...
    pub kind: String,
    pub title: String,
    #[serde(default)]
    pub url: Option<String>,
    pub status: FindingStatus,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub http_status: Option<u16>,
    #[serde(default)]
    pub elapsed_ms: u64,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub discovered: Vec<EntityRef>,
}

impl Finding {
    pub fn new(scan_id: &str, probe: ProbeKind, source: &str, kind: &str, title: &str) -> Self {
        Self {
            scan_id: scan_id.to_string(),
            probe,
            source: source.to_string(),
            kind: kind.to_string(),
            title: title.to_string(),
            url: None,
            status: FindingStatus::Info,
            summary: None,
            category: String::new(),
            http_status: None,
            elapsed_ms: 0,
            detail: None,
            data: Value::Null,
            discovered: Vec::new(),
        }
    }

    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
    pub fn status(mut self, status: FindingStatus) -> Self {
        self.status = status;
        self
    }
    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }
    pub fn category(mut self, category: impl Into<String>) -> Self {
        self.category = category.into();
        self
    }
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
    pub fn data(mut self, data: Value) -> Self {
        self.data = data;
        self
    }
    pub fn discover(mut self, entity_type: EntityType, value: impl Into<String>, label: Option<&str>) -> Self {
        let value = value.into();
        if !value.trim().is_empty() {
            self.discovered.push(EntityRef {
                entity_type,
                value,
                label: label.map(str::to_string),
            });
        }
        self
    }
    pub fn error(mut self, detail: impl Into<String>) -> Self {
        self.status = FindingStatus::Error;
        self.detail = Some(detail.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStarted {
    pub scan_id: String,
    pub probe: ProbeKind,
    pub input: String,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanDone {
    pub scan_id: String,
    pub cancelled: bool,
    pub total: usize,
    pub checked: usize,
    pub found: usize,
    pub elapsed_ms: u64,
    #[serde(default)]
    pub error: Option<String>,
}

/// Where scan events go.
pub trait ScanSink: Send + Sync {
    fn started(&self, event: &ScanStarted);
    fn finding(&self, finding: &Finding);
    fn done(&self, event: &ScanDone);
}

// ---------------------------------------------------------------------------
// Request / options
// ---------------------------------------------------------------------------

fn default_concurrency() -> usize {
    40
}
fn default_timeout() -> u64 {
    15
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanOptions {
    /// Username probe: empty means every category.
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    pub include_nsfw: bool,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub proxy: Option<String>,
    /// Refuse every network probe. Local parsing still works.
    #[serde(default)]
    pub airgap: bool,
    /// Pick a random desktop browser user agent for this scan.
    #[serde(default)]
    pub rotate_user_agent: bool,
    /// Probe-specific knobs.
    #[serde(default)]
    pub extra: Value,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            categories: Vec::new(),
            include_nsfw: false,
            concurrency: default_concurrency(),
            timeout_secs: default_timeout(),
            user_agent: None,
            proxy: None,
            airgap: false,
            rotate_user_agent: false,
            extra: Value::Null,
        }
    }
}

impl ScanOptions {
    pub fn http_options(&self) -> HttpOptions {
        let fallback = if self.rotate_user_agent { random_user_agent() } else { DEFAULT_USER_AGENT };
        HttpOptions {
            user_agent: self
                .user_agent
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(fallback)
                .to_string(),
            timeout_secs: self.timeout_secs.clamp(3, 60),
            proxy: self.proxy.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanRequest {
    pub probe: ProbeKind,
    pub input: String,
    #[serde(default)]
    pub case_id: i64,
    #[serde(default)]
    pub options: ScanOptions,
}

// ---------------------------------------------------------------------------
// Context handed to a running probe
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Counters {
    total: usize,
    checked: usize,
    found: usize,
}

pub struct ScanContext {
    pub scan_id: String,
    pub probe: ProbeKind,
    pub input: String,
    pub sink: Arc<dyn ScanSink>,
    pub client: reqwest::Client,
    pub cancel: CancellationToken,
    pub options: ScanOptions,
    /// API keys loaded from the OS keychain. Never sent to the window.
    pub secrets: HashMap<String, String>,
    counters: Mutex<Counters>,
}

impl ScanContext {
    /// An API key, if the user saved one.
    pub fn secret(&self, name: &str) -> Option<&str> {
        self.secrets.get(name).map(String::as_str).filter(|s| !s.trim().is_empty())
    }

    /// Announce how many steps this scan has. Call once, before emitting findings.
    pub fn start(&self, total: usize) {
        self.counters.lock().expect("counters").total = total;
        self.sink.started(&ScanStarted {
            scan_id: self.scan_id.clone(),
            probe: self.probe,
            input: self.input.clone(),
            total,
        });
    }

    /// Emit one finding and count it.
    pub fn emit(&self, finding: Finding) {
        {
            let mut c = self.counters.lock().expect("counters");
            c.checked += 1;
            if finding.status == FindingStatus::Found {
                c.found += 1;
            }
        }
        self.sink.finding(&finding);
    }

    /// Shorthand for a finding pre-filled with this scan's id and probe.
    pub fn finding(&self, source: &str, kind: &str, title: &str) -> Finding {
        Finding::new(&self.scan_id, self.probe, source, kind, title)
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    fn snapshot(&self) -> (usize, usize, usize) {
        let c = self.counters.lock().expect("counters");
        (c.total, c.checked, c.found)
    }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

pub async fn run_scan(
    sink: Arc<dyn ScanSink>,
    scan_id: String,
    req: ScanRequest,
    cancel: CancellationToken,
) -> Result<ScanDone, String> {
    run_scan_with_secrets(sink, scan_id, req, cancel, HashMap::new()).await
}

fn fail_early(sink: &Arc<dyn ScanSink>, scan_id: String, message: String) -> Result<ScanDone, String> {
    sink.done(&ScanDone {
        scan_id,
        cancelled: false,
        total: 0,
        checked: 0,
        found: 0,
        elapsed_ms: 0,
        error: Some(message.clone()),
    });
    Err(message)
}

pub async fn run_scan_with_secrets(
    sink: Arc<dyn ScanSink>,
    scan_id: String,
    req: ScanRequest,
    cancel: CancellationToken,
    secrets: HashMap<String, String>,
) -> Result<ScanDone, String> {
    let started = Instant::now();
    let input = req.input.trim().to_string();

    if req.options.airgap && req.probe.needs_network() {
        return fail_early(
            &sink,
            scan_id,
            format!("Airgap mode is on: the {} probe needs the network. Phone and image probes still work.", req.probe.as_str()),
        );
    }

    let client = match build_client(&req.options.http_options()) {
        Ok(c) => c,
        Err(e) => return fail_early(&sink, scan_id, format!("Could not build HTTP client: {e}")),
    };

    let ctx = Arc::new(ScanContext {
        scan_id: scan_id.clone(),
        probe: req.probe,
        input: input.clone(),
        sink: sink.clone(),
        client,
        cancel: cancel.clone(),
        options: req.options.clone(),
        secrets,
        counters: Mutex::new(Counters::default()),
    });

    let result = match req.probe {
        ProbeKind::Username => username::run(ctx.clone()).await,
        ProbeKind::Email => email::run(ctx.clone()).await,
        ProbeKind::Phone => phone::run(ctx.clone()).await,
        ProbeKind::Domain => domain::run(ctx.clone()).await,
        ProbeKind::Ip => ip::run(ctx.clone()).await,
        ProbeKind::Image => image::run(ctx.clone()).await,
        ProbeKind::Crypto => crypto::run(ctx.clone()).await,
        ProbeKind::Plugin => plugin::run(ctx.clone()).await,
        ProbeKind::Person => person::run(ctx.clone()).await,
        ProbeKind::Geo => geo::run(ctx.clone()).await,
        ProbeKind::Org => org::run(ctx.clone()).await,
    };

    let (total, checked, found) = ctx.snapshot();
    let done = ScanDone {
        scan_id,
        cancelled: cancel.is_cancelled(),
        total,
        checked,
        found,
        elapsed_ms: started.elapsed().as_millis() as u64,
        error: result.as_ref().err().cloned(),
    };
    sink.done(&done);
    result.map(|_| done)
}
