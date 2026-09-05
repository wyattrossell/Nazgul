//! Username probe: fan out one handle across the WhatsMyName site list.
//!
//! Site data: WhatsMyName project (Micah Hoffman et al.), CC BY-SA 4.0.
//! https://github.com/WebBreacher/WhatsMyName

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::email::urlencode;
use super::launchers;
use super::{EntityType, Finding, FindingStatus, ScanContext, ScanOptions};
use crate::engine::http::describe_error;

static WMN_RAW: &str = include_str!("../../../data/sites/wmn-data.json");

pub const NSFW_CATEGORY: &str = "xx NSFW xx";

// ---------------------------------------------------------------------------
// Site catalog
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // `known` feeds the self-test command in a later phase
pub struct WmnSite {
    pub name: String,
    pub uri_check: String,
    #[serde(default)]
    pub uri_pretty: Option<String>,
    #[serde(default)]
    pub post_body: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    pub e_code: u16,
    #[serde(default)]
    pub e_string: String,
    #[serde(default)]
    pub m_string: String,
    pub m_code: u16,
    #[serde(default)]
    pub cat: String,
    #[serde(default)]
    pub valid: Option<bool>,
    #[serde(default)]
    pub strip_bad_char: Option<String>,
    #[serde(default)]
    pub protection: Option<Vec<String>>,
    #[serde(default)]
    pub known: Vec<String>,
}

#[derive(Deserialize)]
struct WmnFile {
    #[serde(default)]
    license: Vec<String>,
    #[serde(default)]
    authors: Vec<String>,
    sites: Vec<WmnSite>,
}

pub struct SiteCatalog {
    pub license: String,
    pub authors: Vec<String>,
    pub sites: Vec<WmnSite>,
}

pub static CATALOG: Lazy<SiteCatalog> = Lazy::new(|| {
    let file: WmnFile = serde_json::from_str(WMN_RAW).expect("data/sites/wmn-data.json must parse");
    SiteCatalog {
        license: file.license.join(" "),
        authors: file.authors,
        sites: file
            .sites
            .into_iter()
            .filter(|s| s.valid.unwrap_or(true))
            .collect(),
    }
});

pub fn matching_sites(options: &ScanOptions) -> Vec<&'static WmnSite> {
    CATALOG
        .sites
        .iter()
        .filter(|s| options.include_nsfw || s.cat != NSFW_CATEGORY)
        .filter(|s| options.categories.is_empty() || options.categories.iter().any(|c| c == &s.cat))
        .collect()
}

// ---------------------------------------------------------------------------
// Single-site check
// ---------------------------------------------------------------------------

fn sanitize(account: &str, strip: Option<&str>) -> String {
    match strip {
        Some(bad) => account.chars().filter(|c| !bad.contains(*c)).collect(),
        None => account.to_string(),
    }
}

pub async fn check_site(
    client: &reqwest::Client,
    site: &WmnSite,
    account: &str,
    template: Finding,
) -> Finding {
    let account = sanitize(account, site.strip_bad_char.as_deref());
    let check_url = site.uri_check.replace("{account}", &account);
    let url = site
        .uri_pretty
        .as_deref()
        .map(|p| p.replace("{account}", &account))
        .unwrap_or_else(|| check_url.clone());

    let mut request = match &site.post_body {
        Some(body) => client.post(&check_url).body(body.replace("{account}", &account)),
        None => client.get(&check_url),
    };
    if let Some(headers) = &site.headers {
        for (k, v) in headers {
            request = request.header(k.as_str(), v.as_str());
        }
    }

    let started = Instant::now();
    let protection = site.protection.clone().unwrap_or_default();
    let mut finding = template
        .url(url)
        .category(site.cat.clone())
        .status(FindingStatus::Error)
        .data(json!({ "checkUrl": check_url, "protection": protection, "account": account }));

    match request.send().await {
        Err(err) => {
            finding.detail = Some(describe_error(err));
        }
        Ok(response) => {
            let code = response.status().as_u16();
            finding.http_status = Some(code);
            let body = response.text().await.unwrap_or_default();

            let has_exists = site.e_string.is_empty() || body.contains(&site.e_string);
            let has_missing = !site.m_string.is_empty() && body.contains(&site.m_string);

            finding.status = if code == site.e_code && has_exists && !has_missing {
                FindingStatus::Found
            } else if has_missing || (code == site.m_code && site.m_code != site.e_code) {
                FindingStatus::NotFound
            } else {
                finding.detail = Some(format!(
                    "HTTP {} did not match exists ({}) or missing ({}) signature",
                    code, site.e_code, site.m_code
                ));
                FindingStatus::Ambiguous
            };
        }
    }

    finding.elapsed_ms = started.elapsed().as_millis() as u64;
    finding
}

// ---------------------------------------------------------------------------
// Probe entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: Arc<ScanContext>) -> Result<(), String> {
    let account = ctx.input.trim().to_string();
    if account.is_empty() {
        return Err("Enter a username to search for.".to_string());
    }
    if account.chars().any(char::is_whitespace) {
        return Err("Usernames cannot contain spaces.".to_string());
    }

    let sites = matching_sites(&ctx.options);
    if sites.is_empty() {
        return Err("No sites match the selected categories.".to_string());
    }
    let catalog = launchers::plan(EntityType::Username, &launchers::vars_username(&account));
    ctx.start(sites.len() + catalog.len() + 1);

    // Dorks and hand-operated tools first so they are visible while the fan-out runs.
    let quoted = format!("\"{account}\"");
    ctx.emit(
        ctx.finding("dorks", "dorks", "Search engine dorks")
            .category("launchers")
            .status(FindingStatus::Info)
            .url(format!("https://www.google.com/search?q={}", urlencode(&quoted)))
            .summary("Quoted handle on Google; @mention, site-scoped and document dorks in raw data")
            .data(serde_json::json!({
                "exact": format!("https://www.google.com/search?q={}", urlencode(&quoted)),
                "mention": format!("https://www.google.com/search?q={}", urlencode(&format!("\"@{account}\""))),
                "social": format!("https://www.google.com/search?q={}", urlencode(&format!("{quoted} (site:twitter.com OR site:x.com OR site:instagram.com OR site:tiktok.com OR site:facebook.com OR site:reddit.com)"))),
                "documents": format!("https://www.google.com/search?q={}", urlencode(&format!("{quoted} filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:txt"))),
                "inurl": format!("https://www.google.com/search?q={}", urlencode(&format!("inurl:{account}"))),
                "bing": format!("https://www.bing.com/search?q={}", urlencode(&quoted)),
                "duckduckgo": format!("https://duckduckgo.com/?q={}", urlencode(&quoted)),
                "yandex": format!("https://yandex.com/search/?text={}", urlencode(&quoted)),
            })),
    );
    launchers::emit(&ctx, &catalog);

    let semaphore = Arc::new(Semaphore::new(ctx.options.concurrency.clamp(1, 100)));
    let mut tasks: JoinSet<()> = JoinSet::new();

    for site in sites {
        let semaphore = semaphore.clone();
        let ctx = ctx.clone();
        let account = account.clone();

        tasks.spawn(async move {
            let Ok(_permit) = semaphore.acquire_owned().await else { return };
            if ctx.cancelled() {
                return;
            }
            // Small jitter so we do not hammer shared hosts in lockstep.
            let jitter = rand::random::<u64>() % 150;
            tokio::time::sleep(Duration::from_millis(jitter)).await;

            let template = ctx.finding(&site.name, "profile", &site.name);
            tokio::select! {
                _ = ctx.cancel.cancelled() => {},
                finding = check_site(&ctx.client, site, &account, template) => {
                    ctx.emit(finding);
                }
            }
        });
    }

    while tasks.join_next().await.is_some() {}
    Ok(())
}
