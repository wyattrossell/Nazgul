//! Profile cards for sites with public APIs. Runs after the username fan-out and pulls the
//! bio, links, emails and names the site exposes, so each becomes a pivot.
//! Keyless: GitHub (60/h without a token), Hacker News, Keybase, Gravatar.
//! Keyed: Steam, YouTube.

use std::collections::BTreeSet;
use std::sync::Arc;

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};

use super::email::urlencode;
use super::{EntityType, Finding, FindingStatus, ScanContext};
use crate::engine::http::fetch;

static RE_EMAIL: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap());
static RE_URL: Lazy<Regex> = Lazy::new(|| Regex::new(r#"https?://[^\s<>"')\]]+"#).unwrap());

pub fn card_count(ctx: &ScanContext) -> usize {
    4 + usize::from(ctx.secret("steam").is_some()) + usize::from(ctx.secret("youtube").is_some())
}

fn harvest_text(mut f: Finding, text: &str, label: &str) -> Finding {
    let mut seen = BTreeSet::new();
    for m in RE_EMAIL.find_iter(text) {
        let e = m.as_str().to_lowercase();
        if seen.insert(e.clone()) && !e.contains("noreply") {
            f = f.discover(EntityType::Email, e, Some(label));
        }
    }
    for m in RE_URL.find_iter(text) {
        let u = m.as_str().trim_end_matches(['.', ',', ')']).to_string();
        if seen.insert(u.clone()) {
            f = f.discover(EntityType::Url, u, Some(label));
        }
    }
    f
}

async fn github(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = ctx.finding("GitHub", "card", "GitHub profile").category("cards").url(format!("https://github.com/{handle}"));
    let mut req = ctx
        .client
        .get(format!("https://api.github.com/users/{handle}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "nazgul-osint");
    if let Some(token) = ctx.secret("github") {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    match fetch(req).await {
        Err((e, ms)) => {
            f.elapsed_ms = ms;
            f.error(e)
        }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
            match res.status {
                200 => {
                    let s = |k: &str| v[k].as_str().filter(|x| !x.is_empty()).map(str::to_string);
                    let mut parts = Vec::new();
                    if let Some(n) = s("name") {
                        parts.push(n.clone());
                        f = f.discover(EntityType::Person, n, Some("GitHub name"));
                    }
                    if let Some(c) = s("company") {
                        parts.push(c.clone());
                        f = f.discover(EntityType::Org, c.trim_start_matches('@'), Some("GitHub company"));
                    }
                    if let Some(l) = s("location") {
                        parts.push(l.clone());
                        f = f.discover(EntityType::Location, l, Some("GitHub location"));
                    }
                    if let Some(e) = s("email") {
                        f = f.discover(EntityType::Email, e.to_lowercase(), Some("GitHub public email"));
                    }
                    if let Some(t) = s("twitter_username") {
                        f = f.discover(EntityType::Username, t, Some("GitHub → X handle"));
                    }
                    if let Some(b) = s("blog") {
                        let b = if b.starts_with("http") { b } else { format!("https://{b}") };
                        f = f.discover(EntityType::Url, b, Some("GitHub website"));
                    }
                    if let Some(bio) = s("bio") {
                        f = harvest_text(f, &bio, "GitHub bio");
                    }
                    parts.push(format!("{} repos · {} followers · since {}", v["public_repos"].as_u64().unwrap_or(0), v["followers"].as_u64().unwrap_or(0), v["created_at"].as_str().map(|d| d.chars().take(10).collect::<String>()).unwrap_or_default()));

                    // Commit author emails from recent public pushes: the classic pivot.
                    let mut commit_emails = BTreeSet::new();
                    let mut ev = ctx.client.get(format!("https://api.github.com/users/{handle}/events/public?per_page=30")).header("Accept", "application/vnd.github+json").header("User-Agent", "nazgul-osint");
                    if let Some(token) = ctx.secret("github") {
                        ev = ev.header("Authorization", format!("Bearer {token}"));
                    }
                    if let Ok(r) = fetch(ev).await {
                        if let Ok(events) = serde_json::from_str::<Value>(&r.body) {
                            for e in events.as_array().into_iter().flatten() {
                                for c in e["payload"]["commits"].as_array().into_iter().flatten() {
                                    if let Some(email) = c["author"]["email"].as_str() {
                                        let email = email.to_lowercase();
                                        if !email.contains("noreply") && !email.contains("users.noreply") {
                                            commit_emails.insert(email);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    for e in commit_emails.iter().take(10) {
                        f = f.discover(EntityType::Email, e.clone(), Some("GitHub commit author"));
                    }
                    if !commit_emails.is_empty() {
                        parts.push(format!("{} commit email(s)", commit_emails.len()));
                    }
                    f.status(FindingStatus::Found).summary(parts.join(" · ")).data(json!({ "profile": v, "commitEmails": commit_emails }))
                }
                404 => f.status(FindingStatus::NotFound).summary("no GitHub account"),
                403 | 429 => f.status(FindingStatus::Ambiguous).detail("GitHub rate limit reached; add a token in Settings for 5,000 requests/hour".to_string()),
                other => f.status(FindingStatus::Ambiguous).detail(format!("HTTP {other}")),
            }
        }
    }
}

async fn hackernews(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = ctx.finding("Hacker News", "card", "Hacker News profile").category("cards").url(format!("https://news.ycombinator.com/user?id={handle}"));
    match fetch(ctx.client.get(format!("https://hacker-news.firebaseio.com/v0/user/{handle}.json"))).await {
        Err((e, ms)) => {
            f.elapsed_ms = ms;
            f.error(e)
        }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
            if v.is_null() {
                return f.status(FindingStatus::NotFound).summary("no Hacker News account");
            }
            let about = v["about"].as_str().unwrap_or("").replace("&#x2F;", "/").replace("&#x27;", "'").replace("&quot;", "\"");
            let created = v["created"].as_i64().map(|t| format!(" · since {}", chrono_like(t))).unwrap_or_default();
            let mut card = f.status(FindingStatus::Found).summary(format!("{} karma{created}{}", v["karma"].as_u64().unwrap_or(0), if about.is_empty() { String::new() } else { format!(" · about: {}", about.chars().take(120).collect::<String>()) }));
            card = harvest_text(card, &about, "HN about");
            card.data(json!({ "karma": v["karma"], "created": v["created"], "about": about, "submitted": v["submitted"].as_array().map(|a| a.len()).unwrap_or(0) }))
        }
    }
}

/// Unix seconds to YYYY-MM-DD without pulling in a date crate.
fn chrono_like(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

async fn keybase(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = ctx.finding("Keybase", "card", "Keybase identity").category("cards").url(format!("https://keybase.io/{handle}"));
    match fetch(ctx.client.get(format!("https://keybase.io/_/api/1.0/user/lookup.json?usernames={}&fields=basics,profile,proofs_summary", urlencode(handle)))).await {
        Err((e, ms)) => {
            f.elapsed_ms = ms;
            f.error(e)
        }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
            let Some(them) = v["them"].get(0).filter(|t| !t.is_null()) else {
                return f.status(FindingStatus::NotFound).summary("no Keybase account");
            };
            let mut parts = Vec::new();
            if let Some(n) = them["profile"]["full_name"].as_str().filter(|s| !s.is_empty()) {
                parts.push(n.to_string());
                f = f.discover(EntityType::Person, n, Some("Keybase full name"));
            }
            if let Some(l) = them["profile"]["location"].as_str().filter(|s| !s.is_empty()) {
                parts.push(l.to_string());
                f = f.discover(EntityType::Location, l, Some("Keybase location"));
            }
            let proofs = them["proofs_summary"]["all"].as_array().cloned().unwrap_or_default();
            let mut names = Vec::new();
            for p in &proofs {
                let kind = p["proof_type"].as_str().unwrap_or("");
                let tag = p["nametag"].as_str().unwrap_or("");
                if tag.is_empty() {
                    continue;
                }
                names.push(format!("{kind}:{tag}"));
                match kind {
                    "twitter" | "github" | "reddit" | "hackernews" | "facebook" | "mastodon.social" => {
                        f = f.discover(EntityType::Username, tag, Some(&format!("Keybase-proven {kind}")));
                    }
                    "dns" => f = f.discover(EntityType::Domain, tag, Some("Keybase-proven domain")),
                    "generic_web_site" | "http" | "https" => f = f.discover(EntityType::Url, p["service_url"].as_str().unwrap_or(tag), Some("Keybase-proven site")),
                    _ => {}
                }
            }
            if !names.is_empty() {
                parts.push(format!("proofs: {}", names.join(", ")));
            }
            if let Some(bio) = them["profile"]["bio"].as_str() {
                f = harvest_text(f, bio, "Keybase bio");
            }
            f.status(FindingStatus::Found).summary(if parts.is_empty() { "Keybase account exists".to_string() } else { parts.join(" · ") }).data(json!({ "profile": them["profile"], "proofs": proofs, "basics": them["basics"] }))
        }
    }
}

async fn gravatar(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = ctx.finding("Gravatar", "card", "Gravatar profile").category("cards").url(format!("https://www.gravatar.com/{handle}"));
    match fetch(ctx.client.get(format!("https://www.gravatar.com/{}.json", urlencode(handle)))).await {
        Err((e, ms)) => {
            f.elapsed_ms = ms;
            f.error(e)
        }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            if res.status != 200 {
                return f.status(FindingStatus::NotFound).summary("no Gravatar profile under this handle");
            }
            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
            let Some(entry) = v["entry"].get(0) else {
                return f.status(FindingStatus::NotFound).summary("no Gravatar profile under this handle");
            };
            let mut parts = Vec::new();
            if let Some(n) = entry["displayName"].as_str().filter(|s| !s.is_empty()) {
                parts.push(n.to_string());
                f = f.discover(EntityType::Person, n, Some("Gravatar display name"));
            }
            if let Some(loc) = entry["currentLocation"].as_str().filter(|s| !s.is_empty()) {
                parts.push(loc.to_string());
                f = f.discover(EntityType::Location, loc, Some("Gravatar location"));
            }
            for u in entry["urls"].as_array().into_iter().flatten() {
                if let Some(link) = u["value"].as_str() {
                    f = f.discover(EntityType::Url, link, u["title"].as_str());
                }
            }
            for a in entry["accounts"].as_array().into_iter().flatten() {
                if let Some(user) = a["username"].as_str() {
                    f = f.discover(EntityType::Username, user, a["shortname"].as_str().or(a["domain"].as_str()));
                }
            }
            if let Some(about) = entry["aboutMe"].as_str() {
                f = harvest_text(f, about, "Gravatar about");
            }
            f.status(FindingStatus::Found).summary(if parts.is_empty() { "Gravatar profile exists".to_string() } else { parts.join(" · ") }).data(entry.clone())
        }
    }
}

async fn steam(ctx: &ScanContext, handle: &str, key: &str) -> Finding {
    let mut f = ctx.finding("Steam", "card", "Steam profile").category("cards").url(format!("https://steamcommunity.com/id/{handle}"));
    let resolve = format!("https://api.steampowered.com/ISteamUser/ResolveVanityURL/v1/?key={key}&vanityurl={}", urlencode(handle));
    match fetch(ctx.client.get(&resolve)).await {
        Err((e, ms)) => {
            f.elapsed_ms = ms;
            f.error(e)
        }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
            if res.status == 403 {
                return f.error("Steam rejected the API key");
            }
            let Some(steamid) = v["response"]["steamid"].as_str() else {
                return f.status(FindingStatus::NotFound).summary("no Steam vanity URL with this handle");
            };
            let summary_url = format!("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key={key}&steamids={steamid}");
            let p = fetch(ctx.client.get(&summary_url)).await.ok().and_then(|r| serde_json::from_str::<Value>(&r.body).ok()).and_then(|v| v["response"]["players"].get(0).cloned()).unwrap_or(Value::Null);
            let mut parts = vec![format!("steamid {steamid}")];
            if let Some(n) = p["personaname"].as_str() {
                parts.push(n.to_string());
            }
            if let Some(r) = p["realname"].as_str().filter(|s| !s.is_empty()) {
                parts.push(r.to_string());
                f = f.discover(EntityType::Person, r, Some("Steam real name"));
            }
            if let Some(c) = p["loccountrycode"].as_str() {
                parts.push(c.to_string());
            }
            if let Some(t) = p["timecreated"].as_i64() {
                parts.push(format!("since {}", chrono_like(t)));
            }
            f.status(FindingStatus::Found).summary(parts.join(" · ")).data(json!({ "steamid": steamid, "player": p }))
        }
    }
}

async fn youtube(ctx: &ScanContext, handle: &str, key: &str) -> Finding {
    let mut f = ctx.finding("YouTube", "card", "YouTube channel").category("cards").url(format!("https://www.youtube.com/@{handle}"));
    let url = format!("https://www.googleapis.com/youtube/v3/channels?forHandle=%40{}&part=snippet,statistics&key={key}", urlencode(handle));
    match fetch(ctx.client.get(&url)).await {
        Err((e, ms)) => {
            f.elapsed_ms = ms;
            f.error(e)
        }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
            if res.status != 200 {
                return f.error(v["error"]["message"].as_str().unwrap_or("YouTube API request failed").to_string());
            }
            let Some(item) = v["items"].get(0) else {
                return f.status(FindingStatus::NotFound).summary("no channel with this handle");
            };
            let sn = &item["snippet"];
            let st = &item["statistics"];
            let desc = sn["description"].as_str().unwrap_or("");
            let mut card = f.status(FindingStatus::Found).summary(format!("{} · {} subscribers · {} videos · {}{}", sn["title"].as_str().unwrap_or(""), st["subscriberCount"].as_str().unwrap_or("?"), st["videoCount"].as_str().unwrap_or("?"), sn["country"].as_str().unwrap_or("country unknown"), sn["publishedAt"].as_str().map(|d| format!(" · since {}", d.chars().take(10).collect::<String>())).unwrap_or_default()));
            card = harvest_text(card, desc, "YouTube description");
            card.data(json!({ "id": item["id"], "snippet": sn, "statistics": st }))
        }
    }
}

/// Emits one card per API-backed site.
pub async fn username_cards(ctx: &Arc<ScanContext>, handle: &str) {
    if ctx.cancelled() {
        return;
    }
    let (g, h, k, gr) = tokio::join!(github(ctx, handle), hackernews(ctx, handle), keybase(ctx, handle), gravatar(ctx, handle));
    for f in [g, h, k, gr] {
        ctx.emit(f);
    }
    if let Some(key) = ctx.secret("steam") {
        ctx.emit(steam(ctx, handle, key).await);
    }
    if let Some(key) = ctx.secret("youtube") {
        ctx.emit(youtube(ctx, handle, key).await);
    }
}
