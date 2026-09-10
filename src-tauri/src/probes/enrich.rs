//! Profile cards for sites with public APIs. Runs after the username fan-out and pulls the
//! bio, links, emails and names the site exposes, so each becomes a pivot.
//! Keyless: GitHub (60/h without a token), Hacker News, Keybase, Gravatar, GitLab, Mastodon
//! (mastodon.social), Bluesky, Lichess, Chess.com, Docker Hub, Stack Overflow, crates.io.
//! Keyed: Steam, YouTube.

use std::collections::BTreeSet;
use std::sync::Arc;

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};

use super::email::urlencode;
use super::{EntityType, Finding, FindingStatus, ScanContext};
use crate::engine::http::fetch;

const UA: &str = "nazgul-osint/0.2 (https://github.com/wyattrossell/Nazgul)";

static RE_EMAIL: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap());
static RE_URL: Lazy<Regex> = Lazy::new(|| Regex::new(r#"https?://[^\s<>"')\]]+"#).unwrap());
static RE_TAG: Lazy<Regex> = Lazy::new(|| Regex::new(r"<[^>]+>").unwrap());

pub fn card_count(ctx: &ScanContext) -> usize {
    12 + usize::from(ctx.secret("steam").is_some()) + usize::from(ctx.secret("youtube").is_some())
}

fn json_of(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or(Value::Null)
}

fn s(v: &Value) -> Option<String> {
    v.as_str().map(str::trim).filter(|x| !x.is_empty()).map(str::to_string)
}

fn strip_html(html: &str) -> String {
    RE_TAG.replace_all(html, " ").replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'").split_whitespace().collect::<Vec<_>>().join(" ")
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

/// Unix seconds to YYYY-MM-DD without pulling in a date crate.
fn chrono_like(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
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

fn card(ctx: &ScanContext, source: &str, title: &str, url: String) -> Finding {
    ctx.finding(source, "card", title).category("cards").url(url)
}

// ---------------------------------------------------------------------------
// Keyless cards
// ---------------------------------------------------------------------------

async fn github(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = card(ctx, "GitHub", "GitHub profile", format!("https://github.com/{handle}"));
    let mut req = ctx.client.get(format!("https://api.github.com/users/{handle}")).header("Accept", "application/vnd.github+json").header("User-Agent", UA);
    if let Some(token) = ctx.secret("github") {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    match fetch(req).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            match res.status {
                200 => {
                    let mut parts = Vec::new();
                    if let Some(n) = s(&v["name"]) { parts.push(n.clone()); f = f.discover(EntityType::Person, n, Some("GitHub name")); }
                    if let Some(c) = s(&v["company"]) { parts.push(c.clone()); f = f.discover(EntityType::Org, c.trim_start_matches('@'), Some("GitHub company")); }
                    if let Some(l) = s(&v["location"]) { parts.push(l.clone()); f = f.discover(EntityType::Location, l, Some("GitHub location")); }
                    if let Some(e) = s(&v["email"]) { f = f.discover(EntityType::Email, e.to_lowercase(), Some("GitHub public email")); }
                    if let Some(t) = s(&v["twitter_username"]) { f = f.discover(EntityType::Username, t, Some("GitHub → X handle")); }
                    if let Some(b) = s(&v["blog"]) { let b = if b.starts_with("http") { b } else { format!("https://{b}") }; f = f.discover(EntityType::Url, b, Some("GitHub website")); }
                    if let Some(bio) = s(&v["bio"]) { f = harvest_text(f, &bio, "GitHub bio"); }
                    parts.push(format!("{} repos · {} followers · since {}", v["public_repos"].as_u64().unwrap_or(0), v["followers"].as_u64().unwrap_or(0), v["created_at"].as_str().map(|d| d.chars().take(10).collect::<String>()).unwrap_or_default()));

                    let mut commit_emails = BTreeSet::new();
                    let mut ev = ctx.client.get(format!("https://api.github.com/users/{handle}/events/public?per_page=30")).header("Accept", "application/vnd.github+json").header("User-Agent", UA);
                    if let Some(token) = ctx.secret("github") { ev = ev.header("Authorization", format!("Bearer {token}")); }
                    if let Ok(r) = fetch(ev).await {
                        for e in json_of(&r.body).as_array().into_iter().flatten() {
                            for c in e["payload"]["commits"].as_array().into_iter().flatten() {
                                if let Some(email) = c["author"]["email"].as_str() {
                                    let email = email.to_lowercase();
                                    if !email.contains("noreply") { commit_emails.insert(email); }
                                }
                            }
                        }
                    }
                    for e in commit_emails.iter().take(10) { f = f.discover(EntityType::Email, e.clone(), Some("GitHub commit author")); }
                    if !commit_emails.is_empty() { parts.push(format!("{} commit email(s)", commit_emails.len())); }
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
    let mut f = card(ctx, "Hacker News", "Hacker News profile", format!("https://news.ycombinator.com/user?id={handle}"));
    match fetch(ctx.client.get(format!("https://hacker-news.firebaseio.com/v0/user/{handle}.json"))).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            if v.is_null() { return f.status(FindingStatus::NotFound).summary("no Hacker News account"); }
            let about = strip_html(&v["about"].as_str().unwrap_or("").replace("&#x2F;", "/").replace("&#x27;", "'"));
            let created = v["created"].as_i64().map(|t| format!(" · since {}", chrono_like(t))).unwrap_or_default();
            let mut c = f.status(FindingStatus::Found).summary(format!("{} karma{created}{}", v["karma"].as_u64().unwrap_or(0), if about.is_empty() { String::new() } else { format!(" · about: {}", about.chars().take(120).collect::<String>()) }));
            c = harvest_text(c, &about, "HN about");
            c.data(json!({ "karma": v["karma"], "created": v["created"], "about": about, "submitted": v["submitted"].as_array().map(|a| a.len()).unwrap_or(0) }))
        }
    }
}

async fn keybase(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = card(ctx, "Keybase", "Keybase identity", format!("https://keybase.io/{handle}"));
    match fetch(ctx.client.get(format!("https://keybase.io/_/api/1.0/user/lookup.json?usernames={}&fields=basics,profile,proofs_summary", urlencode(handle)))).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            let Some(them) = v["them"].get(0).filter(|t| !t.is_null()) else { return f.status(FindingStatus::NotFound).summary("no Keybase account"); };
            let mut parts = Vec::new();
            if let Some(n) = s(&them["profile"]["full_name"]) { parts.push(n.clone()); f = f.discover(EntityType::Person, n, Some("Keybase full name")); }
            if let Some(l) = s(&them["profile"]["location"]) { parts.push(l.clone()); f = f.discover(EntityType::Location, l, Some("Keybase location")); }
            let proofs = them["proofs_summary"]["all"].as_array().cloned().unwrap_or_default();
            let mut names = Vec::new();
            for p in &proofs {
                let kind = p["proof_type"].as_str().unwrap_or("");
                let tag = p["nametag"].as_str().unwrap_or("");
                if tag.is_empty() { continue; }
                names.push(format!("{kind}:{tag}"));
                match kind {
                    "twitter" | "github" | "reddit" | "hackernews" | "facebook" | "mastodon.social" => f = f.discover(EntityType::Username, tag, Some(&format!("Keybase-proven {kind}"))),
                    "dns" => f = f.discover(EntityType::Domain, tag, Some("Keybase-proven domain")),
                    "generic_web_site" | "http" | "https" => f = f.discover(EntityType::Url, p["service_url"].as_str().unwrap_or(tag), Some("Keybase-proven site")),
                    _ => {}
                }
            }
            if !names.is_empty() { parts.push(format!("proofs: {}", names.join(", "))); }
            if let Some(bio) = them["profile"]["bio"].as_str() { f = harvest_text(f, bio, "Keybase bio"); }
            f.status(FindingStatus::Found).summary(if parts.is_empty() { "Keybase account exists".to_string() } else { parts.join(" · ") }).data(json!({ "profile": them["profile"], "proofs": proofs, "basics": them["basics"] }))
        }
    }
}

async fn gravatar(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = card(ctx, "Gravatar", "Gravatar profile", format!("https://www.gravatar.com/{handle}"));
    match fetch(ctx.client.get(format!("https://www.gravatar.com/{}.json", urlencode(handle)))).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            if res.status != 200 { return f.status(FindingStatus::NotFound).summary("no Gravatar profile under this handle"); }
            let v = json_of(&res.body);
            let Some(entry) = v["entry"].get(0) else { return f.status(FindingStatus::NotFound).summary("no Gravatar profile under this handle"); };
            let mut parts = Vec::new();
            if let Some(n) = s(&entry["displayName"]) { parts.push(n.clone()); f = f.discover(EntityType::Person, n, Some("Gravatar display name")); }
            if let Some(loc) = s(&entry["currentLocation"]) { parts.push(loc.clone()); f = f.discover(EntityType::Location, loc, Some("Gravatar location")); }
            for u in entry["urls"].as_array().into_iter().flatten() { if let Some(link) = u["value"].as_str() { f = f.discover(EntityType::Url, link, u["title"].as_str()); } }
            for a in entry["accounts"].as_array().into_iter().flatten() { if let Some(user) = a["username"].as_str() { f = f.discover(EntityType::Username, user, a["shortname"].as_str().or(a["domain"].as_str())); } }
            if let Some(about) = entry["aboutMe"].as_str() { f = harvest_text(f, about, "Gravatar about"); }
            f.status(FindingStatus::Found).summary(if parts.is_empty() { "Gravatar profile exists".to_string() } else { parts.join(" · ") }).data(entry.clone())
        }
    }
}

async fn gitlab(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = card(ctx, "GitLab", "GitLab profile", format!("https://gitlab.com/{handle}"));
    match fetch(ctx.client.get(format!("https://gitlab.com/api/v4/users?username={}", urlencode(handle))).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let list = json_of(&res.body);
            let Some(u) = list.as_array().and_then(|a| a.first()).cloned() else { return f.status(FindingStatus::NotFound).summary("no GitLab.com account"); };
            let id = u["id"].as_u64().unwrap_or(0);
            let detail = fetch(ctx.client.get(format!("https://gitlab.com/api/v4/users/{id}")).header("User-Agent", UA)).await.ok().map(|r| json_of(&r.body)).unwrap_or(Value::Null);
            let mut parts = Vec::new();
            if let Some(n) = s(&u["name"]) { parts.push(n.clone()); f = f.discover(EntityType::Person, n, Some("GitLab name")); }
            for (key, label, kind) in [("location", "GitLab location", EntityType::Location), ("organization", "GitLab organization", EntityType::Org), ("public_email", "GitLab public email", EntityType::Email), ("website_url", "GitLab website", EntityType::Url)] {
                if let Some(val) = s(&detail[key]) { parts.push(val.clone()); f = f.discover(kind, val, Some(label)); }
            }
            for (key, label) in [("twitter", "GitLab → X"), ("linkedin", "GitLab → LinkedIn"), ("skype", "GitLab → Skype")] {
                if let Some(val) = s(&detail[key]) { f = f.discover(EntityType::Username, val, Some(label)); }
            }
            if let Some(job) = s(&detail["job_title"]) { parts.push(job); }
            if let Some(bio) = s(&detail["bio"]) { f = harvest_text(f, &bio, "GitLab bio"); }
            if let Some(created) = detail["created_at"].as_str() { parts.push(format!("since {}", created.chars().take(10).collect::<String>())); }
            f.status(FindingStatus::Found).summary(parts.join(" · ")).data(json!({ "user": u, "detail": detail }))
        }
    }
}

async fn mastodon(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = card(ctx, "Mastodon", "Mastodon (mastodon.social)", format!("https://mastodon.social/@{handle}"));
    match fetch(ctx.client.get(format!("https://mastodon.social/api/v1/accounts/lookup?acct={}", urlencode(handle))).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            if res.status == 404 { return f.status(FindingStatus::NotFound).summary("no account on mastodon.social (other instances not checked)"); }
            let v = json_of(&res.body);
            if s(&v["username"]).is_none() { return f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status)); }
            let note = strip_html(v["note"].as_str().unwrap_or(""));
            let mut parts = Vec::new();
            if let Some(n) = s(&v["display_name"]) { parts.push(n.clone()); f = f.discover(EntityType::Person, n, Some("Mastodon display name")); }
            parts.push(format!("{} followers · {} posts · since {}", v["followers_count"].as_u64().unwrap_or(0), v["statuses_count"].as_u64().unwrap_or(0), v["created_at"].as_str().map(|d| d.chars().take(10).collect::<String>()).unwrap_or_default()));
            for field in v["fields"].as_array().into_iter().flatten() {
                let raw = field["value"].as_str().unwrap_or("");
                let verified = field["verified_at"].as_str().is_some();
                for m in RE_URL.find_iter(raw) {
                    f = f.discover(EntityType::Url, m.as_str().trim_end_matches('"'), Some(if verified { "Mastodon verified link" } else { "Mastodon profile field" }));
                }
            }
            f = harvest_text(f, &format!("{note} {}", v["note"].as_str().unwrap_or("")), "Mastodon bio");
            if !note.is_empty() { parts.push(note.chars().take(120).collect()); }
            f.status(FindingStatus::Found).url(s(&v["url"]).unwrap_or_else(|| format!("https://mastodon.social/@{handle}"))).summary(parts.join(" · ")).data(json!({ "displayName": v["display_name"], "note": note, "fields": v["fields"], "createdAt": v["created_at"], "followers": v["followers_count"], "statuses": v["statuses_count"], "bot": v["bot"], "locked": v["locked"] }))
        }
    }
}

async fn bluesky(ctx: &ScanContext, handle: &str) -> Finding {
    let actor = if handle.contains('.') { handle.to_string() } else { format!("{handle}.bsky.social") };
    let mut f = card(ctx, "Bluesky", "Bluesky profile", format!("https://bsky.app/profile/{actor}"));
    match fetch(ctx.client.get(format!("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={}", urlencode(&actor))).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            if res.status == 400 { return f.status(FindingStatus::NotFound).summary(format!("no Bluesky account {actor}")); }
            if s(&v["handle"]).is_none() { return f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status)); }
            let mut parts = Vec::new();
            if let Some(n) = s(&v["displayName"]) { parts.push(n.clone()); f = f.discover(EntityType::Person, n, Some("Bluesky display name")); }
            parts.push(format!("{} followers · {} posts · since {}", v["followersCount"].as_u64().unwrap_or(0), v["postsCount"].as_u64().unwrap_or(0), v["createdAt"].as_str().map(|d| d.chars().take(10).collect::<String>()).unwrap_or_default()));
            if let Some(d) = s(&v["description"]) { parts.push(d.chars().take(120).collect()); f = harvest_text(f, &d, "Bluesky bio"); }
            f.status(FindingStatus::Found).summary(parts.join(" · ")).data(json!({ "did": v["did"], "handle": v["handle"], "displayName": v["displayName"], "description": v["description"], "followers": v["followersCount"], "follows": v["followsCount"], "posts": v["postsCount"], "createdAt": v["createdAt"] }))
        }
    }
}

async fn lichess(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = card(ctx, "Lichess", "Lichess profile", format!("https://lichess.org/@/{handle}"));
    match fetch(ctx.client.get(format!("https://lichess.org/api/user/{}", urlencode(handle))).header("Accept", "application/json").header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            if res.status == 404 { return f.status(FindingStatus::NotFound).summary("no Lichess account"); }
            let v = json_of(&res.body);
            if s(&v["username"]).is_none() { return f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status)); }
            let p = &v["profile"];
            let mut parts = Vec::new();
            let name = format!("{} {}", p["firstName"].as_str().unwrap_or(""), p["lastName"].as_str().unwrap_or("")).trim().to_string();
            if !name.is_empty() { parts.push(name.clone()); f = f.discover(EntityType::Person, name, Some("Lichess real name")); }
            if let Some(loc) = s(&p["location"]) { parts.push(loc.clone()); f = f.discover(EntityType::Location, loc, Some("Lichess location")); }
            if let Some(c) = s(&p["flag"]).or_else(|| s(&p["country"])) { parts.push(c); }
            if let Some(links) = s(&p["links"]) { f = harvest_text(f, &links, "Lichess links"); }
            if let Some(bio) = s(&p["bio"]) { f = harvest_text(f, &bio, "Lichess bio"); }
            parts.push(format!("{} games · since {}", v["count"]["all"].as_u64().unwrap_or(0), v["createdAt"].as_i64().map(|ms| chrono_like(ms / 1000)).unwrap_or_default()));
            f.status(FindingStatus::Found).summary(parts.join(" · ")).data(json!({ "profile": p, "createdAt": v["createdAt"], "seenAt": v["seenAt"], "games": v["count"]["all"], "perfs": v["perfs"] }))
        }
    }
}

async fn chesscom(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = card(ctx, "Chess.com", "Chess.com profile", format!("https://www.chess.com/member/{handle}"));
    match fetch(ctx.client.get(format!("https://api.chess.com/pub/player/{}", urlencode(&handle.to_lowercase()))).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            if res.status == 404 { return f.status(FindingStatus::NotFound).summary("no Chess.com account"); }
            let v = json_of(&res.body);
            if s(&v["username"]).is_none() { return f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status)); }
            let mut parts = Vec::new();
            if let Some(n) = s(&v["name"]) { parts.push(n.clone()); f = f.discover(EntityType::Person, n, Some("Chess.com name")); }
            if let Some(loc) = s(&v["location"]) { parts.push(loc.clone()); f = f.discover(EntityType::Location, loc, Some("Chess.com location")); }
            if let Some(c) = s(&v["country"]) { parts.push(c.rsplit('/').next().unwrap_or("").to_string()); }
            if let Some(t) = s(&v["twitch_url"]) { f = f.discover(EntityType::Url, t, Some("Chess.com Twitch")); }
            parts.push(format!("{} · joined {}", s(&v["status"]).unwrap_or_default(), v["joined"].as_i64().map(chrono_like).unwrap_or_default()));
            f.status(FindingStatus::Found).url(s(&v["url"]).unwrap_or_default()).summary(parts.join(" · ")).data(v)
        }
    }
}

async fn dockerhub(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = card(ctx, "Docker Hub", "Docker Hub profile", format!("https://hub.docker.com/u/{handle}"));
    let client = crate::engine::http::build_following_client(&ctx.options.http_options()).unwrap_or_else(|_| ctx.client.clone());
    match fetch(client.get(format!("https://hub.docker.com/v2/users/{}/", urlencode(handle))).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            if res.status == 404 { return f.status(FindingStatus::NotFound).summary("no Docker Hub account"); }
            let v = json_of(&res.body);
            if s(&v["username"]).is_none() { return f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status)); }
            let mut parts = Vec::new();
            if let Some(n) = s(&v["full_name"]) { parts.push(n.clone()); f = f.discover(EntityType::Person, n, Some("Docker Hub name")); }
            if let Some(c) = s(&v["company"]) { parts.push(c.clone()); f = f.discover(EntityType::Org, c, Some("Docker Hub company")); }
            if let Some(l) = s(&v["location"]) { parts.push(l.clone()); f = f.discover(EntityType::Location, l, Some("Docker Hub location")); }
            if let Some(u) = s(&v["profile_url"]) { f = f.discover(EntityType::Url, u, Some("Docker Hub website")); }
            parts.push(format!("{} · joined {}", s(&v["type"]).unwrap_or_default(), v["date_joined"].as_str().map(|d| d.chars().take(10).collect::<String>()).unwrap_or_default()));
            f.status(FindingStatus::Found).summary(parts.join(" · ")).data(v)
        }
    }
}

async fn stackoverflow(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = card(ctx, "Stack Overflow", "Stack Overflow profile", format!("https://stackoverflow.com/users?tab=reputation&filter=all&search={}", urlencode(handle)));
    let url = format!("https://api.stackexchange.com/2.3/users?inname={}&site=stackoverflow&pagesize=5&order=desc&sort=reputation", urlencode(handle));
    match fetch(ctx.client.get(&url).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            let items = v["items"].as_array().cloned().unwrap_or_default();
            let exact: Option<&Value> = items.iter().find(|i| i["display_name"].as_str().map(|n| n.eq_ignore_ascii_case(handle)).unwrap_or(false));
            let Some(u) = exact else {
                return f.status(FindingStatus::NotFound).summary(if items.is_empty() { "no display name matches".to_string() } else { format!("{} loose matches, none exact", items.len()) });
            };
            let mut parts = vec![format!("{} reputation · since {}", u["reputation"].as_u64().unwrap_or(0), u["creation_date"].as_i64().map(chrono_like).unwrap_or_default())];
            if let Some(l) = s(&u["location"]) { parts.push(l.clone()); f = f.discover(EntityType::Location, l, Some("Stack Overflow location")); }
            if let Some(w) = s(&u["website_url"]) { f = f.discover(EntityType::Url, w, Some("Stack Overflow website")); }
            f.status(FindingStatus::Found).url(s(&u["link"]).unwrap_or_default()).summary(parts.join(" · ")).data(u.clone())
        }
    }
}

async fn cratesio(ctx: &ScanContext, handle: &str) -> Finding {
    let mut f = card(ctx, "crates.io", "crates.io profile", format!("https://crates.io/users/{handle}"));
    match fetch(ctx.client.get(format!("https://crates.io/api/v1/users/{}", urlencode(handle))).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            if res.status == 404 { return f.status(FindingStatus::NotFound).summary("no crates.io account"); }
            let v = json_of(&res.body);
            let u = &v["user"];
            if s(&u["login"]).is_none() { return f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status)); }
            let mut parts = Vec::new();
            if let Some(n) = s(&u["name"]) { parts.push(n.clone()); f = f.discover(EntityType::Person, n, Some("crates.io name")); }
            if let Some(url) = s(&u["url"]) { parts.push(url.clone()); f = f.discover(EntityType::Url, url, Some("crates.io linked GitHub")); }
            f.status(FindingStatus::Found).summary(if parts.is_empty() { "crates.io account exists".to_string() } else { parts.join(" · ") }).data(u.clone())
        }
    }
}

// ---------------------------------------------------------------------------
// Keyed cards
// ---------------------------------------------------------------------------

async fn steam(ctx: &ScanContext, handle: &str, key: &str) -> Finding {
    let mut f = card(ctx, "Steam", "Steam profile", format!("https://steamcommunity.com/id/{handle}"));
    match fetch(ctx.client.get(format!("https://api.steampowered.com/ISteamUser/ResolveVanityURL/v1/?key={key}&vanityurl={}", urlencode(handle)))).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            if res.status == 403 { return f.error("Steam rejected the API key"); }
            let Some(steamid) = v["response"]["steamid"].as_str() else { return f.status(FindingStatus::NotFound).summary("no Steam vanity URL with this handle"); };
            let p = fetch(ctx.client.get(format!("https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key={key}&steamids={steamid}"))).await.ok().map(|r| json_of(&r.body)).and_then(|v| v["response"]["players"].get(0).cloned()).unwrap_or(Value::Null);
            let mut parts = vec![format!("steamid {steamid}")];
            if let Some(n) = s(&p["personaname"]) { parts.push(n); }
            if let Some(r) = s(&p["realname"]) { parts.push(r.clone()); f = f.discover(EntityType::Person, r, Some("Steam real name")); }
            if let Some(c) = s(&p["loccountrycode"]) { parts.push(c); }
            if let Some(t) = p["timecreated"].as_i64() { parts.push(format!("since {}", chrono_like(t))); }
            f.status(FindingStatus::Found).summary(parts.join(" · ")).data(json!({ "steamid": steamid, "player": p }))
        }
    }
}

async fn youtube(ctx: &ScanContext, handle: &str, key: &str) -> Finding {
    let mut f = card(ctx, "YouTube", "YouTube channel", format!("https://www.youtube.com/@{handle}"));
    match fetch(ctx.client.get(format!("https://www.googleapis.com/youtube/v3/channels?forHandle=%40{}&part=snippet,statistics&key={key}", urlencode(handle)))).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            if res.status != 200 { return f.error(v["error"]["message"].as_str().unwrap_or("YouTube API request failed").to_string()); }
            let Some(item) = v["items"].get(0) else { return f.status(FindingStatus::NotFound).summary("no channel with this handle"); };
            let (sn, st) = (&item["snippet"], &item["statistics"]);
            let desc = sn["description"].as_str().unwrap_or("");
            let mut c = f.status(FindingStatus::Found).summary(format!("{} · {} subscribers · {} videos · {}{}", sn["title"].as_str().unwrap_or(""), st["subscriberCount"].as_str().unwrap_or("?"), st["videoCount"].as_str().unwrap_or("?"), sn["country"].as_str().unwrap_or("country unknown"), sn["publishedAt"].as_str().map(|d| format!(" · since {}", d.chars().take(10).collect::<String>())).unwrap_or_default()));
            c = harvest_text(c, desc, "YouTube description");
            c.data(json!({ "id": item["id"], "snippet": sn, "statistics": st }))
        }
    }
}

/// Emits one card per API-backed site.
pub async fn username_cards(ctx: &Arc<ScanContext>, handle: &str) {
    if ctx.cancelled() {
        return;
    }
    let (a, b, c, d, e, f6, g, h) = tokio::join!(
        github(ctx, handle),
        hackernews(ctx, handle),
        keybase(ctx, handle),
        gravatar(ctx, handle),
        gitlab(ctx, handle),
        mastodon(ctx, handle),
        bluesky(ctx, handle),
        lichess(ctx, handle)
    );
    for x in [a, b, c, d, e, f6, g, h] {
        ctx.emit(x);
    }
    if ctx.cancelled() {
        return;
    }
    let (i, j, k, l) = tokio::join!(chesscom(ctx, handle), dockerhub(ctx, handle), stackoverflow(ctx, handle), cratesio(ctx, handle));
    for x in [i, j, k, l] {
        ctx.emit(x);
    }
    if let Some(key) = ctx.secret("steam") {
        ctx.emit(steam(ctx, handle, key).await);
    }
    if let Some(key) = ctx.secret("youtube") {
        ctx.emit(youtube(ctx, handle, key).await);
    }
}
