//! Email probe: syntax, mail posture, disposable check, Gravatar, and registration
//! checks against services that answer without contacting the target address.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use md5::{Digest, Md5};
use once_cell::sync::Lazy;
use serde_json::{json, Value};

use super::launchers;
use super::payments;
use super::{EntityType, Finding, FindingStatus, ScanContext};
use crate::engine::dns;
use crate::engine::http::fetch;

static DISPOSABLE_RAW: &str = include_str!("../../../data/disposable-domains.txt");

static DISPOSABLE: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    DISPOSABLE_RAW
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
});

const ROLE_ACCOUNTS: &[&str] = &[
    "admin", "administrator", "info", "support", "sales", "contact", "help", "noreply", "no-reply",
    "postmaster", "webmaster", "abuse", "security", "billing", "marketing", "hello", "team", "office",
    "hr", "jobs", "careers", "press", "media", "privacy", "legal",
];

// ---------------------------------------------------------------------------
// Registration checks (holehe-style, no mail sent to the target)
// ---------------------------------------------------------------------------

enum Method {
    Get,
    PostJson(&'static str),
    PostForm(&'static str),
}

struct Check {
    name: &'static str,
    category: &'static str,
    url: &'static str,
    method: Method,
    /// Any of these substrings in the body means "registered".
    exists: &'static [&'static str],
    /// Any of these substrings means "not registered".
    missing: &'static [&'static str],
    /// HTTP statuses that mean "not registered" on their own.
    missing_status: &'static [u16],
    /// URL the user can open to see the account context.
    open: Option<&'static str>,
}

const CHECKS: &[Check] = &[
    Check {
        name: "Duolingo",
        category: "education",
        url: "https://www.duolingo.com/2017-06-30/users?email={email}",
        method: Method::Get,
        exists: &["\"username\""],
        missing: &["\"users\":[]", "\"users\": []"],
        missing_status: &[],
        open: None,
    },
    Check {
        name: "Mozilla account",
        category: "tech",
        url: "https://api.accounts.firefox.com/v1/account/status",
        method: Method::PostJson("{\"email\":\"{email}\"}"),
        exists: &["\"exists\":true", "\"exists\": true"],
        missing: &["\"exists\":false", "\"exists\": false"],
        missing_status: &[],
        open: None,
    },
    Check {
        name: "Spotify",
        category: "music",
        url: "https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}",
        method: Method::Get,
        exists: &["\"status\":20", "\"status\": 20"],
        missing: &["\"status\":1,", "\"status\": 1,", "\"status\":1}", "\"status\": 1}"],
        missing_status: &[],
        open: None,
    },
    Check {
        name: "Pinterest",
        category: "social",
        url: "https://www.pinterest.com/resource/EmailExistsResource/get/?source_url=%2F&data=%7B%22options%22%3A%7B%22email%22%3A%22{email}%22%7D%2C%22context%22%3A%7B%7D%7D",
        method: Method::Get,
        exists: &["\"data\":true", "\"data\": true"],
        missing: &["\"data\":false", "\"data\": false"],
        missing_status: &[],
        open: None,
    },
    Check {
        name: "Twitter / X",
        category: "social",
        url: "https://api.twitter.com/i/users/email_available.json?email={email}",
        method: Method::Get,
        exists: &["\"valid\":false", "\"valid\": false", "already been taken"],
        missing: &["\"valid\":true", "\"valid\": true"],
        missing_status: &[],
        open: None,
    },
    Check {
        name: "Imgur",
        category: "images",
        url: "https://imgur.com/signin/ajax_email_available",
        method: Method::PostForm("email={email}"),
        exists: &["\"available\":false", "\"available\": false"],
        missing: &["\"available\":true", "\"available\": true"],
        missing_status: &[],
        open: None,
    },
    Check {
        name: "Proton (PGP key)",
        category: "tech",
        url: "https://api.protonmail.ch/pks/lookup?op=index&search={email}",
        method: Method::Get,
        exists: &["info:1:1"],
        missing: &["info:1:0"],
        missing_status: &[404],
        open: None,
    },
    Check {
        name: "Keybase",
        category: "tech",
        url: "https://keybase.io/_/api/1.0/user/lookup.json?email={email}",
        method: Method::Get,
        exists: &["\"username\":"],
        missing: &["\"them\":[null]", "\"them\":[]", "\"them\": []"],
        missing_status: &[],
        open: None,
    },
    Check {
        name: "keys.openpgp.org",
        category: "tech",
        url: "https://keys.openpgp.org/vks/v1/by-email/{email}",
        method: Method::Get,
        exists: &["-----BEGIN PGP PUBLIC KEY BLOCK-----"],
        missing: &[],
        missing_status: &[404],
        open: Some("https://keys.openpgp.org/search?q={email}"),
    },
];

fn encode(email: &str) -> String {
    email.replace('@', "%40").replace('+', "%2B")
}

async fn run_check(ctx: &ScanContext, check: &Check, email: &str) -> Finding {
    let url = check.url.replace("{email}", &encode(email));
    let request = match &check.method {
        Method::Get => ctx.client.get(&url),
        Method::PostJson(body) => ctx
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body.replace("{email}", email)),
        Method::PostForm(body) => ctx
            .client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("X-Requested-With", "XMLHttpRequest")
            .body(body.replace("{email}", &encode(email))),
    };
    let request = request.header("Accept", "application/json, text/plain, */*");

    let mut finding = ctx
        .finding(check.name, "registration", check.name)
        .category(check.category);
    if let Some(open) = check.open {
        finding = finding.url(open.replace("{email}", &encode(email)));
    }

    match fetch(request).await {
        Err((detail, elapsed)) => {
            finding.elapsed_ms = elapsed;
            finding.error(detail)
        }
        Ok(res) => {
            finding.elapsed_ms = res.elapsed_ms;
            finding.http_status = Some(res.status);
            let body = &res.body;
            let exists = check.exists.iter().any(|s| body.contains(s));
            let missing = check.missing.iter().any(|s| body.contains(s)) || check.missing_status.contains(&res.status);
            finding.status = if exists && !missing {
                FindingStatus::Found
            } else if missing {
                FindingStatus::NotFound
            } else {
                finding.detail = Some(format!("HTTP {}: response did not match either signature", res.status));
                FindingStatus::Ambiguous
            };
            if finding.status == FindingStatus::Found {
                finding.summary = Some(format!("An account with this address exists on {}", check.name));
            }
            finding.data = json!({ "checkUrl": url, "bodySample": body.chars().take(300).collect::<String>() });
            finding
        }
    }
}

// ---------------------------------------------------------------------------
// Local analysis
// ---------------------------------------------------------------------------

pub fn split(email: &str) -> Option<(String, String)> {
    let email = email.trim();
    let at = email.rfind('@')?;
    let (local, domain) = (&email[..at], &email[at + 1..]);
    if local.is_empty() || domain.is_empty() || !domain.contains('.') || domain.contains(' ') {
        return None;
    }
    Some((local.to_string(), domain.to_lowercase()))
}

/// Username candidates derived from the local part: `john.doe+news` -> john.doe, johndoe, john_doe.
pub fn username_candidates(local: &str) -> Vec<String> {
    let base = local.split('+').next().unwrap_or(local).to_lowercase();
    let mut out = vec![base.clone()];
    let parts: Vec<&str> = base.split(['.', '_', '-']).filter(|p| !p.is_empty()).collect();
    if parts.len() > 1 {
        out.push(parts.join(""));
        out.push(parts.join("_"));
        out.push(parts.join("."));
    }
    let stripped: String = base.trim_end_matches(|c: char| c.is_ascii_digit()).to_string();
    if stripped.len() >= 3 && stripped != base {
        out.push(stripped);
    }
    let mut seen = HashSet::new();
    out.into_iter().filter(|u| u.len() >= 3 && seen.insert(u.clone())).collect()
}

pub fn gravatar_hash(email: &str) -> String {
    let normalized = email.trim().to_lowercase();
    format!("{:x}", Md5::digest(normalized.as_bytes()))
}

fn provider_from_mx(exchanges: &[String]) -> Option<&'static str> {
    let joined = exchanges.join(" ").to_lowercase();
    let table: &[(&str, &str)] = &[
        ("google.com", "Google Workspace / Gmail"),
        ("googlemail.com", "Google Workspace / Gmail"),
        ("outlook.com", "Microsoft 365 / Outlook"),
        ("protection.outlook.com", "Microsoft 365"),
        ("hotmail.com", "Microsoft Outlook.com"),
        ("yahoodns.net", "Yahoo Mail"),
        ("icloud.com", "Apple iCloud Mail"),
        ("protonmail.ch", "Proton Mail"),
        ("proton.me", "Proton Mail"),
        ("zoho.com", "Zoho Mail"),
        ("pphosted.com", "Proofpoint"),
        ("mimecast.com", "Mimecast"),
        ("messagelabs.com", "Symantec / Broadcom"),
        ("fastmail.com", "Fastmail"),
        ("mail.ru", "Mail.ru"),
        ("yandex.net", "Yandex Mail"),
        ("mx.ovh.net", "OVH"),
        ("secureserver.net", "GoDaddy"),
        ("emailsrvr.com", "Rackspace"),
        ("mailgun.org", "Mailgun"),
        ("tutanota.de", "Tuta"),
    ];
    table.iter().find(|(needle, _)| joined.contains(needle)).map(|(_, name)| *name)
}

// ---------------------------------------------------------------------------
// Probe entry point
// ---------------------------------------------------------------------------

pub async fn run(ctx: Arc<ScanContext>) -> Result<(), String> {
    let email = ctx.input.trim().to_lowercase();
    let Some((local, domain)) = split(&email) else {
        return Err("That does not look like an email address.".to_string());
    };

    // syntax, disposable, mx, spf, dmarc, gravatar, hibp launcher, dorks + checks (+2 keyed HIBP calls)
    let hibp_key = ctx.secret("hibp").map(str::to_string);
    let candidates = username_candidates(&local);
    let payment_handles: Vec<String> = candidates.iter().take(4).cloned().collect();
    let catalog = launchers::plan(EntityType::Email, &launchers::vars_email(&email));
    ctx.start(
        9 + CHECKS.len()
            + catalog.len()
            + payments::MANUAL_LAUNCHER_COUNT
            + payments::handle_check_count(payment_handles.len())
            + if hibp_key.is_some() { 2 } else { 0 },
    );

    // 1. Syntax and derived pivots.
    let mut syntax = ctx
        .finding("parser", "address", "Address parsed")
        .status(FindingStatus::Info)
        .summary(format!("local part \"{local}\" at {domain}"))
        .data(json!({ "local": local, "domain": domain, "usernameCandidates": candidates }))
        .discover(EntityType::Domain, domain.clone(), Some("mail domain"));
    for c in &candidates {
        syntax = syntax.discover(EntityType::Username, c.clone(), Some("from local part"));
    }
    let role = ROLE_ACCOUNTS.contains(&local.split('+').next().unwrap_or(&local));
    if role {
        syntax.summary = Some(format!("\"{local}\" is a role account (shared mailbox), not a person"));
    }
    ctx.emit(syntax);

    // 2. Disposable domain.
    let disposable = DISPOSABLE.contains(domain.as_str());
    ctx.emit(
        ctx.finding("disposable-email-domains", "disposable", "Disposable domain")
            .status(if disposable { FindingStatus::Found } else { FindingStatus::NotFound })
            .summary(if disposable {
                format!("{domain} is a known throwaway mail provider")
            } else {
                format!("{domain} is not on the disposable list")
            })
            .category("posture"),
    );

    if ctx.cancelled() {
        return Ok(());
    }

    // 3-5. DNS mail posture.
    let resolver = dns::resolver();
    let started = Instant::now();
    match dns::mx(&resolver, &domain).await {
        Ok(records) => {
            let exchanges: Vec<String> = records.iter().map(|r| r.exchange.clone()).collect();
            let provider = provider_from_mx(&exchanges);
            let mut f = ctx
                .finding("dns", "mx", "MX records")
                .category("posture")
                .status(if records.is_empty() { FindingStatus::NotFound } else { FindingStatus::Info })
                .summary(if records.is_empty() {
                    "No MX records: this domain cannot receive mail".to_string()
                } else {
                    match provider {
                        Some(p) => format!("{} mail server(s), hosted by {p}", records.len()),
                        None => format!("{} mail server(s): {}", records.len(), exchanges.join(", ")),
                    }
                })
                .data(json!({
                    "records": records.iter().map(|r| json!({"preference": r.preference, "exchange": r.exchange})).collect::<Vec<_>>(),
                    "provider": provider
                }));
            f.elapsed_ms = started.elapsed().as_millis() as u64;
            ctx.emit(f);
        }
        Err(e) => ctx.emit(ctx.finding("dns", "mx", "MX records").category("posture").error(e)),
    }

    let started = Instant::now();
    match dns::txt(&resolver, &domain).await {
        Ok(txts) => {
            let spf = txts.iter().find(|t| t.starts_with("v=spf1"));
            let mut f = ctx
                .finding("dns", "spf", "SPF policy")
                .category("posture")
                .status(if spf.is_some() { FindingStatus::Info } else { FindingStatus::NotFound })
                .summary(match spf {
                    Some(s) => s.clone(),
                    None => "No SPF record: sender spoofing is not restricted".to_string(),
                })
                .data(json!({ "txt": txts }));
            f.elapsed_ms = started.elapsed().as_millis() as u64;
            ctx.emit(f);
        }
        Err(e) => ctx.emit(ctx.finding("dns", "spf", "SPF policy").category("posture").error(e)),
    }

    let started = Instant::now();
    match dns::txt(&resolver, &format!("_dmarc.{domain}")).await {
        Ok(txts) => {
            let dmarc = txts.iter().find(|t| t.starts_with("v=DMARC1"));
            let policy = dmarc
                .and_then(|d| d.split(';').map(str::trim).find(|p| p.starts_with("p=")))
                .map(|p| p.trim_start_matches("p=").to_string());
            let mut f = ctx
                .finding("dns", "dmarc", "DMARC policy")
                .category("posture")
                .status(if dmarc.is_some() { FindingStatus::Info } else { FindingStatus::NotFound })
                .summary(match (&dmarc, &policy) {
                    (Some(_), Some(p)) => format!("DMARC present, policy p={p}"),
                    (Some(d), None) => d.to_string(),
                    _ => "No DMARC record".to_string(),
                })
                .data(json!({ "txt": txts, "policy": policy }));
            f.elapsed_ms = started.elapsed().as_millis() as u64;
            ctx.emit(f);
        }
        Err(e) => ctx.emit(ctx.finding("dns", "dmarc", "DMARC policy").category("posture").error(e)),
    }

    if ctx.cancelled() {
        return Ok(());
    }

    // 6. Gravatar avatar + profile.
    let hash = gravatar_hash(&email);
    let avatar_url = format!("https://www.gravatar.com/avatar/{hash}?d=404&s=200");
    let profile_url = format!("https://www.gravatar.com/{hash}");
    let mut gravatar = ctx
        .finding("Gravatar", "profile", "Gravatar")
        .category("images")
        .url(profile_url.clone());
    match fetch(ctx.client.get(&avatar_url)).await {
        Err((detail, elapsed)) => {
            gravatar.elapsed_ms = elapsed;
            gravatar = gravatar.error(detail);
        }
        Ok(res) => {
            gravatar.elapsed_ms = res.elapsed_ms;
            gravatar.http_status = Some(res.status);
            gravatar.status = match res.status {
                200 => FindingStatus::Found,
                404 => FindingStatus::NotFound,
                _ => FindingStatus::Ambiguous,
            };
            let mut data = json!({ "hash": hash, "avatarUrl": avatar_url });
            if gravatar.status == FindingStatus::Found {
                gravatar.summary = Some("Avatar registered for this address".to_string());
                if let Ok(p) = fetch(ctx.client.get(format!("{profile_url}.json"))).await {
                    if p.status == 200 {
                        if let Ok(v) = serde_json::from_str::<Value>(&p.body) {
                            if let Some(entry) = v["entry"].get(0) {
                                if let Some(name) = entry["displayName"].as_str() {
                                    gravatar.summary = Some(format!("Avatar registered · display name \"{name}\""));
                                    gravatar = gravatar.discover(EntityType::Person, name, Some("Gravatar display name"));
                                }
                                if let Some(user) = entry["preferredUsername"].as_str() {
                                    gravatar = gravatar.discover(EntityType::Username, user, Some("Gravatar username"));
                                }
                                if let Some(urls) = entry["urls"].as_array() {
                                    for u in urls {
                                        if let Some(link) = u["value"].as_str() {
                                            gravatar = gravatar.discover(EntityType::Url, link, u["title"].as_str());
                                        }
                                    }
                                }
                                if let Some(accounts) = entry["accounts"].as_array() {
                                    for a in accounts {
                                        if let Some(user) = a["username"].as_str() {
                                            gravatar = gravatar.discover(
                                                EntityType::Username,
                                                user,
                                                a["shortname"].as_str().or(a["domain"].as_str()),
                                            );
                                        }
                                    }
                                }
                                data["profile"] = entry.clone();
                            }
                        }
                    }
                }
            }
            gravatar.data = data;
        }
    }
    ctx.emit(gravatar);

    // 7. Breach lookup: keyed API when available, launcher otherwise.
    ctx.emit(
        ctx.finding("Have I Been Pwned", "launcher", "Breach lookup")
            .category("breach")
            .status(FindingStatus::Info)
            .url(format!("https://haveibeenpwned.com/account/{}", encode(&email)))
            .summary(if hibp_key.is_some() { "HIBP page for this address (API results below)" } else { "Open HIBP to check breaches by hand, or add an API key in Settings" }),
    );
    if let Some(key) = &hibp_key {
        for (path, kind, title) in [("breachedaccount", "breach", "Breaches"), ("pasteaccount", "paste", "Pastes")] {
            let url = format!("https://haveibeenpwned.com/api/v3/{path}/{}?truncateResponse=false", encode(&email));
            let mut f = ctx.finding("Have I Been Pwned", kind, title).category("breach")
                .url(format!("https://haveibeenpwned.com/account/{}", encode(&email)));
            match fetch(ctx.client.get(&url).header("hibp-api-key", key.as_str()).header("user-agent", "nazgul-osint")).await {
                Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
                Ok(res) => {
                    f.elapsed_ms = res.elapsed_ms;
                    f.http_status = Some(res.status);
                    match res.status {
                        200 => {
                            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                            let items = v.as_array().cloned().unwrap_or_default();
                            let names: Vec<String> = items.iter().filter_map(|b| b["Name"].as_str().or(b["Source"].as_str()).map(str::to_string)).collect();
                            f = f.status(FindingStatus::Found)
                                .summary(format!("{} {}: {}", items.len(), title.to_lowercase(), names.iter().take(8).cloned().collect::<Vec<_>>().join(", ")))
                                .data(json!({ "items": items }));
                        }
                        404 => f = f.status(FindingStatus::NotFound).summary(format!("no {} on record", title.to_lowercase())),
                        401 => f = f.error("HIBP rejected the API key"),
                        429 => f = f.error("HIBP rate limit hit; try again in a few seconds"),
                        other => f = f.status(FindingStatus::Ambiguous).detail(format!("HTTP {other}")),
                    }
                }
            }
            ctx.emit(f);
        }
    }

    // 8. Dorks.
    let q = format!("\"{email}\"");
    ctx.emit(
        ctx.finding("dorks", "launcher", "Search engine dorks")
            .category("dorks")
            .status(FindingStatus::Info)
            .url(format!("https://www.google.com/search?q={}", urlencode(&q)))
            .summary("Quoted address on Google; Bing, DuckDuckGo and code search in raw data")
            .data(json!({
                "google": format!("https://www.google.com/search?q={}", urlencode(&q)),
                "bing": format!("https://www.bing.com/search?q={}", urlencode(&q)),
                "duckduckgo": format!("https://duckduckgo.com/?q={}", urlencode(&q)),
                "grepApp": format!("https://grep.app/search?q={}", urlencode(&email)),
                "githubCode": format!("https://github.com/search?type=code&q={}", urlencode(&q)),
            })),
    );

    // EmailRep reputation (free tier without a key, more with one).
    let mut rep = ctx.finding("EmailRep", "reputation", "EmailRep reputation").category("reputation")
        .url(format!("https://emailrep.io/{}", encode(&email)));
    let mut req = ctx.client.get(format!("https://emailrep.io/{}", encode(&email))).header("User-Agent", "nazgul-osint");
    if let Some(key) = ctx.secret("emailrep") {
        req = req.header("Key", key);
    }
    match fetch(req).await {
        Err((e, ms)) => { rep.elapsed_ms = ms; rep = rep.error(e); }
        Ok(res) => {
            rep.elapsed_ms = res.elapsed_ms;
            rep.http_status = Some(res.status);
            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
            if res.status == 200 && v["reputation"].is_string() {
                let d = &v["details"];
                let profiles: Vec<String> = d["profiles"].as_array().map(|a| a.iter().filter_map(|p| p.as_str().map(str::to_string)).collect()).unwrap_or_default();
                let mut flags = Vec::new();
                for (key, label) in [("credentials_leaked", "credentials leaked"), ("data_breach", "in a breach"), ("malicious_activity", "malicious activity"), ("spam", "spam source"), ("disposable", "disposable"), ("free_provider", "free provider"), ("deliverable", "deliverable")] {
                    if d[key].as_bool().unwrap_or(false) {
                        flags.push(label);
                    }
                }
                let seen = d["first_seen"].as_str().filter(|s| *s != "never").map(|s| format!(" · first seen {s}")).unwrap_or_default();
                rep = rep
                    .status(if !profiles.is_empty() || d["credentials_leaked"].as_bool().unwrap_or(false) { FindingStatus::Found } else { FindingStatus::Info })
                    .summary(format!("reputation {} · {} reference(s){}{}{}", v["reputation"].as_str().unwrap_or("?"), v["references"].as_u64().unwrap_or(0), if profiles.is_empty() { String::new() } else { format!(" · profiles: {}", profiles.join(", ")) }, if flags.is_empty() { String::new() } else { format!(" · {}", flags.join(", ")) }, seen))
                    .data(v.clone());
            } else if res.status == 429 {
                rep = rep.status(FindingStatus::Info).summary("EmailRep daily quota reached; add a key in Settings or open the page");
            } else {
                rep = rep.status(FindingStatus::Ambiguous).detail(format!("HTTP {}: {}", res.status, v["reason"].as_str().unwrap_or("")));
            }
        }
    }
    ctx.emit(rep);
    launchers::emit(&ctx, &catalog);

    // Payment apps: launchers that prefill the address in the user's own apps, then public
    // handle pages for the username candidates.
    for f in payments::manual_launchers(&ctx, &email, "email address") {
        ctx.emit(f);
    }
    payments::check_handles(&ctx, &payment_handles).await;

    // Registration checks, in parallel.
    let mut tasks = tokio::task::JoinSet::new();
    for check in CHECKS {
        let ctx = ctx.clone();
        let email = email.clone();
        tasks.spawn(async move {
            if ctx.cancelled() {
                return;
            }
            tokio::select! {
                _ = ctx.cancel.cancelled() => {},
                f = run_check(&ctx, check, &email) => ctx.emit(f),
            }
        });
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

pub fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
