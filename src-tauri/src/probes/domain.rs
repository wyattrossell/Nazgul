//! Domain probe: registration (RDAP), DNS, mail posture, subdomains (certificate
//! transparency, Wayback, DNS brute force), web technology fingerprint, favicon hash,
//! well-known files, and launchers.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Instant;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use hickory_resolver::proto::rr::RecordType;
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};
use tokio::sync::Semaphore;

use super::email::urlencode;
use super::{EntityType, FindingStatus, ScanContext};
use crate::engine::dns;
use crate::engine::http::{build_following_client, fetch};

const DKIM_SELECTORS: &[&str] = &[
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "mail", "dkim", "s1", "s2", "smtp",
    "mandrill", "mailgun", "mg", "amazonses", "ses", "zoho", "protonmail", "protonmail2", "pm", "mx",
    "sendgrid", "em", "hs1", "hubspot", "mailchimp", "mailjet", "sparkpost", "postmark", "fm1", "fm2",
];

const BRUTE_PREFIXES: &[&str] = &[
    "www", "mail", "ftp", "smtp", "imap", "pop", "webmail", "mx", "ns1", "ns2", "dev", "staging", "stage",
    "test", "qa", "uat", "beta", "demo", "api", "app", "apps", "admin", "portal", "vpn", "remote", "gateway",
    "cdn", "static", "assets", "img", "images", "media", "files", "docs", "wiki", "blog", "shop", "store",
    "m", "mobile", "secure", "login", "sso", "auth", "id", "git", "gitlab", "jenkins", "ci", "jira",
    "confluence", "status", "monitor", "grafana", "kibana", "db", "sql", "backup", "old", "new", "intranet",
    "internal", "corp", "office", "cloud", "s3", "storage", "help", "support", "crm", "erp", "hr", "mta",
    "autodiscover", "lyncdiscover", "sip", "meet", "video", "chat", "forum", "community", "news",
];

static RE_HOST: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$").unwrap());
static RE_TITLE: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?is)<title[^>]*>(.*?)</title>").unwrap());
static RE_GENERATOR: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?is)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']"#).unwrap());
static RE_ICON: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?is)<link[^>]+rel=["'][^"']*icon[^"']*["'][^>]+href=["']([^"']+)["']"#).unwrap());
static RE_GA: Lazy<Regex> = Lazy::new(|| Regex::new(r"\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{6,12}|GTM-[A-Z0-9]{4,9})\b").unwrap());
static RE_EMAIL: Lazy<Regex> = Lazy::new(|| Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").unwrap());

/// Reduce a URL or messy input to a bare host name.
pub fn normalize(input: &str) -> Option<String> {
    let mut s = input.trim().to_lowercase();
    if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
    }
    s = s.split(['/', '?', '#']).next().unwrap_or("").to_string();
    if let Some(at) = s.rfind('@') {
        s = s[at + 1..].to_string();
    }
    s = s.split(':').next().unwrap_or("").trim_end_matches('.').to_string();
    if RE_HOST.is_match(&s) {
        Some(s)
    } else {
        None
    }
}

/// Shodan-compatible favicon hash: murmur3_32 of the base64 body with newlines every 76 chars.
pub fn favicon_hash(bytes: &[u8]) -> i32 {
    let encoded = STANDARD.encode(bytes);
    let mut wrapped = String::with_capacity(encoded.len() + encoded.len() / 76 + 2);
    for chunk in encoded.as_bytes().chunks(76) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        wrapped.push('\n');
    }
    murmur3::murmur3_32(&mut Cursor::new(wrapped.as_bytes()), 0).map(|h| h as i32).unwrap_or(0)
}

fn vcard_field(entity: &Value, name: &str) -> Option<String> {
    entity["vcardArray"]
        .get(1)?
        .as_array()?
        .iter()
        .find(|row| row.get(0).and_then(Value::as_str) == Some(name))
        .and_then(|row| row.get(3))
        .and_then(|v| v.as_str().map(str::to_string))
}

fn rdap_event(v: &Value, action: &str) -> Option<String> {
    v["events"]
        .as_array()?
        .iter()
        .find(|e| e["eventAction"].as_str() == Some(action))
        .and_then(|e| e["eventDate"].as_str())
        .map(|d| d.chars().take(10).collect())
}

fn hostnames_from_ct(v: &Value, domain: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(rows) = v.as_array() {
        for row in rows {
            for field in ["name_value", "common_name"] {
                if let Some(text) = row[field].as_str() {
                    for name in text.split('\n') {
                        let name = name.trim().trim_start_matches("*.").to_lowercase();
                        if (name == domain || name.ends_with(&format!(".{domain}"))) && RE_HOST.is_match(&name) {
                            out.insert(name);
                        }
                    }
                }
            }
        }
    }
    out
}

fn tech_hints(headers: &reqwest::header::HeaderMap, body: &str) -> Vec<String> {
    let mut tech: Vec<String> = Vec::new();
    let h = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_string);
    if let Some(server) = h("server") {
        tech.push(format!("server: {server}"));
    }
    if let Some(p) = h("x-powered-by") {
        tech.push(format!("powered by: {p}"));
    }
    if h("cf-ray").is_some() || h("server").map(|s| s.to_lowercase().contains("cloudflare")).unwrap_or(false) {
        tech.push("Cloudflare".into());
    }
    if h("x-amz-cf-id").is_some() {
        tech.push("Amazon CloudFront".into());
    }
    if h("x-vercel-id").is_some() {
        tech.push("Vercel".into());
    }
    if h("x-github-request-id").is_some() {
        tech.push("GitHub Pages".into());
    }
    if h("x-shopify-stage").is_some() || body.contains("cdn.shopify.com") {
        tech.push("Shopify".into());
    }
    if let Some(cookies) = headers.get_all("set-cookie").iter().next().and_then(|v| v.to_str().ok()) {
        let c = cookies.to_lowercase();
        if c.contains("phpsessid") {
            tech.push("PHP".into());
        }
        if c.contains("asp.net_sessionid") {
            tech.push("ASP.NET".into());
        }
        if c.contains("jsessionid") {
            tech.push("Java (JSESSIONID)".into());
        }
        if c.contains("csrftoken") {
            tech.push("Django".into());
        }
        if c.contains("laravel_session") {
            tech.push("Laravel".into());
        }
    }
    let lower = body.to_lowercase();
    let body_hints: &[(&str, &str)] = &[
        ("wp-content", "WordPress"),
        ("/sites/default/files", "Drupal"),
        ("joomla", "Joomla"),
        ("/_next/static", "Next.js"),
        ("__nuxt", "Nuxt"),
        ("data-reactroot", "React"),
        ("ng-version", "Angular"),
        ("wix.com", "Wix"),
        ("squarespace", "Squarespace"),
        ("hubspot", "HubSpot"),
        ("jquery", "jQuery"),
        ("bootstrap", "Bootstrap"),
        ("tailwind", "Tailwind"),
        ("googletagmanager.com", "Google Tag Manager"),
        ("google-analytics.com", "Google Analytics"),
        ("cdn.jsdelivr.net", "jsDelivr CDN"),
        ("recaptcha", "reCAPTCHA"),
        ("hcaptcha", "hCaptcha"),
        ("intercom", "Intercom"),
        ("stripe.com", "Stripe"),
    ];
    for (needle, name) in body_hints {
        if lower.contains(needle) {
            tech.push((*name).to_string());
        }
    }
    if let Some(cap) = RE_GENERATOR.captures(body) {
        tech.push(format!("generator: {}", cap[1].trim()));
    }
    tech.dedup();
    tech
}

pub async fn run(ctx: Arc<ScanContext>) -> Result<(), String> {
    let Some(domain) = normalize(&ctx.input) else {
        return Err("Enter a bare domain like example.com (a URL is fine too).".to_string());
    };
    let follower = build_following_client(&ctx.options.http_options()).map_err(|e| e.to_string())?;
    let resolver = dns::resolver();

    // rdap + 8 record types + spf + dmarc + dkim + ct + wayback + http + favicon + 3 well-known + 5 launchers + brute summary
    let keyed = ["shodan", "hunter", "virustotal"].iter().filter(|k| ctx.secret(k).is_some()).count();
    ctx.start(25 + keyed);
    let mut subdomains: BTreeSet<String> = BTreeSet::new();

    // ------------------------------------------------------------------ RDAP
    let started = Instant::now();
    let mut reg = ctx.finding("rdap", "registration", "Registration").category("whois");
    match fetch(follower.get(format!("https://rdap.org/domain/{domain}")).header("Accept", "application/rdap+json")).await {
        Err((e, ms)) => {
            reg.elapsed_ms = ms;
            reg = reg.error(e);
        }
        Ok(res) => {
            reg.elapsed_ms = res.elapsed_ms;
            reg.http_status = Some(res.status);
            if res.status == 200 {
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                let registrar = v["entities"]
                    .as_array()
                    .and_then(|ents| {
                        ents.iter()
                            .find(|e| e["roles"].as_array().map(|r| r.iter().any(|x| x == "registrar")).unwrap_or(false))
                            .and_then(|e| vcard_field(e, "fn"))
                    });
                let registered = rdap_event(&v, "registration");
                let expires = rdap_event(&v, "expiration");
                let changed = rdap_event(&v, "last changed");
                let statuses: Vec<String> = v["status"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                let nameservers: Vec<String> = v["nameservers"]
                    .as_array()
                    .map(|a| a.iter().filter_map(|n| n["ldhName"].as_str().map(|s| s.to_lowercase())).collect())
                    .unwrap_or_default();
                let mut emails = BTreeSet::new();
                for cap in RE_EMAIL.find_iter(&res.body) {
                    emails.insert(cap.as_str().to_lowercase());
                }
                let mut parts = Vec::new();
                if let Some(r) = &registered {
                    parts.push(format!("registered {r}"));
                }
                if let Some(e) = &expires {
                    parts.push(format!("expires {e}"));
                }
                if let Some(r) = &registrar {
                    parts.push(format!("via {r}"));
                }
                reg = reg
                    .status(FindingStatus::Info)
                    .summary(if parts.is_empty() { "RDAP record found".to_string() } else { parts.join(" · ") })
                    .url(format!("https://rdap.org/domain/{domain}"))
                    .data(json!({
                        "registrar": registrar, "registered": registered, "expires": expires, "lastChanged": changed,
                        "status": statuses, "nameservers": nameservers, "contactEmails": emails,
                    }));
                for e in emails.iter().take(5) {
                    if !e.contains("abuse") {
                        reg = reg.discover(EntityType::Email, e.clone(), Some("RDAP contact"));
                    }
                }
            } else if res.status == 404 {
                reg = reg.status(FindingStatus::NotFound).summary("No RDAP record: the domain may be unregistered");
            } else {
                reg = reg.status(FindingStatus::Ambiguous).detail(format!("RDAP answered HTTP {}", res.status));
            }
        }
    }
    ctx.emit(reg);

    if ctx.cancelled() {
        return Ok(());
    }

    // ------------------------------------------------------------------ DNS
    for (rtype, label) in [
        (RecordType::A, "A"),
        (RecordType::AAAA, "AAAA"),
        (RecordType::CNAME, "CNAME"),
        (RecordType::NS, "NS"),
        (RecordType::MX, "MX"),
        (RecordType::TXT, "TXT"),
        (RecordType::SOA, "SOA"),
        (RecordType::CAA, "CAA"),
    ] {
        let started = Instant::now();
        let mut f = ctx.finding("dns", "dns_record", &format!("{label} records")).category("dns");
        match dns::records(&resolver, &domain, rtype).await {
            Ok(values) => {
                f.elapsed_ms = started.elapsed().as_millis() as u64;
                f.status = if values.is_empty() { FindingStatus::NotFound } else { FindingStatus::Info };
                f.summary = Some(if values.is_empty() {
                    format!("no {label} records")
                } else {
                    values.iter().take(6).cloned().collect::<Vec<_>>().join(" · ")
                });
                if matches!(rtype, RecordType::A | RecordType::AAAA) {
                    for ip in &values {
                        f = f.discover(EntityType::Ip, ip.clone(), Some(&format!("{label} record")));
                    }
                }
                f.data = json!({ "type": label, "values": values });
            }
            Err(e) => f = f.error(e),
        }
        ctx.emit(f);
    }

    // ------------------------------------------------------------------ mail posture
    let txts = dns::txt(&resolver, &domain).await.unwrap_or_default();
    let spf = txts.iter().find(|t| t.starts_with("v=spf1")).cloned();
    ctx.emit(
        ctx.finding("dns", "spf", "SPF policy")
            .category("mail")
            .status(if spf.is_some() { FindingStatus::Info } else { FindingStatus::NotFound })
            .summary(spf.clone().unwrap_or_else(|| "No SPF record".to_string()))
            .data(json!({ "spf": spf })),
    );
    let dmarc_txt = dns::txt(&resolver, &format!("_dmarc.{domain}")).await.unwrap_or_default();
    let dmarc = dmarc_txt.iter().find(|t| t.starts_with("v=DMARC1")).cloned();
    ctx.emit(
        ctx.finding("dns", "dmarc", "DMARC policy")
            .category("mail")
            .status(if dmarc.is_some() { FindingStatus::Info } else { FindingStatus::NotFound })
            .summary(dmarc.clone().unwrap_or_else(|| "No DMARC record".to_string()))
            .data(json!({ "dmarc": dmarc })),
    );
    let mut selectors_found = Vec::new();
    for selector in DKIM_SELECTORS {
        if ctx.cancelled() {
            break;
        }
        if let Ok(t) = dns::txt(&resolver, &format!("{selector}._domainkey.{domain}")).await {
            if t.iter().any(|r| r.contains("v=DKIM1") || r.contains("k=rsa") || r.contains("p=")) {
                selectors_found.push(selector.to_string());
            }
        }
    }
    ctx.emit(
        ctx.finding("dns", "dkim", "DKIM selectors")
            .category("mail")
            .status(if selectors_found.is_empty() { FindingStatus::NotFound } else { FindingStatus::Info })
            .summary(if selectors_found.is_empty() {
                format!("none of {} common selectors published", DKIM_SELECTORS.len())
            } else {
                format!("selectors: {}", selectors_found.join(", "))
            })
            .data(json!({ "selectors": selectors_found, "tried": DKIM_SELECTORS })),
    );

    if ctx.cancelled() {
        return Ok(());
    }

    // ------------------------------------------------------------------ certificate transparency
    let _ = started;
    let mut ct = ctx.finding("crt.sh", "certificates", "Certificate transparency").category("subdomains")
        .url(format!("https://crt.sh/?q=%25.{domain}"));
    match fetch(follower.get(format!("https://crt.sh/?q=%25.{domain}&output=json"))).await {
        Err((e, ms)) => {
            ct.elapsed_ms = ms;
            ct = ct.error(e);
        }
        Ok(res) => {
            ct.elapsed_ms = res.elapsed_ms;
            ct.http_status = Some(res.status);
            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
            let names = hostnames_from_ct(&v, &domain);
            let count = names.len();
            subdomains.extend(names.iter().cloned());
            ct = ct
                .status(if count > 0 { FindingStatus::Info } else { FindingStatus::NotFound })
                .summary(format!("{count} unique host names seen in certificates"))
                .data(json!({ "hostnames": names.iter().take(500).collect::<Vec<_>>(), "certificates": v.as_array().map(|a| a.len()).unwrap_or(0) }));
        }
    }
    ctx.emit(ct);

    // ------------------------------------------------------------------ Wayback
    let mut wb = ctx.finding("Wayback Machine", "archive", "Wayback Machine").category("archive")
        .url(format!("https://web.archive.org/web/*/{domain}"));
    match fetch(follower.get(format!("https://web.archive.org/cdx/search/cdx?url={domain}&output=json&fl=timestamp&limit=1"))).await {
        Err((e, ms)) => {
            wb.elapsed_ms = ms;
            wb = wb.error(e);
        }
        Ok(res) => {
            wb.elapsed_ms = res.elapsed_ms;
            wb.http_status = Some(res.status);
            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
            let first = v.get(1).and_then(|r| r.get(0)).and_then(Value::as_str).map(str::to_string);
            let latest = fetch(follower.get(format!("https://archive.org/wayback/available?url={domain}")))
                .await
                .ok()
                .and_then(|r| serde_json::from_str::<Value>(&r.body).ok())
                .and_then(|v| v["archived_snapshots"]["closest"]["timestamp"].as_str().map(str::to_string));
            let fmt = |t: &str| format!("{}-{}-{}", &t[..4], &t[4..6], &t[6..8]);
            wb = match (&first, &latest) {
                (Some(f), Some(l)) if f.len() >= 8 && l.len() >= 8 => wb
                    .status(FindingStatus::Info)
                    .summary(format!("archived from {} to {}", fmt(f), fmt(l))),
                (Some(f), None) if f.len() >= 8 => wb.status(FindingStatus::Info).summary(format!("first archived {}", fmt(f))),
                _ => wb.status(FindingStatus::NotFound).summary("no snapshots"),
            };
            wb.data = json!({ "firstSnapshot": first, "latestSnapshot": latest });
            // Hostnames the archive has seen.
            if let Ok(r) = fetch(follower.get(format!(
                "https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=400"
            )))
            .await
            {
                if let Ok(v) = serde_json::from_str::<Value>(&r.body) {
                    for row in v.as_array().into_iter().flatten().skip(1) {
                        if let Some(u) = row.get(0).and_then(Value::as_str) {
                            if let Some(host) = normalize(u) {
                                if host.ends_with(&format!(".{domain}")) {
                                    subdomains.insert(host);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    ctx.emit(wb);

    if ctx.cancelled() {
        return Ok(());
    }

    // ------------------------------------------------------------------ HTTP fingerprint + favicon
    let mut web = ctx.finding("http", "technology", "Web technologies").category("web").url(format!("https://{domain}/"));
    let mut icon_href: Option<String> = None;
    let started = Instant::now();
    match follower.get(format!("https://{domain}/")).send().await {
        Err(e) => {
            web.elapsed_ms = started.elapsed().as_millis() as u64;
            web = web.error(crate::engine::http::describe_error(e));
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let final_url = resp.url().to_string();
            let headers = resp.headers().clone();
            let body = resp.text().await.unwrap_or_default();
            web.elapsed_ms = started.elapsed().as_millis() as u64;
            web.http_status = Some(status);
            let title = RE_TITLE.captures(&body).map(|c| c[1].split_whitespace().collect::<Vec<_>>().join(" "));
            let tech = tech_hints(&headers, &body);
            let mut ids = BTreeSet::new();
            for cap in RE_GA.find_iter(&body) {
                ids.insert(cap.as_str().to_string());
            }
            let mut emails = BTreeSet::new();
            for cap in RE_EMAIL.find_iter(&body) {
                let e = cap.as_str().to_lowercase();
                if !e.ends_with(".png") && !e.ends_with(".jpg") && !e.ends_with(".svg") {
                    emails.insert(e);
                }
            }
            icon_href = RE_ICON.captures(&body).map(|c| c[1].to_string());
            let header_map: serde_json::Map<String, Value> = headers
                .iter()
                .map(|(k, v)| (k.to_string(), Value::String(v.to_str().unwrap_or("").to_string())))
                .collect();
            web = web
                .status(FindingStatus::Info)
                .summary(format!(
                    "HTTP {status}{} · {}",
                    title.as_ref().map(|t| format!(" · \"{}\"", t.chars().take(80).collect::<String>())).unwrap_or_default(),
                    if tech.is_empty() { "no obvious stack markers".to_string() } else { tech.join(", ") }
                ))
                .data(json!({ "finalUrl": final_url, "title": title, "technologies": tech, "trackingIds": ids, "headers": header_map, "emails": emails }));
            for e in emails.iter().take(10) {
                web = web.discover(EntityType::Email, e.clone(), Some("on homepage"));
            }
        }
    }
    ctx.emit(web);

    let icon_url = match icon_href {
        Some(href) if href.starts_with("http") => href,
        Some(href) if href.starts_with("//") => format!("https:{href}"),
        Some(href) => format!("https://{domain}/{}", href.trim_start_matches('/')),
        None => format!("https://{domain}/favicon.ico"),
    };
    let mut fav = ctx.finding("favicon", "favicon", "Favicon hash").category("web");
    let started = Instant::now();
    match follower.get(&icon_url).send().await {
        Err(e) => {
            fav.elapsed_ms = started.elapsed().as_millis() as u64;
            fav = fav.error(crate::engine::http::describe_error(e));
        }
        Ok(resp) => {
            let status = resp.status().as_u16();
            let bytes = resp.bytes().await.map(|b| b.to_vec()).unwrap_or_default();
            fav.elapsed_ms = started.elapsed().as_millis() as u64;
            fav.http_status = Some(status);
            if status == 200 && !bytes.is_empty() {
                let hash = favicon_hash(&bytes);
                fav = fav
                    .status(FindingStatus::Info)
                    .summary(format!("mmh3 {hash} · search Shodan for hosts serving the same icon"))
                    .url(format!("https://www.shodan.io/search?query=http.favicon.hash%3A{hash}"))
                    .data(json!({ "hash": hash, "iconUrl": icon_url, "bytes": bytes.len() }));
            } else {
                fav = fav.status(FindingStatus::NotFound).summary("no favicon served");
            }
        }
    }
    ctx.emit(fav);

    // ------------------------------------------------------------------ well-known files
    for (path, kind, title) in [
        ("robots.txt", "robots", "robots.txt"),
        ("sitemap.xml", "sitemap", "sitemap.xml"),
        (".well-known/security.txt", "securitytxt", "security.txt"),
    ] {
        let url = format!("https://{domain}/{path}");
        let mut f = ctx.finding("http", kind, title).category("web").url(url.clone());
        match fetch(follower.get(&url)).await {
            Err((e, ms)) => {
                f.elapsed_ms = ms;
                f = f.error(e);
            }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let looks_html = res.body.trim_start().to_lowercase().starts_with("<!doctype html") || res.body.to_lowercase().contains("<html");
                if res.status == 200 && !(kind != "sitemap" && looks_html) {
                    let summary = match kind {
                        "robots" => {
                            let disallow = res.body.lines().filter(|l| l.to_lowercase().starts_with("disallow:")).count();
                            let sitemaps = res.body.lines().filter(|l| l.to_lowercase().starts_with("sitemap:")).count();
                            format!("{disallow} Disallow rules · {sitemaps} sitemap hints")
                        }
                        "sitemap" => format!("{} <loc> entries", res.body.matches("<loc>").count()),
                        _ => {
                            let contact = res.body.lines().find(|l| l.to_lowercase().starts_with("contact:")).unwrap_or("no contact line");
                            contact.to_string()
                        }
                    };
                    f = f.status(FindingStatus::Found).summary(summary).data(json!({ "body": res.body.chars().take(4000).collect::<String>() }));
                    if kind == "securitytxt" {
                        for cap in RE_EMAIL.find_iter(&res.body) {
                            f = f.discover(EntityType::Email, cap.as_str().to_lowercase(), Some("security.txt contact"));
                        }
                    }
                } else {
                    f = f.status(FindingStatus::NotFound).summary(format!("HTTP {}", res.status));
                }
            }
        }
        ctx.emit(f);
    }

    if ctx.cancelled() {
        return Ok(());
    }

    // ------------------------------------------------------------------ keyed services
    if let Some(key) = ctx.secret("shodan") {
        let mut f = ctx.finding("Shodan", "dns", "Shodan DNS data").category("subdomains").url(format!("https://www.shodan.io/domain/{domain}"));
        match fetch(follower.get(format!("https://api.shodan.io/dns/domain/{domain}?key={key}"))).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                if res.status == 200 {
                    let subs: Vec<String> = v["subdomains"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|s| format!("{s}.{domain}"))).collect()).unwrap_or_default();
                    for sd in &subs { subdomains.insert(sd.clone()); }
                    f = f.status(if subs.is_empty() { FindingStatus::NotFound } else { FindingStatus::Info })
                        .summary(format!("{} subdomain(s) known to Shodan · {} DNS record(s)", subs.len(), v["data"].as_array().map(|a| a.len()).unwrap_or(0)))
                        .data(json!({ "subdomains": subs, "records": v["data"], "tags": v["tags"] }));
                } else if res.status == 401 {
                    f = f.error("Shodan rejected the API key");
                } else {
                    f = f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status));
                }
            }
        }
        ctx.emit(f);
    }
    if let Some(key) = ctx.secret("hunter") {
        let mut f = ctx.finding("Hunter.io", "emails", "Hunter.io addresses").category("people").url(format!("https://hunter.io/search/{domain}"));
        match fetch(follower.get(format!("https://api.hunter.io/v2/domain-search?domain={domain}&api_key={key}&limit=50"))).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                let d = &v["data"];
                if res.status == 200 && d.is_object() {
                    let emails = d["emails"].as_array().cloned().unwrap_or_default();
                    f = f.status(if emails.is_empty() { FindingStatus::NotFound } else { FindingStatus::Found })
                        .summary(format!("{} address(es) · pattern {} · {}", emails.len(), d["pattern"].as_str().unwrap_or("?"), d["organization"].as_str().unwrap_or("")))
                        .data(json!({ "pattern": d["pattern"], "organization": d["organization"], "emails": emails }));
                    for e in emails.iter().take(50) {
                        if let Some(addr) = e["value"].as_str() {
                            f = f.discover(EntityType::Email, addr.to_lowercase(), e["position"].as_str());
                            let name = format!("{} {}", e["first_name"].as_str().unwrap_or(""), e["last_name"].as_str().unwrap_or("")).trim().to_string();
                            if !name.is_empty() {
                                f = f.discover(EntityType::Person, name, Some(addr));
                            }
                        }
                    }
                } else {
                    f = f.error(v["errors"][0]["details"].as_str().unwrap_or("Hunter request failed").to_string());
                }
            }
        }
        ctx.emit(f);
    }
    if let Some(key) = ctx.secret("virustotal") {
        let mut f = ctx.finding("VirusTotal", "reputation", "VirusTotal verdicts").category("web").url(format!("https://www.virustotal.com/gui/domain/{domain}"));
        match fetch(follower.get(format!("https://www.virustotal.com/api/v3/domains/{domain}")).header("x-apikey", key)).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                let a = &v["data"]["attributes"];
                if res.status == 200 && a.is_object() {
                    let stats = &a["last_analysis_stats"];
                    let malicious = stats["malicious"].as_u64().unwrap_or(0);
                    let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
                    let cats: Vec<String> = a["categories"].as_object().map(|o| o.values().filter_map(|c| c.as_str().map(str::to_string)).collect()).unwrap_or_default();
                    f = f.status(if malicious + suspicious > 0 { FindingStatus::Found } else { FindingStatus::NotFound })
                        .summary(format!("{malicious} malicious · {suspicious} suspicious · {} harmless{}", stats["harmless"].as_u64().unwrap_or(0), if cats.is_empty() { String::new() } else { format!(" · {}", cats.join(", ")) }))
                        .data(json!({ "stats": stats, "categories": a["categories"], "reputation": a["reputation"], "registrar": a["registrar"], "creationDate": a["creation_date"], "popularityRanks": a["popularity_ranks"] }));
                } else {
                    f = f.error(v["error"]["message"].as_str().unwrap_or("VirusTotal request failed").to_string());
                }
            }
        }
        ctx.emit(f);
    }

    // ------------------------------------------------------------------ launchers
    let launchers: &[(&str, &str, String, &str)] = &[
        ("dorks", "Search engine dorks", format!("https://www.google.com/search?q={}", urlencode(&format!("site:{domain}"))), "site: dork on Google; filetype and mention dorks in raw data"),
        ("Shodan", "Shodan hostname search", format!("https://www.shodan.io/search?query=hostname%3A{domain}"), "Hosts Shodan associates with this domain"),
        ("Hunter.io", "Email pattern lookup", format!("https://hunter.io/search/{domain}"), "Email address format and known addresses (API key support later)"),
        ("VirusTotal", "VirusTotal domain report", format!("https://www.virustotal.com/gui/domain/{domain}"), "Reputation, passive DNS, related files"),
        ("urlscan.io", "urlscan.io history", format!("https://urlscan.io/search/#{domain}"), "Past scans, screenshots, redirects"),
    ];
    for (source, title, url, summary) in launchers {
        let mut f = ctx.finding(source, "launcher", title).category("launchers").status(FindingStatus::Info).url(url.clone()).summary(*summary);
        if *source == "dorks" {
            f.data = json!({
                "site": url,
                "filetypes": format!("https://www.google.com/search?q={}", urlencode(&format!("site:{domain} filetype:pdf OR filetype:xlsx OR filetype:docx"))),
                "mentions": format!("https://www.google.com/search?q={}", urlencode(&format!("\"{domain}\" -site:{domain}"))),
                "loginPages": format!("https://www.google.com/search?q={}", urlencode(&format!("site:{domain} inurl:login OR inurl:admin"))),
            });
        }
        ctx.emit(f);
    }

    // ------------------------------------------------------------------ DNS brute force
    let sem = Arc::new(Semaphore::new(20));
    let mut tasks = tokio::task::JoinSet::new();
    for prefix in BRUTE_PREFIXES {
        let host = format!("{prefix}.{domain}");
        let resolver = resolver.clone();
        let sem = sem.clone();
        let cancel = ctx.cancel.clone();
        tasks.spawn(async move {
            let _p = sem.acquire_owned().await.ok()?;
            if cancel.is_cancelled() {
                return None;
            }
            match dns::records(&resolver, &host, RecordType::A).await {
                Ok(v) if !v.is_empty() => Some((host, v)),
                _ => None,
            }
        });
    }
    let mut brute_hits = Vec::new();
    while let Some(r) = tasks.join_next().await {
        if let Ok(Some((host, ips))) = r {
            subdomains.insert(host.clone());
            brute_hits.push(json!({ "host": host, "a": ips }));
        }
    }
    ctx.emit(
        ctx.finding("dns-brute", "brute", "DNS brute force")
            .category("subdomains")
            .status(if brute_hits.is_empty() { FindingStatus::NotFound } else { FindingStatus::Info })
            .summary(format!("{} of {} common prefixes resolve", brute_hits.len(), BRUTE_PREFIXES.len()))
            .data(json!({ "hits": brute_hits })),
    );

    // One finding per subdomain (capped), each a pivot.
    subdomains.remove(&domain);
    let cap = 80;
    for (i, host) in subdomains.iter().enumerate() {
        if i >= cap || ctx.cancelled() {
            break;
        }
        ctx.emit(
            ctx.finding("subdomains", "subdomain", host)
                .category("subdomains")
                .status(FindingStatus::Found)
                .url(format!("https://{host}/"))
                .discover(EntityType::Domain, host.clone(), Some("subdomain")),
        );
    }
    if subdomains.len() > cap {
        ctx.emit(
            ctx.finding("subdomains", "note", "More subdomains")
                .category("subdomains")
                .status(FindingStatus::Info)
                .summary(format!("{} more host names not listed individually; see the certificate transparency finding", subdomains.len() - cap)),
        );
    }

    Ok(())
}
