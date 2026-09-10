//! Network intelligence helpers for the domain, IP, email and file probes:
//! HackerTarget, Cert Spotter, MDN HTTP Observatory, ipwho.is, Kickbox, and the abuse.ch
//! family (URLhaus, ThreatFox, MalwareBazaar) plus FullHunt with keys.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::ip::registrable;
use super::{EntityType, Finding, FindingStatus, ScanContext};
use crate::engine::http::fetch;

const UA: &str = "nazgul-osint/0.2 (https://github.com/wyattrossell/Nazgul)";

fn json_of(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or(Value::Null)
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn hackertarget_error(body: &str) -> Option<String> {
    let t = body.trim();
    if t.starts_with("error") || t.contains("API count exceeded") || t.contains("Invalid") {
        Some(t.chars().take(120).collect())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

/// HackerTarget host search: subdomains with their IPs. Returns the hostnames found.
pub async fn hackertarget_hosts(ctx: &ScanContext, domain: &str) -> (Finding, BTreeSet<String>) {
    let mut f = ctx.finding("HackerTarget", "subdomains", "HackerTarget host search").category("subdomains")
        .url(format!("https://hackertarget.com/find-dns-host-records/?q={domain}"));
    let mut hosts = BTreeSet::new();
    match fetch(ctx.client.get(format!("https://api.hackertarget.com/hostsearch/?q={domain}")).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            if let Some(err) = hackertarget_error(&res.body) {
                f = f.status(FindingStatus::Info).summary(err);
            } else {
                let mut rows = Vec::new();
                for line in res.body.lines() {
                    let mut parts = line.trim().splitn(2, ',');
                    if let (Some(h), Some(ip)) = (parts.next(), parts.next()) {
                        let h = h.to_lowercase();
                        if h.ends_with(domain) {
                            hosts.insert(h.clone());
                            rows.push(json!({ "host": h, "ip": ip }));
                        }
                    }
                }
                f = f.status(if rows.is_empty() { FindingStatus::NotFound } else { FindingStatus::Info })
                    .summary(format!("{} host record(s) (free tier: 50 queries/day)", rows.len()))
                    .data(json!({ "records": rows }));
            }
        }
    }
    (f, hosts)
}

/// Cert Spotter certificate transparency issuances.
pub async fn certspotter(ctx: &ScanContext, domain: &str) -> (Finding, BTreeSet<String>) {
    let mut f = ctx.finding("Cert Spotter", "certificates", "Cert Spotter issuances").category("subdomains")
        .url(format!("https://sslmate.com/ct/search?q={domain}"));
    let mut hosts = BTreeSet::new();
    let url = format!("https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer");
    match fetch(ctx.client.get(&url).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            match res.status {
                200 => {
                    let issuances = v.as_array().cloned().unwrap_or_default();
                    let mut latest: Option<String> = None;
                    for i in &issuances {
                        for n in i["dns_names"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                            let n = n.trim_start_matches("*.").to_lowercase();
                            if n == domain || n.ends_with(&format!(".{domain}")) {
                                hosts.insert(n);
                            }
                        }
                        if let Some(nb) = i["not_before"].as_str() {
                            if latest.as_deref().map(|l| nb > l).unwrap_or(true) {
                                latest = Some(nb.to_string());
                            }
                        }
                    }
                    f = f.status(if hosts.is_empty() { FindingStatus::NotFound } else { FindingStatus::Info })
                        .summary(format!("{} certificate(s) · {} host name(s){}", issuances.len(), hosts.len(), latest.map(|l| format!(" · latest issued {}", l.chars().take(10).collect::<String>())).unwrap_or_default()))
                        .data(json!({ "hostnames": hosts, "issuances": issuances.iter().take(50).map(|i| json!({ "notBefore": i["not_before"], "notAfter": i["not_after"], "issuer": i["issuer"]["friendly_name"], "dnsNames": i["dns_names"] })).collect::<Vec<_>>() }));
                }
                429 => f = f.status(FindingStatus::Info).summary("Cert Spotter anonymous rate limit reached; try again in an hour"),
                other => f = f.status(FindingStatus::Ambiguous).detail(format!("HTTP {other}")),
            }
        }
    }
    (f, hosts)
}

/// MDN HTTP Observatory: security-header grade.
pub async fn observatory(ctx: &ScanContext, domain: &str) -> Finding {
    let mut f = ctx.finding("MDN HTTP Observatory", "headers", "HTTP security headers grade").category("web")
        .url(format!("https://developer.mozilla.org/en-US/observatory/analyze?host={domain}"));
    match fetch(ctx.client.post(format!("https://observatory-api.mdn.mozilla.net/api/v2/scan?host={domain}")).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            match v["grade"].as_str() {
                Some(grade) => f.status(FindingStatus::Info)
                    .summary(format!("grade {grade} · score {} · {} of {} tests passed", v["score"], v["tests_passed"], v["tests_quantity"]))
                    .data(json!({ "grade": grade, "score": v["score"], "testsPassed": v["tests_passed"], "testsFailed": v["tests_failed"], "scannedAt": v["scanned_at"], "detailsUrl": v["details_url"] })),
                None => f.status(FindingStatus::Ambiguous).detail(s(&v["error"]).chars().take(120).collect::<String>()),
            }
        }
    }
}

/// FullHunt subdomain inventory (keyed).
pub async fn fullhunt(ctx: &ScanContext, domain: &str, key: &str) -> (Finding, BTreeSet<String>) {
    let mut f = ctx.finding("FullHunt", "subdomains", "FullHunt subdomains").category("subdomains")
        .url(format!("https://fullhunt.io/search?domain={domain}"));
    let mut hosts = BTreeSet::new();
    match fetch(ctx.client.get(format!("https://fullhunt.io/api/v1/domain/{domain}/subdomains")).header("X-API-KEY", key).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            if res.status == 200 {
                for h in v["hosts"].as_array().into_iter().flatten().filter_map(Value::as_str) {
                    hosts.insert(h.to_lowercase());
                }
                f = f.status(if hosts.is_empty() { FindingStatus::NotFound } else { FindingStatus::Info })
                    .summary(format!("{} host name(s) in the FullHunt index", hosts.len()))
                    .data(json!({ "hostnames": hosts }));
            } else if res.status == 401 || res.status == 403 {
                f = f.error("FullHunt rejected the API key");
            } else {
                f = f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}: {}", res.status, s(&v["message"])));
            }
        }
    }
    (f, hosts)
}

// ---------------------------------------------------------------------------
// abuse.ch (keyed)
// ---------------------------------------------------------------------------

pub async fn urlhaus_host(ctx: &ScanContext, host: &str, key: &str) -> Finding {
    let mut f = ctx.finding("URLhaus", "malware_urls", "URLhaus malware URLs").category("exposure")
        .url(format!("https://urlhaus.abuse.ch/host/{host}/"));
    match fetch(ctx.client.post("https://urlhaus-api.abuse.ch/v1/host/").header("Auth-Key", key).header("User-Agent", UA).form(&[("host", host)])).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            match s(&v["query_status"]).as_str() {
                "ok" => {
                    let urls = v["urls"].as_array().cloned().unwrap_or_default();
                    let online = urls.iter().filter(|u| s(&u["url_status"]) == "online").count();
                    f.status(FindingStatus::Found)
                        .summary(format!("{} malware URL(s) seen on this host, {online} online · first seen {} · blacklists: {}", urls.len(), s(&v["firstseen"]), v["blacklists"].as_object().map(|b| b.iter().filter(|(_, val)| val.as_str().map(|x| x != "not listed").unwrap_or(false)).map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default()))
                        .data(json!({ "firstSeen": v["firstseen"], "urlCount": v["url_count"], "blacklists": v["blacklists"], "urls": urls.iter().take(20).map(|u| json!({ "url": u["url"], "status": u["url_status"], "added": u["date_added"], "threat": u["threat"], "tags": u["tags"] })).collect::<Vec<_>>() }))
                }
                "no_results" => f.status(FindingStatus::NotFound).summary("no malware URLs recorded for this host"),
                other => {
                    if res.status == 401 { f.error("abuse.ch rejected the auth key") } else { f.status(FindingStatus::Ambiguous).detail(format!("query_status {other}")) }
                }
            }
        }
    }
}

pub async fn threatfox(ctx: &ScanContext, ioc: &str, key: &str) -> Finding {
    let mut f = ctx.finding("ThreatFox", "ioc", "ThreatFox indicators").category("exposure")
        .url(format!("https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}"));
    match fetch(ctx.client.post("https://threatfox-api.abuse.ch/api/v1/").header("Auth-Key", key).header("User-Agent", UA).json(&json!({ "query": "search_ioc", "search_term": ioc }))).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            match s(&v["query_status"]).as_str() {
                "ok" => {
                    let data = v["data"].as_array().cloned().unwrap_or_default();
                    let sample: Vec<String> = data.iter().take(4).map(|d| format!("{} / {} ({}% confidence, {})", s(&d["threat_type"]), s(&d["malware_printable"]), d["confidence_level"], s(&d["first_seen"]).chars().take(10).collect::<String>())).collect();
                    f.status(FindingStatus::Found).summary(format!("{} indicator(s): {}", data.len(), sample.join(" · "))).data(json!({ "indicators": data.iter().take(20).cloned().collect::<Vec<_>>() }))
                }
                "no_result" | "no_results" => f.status(FindingStatus::NotFound).summary("not a known ThreatFox indicator"),
                other => if res.status == 401 { f.error("abuse.ch rejected the auth key") } else { f.status(FindingStatus::Ambiguous).detail(format!("query_status {other}")) },
            }
        }
    }
}

pub async fn malwarebazaar(ctx: &ScanContext, sha256: &str, key: &str) -> Finding {
    let mut f = ctx.finding("MalwareBazaar", "malware", "MalwareBazaar sample lookup").category("file")
        .url(format!("https://bazaar.abuse.ch/sample/{sha256}/"));
    match fetch(ctx.client.post("https://mb-api.abuse.ch/api/v1/").header("Auth-Key", key).header("User-Agent", UA).form(&[("query", "get_info"), ("hash", sha256)])).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            match s(&v["query_status"]).as_str() {
                "ok" => {
                    let d = v["data"].as_array().and_then(|a| a.first()).cloned().unwrap_or(Value::Null);
                    f.status(FindingStatus::Found)
                        .summary(format!("known malware sample: {} · {} · first seen {} · tags {}", s(&d["signature"]), s(&d["file_type"]), s(&d["first_seen"]), d["tags"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default()))
                        .data(d)
                }
                "hash_not_found" => f.status(FindingStatus::NotFound).summary("hash not in MalwareBazaar"),
                other => if res.status == 401 { f.error("abuse.ch rejected the auth key") } else { f.status(FindingStatus::Ambiguous).detail(format!("query_status {other}")) },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IP
// ---------------------------------------------------------------------------

pub async fn ipwho(ctx: &ScanContext, ip: &str) -> Finding {
    let mut f = ctx.finding("ipwho.is", "geo", "ipwho.is geolocation").category("geo").url(format!("https://ipwho.is/{ip}"));
    match fetch(ctx.client.get(format!("https://ipwho.is/{ip}")).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            if v["success"].as_bool().unwrap_or(false) {
                let c = &v["connection"];
                let mut card = f.status(FindingStatus::Info)
                    .summary(format!("{}, {}, {} · AS{} {} · {}", s(&v["city"]), s(&v["region"]), s(&v["country"]), c["asn"], s(&c["org"]), s(&c["isp"])))
                    .url(format!("https://www.openstreetmap.org/?mlat={}&mlon={}#map=10/{}/{}", v["latitude"], v["longitude"], v["latitude"], v["longitude"]))
                    .data(v.clone());
                if let Some(d) = c["domain"].as_str().filter(|d| !d.is_empty()) {
                    card = card.discover(EntityType::Domain, registrable(d), Some("ipwho.is network domain"));
                }
                card
            } else {
                f.status(FindingStatus::Ambiguous).detail(s(&v["message"]))
            }
        }
    }
}

/// HackerTarget reverse IP: other host names served from the same address.
pub async fn hackertarget_reverse_ip(ctx: &ScanContext, ip: &str) -> Finding {
    let mut f = ctx.finding("HackerTarget", "reverse_ip", "Reverse IP lookup").category("dns")
        .url(format!("https://hackertarget.com/reverse-ip-lookup/?q={ip}"));
    match fetch(ctx.client.get(format!("https://api.hackertarget.com/reverseiplookup/?q={ip}")).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            if let Some(err) = hackertarget_error(&res.body) {
                return f.status(FindingStatus::Info).summary(err);
            }
            let hosts: Vec<String> = res.body.lines().map(|l| l.trim().to_lowercase()).filter(|l| !l.is_empty() && l.contains('.')).collect();
            if hosts.is_empty() || hosts.iter().any(|h| h.contains("no records")) {
                return f.status(FindingStatus::NotFound).summary("no other host names on this address");
            }
            let mut apexes: Vec<String> = hosts.iter().map(|h| registrable(h)).collect();
            apexes.sort();
            apexes.dedup();
            let mut card = f.status(FindingStatus::Found)
                .summary(format!("{} host name(s) share this IP across {} registrable domain(s): {}", hosts.len(), apexes.len(), apexes.iter().take(8).cloned().collect::<Vec<_>>().join(", ")))
                .data(json!({ "hosts": hosts.iter().take(500).collect::<Vec<_>>(), "domains": apexes }));
            if apexes.len() <= 25 {
                for d in &apexes {
                    card = card.discover(EntityType::Domain, d.clone(), Some("shares this IP"));
                }
            }
            card
        }
    }
}

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------

pub async fn kickbox_disposable(ctx: &ScanContext, email: &str) -> Finding {
    let mut f = ctx.finding("Kickbox", "disposable", "Kickbox disposable check").category("posture");
    match fetch(ctx.client.get(format!("https://open.kickbox.com/v1/disposable/{}", email.replace('@', "%40"))).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            match v["disposable"].as_bool() {
                Some(true) => f.status(FindingStatus::Found).summary("Kickbox classifies this domain as disposable"),
                Some(false) => f.status(FindingStatus::NotFound).summary("not disposable per Kickbox"),
                None => f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status)),
            }
        }
    }
}
