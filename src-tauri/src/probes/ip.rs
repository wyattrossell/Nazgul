//! IP probe: classification, reverse DNS, geolocation and ASN, Shodan InternetDB
//! (ports, CVEs, hostnames), Tor exit check, RDAP allocation, and launchers.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use serde_json::{json, Value};

use super::launchers;
use super::{EntityType, FindingStatus, ScanContext};
use crate::engine::dns;
use crate::engine::http::{build_following_client, fetch};

fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 100 && (64..=127).contains(&v4.octets()[1]))
        }
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80),
    }
}

/// `mail.corp.example.co.uk` -> `example.co.uk` (good enough without a public-suffix list).
pub fn registrable(host: &str) -> String {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    if labels.len() <= 2 {
        return host.to_string();
    }
    let second_level = ["co", "com", "org", "net", "gov", "ac", "edu", "or", "ne", "go"];
    let tld = labels[labels.len() - 1];
    let sld = labels[labels.len() - 2];
    if tld.len() == 2 && second_level.contains(&sld) && labels.len() >= 3 {
        labels[labels.len() - 3..].join(".")
    } else {
        labels[labels.len() - 2..].join(".")
    }
}

pub async fn run(ctx: Arc<ScanContext>) -> Result<(), String> {
    let ip: IpAddr = ctx
        .input
        .trim()
        .parse()
        .map_err(|_| format!("\"{}\" is not an IPv4 or IPv6 address.", ctx.input.trim()))?;
    let follower = build_following_client(&ctx.options.http_options()).map_err(|e| e.to_string())?;
    let resolver = dns::resolver();
    let public = is_public(&ip);

    // classification, ptr, geo, internetdb, tor, rdap, 6 launchers, + one per keyed service
    let keyed = ["shodan", "ipinfo", "abuseipdb", "virustotal", "greynoise", "pulsedive", "ipqs"].iter().filter(|k| ctx.secret(k).is_some()).count()
        + usize::from(ctx.secret("censys_id").is_some() && ctx.secret("censys_secret").is_some())
        + 1; // OTX passive DNS runs with or without a key
    let catalog = launchers::plan(EntityType::Ip, &launchers::vars_ip(&ip.to_string()));
    ctx.start(if public { 12 + keyed + catalog.len() } else { 2 });

    ctx.emit(
        ctx.finding("parser", "classification", "Address class")
            .category("address")
            .status(FindingStatus::Info)
            .summary(if public {
                format!("{} public {}", ip, if ip.is_ipv4() { "IPv4" } else { "IPv6" })
            } else {
                format!("{ip} is private, loopback or reserved: network lookups skipped")
            })
            .data(json!({ "ip": ip.to_string(), "public": public, "version": if ip.is_ipv4() { 4 } else { 6 } })),
    );

    // Reverse DNS.
    let started = Instant::now();
    let mut ptr = ctx.finding("dns", "ptr", "Reverse DNS").category("dns");
    match dns::reverse(&resolver, ip).await {
        Ok(names) => {
            ptr.elapsed_ms = started.elapsed().as_millis() as u64;
            ptr.status = if names.is_empty() { FindingStatus::NotFound } else { FindingStatus::Info };
            ptr.summary = Some(if names.is_empty() { "no PTR record".to_string() } else { names.join(", ") });
            for n in &names {
                ptr = ptr.discover(EntityType::Domain, registrable(n), Some("PTR record"));
            }
            ptr.data = json!({ "names": names });
        }
        Err(e) => ptr = ptr.error(e),
    }
    ctx.emit(ptr);

    if !public || ctx.cancelled() {
        return Ok(());
    }

    // Geolocation + ASN (ip-api.com, free tier is HTTP only).
    let mut geo = ctx.finding("ip-api.com", "geo", "Geolocation and network").category("geo");
    let fields = "status,message,continent,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting";
    match fetch(follower.get(format!("http://ip-api.com/json/{ip}?fields={fields}"))).await {
        Err((e, ms)) => {
            geo.elapsed_ms = ms;
            geo = geo.error(e);
        }
        Ok(res) => {
            geo.elapsed_ms = res.elapsed_ms;
            geo.http_status = Some(res.status);
            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
            if v["status"] == "success" {
                let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
                let place = [s("city"), s("regionName"), s("country")].into_iter().filter(|p| !p.is_empty()).collect::<Vec<_>>().join(", ");
                let flags: Vec<&str> = [("proxy", "proxy/VPN"), ("hosting", "datacenter"), ("mobile", "mobile")]
                    .iter()
                    .filter(|(k, _)| v[*k].as_bool().unwrap_or(false))
                    .map(|(_, label)| *label)
                    .collect();
                geo = geo
                    .status(FindingStatus::Info)
                    .summary(format!(
                        "{place} · {} · {}{}",
                        s("isp"),
                        s("as"),
                        if flags.is_empty() { String::new() } else { format!(" · {}", flags.join(", ")) }
                    ))
                    .url(format!("https://www.openstreetmap.org/?mlat={}&mlon={}#map=10/{}/{}", v["lat"], v["lon"], v["lat"], v["lon"]))
                    .data(v.clone());
                if let Some(r) = v["reverse"].as_str().filter(|r| !r.is_empty()) {
                    geo = geo.discover(EntityType::Domain, registrable(r), Some("reverse name"));
                }
            } else {
                geo = geo.status(FindingStatus::Ambiguous).detail(v["message"].as_str().unwrap_or("lookup failed").to_string());
            }
        }
    }
    ctx.emit(geo);

    // Shodan InternetDB (free, no key).
    let mut idb = ctx.finding("Shodan InternetDB", "ports", "Open ports and CVEs").category("exposure")
        .url(format!("https://internetdb.shodan.io/{ip}"));
    match fetch(follower.get(format!("https://internetdb.shodan.io/{ip}"))).await {
        Err((e, ms)) => {
            idb.elapsed_ms = ms;
            idb = idb.error(e);
        }
        Ok(res) => {
            idb.elapsed_ms = res.elapsed_ms;
            idb.http_status = Some(res.status);
            if res.status == 200 {
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                let ports: Vec<u64> = v["ports"].as_array().map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
                let vulns: Vec<String> = v["vulns"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
                let hostnames: Vec<String> = v["hostnames"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
                let tags: Vec<String> = v["tags"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
                idb = idb
                    .status(if ports.is_empty() { FindingStatus::NotFound } else { FindingStatus::Found })
                    .summary(format!(
                        "{} open port(s){} · {} CVE(s){}",
                        ports.len(),
                        if ports.is_empty() { String::new() } else { format!(": {}", ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")) },
                        vulns.len(),
                        if tags.is_empty() { String::new() } else { format!(" · tags: {}", tags.join(", ")) }
                    ))
                    .data(v.clone());
                for h in hostnames.iter().take(10) {
                    idb = idb.discover(EntityType::Domain, h.clone(), Some("Shodan hostname"));
                }
            } else if res.status == 404 {
                idb = idb.status(FindingStatus::NotFound).summary("Shodan has no data for this address");
            } else {
                idb = idb.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status));
            }
        }
    }
    ctx.emit(idb);

    if ctx.cancelled() {
        return Ok(());
    }

    // Tor exit list.
    let mut tor = ctx.finding("Tor Project", "tor", "Tor exit node").category("exposure")
        .url("https://metrics.torproject.org/exonerator.html".to_string());
    match fetch(follower.get("https://check.torproject.org/torbulkexitlist")).await {
        Err((e, ms)) => {
            tor.elapsed_ms = ms;
            tor = tor.error(e);
        }
        Ok(res) => {
            tor.elapsed_ms = res.elapsed_ms;
            tor.http_status = Some(res.status);
            let ip_text = ip.to_string();
            let is_exit = res.status == 200 && res.body.lines().any(|l| l.trim() == ip_text);
            tor = tor
                .status(if is_exit { FindingStatus::Found } else { FindingStatus::NotFound })
                .summary(if is_exit { "listed as a current Tor exit" } else { "not in the current Tor exit list" });
        }
    }
    ctx.emit(tor);

    // RDAP allocation.
    let mut rdap = ctx.finding("rdap", "allocation", "Network allocation").category("whois")
        .url(format!("https://rdap.org/ip/{ip}"));
    match fetch(follower.get(format!("https://rdap.org/ip/{ip}")).header("Accept", "application/rdap+json")).await {
        Err((e, ms)) => {
            rdap.elapsed_ms = ms;
            rdap = rdap.error(e);
        }
        Ok(res) => {
            rdap.elapsed_ms = res.elapsed_ms;
            rdap.http_status = Some(res.status);
            if res.status == 200 {
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                let name = v["name"].as_str().unwrap_or("").to_string();
                let range = format!("{} - {}", v["startAddress"].as_str().unwrap_or("?"), v["endAddress"].as_str().unwrap_or("?"));
                let country = v["country"].as_str().unwrap_or("").to_string();
                let abuse = v["entities"].as_array().and_then(|ents| {
                    ents.iter().flat_map(|e| {
                        let mut list = vec![e.clone()];
                        if let Some(sub) = e["entities"].as_array() { list.extend(sub.iter().cloned()); }
                        list
                    }).find(|e| e["roles"].as_array().map(|r| r.iter().any(|x| x == "abuse")).unwrap_or(false))
                    .and_then(|e| {
                        e["vcardArray"].get(1)?.as_array()?.iter()
                            .find(|row| row.get(0).and_then(Value::as_str) == Some("email"))
                            .and_then(|row| row.get(3)).and_then(|x| x.as_str().map(str::to_string))
                    })
                });
                rdap = rdap
                    .status(FindingStatus::Info)
                    .summary(format!("{name} · {range}{}{}", if country.is_empty() { String::new() } else { format!(" · {country}") }, abuse.as_ref().map(|a| format!(" · abuse: {a}")).unwrap_or_default()))
                    .data(json!({ "name": name, "range": range, "country": country, "abuseContact": abuse, "handle": v["handle"], "type": v["type"] }));
            } else {
                rdap = rdap.status(FindingStatus::Ambiguous).detail(format!("RDAP answered HTTP {}", res.status));
            }
        }
    }
    ctx.emit(rdap);

    // Keyed services.
    if let Some(key) = ctx.secret("shodan") {
        let mut f = ctx.finding("Shodan", "host", "Shodan host").category("exposure").url(format!("https://www.shodan.io/host/{ip}"));
        match fetch(follower.get(format!("https://api.shodan.io/shodan/host/{ip}?key={key}"))).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                if res.status == 200 {
                    let ports: Vec<String> = v["ports"].as_array().map(|a| a.iter().filter_map(Value::as_u64).map(|p| p.to_string()).collect()).unwrap_or_default();
                    let products: Vec<String> = v["data"].as_array().map(|a| a.iter().filter_map(|d| d["product"].as_str().map(str::to_string)).collect()).unwrap_or_default();
                    let vulns = v["vulns"].as_array().map(|a| a.len()).unwrap_or(0);
                    f = f.status(if ports.is_empty() { FindingStatus::NotFound } else { FindingStatus::Found })
                        .summary(format!("{} · {} · ports {} · {} CVE(s){}", v["org"].as_str().unwrap_or("?"), v["os"].as_str().unwrap_or("os unknown"), ports.join(","), vulns, if products.is_empty() { String::new() } else { format!(" · {}", products.join(", ")) }))
                        .data(json!({ "org": v["org"], "isp": v["isp"], "os": v["os"], "ports": v["ports"], "hostnames": v["hostnames"], "domains": v["domains"], "vulns": v["vulns"], "tags": v["tags"], "lastUpdate": v["last_update"], "services": v["data"].as_array().map(|a| a.iter().map(|d| json!({"port": d["port"], "transport": d["transport"], "product": d["product"], "version": d["version"]})).collect::<Vec<_>>()) }));
                    for h in v["hostnames"].as_array().into_iter().flatten().filter_map(Value::as_str).take(10) {
                        f = f.discover(EntityType::Domain, h, Some("Shodan hostname"));
                    }
                } else if res.status == 404 {
                    f = f.status(FindingStatus::NotFound).summary("no Shodan record");
                } else if res.status == 401 {
                    f = f.error("Shodan rejected the API key");
                } else {
                    f = f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status));
                }
            }
        }
        ctx.emit(f);
    }
    if let Some(token) = ctx.secret("ipinfo") {
        let mut f = ctx.finding("ipinfo.io", "geo", "ipinfo.io").category("geo").url(format!("https://ipinfo.io/{ip}"));
        match fetch(follower.get(format!("https://ipinfo.io/{ip}?token={token}"))).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                if res.status == 200 {
                    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
                    f = f.status(FindingStatus::Info)
                        .summary([s("city"), s("region"), s("country"), s("org")].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" · "))
                        .data(v.clone());
                    if let Some(h) = v["hostname"].as_str() {
                        f = f.discover(EntityType::Domain, registrable(h), Some("ipinfo hostname"));
                    }
                } else {
                    f = f.error(v["error"]["message"].as_str().unwrap_or("ipinfo request failed").to_string());
                }
            }
        }
        ctx.emit(f);
    }
    if let Some(key) = ctx.secret("abuseipdb") {
        let mut f = ctx.finding("AbuseIPDB", "abuse", "Abuse reports").category("exposure").url(format!("https://www.abuseipdb.com/check/{ip}"));
        match fetch(follower.get(format!("https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90")).header("Key", key).header("Accept", "application/json")).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                let d = &v["data"];
                if res.status == 200 && d.is_object() {
                    let score = d["abuseConfidenceScore"].as_u64().unwrap_or(0);
                    let reports = d["totalReports"].as_u64().unwrap_or(0);
                    f = f.status(if score > 0 { FindingStatus::Found } else { FindingStatus::NotFound })
                        .summary(format!("confidence {score}% · {reports} report(s) in 90 days · {} · {}{}", d["usageType"].as_str().unwrap_or("?"), d["isp"].as_str().unwrap_or("?"), if d["isTor"].as_bool().unwrap_or(false) { " · Tor" } else { "" }))
                        .data(d.clone());
                } else {
                    f = f.error(v["errors"][0]["detail"].as_str().unwrap_or("AbuseIPDB request failed").to_string());
                }
            }
        }
        ctx.emit(f);
    }
    if let (Some(id), Some(secret)) = (ctx.secret("censys_id"), ctx.secret("censys_secret")) {
        let mut f = ctx.finding("Censys", "host", "Censys host").category("exposure").url(format!("https://search.censys.io/hosts/{ip}"));
        match fetch(follower.get(format!("https://search.censys.io/api/v2/hosts/{ip}")).basic_auth(id, Some(secret))).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                let r = &v["result"];
                if res.status == 200 && r.is_object() {
                    let services: Vec<String> = r["services"].as_array().map(|a| a.iter().map(|s| format!("{}/{}", s["port"], s["service_name"].as_str().unwrap_or("?"))).collect()).unwrap_or_default();
                    f = f.status(if services.is_empty() { FindingStatus::NotFound } else { FindingStatus::Found })
                        .summary(format!("{} service(s): {} · AS{} {}", services.len(), services.join(", "), r["autonomous_system"]["asn"], r["autonomous_system"]["name"].as_str().unwrap_or("")))
                        .data(json!({ "services": r["services"], "location": r["location"], "autonomousSystem": r["autonomous_system"], "os": r["operating_system"], "lastUpdated": r["last_updated_at"] }));
                } else {
                    f = f.error(v["error"].as_str().unwrap_or("Censys request failed").to_string());
                }
            }
        }
        ctx.emit(f);
    }
    if let Some(key) = ctx.secret("virustotal") {
        let mut f = ctx.finding("VirusTotal", "reputation", "VirusTotal verdicts").category("exposure").url(format!("https://www.virustotal.com/gui/ip-address/{ip}"));
        match fetch(follower.get(format!("https://www.virustotal.com/api/v3/ip_addresses/{ip}")).header("x-apikey", key)).await {
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
                    f = f.status(if malicious + suspicious > 0 { FindingStatus::Found } else { FindingStatus::NotFound })
                        .summary(format!("{malicious} malicious · {suspicious} suspicious · {} harmless · {}", stats["harmless"].as_u64().unwrap_or(0), a["as_owner"].as_str().unwrap_or("")))
                        .data(json!({ "stats": stats, "asOwner": a["as_owner"], "country": a["country"], "reputation": a["reputation"], "tags": a["tags"] }));
                } else {
                    f = f.error(v["error"]["message"].as_str().unwrap_or("VirusTotal request failed").to_string());
                }
            }
        }
        ctx.emit(f);
    }

    if let Some(key) = ctx.secret("greynoise") {
        let mut f = ctx.finding("GreyNoise", "scanner", "GreyNoise classification").category("exposure").url(format!("https://viz.greynoise.io/ip/{ip}"));
        match fetch(follower.get(format!("https://api.greynoise.io/v3/community/{ip}")).header("key", key).header("Accept", "application/json")).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                match res.status {
                    200 => {
                        let noise = v["noise"].as_bool().unwrap_or(false);
                        let riot = v["riot"].as_bool().unwrap_or(false);
                        f = f.status(if noise || riot { FindingStatus::Found } else { FindingStatus::NotFound })
                            .summary(format!("{}{}{} · {}", if noise { "internet scanner (noise)" } else { "not a known scanner" }, if riot { " · common business service (RIOT)" } else { "" }, v["classification"].as_str().map(|c| format!(" · {c}")).unwrap_or_default(), v["name"].as_str().unwrap_or("unnamed")))
                            .data(v.clone());
                    }
                    404 => f = f.status(FindingStatus::NotFound).summary("GreyNoise has not observed this IP"),
                    401 => f = f.error("GreyNoise rejected the API key"),
                    429 => f = f.error("GreyNoise community quota reached"),
                    other => f = f.status(FindingStatus::Ambiguous).detail(format!("HTTP {other}")),
                }
            }
        }
        ctx.emit(f);
    }
    if let Some(key) = ctx.secret("ipqs") {
        let mut f = ctx.finding("IPQualityScore", "fraud", "IPQS fraud score").category("exposure");
        match fetch(follower.get(format!("https://ipqualityscore.com/api/json/ip/{key}/{ip}?strictness=1&allow_public_access_points=true"))).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                if v["success"].as_bool().unwrap_or(false) {
                    let score = v["fraud_score"].as_u64().unwrap_or(0);
                    let flags: Vec<&str> = [("proxy", "proxy"), ("vpn", "VPN"), ("tor", "Tor"), ("bot_status", "bot"), ("recent_abuse", "recent abuse"), ("is_crawler", "crawler")].iter().filter(|(k, _)| v[*k].as_bool().unwrap_or(false)).map(|(_, l)| *l).collect();
                    f = f.status(if score >= 75 || !flags.is_empty() { FindingStatus::Found } else { FindingStatus::NotFound })
                        .summary(format!("fraud score {score}/100 · {} · {}{}", v["ISP"].as_str().unwrap_or("?"), v["connection_type"].as_str().unwrap_or("?"), if flags.is_empty() { String::new() } else { format!(" · {}", flags.join(", ")) }))
                        .data(v.clone());
                } else {
                    f = f.error(v["message"].as_str().unwrap_or("IPQS request failed").to_string());
                }
            }
        }
        ctx.emit(f);
    }
    if let Some(key) = ctx.secret("pulsedive") {
        let mut f = ctx.finding("Pulsedive", "threat", "Pulsedive risk").category("exposure").url(format!("https://pulsedive.com/indicator/?ioc={ip}"));
        match fetch(follower.get(format!("https://pulsedive.com/api/info.php?indicator={ip}&pretty=0&key={key}"))).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                if let Some(risk) = v["risk"].as_str() {
                    let threats: Vec<String> = v["threats"].as_array().map(|a| a.iter().filter_map(|t| t["name"].as_str().map(str::to_string)).collect()).unwrap_or_default();
                    f = f.status(if risk == "none" || risk == "unknown" { FindingStatus::NotFound } else { FindingStatus::Found })
                        .summary(format!("risk {risk}{}", if threats.is_empty() { String::new() } else { format!(" · threats: {}", threats.join(", ")) }))
                        .data(v.clone());
                } else if v["error"].as_str() == Some("Indicator not found.") {
                    f = f.status(FindingStatus::NotFound).summary("not in Pulsedive");
                } else {
                    f = f.error(v["error"].as_str().unwrap_or("Pulsedive request failed").to_string());
                }
            }
        }
        ctx.emit(f);
    }
    {
        let mut f = ctx.finding("AlienVault OTX", "passive_dns", "Passive DNS").category("dns").url(format!("https://otx.alienvault.com/indicator/ip/{ip}"));
        let mut req = follower.get(format!("https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/passive_dns"));
        if let Some(key) = ctx.secret("otx") {
            req = req.header("X-OTX-API-KEY", key);
        }
        match fetch(req).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                let rows = v["passive_dns"].as_array().cloned().unwrap_or_default();
                if res.status == 200 {
                    let mut hosts: Vec<String> = rows.iter().filter_map(|r| r["hostname"].as_str().map(str::to_string)).collect();
                    hosts.sort();
                    hosts.dedup();
                    f = f.status(if hosts.is_empty() { FindingStatus::NotFound } else { FindingStatus::Found })
                        .summary(format!("{} host name(s) historically resolved here{}", hosts.len(), if hosts.is_empty() { String::new() } else { format!(": {}", hosts.iter().take(8).cloned().collect::<Vec<_>>().join(", ")) }))
                        .data(json!({ "hostnames": hosts, "records": rows.iter().take(200).cloned().collect::<Vec<_>>() }));
                    for h in hosts.iter().take(15) {
                        f = f.discover(EntityType::Domain, registrable(h), Some("OTX passive DNS"));
                    }
                } else {
                    f = f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status));
                }
            }
        }
        ctx.emit(f);
    }

    // Launchers.
    let pages: &[(&str, &str, String, &str)] = &[
        ("Shodan", "Shodan host page", format!("https://www.shodan.io/host/{ip}"), "Banners, services and history (login for full detail)"),
        ("Censys", "Censys host page", format!("https://search.censys.io/hosts/{ip}"), "Certificates, services, autonomous system"),
        ("AbuseIPDB", "Abuse reports", format!("https://www.abuseipdb.com/check/{ip}"), "Community abuse reports and confidence score"),
        ("VirusTotal", "VirusTotal IP report", format!("https://www.virustotal.com/gui/ip-address/{ip}"), "Reputation, passive DNS, related samples"),
        ("GreyNoise", "GreyNoise", format!("https://viz.greynoise.io/ip/{ip}"), "Internet-wide scanner classification"),
        ("bgp.tools", "BGP prefix", format!("https://bgp.tools/prefix/{ip}"), "Routing, upstreams, prefix ownership"),
    ];
    for (source, title, url, summary) in pages {
        ctx.emit(ctx.finding(source, "launcher", title).category("launchers").status(FindingStatus::Info).url(url.clone()).summary(*summary));
    }
    launchers::emit(&ctx, &catalog);

    Ok(())
}
