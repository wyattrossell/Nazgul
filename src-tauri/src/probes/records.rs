//! Public-records lookups for names and organisations: Wikidata, FBI Wanted, CourtListener,
//! NPI registry, FEC contributions, ProPublica nonprofits, Nationalize, OpenSanctions,
//! Companies House. Keyless unless noted.

use std::sync::Arc;

use serde_json::{json, Value};

use super::email::urlencode;
use super::{EntityType, Finding, FindingStatus, ScanContext};
use crate::engine::http::fetch;

const UA: &str = "nazgul-osint/0.2 (https://github.com/wyattrossell/Nazgul)";

fn json_of(body: &str) -> Value {
    serde_json::from_str(body).unwrap_or(Value::Null)
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

/// Steps these helpers emit for a person, given which keys exist.
pub fn person_count(ctx: &ScanContext) -> usize {
    6 + usize::from(ctx.secret("opensanctions").is_some()) + usize::from(ctx.secret("companieshouse").is_some())
}

/// Steps these helpers emit for an organisation.
pub fn org_count(ctx: &ScanContext) -> usize {
    4 + usize::from(ctx.secret("opensanctions").is_some()) + usize::from(ctx.secret("companieshouse").is_some())
}

// ---------------------------------------------------------------------------
// Wikidata / Wikipedia
// ---------------------------------------------------------------------------

pub async fn wikidata(ctx: &ScanContext, name: &str, kind: EntityType) -> Finding {
    let mut f = ctx.finding("Wikidata", "notable", "Wikidata / Wikipedia").category("reference")
        .url(format!("https://www.wikidata.org/w/index.php?search={}", urlencode(name)));
    let url = format!("https://www.wikidata.org/w/api.php?action=wbsearchentities&search={}&language=en&format=json&limit=5", urlencode(name));
    match fetch(ctx.client.get(&url).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            let hits = v["search"].as_array().cloned().unwrap_or_default();
            if hits.is_empty() {
                return f.status(FindingStatus::NotFound).summary("no Wikidata entity with this name");
            }
            let top = &hits[0];
            let label = s(&top["label"]);
            let desc = s(&top["description"]);
            // Wikipedia summary for the top hit, best effort.
            let summary_url = format!("https://en.wikipedia.org/api/rest_v1/page/summary/{}", urlencode(&label.replace(' ', "_")));
            let wiki = fetch(ctx.client.get(&summary_url).header("User-Agent", UA)).await.ok().map(|r| json_of(&r.body)).unwrap_or(Value::Null);
            let extract: String = s(&wiki["extract"]).chars().take(240).collect();
            let page = s(&wiki["content_urls"]["desktop"]["page"]);
            let mut card = f
                .status(FindingStatus::Found)
                .summary(format!("{label} · {desc}{}", if extract.is_empty() { String::new() } else { format!(" · {extract}") }))
                .data(json!({ "matches": hits, "wikipedia": { "title": wiki["title"], "description": wiki["description"], "extract": wiki["extract"], "page": page } }));
            if !page.is_empty() {
                card = card.url(page);
            }
            if kind == EntityType::Person && hits.len() > 1 {
                card.detail = Some(format!("{} entities share this name; the summary is for the first", hits.len()));
            }
            card
        }
    }
}

// ---------------------------------------------------------------------------
// FBI Wanted
// ---------------------------------------------------------------------------

pub async fn fbi_wanted(ctx: &ScanContext, name: &str) -> Finding {
    let mut f = ctx.finding("FBI Wanted", "wanted", "FBI Wanted").category("records")
        .url(format!("https://www.fbi.gov/wanted/search?query={}", urlencode(name)));
    let url = format!("https://api.fbi.gov/wanted/v1/list?title={}", urlencode(name));
    match fetch(ctx.client.get(&url).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            let items = v["items"].as_array().cloned().unwrap_or_default();
            // The title search is fuzzy; keep only entries whose title contains every name token.
            let tokens: Vec<String> = name.split_whitespace().map(|t| t.to_lowercase()).collect();
            let exact: Vec<&Value> = items.iter().filter(|i| { let t = s(&i["title"]).to_lowercase(); tokens.iter().all(|tok| t.contains(tok)) }).collect();
            if exact.is_empty() {
                return f.status(FindingStatus::NotFound).summary(format!("no FBI Wanted entry matches the full name ({} loose matches)", items.len()));
            }
            let titles: Vec<String> = exact.iter().take(5).map(|i| format!("{} [{}]", s(&i["title"]), i["subjects"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default())).collect();
            f.status(FindingStatus::Found)
                .summary(format!("{} FBI Wanted entr{}: {}", exact.len(), if exact.len() == 1 { "y" } else { "ies" }, titles.join(" · ")))
                .url(s(&exact[0]["url"]))
                .data(json!({ "matches": exact.iter().take(10).map(|i| json!({ "title": i["title"], "url": i["url"], "subjects": i["subjects"], "reward": i["reward_text"], "fieldOffices": i["field_offices"], "aliases": i["aliases"], "placeOfBirth": i["place_of_birth"], "datesOfBirthUsed": i["dates_of_birth_used"] })).collect::<Vec<_>>() }))
        }
    }
}

// ---------------------------------------------------------------------------
// CourtListener
// ---------------------------------------------------------------------------

pub async fn courtlistener(ctx: &ScanContext, name: &str) -> Finding {
    let quoted = format!("\"{name}\"");
    let mut f = ctx.finding("CourtListener", "court", "Court opinions and dockets").category("records")
        .url(format!("https://www.courtlistener.com/?q={}", urlencode(&quoted)));
    let mut req = ctx.client.get(format!("https://www.courtlistener.com/api/rest/v4/search/?q={}&type=o", urlencode(&quoted))).header("User-Agent", UA);
    if let Some(t) = ctx.secret("courtlistener") {
        req = req.header("Authorization", format!("Token {t}"));
    }
    match fetch(req).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            if res.status != 200 {
                return f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}: {}", res.status, s(&v["detail"])));
            }
            let count = v["count"].as_u64().unwrap_or(0);
            let cases: Vec<String> = v["results"].as_array().into_iter().flatten().take(5).map(|r| format!("{} ({}, {})", s(&r["caseName"]), s(&r["court"]), s(&r["dateFiled"]).chars().take(4).collect::<String>())).collect();
            f.status(if count > 0 { FindingStatus::Found } else { FindingStatus::NotFound })
                .summary(if count == 0 { "no opinions mention this exact name".to_string() } else { format!("{count} opinion(s) mention the name: {}", cases.join(" · ")) })
                .data(json!({ "count": count, "results": v["results"].as_array().into_iter().flatten().take(20).map(|r| json!({ "caseName": r["caseName"], "court": r["court"], "dateFiled": r["dateFiled"], "url": format!("https://www.courtlistener.com{}", s(&r["absolute_url"])) })).collect::<Vec<_>>() }))
        }
    }
}

// ---------------------------------------------------------------------------
// NPI registry (US healthcare providers)
// ---------------------------------------------------------------------------

pub async fn npi(ctx: &ScanContext, name: &str, org: bool) -> Finding {
    let mut f = ctx.finding("NPI Registry", "npi", "US healthcare provider registry").category("records")
        .url("https://npiregistry.cms.hhs.gov/search");
    let url = if org {
        format!("https://npiregistry.cms.hhs.gov/api/?version=2.1&organization_name={}&limit=10", urlencode(name))
    } else {
        let parts: Vec<&str> = name.split_whitespace().collect();
        let (first, last) = (parts.first().copied().unwrap_or(""), parts.last().copied().unwrap_or(""));
        format!("https://npiregistry.cms.hhs.gov/api/?version=2.1&first_name={}&last_name={}&limit=10", urlencode(first), urlencode(last))
    };
    match fetch(ctx.client.get(&url).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            let results = v["results"].as_array().cloned().unwrap_or_default();
            let count = v["result_count"].as_u64().unwrap_or(results.len() as u64);
            if count == 0 {
                return f.status(FindingStatus::NotFound).summary("no provider with this name");
            }
            let rows: Vec<Value> = results.iter().map(|r| {
                let b = &r["basic"];
                let addr = r["addresses"].as_array().and_then(|a| a.first()).cloned().unwrap_or(Value::Null);
                json!({
                    "npi": r["number"],
                    "name": if org { s(&b["organization_name"]) } else { format!("{} {} {}", s(&b["first_name"]), s(&b["last_name"]), s(&b["credential"])).trim().to_string() },
                    "taxonomy": r["taxonomies"].as_array().and_then(|t| t.first()).map(|t| s(&t["desc"])).unwrap_or_default(),
                    "city": addr["city"], "state": addr["state"], "phone": addr["telephone_number"], "address": addr["address_1"]
                })
            }).collect();
            let sample: Vec<String> = rows.iter().take(4).map(|r| format!("{} · {} · {}, {}", s(&r["name"]), s(&r["taxonomy"]), s(&r["city"]), s(&r["state"]))).collect();
            let mut card = f.status(FindingStatus::Found).summary(format!("{count} provider(s): {}", sample.join(" · "))).data(json!({ "count": count, "providers": rows }));
            if count == 1 {
                if let Some(p) = rows.first().and_then(|r| r["phone"].as_str()).filter(|p| !p.is_empty()) {
                    card = card.discover(EntityType::Phone, p, Some("NPI practice phone"));
                }
            }
            card
        }
    }
}

// ---------------------------------------------------------------------------
// FEC campaign contributions
// ---------------------------------------------------------------------------

pub async fn fec(ctx: &ScanContext, name: &str, by_employer: bool) -> Finding {
    let key = ctx.secret("fec").unwrap_or("DEMO_KEY");
    let field = if by_employer { "contributor_employer" } else { "contributor_name" };
    let mut f = ctx.finding("FEC", "donations", if by_employer { "FEC donations by employees" } else { "FEC campaign contributions" }).category("records")
        .url(format!("https://www.fec.gov/data/receipts/?{field}={}", urlencode(name)));
    let url = format!("https://api.open.fec.gov/v1/schedules/schedule_a/?api_key={key}&{field}={}&per_page=20&sort=-contribution_receipt_date", urlencode(name));
    match fetch(ctx.client.get(&url).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            if res.status == 429 {
                return f.status(FindingStatus::Info).summary("FEC DEMO_KEY hourly limit reached; add your own free key in Settings");
            }
            if res.status != 200 {
                return f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}: {}", res.status, s(&v["message"])));
            }
            let results = v["results"].as_array().cloned().unwrap_or_default();
            let count = v["pagination"]["count"].as_u64().unwrap_or(results.len() as u64);
            if results.is_empty() {
                return f.status(FindingStatus::NotFound).summary("no federal contributions on record");
            }
            let rows: Vec<Value> = results.iter().map(|r| json!({
                "name": r["contributor_name"], "employer": r["contributor_employer"], "occupation": r["contributor_occupation"],
                "city": r["contributor_city"], "state": r["contributor_state"], "zip": r["contributor_zip"],
                "amount": r["contribution_receipt_amount"], "date": r["contribution_receipt_date"], "committee": r["committee"]["name"]
            })).collect();
            let mut card = f.status(FindingStatus::Found).data(json!({ "count": count, "contributions": rows }));
            if by_employer {
                let mut people: Vec<String> = rows.iter().map(|r| s(&r["name"])).filter(|n| !n.is_empty()).collect();
                people.sort();
                people.dedup();
                card = card.summary(format!("{count} contribution(s) listing this employer · {} distinct donor name(s): {}", people.len(), people.iter().take(6).cloned().collect::<Vec<_>>().join(", ")));
                for p in people.iter().take(10) {
                    card = card.discover(EntityType::Person, p.clone(), Some("FEC donor listing this employer"));
                }
            } else {
                let top = &rows[0];
                card = card.summary(format!("{count} contribution(s) · latest {} ${} to {} · {} · {} · {}, {}", s(&top["date"]).chars().take(10).collect::<String>(), top["amount"].as_f64().unwrap_or(0.0), s(&top["committee"]), s(&top["employer"]), s(&top["occupation"]), s(&top["city"]), s(&top["state"])));
                let mut employers: Vec<String> = rows.iter().map(|r| s(&r["employer"])).filter(|e| !e.is_empty() && !["NONE", "RETIRED", "NOT EMPLOYED", "SELF-EMPLOYED", "SELF", "N/A"].contains(&e.to_uppercase().as_str())).collect();
                employers.sort();
                employers.dedup();
                for e in employers.iter().take(5) {
                    card = card.discover(EntityType::Org, e.clone(), Some("FEC employer"));
                }
                let mut places: Vec<String> = rows.iter().map(|r| format!("{}, {}", s(&r["city"]), s(&r["state"]))).filter(|p| p != ", ").collect();
                places.sort();
                places.dedup();
                for p in places.iter().take(3) {
                    card = card.discover(EntityType::Location, p.clone(), Some("FEC contributor address"));
                }
                if count > 1 {
                    card.detail = Some("Contributions may belong to several people sharing the name; check employer and city".to_string());
                }
            }
            card
        }
    }
}

// ---------------------------------------------------------------------------
// ProPublica Nonprofit Explorer
// ---------------------------------------------------------------------------

pub async fn nonprofits(ctx: &ScanContext, name: &str) -> Finding {
    let mut f = ctx.finding("ProPublica Nonprofit Explorer", "nonprofits", "US nonprofit filings").category("company")
        .url(format!("https://projects.propublica.org/nonprofits/search?q={}", urlencode(name)));
    let url = format!("https://projects.propublica.org/nonprofits/api/v2/search.json?q={}", urlencode(name));
    match fetch(ctx.client.get(&url).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            let orgs = v["organizations"].as_array().cloned().unwrap_or_default();
            let total = v["total_results"].as_u64().unwrap_or(orgs.len() as u64);
            if orgs.is_empty() {
                return f.status(FindingStatus::NotFound).summary("no IRS-registered nonprofit with this name");
            }
            let sample: Vec<String> = orgs.iter().take(4).map(|o| format!("{} (EIN {}, {}, {})", s(&o["name"]), s(&o["strein"]), s(&o["city"]), s(&o["state"]))).collect();
            f.status(FindingStatus::Found)
                .summary(format!("{total} nonprofit(s): {}", sample.join(" · ")))
                .url(format!("https://projects.propublica.org/nonprofits/organizations/{}", orgs[0]["ein"]))
                .data(json!({ "total": total, "organizations": orgs.iter().take(20).map(|o| json!({ "name": o["name"], "ein": o["strein"], "city": o["city"], "state": o["state"], "ntee": o["ntee_code"], "url": format!("https://projects.propublica.org/nonprofits/organizations/{}", o["ein"]) })).collect::<Vec<_>>() }))
        }
    }
}

// ---------------------------------------------------------------------------
// Nationalize (surname origin estimate)
// ---------------------------------------------------------------------------

pub async fn nationalize(ctx: &ScanContext, name: &str) -> Finding {
    let last = name.split_whitespace().last().unwrap_or(name);
    let mut f = ctx.finding("Nationalize", "origin", "Surname origin estimate").category("reference")
        .url(format!("https://nationalize.io/?name={}", urlencode(last)));
    match fetch(ctx.client.get(format!("https://api.nationalize.io/?name={}", urlencode(last))).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            let countries: Vec<String> = v["country"].as_array().into_iter().flatten().take(4).map(|c| format!("{} {:.0}%", s(&c["country_id"]), c["probability"].as_f64().unwrap_or(0.0) * 100.0)).collect();
            if countries.is_empty() {
                return f.status(FindingStatus::NotFound).summary(format!("no signal for the surname \"{last}\""));
            }
            f.status(FindingStatus::Info).summary(format!("\"{last}\" most common in: {} (statistical guess, not evidence)", countries.join(", "))).data(v)
        }
    }
}

// ---------------------------------------------------------------------------
// OpenSanctions (keyed)
// ---------------------------------------------------------------------------

pub async fn opensanctions(ctx: &ScanContext, name: &str, key: &str) -> Finding {
    let mut f = ctx.finding("OpenSanctions", "sanctions", "Sanctions and PEP screening").category("records")
        .url(format!("https://www.opensanctions.org/search/?q={}", urlencode(name)));
    let url = format!("https://api.opensanctions.org/search/default?q={}&limit=10", urlencode(name));
    match fetch(ctx.client.get(&url).header("Authorization", format!("ApiKey {key}")).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            if res.status == 401 || res.status == 403 {
                return f.error("OpenSanctions rejected the API key");
            }
            let results = v["results"].as_array().cloned().unwrap_or_default();
            if results.is_empty() {
                return f.status(FindingStatus::NotFound).summary("no sanctions, PEP or crime-list entries match");
            }
            let rows: Vec<Value> = results.iter().map(|r| json!({
                "caption": r["caption"], "schema": r["schema"], "topics": r["properties"]["topics"], "countries": r["properties"]["country"],
                "birthDate": r["properties"]["birthDate"], "datasets": r["datasets"], "firstSeen": r["first_seen"], "url": format!("https://www.opensanctions.org/entities/{}/", s(&r["id"]))
            })).collect();
            let sample: Vec<String> = rows.iter().take(4).map(|r| format!("{} [{}]", s(&r["caption"]), r["topics"].as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(",")).unwrap_or_default())).collect();
            f.status(FindingStatus::Found).summary(format!("{} match(es): {}", results.len(), sample.join(" · "))).data(json!({ "results": rows }))
        }
    }
}

// ---------------------------------------------------------------------------
// Companies House (keyed)
// ---------------------------------------------------------------------------

pub async fn companies_house(ctx: &ScanContext, name: &str, officers: bool, key: &str) -> Finding {
    let (path, kind, title) = if officers { ("officers", "officers", "Companies House officers") } else { ("companies", "companies", "Companies House companies") };
    let mut f = ctx.finding("Companies House", kind, title).category("company-uk")
        .url(format!("https://find-and-update.company-information.service.gov.uk/search/{path}?q={}", urlencode(name)));
    let url = format!("https://api.company-information.service.gov.uk/search/{path}?q={}&items_per_page=10", urlencode(name));
    match fetch(ctx.client.get(&url).basic_auth(key, Some("")).header("User-Agent", UA)).await {
        Err((e, ms)) => { f.elapsed_ms = ms; f.error(e) }
        Ok(res) => {
            f.elapsed_ms = res.elapsed_ms;
            f.http_status = Some(res.status);
            let v = json_of(&res.body);
            if res.status == 401 {
                return f.error("Companies House rejected the API key");
            }
            let items = v["items"].as_array().cloned().unwrap_or_default();
            let total = v["total_results"].as_u64().unwrap_or(items.len() as u64);
            if items.is_empty() {
                return f.status(FindingStatus::NotFound).summary(format!("no UK {path} match"));
            }
            let sample: Vec<String> = items.iter().take(4).map(|i| {
                if officers {
                    format!("{} · {} appointment(s) · born {}/{} · {}", s(&i["title"]), i["appointment_count"].as_u64().unwrap_or(0), i["date_of_birth"]["month"], i["date_of_birth"]["year"], s(&i["address_snippet"]))
                } else {
                    format!("{} ({}, {}, since {})", s(&i["title"]), s(&i["company_number"]), s(&i["company_status"]), s(&i["date_of_creation"]))
                }
            }).collect();
            f.status(FindingStatus::Found).summary(format!("{total} {path}: {}", sample.join(" · ")))
                .data(json!({ "total": total, "items": items.iter().take(20).map(|i| json!({ "title": i["title"], "address": i["address_snippet"], "number": i["company_number"], "status": i["company_status"], "created": i["date_of_creation"], "appointments": i["appointment_count"], "dateOfBirth": i["date_of_birth"], "link": format!("https://find-and-update.company-information.service.gov.uk{}", s(&i["links"]["self"])) })).collect::<Vec<_>>() }))
        }
    }
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

pub async fn person_records(ctx: &Arc<ScanContext>, name: &str) {
    let (w, fbi, cl, n, fe, nat) = tokio::join!(
        wikidata(ctx, name, EntityType::Person),
        fbi_wanted(ctx, name),
        courtlistener(ctx, name),
        npi(ctx, name, false),
        fec(ctx, name, false),
        nationalize(ctx, name)
    );
    for f in [w, fbi, cl, n, fe, nat] {
        ctx.emit(f);
    }
    if let Some(key) = ctx.secret("opensanctions") {
        ctx.emit(opensanctions(ctx, name, key).await);
    }
    if let Some(key) = ctx.secret("companieshouse") {
        ctx.emit(companies_house(ctx, name, true, key).await);
    }
}

pub async fn org_records(ctx: &Arc<ScanContext>, name: &str) {
    let (w, np, fe, n) = tokio::join!(
        wikidata(ctx, name, EntityType::Org),
        nonprofits(ctx, name),
        fec(ctx, name, true),
        npi(ctx, name, true)
    );
    for f in [w, np, fe, n] {
        ctx.emit(f);
    }
    if let Some(key) = ctx.secret("opensanctions") {
        ctx.emit(opensanctions(ctx, name, key).await);
    }
    if let Some(key) = ctx.secret("companieshouse") {
        ctx.emit(companies_house(ctx, name, false, key).await);
    }
}
