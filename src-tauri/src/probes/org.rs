//! Company probe: OpenCorporates search where the API allows it, plus every company
//! register and directory in the catalog, and document dorks.

use std::sync::Arc;

use serde_json::{json, Value};

use super::email::urlencode;
use super::launchers;
use super::{EntityType, FindingStatus, ScanContext};
use crate::engine::http::{build_following_client, fetch};

pub async fn run(ctx: Arc<ScanContext>) -> Result<(), String> {
    let name = ctx.input.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.len() < 2 {
        return Err("Enter a company or organisation name.".to_string());
    }
    let client = build_following_client(&ctx.options.http_options()).map_err(|e| e.to_string())?;
    let vars = launchers::vars_org(&name);
    let planned = launchers::plan(EntityType::Org, &vars);
    ctx.start(2 + planned.len());

    // OpenCorporates public search (works unauthenticated at low volume; degrades gracefully).
    let mut oc = ctx
        .finding("OpenCorporates", "companies", "OpenCorporates matches")
        .category("company")
        .url(format!("https://opencorporates.com/companies?q={}", urlencode(&name)));
    match fetch(client.get(format!("https://api.opencorporates.com/v0.4/companies/search?q={}&per_page=10", urlencode(&name)))).await {
        Err((e, ms)) => {
            oc.elapsed_ms = ms;
            oc = oc.error(e);
        }
        Ok(res) => {
            oc.elapsed_ms = res.elapsed_ms;
            oc.http_status = Some(res.status);
            let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
            let companies: Vec<Value> = v["results"]["companies"]
                .as_array()
                .map(|a| a.iter().map(|c| c["company"].clone()).collect())
                .unwrap_or_default();
            if res.status == 200 {
                let total = v["results"]["total_count"].as_u64().unwrap_or(companies.len() as u64);
                let sample: Vec<String> = companies
                    .iter()
                    .take(5)
                    .map(|c| format!("{} ({}, {})", c["name"].as_str().unwrap_or("?"), c["jurisdiction_code"].as_str().unwrap_or("?"), c["current_status"].as_str().unwrap_or("?")))
                    .collect();
                oc = oc
                    .status(if companies.is_empty() { FindingStatus::NotFound } else { FindingStatus::Found })
                    .summary(if companies.is_empty() { "no registered companies matched".to_string() } else { format!("{total} match(es): {}", sample.join(" · ")) })
                    .data(json!({ "total": total, "companies": companies }));
            } else if res.status == 401 || res.status == 403 {
                oc = oc.status(FindingStatus::Info).summary("OpenCorporates API needs a token for this query; open the site search instead");
            } else if res.status == 429 {
                oc = oc.status(FindingStatus::Info).summary("OpenCorporates rate limit reached; open the site search instead");
            } else {
                oc = oc.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status));
            }
        }
    }
    ctx.emit(oc);

    let quoted = format!("\"{name}\"");
    ctx.emit(
        ctx.finding("dorks", "dorks", "Search engine dorks")
            .category("launchers")
            .status(FindingStatus::Info)
            .url(format!("https://www.google.com/search?q={}", urlencode(&quoted)))
            .summary("Exact name on Google; filings, documents, LinkedIn and news dorks in raw data")
            .data(json!({
                "exact": format!("https://www.google.com/search?q={}", urlencode(&quoted)),
                "documents": format!("https://www.google.com/search?q={}", urlencode(&format!("{quoted} filetype:pdf OR filetype:xlsx OR filetype:docx"))),
                "linkedinPeople": format!("https://www.google.com/search?q={}", urlencode(&format!("{quoted} site:linkedin.com/in"))),
                "news": format!("https://news.google.com/search?q={}", urlencode(&quoted)),
                "secFilings": format!("https://efts.sec.gov/LATEST/search-index?q={}", urlencode(&quoted)),
                "courtListener": format!("https://www.courtlistener.com/?q={}", urlencode(&quoted)),
            })),
    );

    launchers::emit(&ctx, &planned);
    Ok(())
}
