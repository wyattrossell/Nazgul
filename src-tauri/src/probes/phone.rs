//! Phone probe: libphonenumber parsing plus launchers for reverse lookup.
//! Everything here is local except the launcher URLs the user chooses to open.

use std::sync::Arc;

use phonenumber::{country, Mode};
use serde_json::json;

use super::email::urlencode;
use super::launchers;
use super::payments;
use super::{EntityType, FindingStatus, ScanContext};
use crate::engine::http::fetch;

const COUNTRY_NAMES: &[(&str, &str)] = &[
    ("US", "United States"), ("CA", "Canada"), ("GB", "United Kingdom"), ("IE", "Ireland"),
    ("AU", "Australia"), ("NZ", "New Zealand"), ("DE", "Germany"), ("FR", "France"), ("ES", "Spain"),
    ("IT", "Italy"), ("PT", "Portugal"), ("NL", "Netherlands"), ("BE", "Belgium"), ("CH", "Switzerland"),
    ("AT", "Austria"), ("SE", "Sweden"), ("NO", "Norway"), ("DK", "Denmark"), ("FI", "Finland"),
    ("PL", "Poland"), ("CZ", "Czechia"), ("HU", "Hungary"), ("RO", "Romania"), ("GR", "Greece"),
    ("TR", "Türkiye"), ("RU", "Russia"), ("UA", "Ukraine"), ("IL", "Israel"), ("AE", "United Arab Emirates"),
    ("SA", "Saudi Arabia"), ("IN", "India"), ("PK", "Pakistan"), ("BD", "Bangladesh"), ("CN", "China"),
    ("HK", "Hong Kong"), ("TW", "Taiwan"), ("JP", "Japan"), ("KR", "South Korea"), ("SG", "Singapore"),
    ("MY", "Malaysia"), ("TH", "Thailand"), ("VN", "Vietnam"), ("PH", "Philippines"), ("ID", "Indonesia"),
    ("MX", "Mexico"), ("BR", "Brazil"), ("AR", "Argentina"), ("CL", "Chile"), ("CO", "Colombia"),
    ("PE", "Peru"), ("ZA", "South Africa"), ("NG", "Nigeria"), ("KE", "Kenya"), ("EG", "Egypt"),
    ("MA", "Morocco"),
];

fn country_name(code: &str) -> String {
    COUNTRY_NAMES
        .iter()
        .find(|(c, _)| *c == code)
        .map(|(_, n)| n.to_string())
        .unwrap_or_else(|| code.to_string())
}

fn default_region(ctx: &ScanContext) -> country::Id {
    ctx.options.extra["region"]
        .as_str()
        .and_then(|r| r.to_uppercase().parse::<country::Id>().ok())
        .unwrap_or(country::US)
}

pub async fn run(ctx: Arc<ScanContext>) -> Result<(), String> {
    let raw = ctx.input.trim().to_string();
    let region = default_region(&ctx);

    let number = phonenumber::parse(Some(region), &raw)
        .map_err(|e| format!("Could not parse \"{raw}\" as a phone number ({e}). Try the international form, e.g. +1 415 555 0100."))?;

    // parsed, country, launchers x4, messaging x2 (+1 keyed NumVerify)
    let numverify = ctx.secret("numverify").map(str::to_string);

    let valid = phonenumber::is_valid(&number);
    let e164 = number.format().mode(Mode::E164).to_string();
    let international = number.format().mode(Mode::International).to_string();
    let national = number.format().mode(Mode::National).to_string();
    let rfc = number.format().mode(Mode::Rfc3966).to_string();
    let region_code = number.country().id().map(|id| format!("{id:?}")).unwrap_or_default();
    let country_code = number.country().code();
    let kind = format!("{:?}", number.number_type(&phonenumber::metadata::DATABASE));
    let digits: String = e164.chars().filter(|c| c.is_ascii_digit()).collect();
    let catalog = launchers::plan(EntityType::Phone, &launchers::vars_phone(&e164, &national));
    let keyed = if ctx.options.airgap { 0 } else { usize::from(numverify.is_some()) + usize::from(ctx.secret("veriphone").is_some()) + usize::from(ctx.secret("ipqs").is_some()) };
    ctx.start(8 + catalog.len() + payments::MANUAL_LAUNCHER_COUNT + keyed);

    ctx.emit(
        ctx.finding("libphonenumber", "number", "Parsed number")
            .category("number")
            .status(if valid { FindingStatus::Found } else { FindingStatus::Ambiguous })
            .summary(if valid {
                format!("{international} · {kind} · valid for {}", country_name(&region_code))
            } else {
                format!("{international} parses but is not a valid assigned number pattern")
            })
            .data(json!({
                "valid": valid,
                "e164": e164,
                "international": international,
                "national": national,
                "rfc3966": rfc,
                "countryCode": country_code,
                "region": region_code,
                "type": kind,
            })),
    );

    ctx.emit(
        ctx.finding("libphonenumber", "country", "Country")
            .category("number")
            .status(FindingStatus::Info)
            .summary(format!("+{country_code} {} ({})", country_name(&region_code), region_code))
            .data(json!({ "countryCode": country_code, "region": region_code, "name": country_name(&region_code) })),
    );

    // Messaging launchers.
    ctx.emit(
        ctx.finding("WhatsApp", "launcher", "WhatsApp click-to-chat")
            .category("messaging")
            .status(FindingStatus::Info)
            .url(format!("https://wa.me/{digits}"))
            .summary("Opens a chat if the number is on WhatsApp; the page reveals the profile photo and about text when public"),
    );
    ctx.emit(
        ctx.finding("Telegram", "launcher", "Telegram link")
            .category("messaging")
            .status(FindingStatus::Info)
            .url(format!("https://t.me/{}", e164))
            .summary("Resolves to a profile when the number is registered and discoverable"),
    );

    // Payment apps: no public phone lookup exists, so open the user's own apps prefilled.
    for f in payments::manual_launchers(&ctx, &e164, "phone number") {
        ctx.emit(f);
    }

    launchers::emit(&ctx, &catalog);

    // Reverse-lookup launchers with several formats quoted.
    let query = format!("\"{e164}\" OR \"{international}\" OR \"{national}\"");
    ctx.emit(
        ctx.finding("dorks", "launcher", "Search engine dorks")
            .category("dorks")
            .status(FindingStatus::Info)
            .url(format!("https://www.google.com/search?q={}", urlencode(&query)))
            .summary("Number in three formats, quoted, on Google; Bing and DuckDuckGo in raw data")
            .data(json!({
                "google": format!("https://www.google.com/search?q={}", urlencode(&query)),
                "bing": format!("https://www.bing.com/search?q={}", urlencode(&query)),
                "duckduckgo": format!("https://duckduckgo.com/?q={}", urlencode(&query)),
            })),
    );
    ctx.emit(
        ctx.finding("Truecaller", "launcher", "Truecaller")
            .category("reverse")
            .status(FindingStatus::Info)
            .url(format!("https://www.truecaller.com/search/{}/{}", region_code.to_lowercase(), digits))
            .summary("Crowd-sourced caller ID (login required to see names)"),
    );
    ctx.emit(
        ctx.finding("Sync.me", "launcher", "Sync.me")
            .category("reverse")
            .status(FindingStatus::Info)
            .url(format!("https://sync.me/search/?number={digits}"))
            .summary("Reverse phone directory"),
    );
    if let (Some(key), false) = (&numverify, ctx.options.airgap) {
        let url = format!("http://apilayer.net/api/validate?access_key={key}&number={}&format=1", digits);
        let mut f = ctx.finding("NumVerify", "carrier", "Carrier and line type").category("number");
        match fetch(ctx.client.get(&url)).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: serde_json::Value = serde_json::from_str(&res.body).unwrap_or(serde_json::Value::Null);
                if v["valid"].is_boolean() {
                    let carrier = v["carrier"].as_str().unwrap_or("").to_string();
                    let line = v["line_type"].as_str().unwrap_or("").to_string();
                    let location = v["location"].as_str().unwrap_or("").to_string();
                    f = f.status(if v["valid"].as_bool().unwrap_or(false) { FindingStatus::Found } else { FindingStatus::NotFound })
                        .summary([carrier, line, location].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" · "))
                        .data(v.clone());
                } else {
                    f = f.error(v["error"]["info"].as_str().unwrap_or("NumVerify returned an unexpected response").to_string());
                }
            }
        }
        ctx.emit(f);
    }
    if let (Some(key), false) = (ctx.secret("veriphone"), ctx.options.airgap) {
        let mut f = ctx.finding("Veriphone", "carrier", "Veriphone carrier and type").category("number");
        match fetch(ctx.client.get(format!("https://api.veriphone.io/v2/verify?phone={}&key={key}", urlencode(&e164)))).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: serde_json::Value = serde_json::from_str(&res.body).unwrap_or(serde_json::Value::Null);
                if v["status"].as_str() == Some("success") {
                    let s = |k: &str| v[k].as_str().unwrap_or("").to_string();
                    f = f.status(if v["phone_valid"].as_bool().unwrap_or(false) { FindingStatus::Found } else { FindingStatus::NotFound })
                        .summary([s("carrier"), s("phone_type"), s("phone_region"), s("country")].into_iter().filter(|x| !x.is_empty()).collect::<Vec<_>>().join(" · "))
                        .data(v.clone());
                } else {
                    f = f.error(v["message"].as_str().unwrap_or("Veriphone request failed").to_string());
                }
            }
        }
        ctx.emit(f);
    }
    if let (Some(key), false) = (ctx.secret("ipqs"), ctx.options.airgap) {
        let mut f = ctx.finding("IPQualityScore", "validation", "IPQS phone validation").category("number");
        match fetch(ctx.client.get(format!("https://ipqualityscore.com/api/json/phone/{key}/{digits}"))).await {
            Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
            Ok(res) => {
                f.elapsed_ms = res.elapsed_ms;
                f.http_status = Some(res.status);
                let v: serde_json::Value = serde_json::from_str(&res.body).unwrap_or(serde_json::Value::Null);
                if v["success"].as_bool().unwrap_or(false) {
                    let flags: Vec<&str> = [("active", "active"), ("leaked", "in a leak"), ("risky", "risky"), ("VOIP", "VoIP"), ("prepaid", "prepaid"), ("do_not_call", "do-not-call list")].iter().filter(|(k, _)| v[*k].as_bool().unwrap_or(false)).map(|(_, l)| *l).collect();
                    let mut g = f.status(if v["valid"].as_bool().unwrap_or(false) { FindingStatus::Found } else { FindingStatus::NotFound })
                        .summary(format!("{} · {} · {}{}{}", v["carrier"].as_str().unwrap_or("carrier ?"), v["line_type"].as_str().unwrap_or("type ?"), [v["city"].as_str().unwrap_or(""), v["region"].as_str().unwrap_or("")].iter().filter(|x| !x.is_empty()).cloned().collect::<Vec<_>>().join(", "), v["name"].as_str().filter(|n| !n.is_empty() && *n != "N/A").map(|n| format!(" · name on record: {n}")).unwrap_or_default(), if flags.is_empty() { String::new() } else { format!(" · {}", flags.join(", ")) }))
                        .data(v.clone());
                    if let Some(n) = v["name"].as_str().filter(|n| !n.is_empty() && *n != "N/A") {
                        g = g.discover(super::EntityType::Person, n, Some("IPQS subscriber name"));
                    }
                    f = g;
                } else {
                    f = f.error(v["message"].as_str().unwrap_or("IPQS request failed").to_string());
                }
            }
        }
        ctx.emit(f);
    }
    ctx.emit(
        ctx.finding("NumLookup", "launcher", "Carrier lookup")
            .category("reverse")
            .status(FindingStatus::Info)
            .url(format!("https://www.numlookup.com/?q={}", urlencode(&e164)))
            .summary("Free carrier and line-type lookup; NumVerify / Twilio arrive with keyed integrations"),
    );

    Ok(())
}
