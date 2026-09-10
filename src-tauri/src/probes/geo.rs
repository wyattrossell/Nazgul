//! Location probe: coordinates or a place name in, reverse/forward geocoding via
//! Nominatim, and every geolocation tool in the catalog prefilled with the point.

use std::sync::Arc;

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{json, Value};

use super::email::urlencode;
use super::launchers;
use super::{EntityType, FindingStatus, ScanContext};
use crate::engine::http::{build_following_client, fetch};

static RE_DECIMAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\s*(-?\d{1,2}(?:\.\d+)?)\s*°?\s*([NnSs])?\s*[,;/ ]\s*(-?\d{1,3}(?:\.\d+)?)\s*°?\s*([EeWw])?\s*$").unwrap());
static RE_DMS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(\d{1,3})[°\s]+(\d{1,2})['′\s]+(\d{1,2}(?:\.\d+)?)["″\s]*([NSEW])"#).unwrap()
});

/// Parses "40.7128, -74.0060", "40.7128 N 74.0060 W" or DMS pairs. Returns (lat, lon).
pub fn parse_coordinates(input: &str) -> Option<(f64, f64)> {
    if let Some(c) = RE_DECIMAL.captures(input) {
        let mut lat: f64 = c[1].parse().ok()?;
        let mut lon: f64 = c[3].parse().ok()?;
        if c.get(2).map(|m| m.as_str().eq_ignore_ascii_case("S")).unwrap_or(false) {
            lat = -lat.abs();
        }
        if c.get(4).map(|m| m.as_str().eq_ignore_ascii_case("W")).unwrap_or(false) {
            lon = -lon.abs();
        }
        if (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon) {
            return Some((lat, lon));
        }
        return None;
    }
    let parts: Vec<(f64, char)> = RE_DMS
        .captures_iter(input)
        .filter_map(|c| {
            let d: f64 = c[1].parse().ok()?;
            let m: f64 = c[2].parse().ok()?;
            let s: f64 = c[3].parse().ok()?;
            let hemi = c[4].chars().next()?.to_ascii_uppercase();
            let mut v = d + m / 60.0 + s / 3600.0;
            if hemi == 'S' || hemi == 'W' {
                v = -v;
            }
            Some((v, hemi))
        })
        .collect();
    if parts.len() == 2 {
        let lat = parts.iter().find(|(_, h)| *h == 'N' || *h == 'S')?.0;
        let lon = parts.iter().find(|(_, h)| *h == 'E' || *h == 'W')?.0;
        return Some((lat, lon));
    }
    None
}

const NOMINATIM_UA: &str = "nazgul-osint/0.1 (desktop; https://github.com/wyattrossell/Nazgul)";

pub async fn run(ctx: Arc<ScanContext>) -> Result<(), String> {
    let input = ctx.input.trim().to_string();
    if input.is_empty() {
        return Err("Enter coordinates or a place name.".to_string());
    }
    let client = build_following_client(&ctx.options.http_options()).map_err(|e| e.to_string())?;

    let mut point = parse_coordinates(&input);
    let mut planned = point.map(|(lat, lon)| launchers::plan(EntityType::Location, &launchers::vars_location(lat, lon)));
    // geocode/reverse (1) + nearby places + aircraft overhead + launchers
    ctx.start(3 + planned.as_ref().map(|p| p.len()).unwrap_or_else(|| launchers::for_type(EntityType::Location).len()));

    match point {
        Some((lat, lon)) => {
            let url = format!("https://nominatim.openstreetmap.org/reverse?lat={lat}&lon={lon}&format=jsonv2&zoom=18");
            let mut f = ctx
                .finding("Nominatim", "coordinates", "Coordinates")
                .category("geo")
                .status(FindingStatus::Found)
                .url(format!("https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"));
            match fetch(client.get(&url).header("User-Agent", NOMINATIM_UA)).await {
                Err((e, ms)) => {
                    f.elapsed_ms = ms;
                    f = f.summary(format!("{lat:.6}, {lon:.6} · reverse geocode failed: {e}"));
                }
                Ok(res) => {
                    f.elapsed_ms = res.elapsed_ms;
                    f.http_status = Some(res.status);
                    let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                    let display = v["display_name"].as_str().unwrap_or("no address returned").to_string();
                    f = f.summary(format!("{lat:.6}, {lon:.6} · {display}"))
                        .data(json!({ "lat": lat, "lon": lon, "displayName": display, "address": v["address"], "osmType": v["osm_type"], "osmId": v["osm_id"] }));
                }
            }
            ctx.emit(f);
        }
        None => {
            let url = format!("https://nominatim.openstreetmap.org/search?q={}&format=jsonv2&limit=5&addressdetails=1", urlencode(&input));
            let mut f = ctx.finding("Nominatim", "geocode", "Geocoded place").category("geo");
            match fetch(client.get(&url).header("User-Agent", NOMINATIM_UA)).await {
                Err((e, ms)) => {
                    f.elapsed_ms = ms;
                    f = f.error(e);
                }
                Ok(res) => {
                    f.elapsed_ms = res.elapsed_ms;
                    f.http_status = Some(res.status);
                    let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                    let hits = v.as_array().cloned().unwrap_or_default();
                    match hits.first() {
                        Some(top) => {
                            let lat: f64 = top["lat"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0.0);
                            let lon: f64 = top["lon"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0.0);
                            point = Some((lat, lon));
                            planned = Some(launchers::plan(EntityType::Location, &launchers::vars_location(lat, lon)));
                            f = f
                                .status(FindingStatus::Found)
                                .summary(format!("{} · {lat:.6}, {lon:.6}{}", top["display_name"].as_str().unwrap_or(""), if hits.len() > 1 { format!(" · {} other matches in raw data", hits.len() - 1) } else { String::new() }))
                                .url(format!("https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"))
                                .data(json!({ "lat": lat, "lon": lon, "matches": hits }))
                                .discover(EntityType::Location, format!("{lat:.6},{lon:.6}"), Some("geocoded"));
                        }
                        None => f = f.status(FindingStatus::NotFound).summary("Nominatim found nothing for this text"),
                    }
                }
            }
            ctx.emit(f);
        }
    }

    if let Some((lat, lon)) = point {
        // Nearby notable places (Wikipedia) and live aircraft overhead (OpenSky).
        let mut near = ctx.finding("Wikipedia", "nearby", "Nearby notable places").category("geo")
            .url(format!("https://en.wikipedia.org/wiki/Special:Nearby#/coord/{lat},{lon}"));
        match fetch(client.get(format!("https://en.wikipedia.org/w/api.php?action=query&list=geosearch&gscoord={lat}%7C{lon}&gsradius=2000&gslimit=10&format=json")).header("User-Agent", NOMINATIM_UA)).await {
            Err((e, ms)) => { near.elapsed_ms = ms; near = near.error(e); }
            Ok(res) => {
                near.elapsed_ms = res.elapsed_ms;
                near.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                let places: Vec<Value> = v["query"]["geosearch"].as_array().cloned().unwrap_or_default();
                let names: Vec<String> = places.iter().map(|p| format!("{} ({:.0} m)", p["title"].as_str().unwrap_or("?"), p["dist"].as_f64().unwrap_or(0.0))).collect();
                near = near.status(if places.is_empty() { FindingStatus::NotFound } else { FindingStatus::Info })
                    .summary(if names.is_empty() { "no Wikipedia-listed places within 2 km".to_string() } else { format!("within 2 km: {}", names.join(", ")) })
                    .data(json!({ "places": places.iter().map(|p| json!({ "title": p["title"], "distanceM": p["dist"], "lat": p["lat"], "lon": p["lon"], "url": format!("https://en.wikipedia.org/?curid={}", p["pageid"]) })).collect::<Vec<_>>() }));
            }
        }
        ctx.emit(near);

        let (lamin, lamax, lomin, lomax) = (lat - 0.25, lat + 0.25, lon - 0.35, lon + 0.35);
        let mut air = ctx.finding("OpenSky Network", "aircraft", "Aircraft overhead right now").category("geo")
            .url(format!("https://globe.adsbexchange.com/?lat={lat}&lon={lon}&zoom=9"));
        match fetch(client.get(format!("https://opensky-network.org/api/states/all?lamin={lamin}&lomin={lomin}&lamax={lamax}&lomax={lomax}")).header("User-Agent", NOMINATIM_UA)).await {
            Err((e, ms)) => { air.elapsed_ms = ms; air = air.error(e); }
            Ok(res) => {
                air.elapsed_ms = res.elapsed_ms;
                air.http_status = Some(res.status);
                let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                let states: Vec<Value> = v["states"].as_array().cloned().unwrap_or_default();
                let rows: Vec<Value> = states.iter().map(|s| json!({
                    "icao24": s[0], "callsign": s[1].as_str().map(str::trim), "country": s[2], "lon": s[5], "lat": s[6], "altitudeM": s[7], "onGround": s[8], "velocityMs": s[9], "heading": s[10]
                })).collect();
                let calls: Vec<String> = rows.iter().filter_map(|r| r["callsign"].as_str().map(str::to_string)).filter(|c| !c.is_empty()).take(8).collect();
                air = air.status(if res.status == 200 { FindingStatus::Info } else { FindingStatus::Ambiguous })
                    .summary(if res.status != 200 { format!("OpenSky answered HTTP {} (anonymous quota is small)", res.status) } else if rows.is_empty() { "no ADS-B aircraft in a ~50 km box at this moment".to_string() } else { format!("{} aircraft in a ~50 km box: {}", rows.len(), calls.join(", ")) })
                    .data(json!({ "time": v["time"], "box": { "lamin": lamin, "lamax": lamax, "lomin": lomin, "lomax": lomax }, "aircraft": rows }));
            }
        }
        ctx.emit(air);
    }
    if let Some(p) = planned {
        launchers::emit(&ctx, &p);
    }
    Ok(())
}
