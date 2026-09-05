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
    // geocode/reverse (1) + launchers (unknown until geocoded: assume the catalog size)
    ctx.start(1 + planned.as_ref().map(|p| p.len()).unwrap_or_else(|| launchers::for_type(EntityType::Location).len()));

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

    if let Some(p) = planned {
        launchers::emit(&ctx, &p);
    }
    let _ = point;
    Ok(())
}
