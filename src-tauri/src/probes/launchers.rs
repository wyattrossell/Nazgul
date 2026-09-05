//! Launcher catalog shared by the probes and the Toolbox page (data/launchers.json).
//! A launcher is a site the user opens by hand, prefilled with the identifier when the
//! site supports a query URL, or with a "paste it" note when it does not.

use std::collections::HashMap;
use std::sync::Arc;

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::email::urlencode;
use super::{EntityType, FindingStatus, ScanContext};

static RAW: &str = include_str!("../../../data/launchers.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Launcher {
    pub name: String,
    pub category: String,
    pub types: Vec<EntityType>,
    pub url: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub paste: bool,
}

#[derive(Deserialize)]
struct File {
    launchers: Vec<Launcher>,
}

pub static CATALOG: Lazy<Vec<Launcher>> = Lazy::new(|| {
    serde_json::from_str::<File>(RAW).expect("data/launchers.json must parse").launchers
});

pub type Vars = HashMap<&'static str, String>;

/// Fills `{var}` placeholders. Returns None when a placeholder has no value.
pub fn render(template: &str, vars: &Vars) -> Option<String> {
    let mut out = String::with_capacity(template.len() + 32);
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after.find('}')?;
        let key = &after[..end];
        out.push_str(vars.get(key)?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

pub fn for_type(t: EntityType) -> Vec<&'static Launcher> {
    CATALOG.iter().filter(|l| l.types.contains(&t)).collect()
}

/// (launcher, url) pairs that can actually be rendered with the given variables.
pub fn plan(t: EntityType, vars: &Vars) -> Vec<(&'static Launcher, String)> {
    for_type(t)
        .into_iter()
        .filter_map(|l| render(&l.url, vars).map(|u| (l, u)))
        .collect()
}

pub fn emit(ctx: &Arc<ScanContext>, planned: &[(&Launcher, String)]) {
    for (l, url) in planned {
        let summary = if l.paste {
            format!("{} · paste the value on the page", l.note)
        } else {
            l.note.clone()
        };
        ctx.emit(
            ctx.finding(&l.name, "launcher", &l.name)
                .category(l.category.clone())
                .status(FindingStatus::Info)
                .url(url.clone())
                .summary(summary)
                .data(json!({ "paste": l.paste, "types": l.types })),
        );
    }
}

// ---------------------------------------------------------------------------
// Variable builders
// ---------------------------------------------------------------------------

fn base(raw: &str) -> Vars {
    let mut v: Vars = HashMap::new();
    v.insert("raw", raw.to_string());
    v.insert("q", urlencode(raw));
    v
}

pub fn vars_username(handle: &str) -> Vars {
    let mut v = base(handle);
    v.insert("handle", handle.to_string());
    v
}

pub fn vars_email(email: &str) -> Vars {
    base(email)
}

pub fn vars_domain(domain: &str) -> Vars {
    let mut v = base(domain);
    v.insert("domain", domain.to_string());
    v
}

pub fn vars_ip(ip: &str) -> Vars {
    let mut v = base(ip);
    v.insert("ip", ip.to_string());
    v
}

pub fn vars_org(name: &str) -> Vars {
    base(name)
}

pub fn vars_wallet(addr: &str) -> Vars {
    base(addr)
}

pub fn vars_image(path: &str) -> Vars {
    base(path)
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

pub fn vars_person(name: &str) -> Vars {
    let mut v = base(name);
    let tokens: Vec<String> = name
        .split_whitespace()
        .map(|t| t.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    if let (Some(first), Some(last)) = (tokens.first(), tokens.last()) {
        if tokens.len() >= 2 {
            v.insert("first", first.clone());
            v.insert("last", last.clone());
            v.insert("First", capitalize(first));
            v.insert("Last", capitalize(last));
        }
    }
    v
}

/// `digits` is the E.164 number without the plus; `national` the national significant number.
pub fn vars_phone(e164: &str, national: &str) -> Vars {
    let mut v = base(e164);
    let digits: String = e164.chars().filter(|c| c.is_ascii_digit()).collect();
    let nat: String = national.chars().filter(|c| c.is_ascii_digit()).collect();
    v.insert("digits", digits);
    if nat.len() == 10 {
        v.insert("nd", format!("{}-{}-{}", &nat[..3], &nat[3..6], &nat[6..]));
    }
    v.insert("national", nat);
    v
}

pub fn vars_location(lat: f64, lon: f64) -> Vars {
    let mut v = base(&format!("{lat},{lon}"));
    v.insert("lat", format!("{lat:.6}"));
    v.insert("lon", format!("{lon:.6}"));
    v.insert("latabs", format!("{:.6}", lat.abs()));
    v.insert("lonabs", format!("{:.6}", lon.abs()));
    v.insert("ns", if lat < 0.0 { "S" } else { "N" }.to_string());
    v.insert("ew", if lon < 0.0 { "W" } else { "E" }.to_string());
    v
}
