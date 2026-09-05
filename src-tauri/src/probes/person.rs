//! Name probe: turn a full name into handle candidates, check them on payment sites, and
//! open people-search, social and dork launchers. Handles pivot straight into the username probe.

use std::sync::Arc;

use serde_json::json;

use super::email::urlencode;
use super::payments;
use super::{EntityType, FindingStatus, ScanContext};

fn clean_token(t: &str) -> String {
    t.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase()
}

/// Handle candidates from a name. `John Ronald Doe` -> johndoe, john.doe, john_doe, jdoe, johnd, doejohn...
pub fn handle_candidates(name: &str) -> Vec<String> {
    let tokens: Vec<String> = name.split_whitespace().map(clean_token).filter(|t| !t.is_empty()).collect();
    let mut out: Vec<String> = Vec::new();
    let mut push = |s: String| {
        if s.len() >= 3 && !out.contains(&s) {
            out.push(s);
        }
    };
    match tokens.len() {
        0 => {}
        1 => push(tokens[0].clone()),
        _ => {
            let first = &tokens[0];
            let last = &tokens[tokens.len() - 1];
            let fi = &first[..1];
            let li = &last[..1];
            push(format!("{first}{last}"));
            push(format!("{first}.{last}"));
            push(format!("{first}_{last}"));
            push(format!("{first}-{last}"));
            push(format!("{fi}{last}"));
            push(format!("{first}{li}"));
            push(format!("{fi}.{last}"));
            push(format!("{fi}_{last}"));
            push(format!("{last}{first}"));
            push(format!("{last}.{first}"));
            push(format!("{last}{fi}"));
            push(tokens.join(""));
            if tokens.len() > 2 {
                let mi = &tokens[1][..1];
                push(format!("{first}{mi}{last}"));
                push(format!("{fi}{mi}{last}"));
            }
        }
    }
    out.truncate(14);
    out
}

pub async fn run(ctx: Arc<ScanContext>) -> Result<(), String> {
    let name = ctx.input.split_whitespace().collect::<Vec<_>>().join(" ");
    if name.chars().filter(|c| c.is_alphabetic()).count() < 3 {
        return Err("Enter a person's name, e.g. John Doe.".to_string());
    }
    let candidates = handle_candidates(&name);
    let quoted = format!("\"{name}\"");
    let enc = urlencode(&name);
    let dashed = name.split(' ').map(|t| clean_token(t)).filter(|t| !t.is_empty()).collect::<Vec<_>>().join("-");
    let title_dashed: String = dashed
        .split('-')
        .map(|t| {
            let mut c = t.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-");

    let launchers: Vec<(&str, &str, &str, String, String)> = vec![
        ("dorks", "dorks", "Search engine dorks", format!("https://www.google.com/search?q={}", urlencode(&quoted)), "Exact name on Google; payment-site, social and document dorks in raw data".into()),
        ("Venmo", "dork", "Venmo profiles by name", format!("https://www.google.com/search?q={}", urlencode(&format!("{quoted} site:venmo.com"))), "Venmo has no public name search; search engines index public profiles".into()),
        ("Cash App", "dork", "Cash App profiles by name", format!("https://www.google.com/search?q={}", urlencode(&format!("{quoted} site:cash.app"))), "Indexed $cashtag pages carrying this display name".into()),
        ("PayPal", "dork", "PayPal.Me pages by name", format!("https://www.google.com/search?q={}", urlencode(&format!("{quoted} (site:paypal.me OR site:paypal.com/paypalme)"))), "Indexed PayPal.Me pages carrying this display name".into()),
        ("LinkedIn", "people", "LinkedIn people search", format!("https://www.linkedin.com/search/results/people/?keywords={enc}"), "Requires a LinkedIn login; results show employer and location".into()),
        ("Facebook", "people", "Facebook people search", format!("https://www.facebook.com/search/people/?q={enc}"), "Requires a Facebook login".into()),
        ("X", "people", "X user search", format!("https://x.com/search?q={}&f=user", urlencode(&quoted)), "Accounts whose display name matches".into()),
        ("TikTok", "people", "TikTok user search", format!("https://www.tiktok.com/search/user?q={enc}"), "Display-name matches".into()),
        ("Instagram", "dork", "Instagram by name", format!("https://www.google.com/search?q={}", urlencode(&format!("{quoted} site:instagram.com"))), "Instagram has no open name search; dork instead".into()),
        ("TruePeopleSearch", "people", "TruePeopleSearch", format!("https://www.truepeoplesearch.com/results?name={enc}"), "US public-records aggregator: age, relatives, addresses, phones".into()),
        ("FastPeopleSearch", "people", "FastPeopleSearch", format!("https://www.fastpeoplesearch.com/name/{dashed}"), "US public-records aggregator".into()),
        ("Whitepages", "people", "Whitepages", format!("https://www.whitepages.com/name/{title_dashed}"), "US directory listing".into()),
        ("Spokeo", "people", "Spokeo", format!("https://www.spokeo.com/{title_dashed}"), "Aggregated profiles (paywalled detail)".into()),
        ("ThatsThem", "people", "ThatsThem", format!("https://thatsthem.com/name/{title_dashed}"), "Free US people search".into()),
        ("Wikipedia", "reference", "Wikipedia", format!("https://en.wikipedia.org/w/index.php?search={enc}"), "Notable-person check".into()),
    ];

    ctx.start(1 + launchers.len() + payments::handle_check_count(candidates.len()));

    // Candidates finding: the top three become username entities for pivoting.
    let mut cand = ctx
        .finding("parser", "handles", "Handle candidates")
        .category("handles")
        .status(FindingStatus::Info)
        .summary(candidates.join(", "))
        .data(json!({ "name": name, "candidates": candidates }));
    for c in candidates.iter().take(3) {
        cand = cand.discover(EntityType::Username, c.clone(), Some("name variant"));
    }
    ctx.emit(cand);

    for (source, kind, title, url, summary) in &launchers {
        let mut f = ctx
            .finding(source, kind, title)
            .category(if *kind == "people" { "people-search" } else { "launchers" })
            .status(FindingStatus::Info)
            .url(url.clone())
            .summary(summary.clone());
        if *source == "dorks" {
            f.data = json!({
                "exact": url,
                "documents": format!("https://www.google.com/search?q={}", urlencode(&format!("{quoted} filetype:pdf OR filetype:docx OR filetype:xlsx"))),
                "linkedin": format!("https://www.google.com/search?q={}", urlencode(&format!("{quoted} site:linkedin.com/in"))),
                "github": format!("https://github.com/search?type=users&q={}", urlencode(&quoted)),
                "news": format!("https://news.google.com/search?q={}", urlencode(&quoted)),
                "images": format!("https://www.google.com/search?tbm=isch&q={}", urlencode(&quoted)),
            });
        }
        ctx.emit(f);
    }

    if ctx.cancelled() {
        return Ok(());
    }
    payments::check_handles(&ctx, &candidates).await;
    Ok(())
}
