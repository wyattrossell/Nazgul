//! Keyless profile cards and free APIs that need no key.

use std::sync::{Arc, Mutex};

use nazgul_lib::engine::secrets::{status, KEYS};
use nazgul_lib::probes::{
    run_scan, EntityType, Finding, FindingStatus, ProbeKind, ScanDone, ScanOptions, ScanRequest, ScanSink, ScanStarted,
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Recorder {
    findings: Mutex<Vec<Finding>>,
}

impl ScanSink for Recorder {
    fn started(&self, _: &ScanStarted) {}
    fn finding(&self, f: &Finding) {
        self.findings.lock().unwrap().push(f.clone());
    }
    fn done(&self, _: &ScanDone) {}
}

async fn run(probe: ProbeKind, input: &str, categories: Vec<String>) -> Vec<Finding> {
    let rec = Arc::new(Recorder::default());
    let sink: Arc<dyn ScanSink> = rec.clone();
    let req = ScanRequest {
        probe,
        input: input.to_string(),
        case_id: 0,
        options: ScanOptions {
            categories,
            timeout_secs: 20,
            ..ScanOptions::default()
        },
    };
    run_scan(sink, "e".into(), req, CancellationToken::new()).await.unwrap();
    let out = rec.findings.lock().unwrap().clone();
    out
}

#[test]
fn every_key_has_a_signup_link_and_tier_note() {
    assert!(KEYS.len() >= 20, "{}", KEYS.len());
    for (name, label, description, url, free) in KEYS {
        assert!(url.starts_with("https://"), "{name}: {url}");
        assert!(!label.is_empty() && !description.is_empty() && !free.is_empty(), "{name}");
    }
    let st = status();
    assert_eq!(st.len(), KEYS.len());
    let free = st.iter().filter(|s| !s.free.to_lowercase().starts_with("paid")).count();
    assert!(free >= KEYS.len() - 1, "only HIBP is paid: {free} free of {}", KEYS.len());
}

#[tokio::test]
async fn username_cards_pull_github_hn_and_keybase_profiles() {
    let findings = run(ProbeKind::Username, "torvalds", vec!["archived".into()]).await;
    let github = findings.iter().find(|f| f.source == "GitHub" && f.kind == "card").expect("GitHub card");
    assert!(matches!(github.status, FindingStatus::Found | FindingStatus::Ambiguous), "{github:?}");
    if github.status == FindingStatus::Found {
        assert!(github.summary.as_deref().unwrap_or("").contains("Linus"), "{github:?}");
        assert!(github.discovered.iter().any(|d| d.entity_type == EntityType::Person));
    }
    assert!(findings.iter().any(|f| f.source == "Hacker News" && f.kind == "card"));
    let keybase = findings.iter().find(|f| f.source == "Keybase" && f.kind == "card").expect("Keybase card");
    assert!(matches!(keybase.status, FindingStatus::Found | FindingStatus::NotFound), "{keybase:?}");
    assert!(findings.iter().any(|f| f.source == "Gravatar" && f.kind == "card"));
}

#[tokio::test]
async fn keybase_card_exposes_proofs_as_pivots() {
    let findings = run(ProbeKind::Username, "chris", vec!["archived".into()]).await;
    let keybase = findings.iter().find(|f| f.source == "Keybase" && f.kind == "card").unwrap();
    assert_eq!(keybase.status, FindingStatus::Found, "{keybase:?}");
    assert!(keybase.summary.as_deref().unwrap_or("").contains("Chris Coyne"), "{keybase:?}");
    assert!(keybase.discovered.iter().any(|d| d.entity_type == EntityType::Person));
}

#[tokio::test]
async fn hackernews_card_reads_karma() {
    let findings = run(ProbeKind::Username, "pg", vec!["archived".into()]).await;
    let hn = findings.iter().find(|f| f.source == "Hacker News" && f.kind == "card").unwrap();
    assert_eq!(hn.status, FindingStatus::Found, "{hn:?}");
    assert!(hn.summary.as_deref().unwrap_or("").contains("karma"));
    assert!(hn.summary.as_deref().unwrap_or("").contains("since 2006"), "{hn:?}");
}

#[tokio::test]
async fn email_probe_runs_leakcheck_without_a_key() {
    let findings = run(ProbeKind::Email, "test@example.com", vec![]).await;
    let leak = findings.iter().find(|f| f.source == "LeakCheck").expect("LeakCheck finding");
    assert!(matches!(leak.status, FindingStatus::Found | FindingStatus::NotFound | FindingStatus::Info | FindingStatus::Error), "{leak:?}");
    if leak.status == FindingStatus::Found {
        assert!(leak.summary.as_deref().unwrap_or("").contains("record"), "{leak:?}");
    }
}

#[tokio::test]
async fn domain_probe_runs_urlscan_and_otx_without_keys() {
    let findings = run(ProbeKind::Domain, "example.com", vec![]).await;
    assert!(findings.iter().any(|f| f.source == "urlscan.io"), "urlscan finding present");
    assert!(findings.iter().any(|f| f.source == "AlienVault OTX"), "OTX finding present");
}
