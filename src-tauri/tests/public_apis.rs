//! Free public APIs folded in from the public-apis list. All of these run without a key.

use std::sync::{Arc, Mutex};

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
            timeout_secs: 25,
            ..ScanOptions::default()
        },
    };
    run_scan(sink, "p".into(), req, CancellationToken::new()).await.unwrap();
    let out = rec.findings.lock().unwrap().clone();
    out
}

/// First non-launcher finding from a source (catalog launchers can share the source name).
fn find<'a>(findings: &'a [Finding], source: &str) -> &'a Finding {
    findings
        .iter()
        .find(|f| f.source == source && f.kind != "launcher")
        .unwrap_or_else(|| panic!("no finding from {source}"))
}

#[tokio::test]
async fn username_cards_cover_the_new_sites() {
    let findings = run(ProbeKind::Username, "thibault", vec!["archived".into()]).await;
    for source in ["GitLab", "Mastodon", "Bluesky", "Lichess", "Chess.com", "Docker Hub", "Stack Overflow", "crates.io"] {
        let f = find(&findings, source);
        assert_eq!(f.kind, "card", "{source}");
        assert!(matches!(f.status, FindingStatus::Found | FindingStatus::NotFound | FindingStatus::Ambiguous | FindingStatus::Error), "{f:?}");
    }
    let lichess = find(&findings, "Lichess");
    assert_eq!(lichess.status, FindingStatus::Found, "{lichess:?}");
    assert!(lichess.summary.as_deref().unwrap_or("").contains("games"));
}

#[tokio::test]
async fn mastodon_card_reads_gargron() {
    let findings = run(ProbeKind::Username, "Gargron", vec!["archived".into()]).await;
    let m = find(&findings, "Mastodon");
    assert_eq!(m.status, FindingStatus::Found, "{m:?}");
    assert!(m.summary.as_deref().unwrap_or("").contains("Eugen"), "{m:?}");
    assert!(m.discovered.iter().any(|d| d.entity_type == EntityType::Person));
}

#[tokio::test]
async fn name_probe_pulls_public_records() {
    let findings = run(ProbeKind::Person, "Linus Torvalds", vec![]).await;
    let wd = find(&findings, "Wikidata");
    assert_eq!(wd.status, FindingStatus::Found, "{wd:?}");
    assert!(wd.summary.as_deref().unwrap_or("").contains("Linux"), "{wd:?}");
    let fbi = find(&findings, "FBI Wanted");
    assert_eq!(fbi.status, FindingStatus::NotFound, "{fbi:?}");
    let cl = find(&findings, "CourtListener");
    assert!(matches!(cl.status, FindingStatus::Found | FindingStatus::NotFound), "{cl:?}");
    assert!(findings.iter().any(|f| f.source == "NPI Registry"));
    let fec = find(&findings, "FEC");
    assert!(matches!(fec.status, FindingStatus::Found | FindingStatus::NotFound | FindingStatus::Info), "{fec:?}");
    let nat = find(&findings, "Nationalize");
    assert_eq!(nat.status, FindingStatus::Info, "{nat:?}");
}

#[tokio::test]
async fn company_probe_pulls_nonprofits_and_donors() {
    let findings = run(ProbeKind::Org, "Red Cross", vec![]).await;
    let np = find(&findings, "ProPublica Nonprofit Explorer");
    assert_eq!(np.status, FindingStatus::Found, "{np:?}");
    assert!(np.summary.as_deref().unwrap_or("").contains("EIN"), "{np:?}");
    let fec = find(&findings, "FEC");
    assert!(matches!(fec.status, FindingStatus::Found | FindingStatus::NotFound | FindingStatus::Info), "{fec:?}");
    assert!(findings.iter().any(|f| f.source == "Wikidata"));
}

#[tokio::test]
async fn domain_probe_uses_hackertarget_certspotter_and_observatory() {
    let findings = run(ProbeKind::Domain, "example.com", vec![]).await;
    let ht = find(&findings, "HackerTarget");
    assert!(matches!(ht.status, FindingStatus::Info | FindingStatus::NotFound | FindingStatus::Error), "{ht:?}");
    let cs = find(&findings, "Cert Spotter");
    assert!(matches!(cs.status, FindingStatus::Info | FindingStatus::NotFound | FindingStatus::Error), "{cs:?}");
    let ob = find(&findings, "MDN HTTP Observatory");
    if ob.status == FindingStatus::Info {
        assert!(ob.summary.as_deref().unwrap_or("").starts_with("grade "), "{ob:?}");
    }
}

#[tokio::test]
async fn ip_probe_uses_ipwho_and_reverse_ip() {
    let findings = run(ProbeKind::Ip, "1.1.1.1", vec![]).await;
    let w = find(&findings, "ipwho.is");
    assert_eq!(w.status, FindingStatus::Info, "{w:?}");
    assert!(w.summary.as_deref().unwrap_or("").contains("AS13335"), "{w:?}");
    let rev = findings.iter().find(|f| f.kind == "reverse_ip").expect("reverse ip finding");
    assert!(matches!(rev.status, FindingStatus::Found | FindingStatus::NotFound | FindingStatus::Info | FindingStatus::Error), "{rev:?}");
}

#[tokio::test]
async fn email_probe_uses_kickbox() {
    let findings = run(ProbeKind::Email, "someone@mailinator.com", vec![]).await;
    let k = find(&findings, "Kickbox");
    assert_eq!(k.status, FindingStatus::Found, "{k:?}");
}

#[tokio::test]
async fn location_probe_lists_nearby_places_and_aircraft() {
    let findings = run(ProbeKind::Geo, "48.8584, 2.2945", vec![]).await;
    let near = find(&findings, "Wikipedia");
    assert_eq!(near.status, FindingStatus::Info, "{near:?}");
    assert!(near.summary.as_deref().unwrap_or("").contains("Eiffel"), "{near:?}");
    let air = find(&findings, "OpenSky Network");
    assert!(matches!(air.status, FindingStatus::Info | FindingStatus::Ambiguous | FindingStatus::Error), "{air:?}");
}
