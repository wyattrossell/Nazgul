//! Integration tests. Network tests hit real sites.

use std::sync::{Arc, Mutex};

use nazgul_lib::db::Db;
use nazgul_lib::engine::http::{build_client, HttpOptions};
use nazgul_lib::probes::username::{check_site, CATALOG};
use nazgul_lib::probes::{
    run_scan, EntityType, Finding, FindingStatus, ProbeKind, ScanDone, ScanOptions, ScanRequest, ScanSink,
    ScanStarted,
};
use tokio_util::sync::CancellationToken;

fn site(name: &str) -> &'static nazgul_lib::probes::username::WmnSite {
    CATALOG
        .sites
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("site {name} missing from catalog"))
}

fn template(source: &str) -> Finding {
    Finding::new("test", ProbeKind::Username, source, "profile", source)
}

#[test]
fn catalog_loads_with_hundreds_of_sites() {
    assert!(CATALOG.sites.len() > 500, "got {}", CATALOG.sites.len());
    assert!(CATALOG.license.contains("Creative Commons"));
}

#[tokio::test]
async fn github_known_account_is_found() {
    let client = build_client(&HttpOptions::default()).unwrap();
    let f = check_site(&client, site("GitHub (User)"), "torvalds", template("GitHub (User)")).await;
    assert_eq!(f.status, FindingStatus::Found, "{f:?}");
    assert!(f.url.as_deref().unwrap_or("").contains("torvalds"));
}

#[tokio::test]
async fn github_random_account_is_not_found() {
    let client = build_client(&HttpOptions::default()).unwrap();
    let f = check_site(
        &client,
        site("GitHub (User)"),
        "nazgul-no-such-user-9f3k2q8x",
        template("GitHub (User)"),
    )
    .await;
    assert_eq!(f.status, FindingStatus::NotFound, "{f:?}");
}

// ---------------------------------------------------------------------------
// Full scan through the scheduler
// ---------------------------------------------------------------------------

#[derive(Default)]
struct Recorder {
    started: Mutex<Vec<ScanStarted>>,
    findings: Mutex<Vec<Finding>>,
    done: Mutex<Vec<ScanDone>>,
}

impl ScanSink for Recorder {
    fn started(&self, e: &ScanStarted) {
        self.started.lock().unwrap().push(e.clone());
    }
    fn finding(&self, f: &Finding) {
        self.findings.lock().unwrap().push(f.clone());
    }
    fn done(&self, e: &ScanDone) {
        self.done.lock().unwrap().push(e.clone());
    }
}

fn coding_request(account: &str) -> ScanRequest {
    ScanRequest {
        probe: ProbeKind::Username,
        input: account.to_string(),
        case_id: 0,
        options: ScanOptions {
            categories: vec!["coding".to_string()],
            concurrency: 20,
            timeout_secs: 10,
            ..ScanOptions::default()
        },
    }
}

#[tokio::test]
async fn coding_category_scan_streams_every_site_then_finishes() {
    let rec = Arc::new(Recorder::default());
    let sink: Arc<dyn ScanSink> = rec.clone();
    let done = run_scan(sink, "t1".into(), coding_request("torvalds"), CancellationToken::new())
        .await
        .unwrap();

    let started = rec.started.lock().unwrap();
    let findings = rec.findings.lock().unwrap();
    assert_eq!(started.len(), 1);
    let total = started[0].total;
    assert!(total > 10, "coding category should have many sites, got {total}");
    assert_eq!(findings.len(), total, "one finding per site");
    assert_eq!(done.checked, total);
    assert!(!done.cancelled);
    assert!(done.found >= 1, "torvalds should be found on GitHub at least: {done:?}");
    let github = findings.iter().find(|f| f.source == "GitHub (User)").expect("github finding");
    assert_eq!(github.status, FindingStatus::Found);
    assert_eq!(rec.done.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn cancelling_stops_the_scan_early() {
    let rec = Arc::new(Recorder::default());
    let sink: Arc<dyn ScanSink> = rec.clone();
    let token = CancellationToken::new();
    let canceller = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        canceller.cancel();
    });
    let done = run_scan(sink, "t2".into(), coding_request("torvalds"), token).await.unwrap();
    assert!(done.cancelled);
    assert!(done.checked < done.total, "cancel should stop before all {} sites", done.total);
}

#[tokio::test]
async fn invalid_input_reports_an_error_and_still_finishes() {
    let rec = Arc::new(Recorder::default());
    let sink: Arc<dyn ScanSink> = rec.clone();
    let req = ScanRequest {
        probe: ProbeKind::Crypto,
        input: "1BoatSLRHtKNngkdXEeobR76b53LETtpyX".to_string(),
        case_id: 0,
        options: ScanOptions::default(),
    };
    let result = run_scan(sink, "t3".into(), req, CancellationToken::new()).await;
    assert!(result.is_err());
    assert_eq!(rec.done.lock().unwrap().len(), 1, "done is emitted even on failure");
}

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

#[test]
fn database_round_trips_cases_entities_scans_and_findings() {
    let db = Db::open_in_memory().unwrap();

    let cases = db.list_cases().unwrap();
    assert_eq!(cases.len(), 1, "a default case exists");
    let case = db.create_case("acme", "test case").unwrap();

    let jdoe = db.upsert_entity(case.id, EntityType::Username, "jdoe", None).unwrap();
    let again = db.upsert_entity(case.id, EntityType::Username, "jdoe", Some("John")).unwrap();
    assert_eq!(jdoe, again, "upsert is idempotent");

    db.insert_scan("s1", case.id, Some(jdoe), ProbeKind::Username, "jdoe", &serde_json::json!({}))
        .unwrap();
    db.set_scan_total("s1", 3).unwrap();

    let mut f = Finding::new("s1", ProbeKind::Username, "GitHub (User)", "profile", "GitHub (User)")
        .url("https://github.com/jdoe")
        .status(FindingStatus::Found)
        .discover(EntityType::Email, "jdoe@example.com", Some("commit email"));
    f.category = "coding".into();
    db.insert_finding(case.id, Some(jdoe), &f).unwrap();
    let email = db.upsert_entity(case.id, EntityType::Email, "jdoe@example.com", None).unwrap();
    db.add_link(case.id, jdoe, email, "GitHub (User):profile", Some("s1")).unwrap();
    db.finish_scan("s1", "done", 3, 1, 1234, None).unwrap();

    let scans = db.list_scans(Some(case.id), 50).unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].status, "done");
    assert_eq!(scans[0].found, 1);
    assert_eq!(scans[0].case_name, "acme");

    let findings = db.list_findings("s1").unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].discovered.len(), 1);
    assert_eq!(findings[0].category, "coding");

    let entities = db.list_entities(case.id).unwrap();
    assert_eq!(entities.len(), 2);
    db.set_tags(jdoe, &["Target".into(), "  ".into(), "verified".into()]).unwrap();
    let entities = db.list_entities(case.id).unwrap();
    let e = entities.iter().find(|e| e.id == jdoe).unwrap();
    assert_eq!(e.tags, vec!["target", "verified"]);
    assert_eq!(e.found_count, 1);

    let note = db.add_note(case.id, Some(jdoe), "primary handle").unwrap();
    assert_eq!(db.list_notes(case.id, Some(jdoe)).unwrap().len(), 1);
    assert_eq!(db.list_notes(case.id, None).unwrap().len(), 0);
    db.delete_note(note.id).unwrap();

    let graph = db.graph(case.id, 100).unwrap();
    assert_eq!(graph.nodes.len(), 3, "two entities + one profile node");
    assert_eq!(graph.edges.len(), 2, "one link + one profile edge");

    db.delete_case(case.id).unwrap();
    assert_eq!(db.list_scans(None, 50).unwrap().len(), 0, "cascade removed the scan");
    assert_eq!(db.list_cases().unwrap().len(), 1);
}
