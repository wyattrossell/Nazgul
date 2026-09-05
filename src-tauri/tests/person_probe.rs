//! Name probe and payment helper tests. The payment handle checks hit live sites.

use std::sync::{Arc, Mutex};

use nazgul_lib::probes::payments::{handle_check_count, handle_sites};
use nazgul_lib::probes::person::handle_candidates;
use nazgul_lib::probes::{
    run_scan, Finding, FindingStatus, ProbeKind, ScanDone, ScanOptions, ScanRequest, ScanSink, ScanStarted,
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

#[test]
fn candidates_cover_the_usual_handle_shapes() {
    let c = handle_candidates("John Ronald Doe");
    for expected in ["johndoe", "john.doe", "john_doe", "jdoe", "johnd", "doejohn", "johnronalddoe", "jrdoe"] {
        assert!(c.contains(&expected.to_string()), "missing {expected} in {c:?}");
    }
    assert!(c.len() <= 14);
    assert_eq!(handle_candidates("Cher"), vec!["cher".to_string()]);
    assert!(handle_candidates("").is_empty());
}

#[test]
fn payment_sites_come_from_the_catalog() {
    let sites = handle_sites();
    let names: Vec<&str> = sites.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"Venmo") && names.contains(&"PayPal.Me") && names.contains(&"Revolut"), "{names:?}");
    assert_eq!(handle_check_count(4), sites.len() * 4);
}

#[tokio::test]
async fn name_probe_emits_candidates_launchers_and_payment_checks() {
    let rec = Arc::new(Recorder::default());
    let sink: Arc<dyn ScanSink> = rec.clone();
    let req = ScanRequest {
        probe: ProbeKind::Person,
        input: "Linus Torvalds".to_string(),
        case_id: 0,
        options: ScanOptions {
            timeout_secs: 15,
            ..ScanOptions::default()
        },
    };
    let done = run_scan(sink, "n1".into(), req, CancellationToken::new()).await.unwrap();
    let findings = rec.findings.lock().unwrap();

    let cand = findings.iter().find(|f| f.kind == "handles").expect("candidates finding");
    assert!(cand.summary.as_deref().unwrap_or("").contains("linustorvalds"));
    assert_eq!(cand.discovered.len(), 3, "top three candidates pivot to the username probe");

    assert!(findings.iter().filter(|f| f.category == "people-search").count() >= 5);
    assert!(findings.iter().any(|f| f.source == "Venmo" && f.kind == "dork"));
    let payment = findings.iter().filter(|f| f.kind == "payment_profile").count();
    assert_eq!(payment, handle_check_count(handle_candidates("Linus Torvalds").len()), "one check per handle per site");
    assert!(done.checked >= done.total.saturating_sub(1), "{done:?}");
}

#[tokio::test]
async fn name_probe_rejects_non_names() {
    let rec = Arc::new(Recorder::default());
    let sink: Arc<dyn ScanSink> = rec.clone();
    let req = ScanRequest {
        probe: ProbeKind::Person,
        input: "42".to_string(),
        case_id: 0,
        options: ScanOptions::default(),
    };
    assert!(run_scan(sink, "n2".into(), req, CancellationToken::new()).await.is_err());
}

#[tokio::test]
async fn phone_probe_includes_payment_launchers() {
    let rec = Arc::new(Recorder::default());
    let sink: Arc<dyn ScanSink> = rec.clone();
    let req = ScanRequest {
        probe: ProbeKind::Phone,
        input: "+1 415 555 2671".to_string(),
        case_id: 0,
        options: ScanOptions::default(),
    };
    run_scan(sink, "n3".into(), req, CancellationToken::new()).await.unwrap();
    let findings = rec.findings.lock().unwrap();
    let venmo = findings.iter().find(|f| f.source == "Venmo" && f.kind == "manual").expect("venmo launcher");
    assert!(venmo.url.as_deref().unwrap_or("").contains("recipients=14155552671"), "{venmo:?}");
    assert!(findings.iter().any(|f| f.source == "PayPal" && f.kind == "manual"));
    assert!(findings.iter().any(|f| f.source == "Cash App"));
    assert_eq!(findings.iter().filter(|f| f.status == FindingStatus::Error).count(), 0);
}
