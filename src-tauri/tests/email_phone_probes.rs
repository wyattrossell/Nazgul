//! Email and phone probe tests. Some hit the network (DNS, Gravatar).

use std::sync::{Arc, Mutex};

use nazgul_lib::probes::email::{gravatar_hash, split, username_candidates};
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

async fn run(probe: ProbeKind, input: &str, extra: serde_json::Value) -> (Result<ScanDone, String>, Vec<Finding>) {
    let rec = Arc::new(Recorder::default());
    let sink: Arc<dyn ScanSink> = rec.clone();
    let req = ScanRequest {
        probe,
        input: input.to_string(),
        case_id: 0,
        options: ScanOptions {
            timeout_secs: 10,
            extra,
            ..ScanOptions::default()
        },
    };
    let result = run_scan(sink, "t".into(), req, CancellationToken::new()).await;
    let findings = rec.findings.lock().unwrap().clone();
    (result, findings)
}

#[test]
fn email_helpers() {
    assert_eq!(split("John.Doe+news@Example.com"), Some(("John.Doe+news".into(), "example.com".into())));
    assert_eq!(split("nope"), None);
    let c = username_candidates("john.doe+news");
    assert!(c.contains(&"john.doe".to_string()));
    assert!(c.contains(&"johndoe".to_string()));
    assert!(c.contains(&"john_doe".to_string()));
    assert_eq!(gravatar_hash(" MyEmailAddress@example.com "), "0bc83cb571cd1c50ba6f3e8a78ef1346");
}

#[tokio::test]
async fn email_probe_flags_disposable_domain_and_pivots() {
    let (result, findings) = run(ProbeKind::Email, "someone@mailinator.com", serde_json::Value::Null).await;
    result.unwrap();
    let disposable = findings.iter().find(|f| f.kind == "disposable").unwrap();
    assert_eq!(disposable.status, FindingStatus::Found);
    let parsed = findings.iter().find(|f| f.kind == "address").unwrap();
    assert!(parsed.discovered.iter().any(|d| d.value == "mailinator.com"));
    assert!(parsed.discovered.iter().any(|d| d.value == "someone"));
    assert!(findings.iter().any(|f| f.kind == "registration"), "registration checks ran");
}

#[tokio::test]
async fn email_probe_reads_gmail_mail_posture() {
    let (result, findings) = run(ProbeKind::Email, "nazgul-test-9f3k2q8x@gmail.com", serde_json::Value::Null).await;
    result.unwrap();
    let mx = findings.iter().find(|f| f.kind == "mx").unwrap();
    assert_eq!(mx.status, FindingStatus::Info, "{mx:?}");
    assert!(mx.summary.as_deref().unwrap_or("").contains("Google"), "{mx:?}");
    let spf = findings.iter().find(|f| f.kind == "spf").unwrap();
    assert_eq!(spf.status, FindingStatus::Info, "{spf:?}");
    let dmarc = findings.iter().find(|f| f.kind == "dmarc").unwrap();
    assert_eq!(dmarc.status, FindingStatus::Info, "{dmarc:?}");
    let gravatar = findings.iter().find(|f| f.source == "Gravatar").unwrap();
    assert_eq!(gravatar.status, FindingStatus::NotFound, "{gravatar:?}");
}

#[tokio::test]
async fn email_probe_rejects_garbage() {
    let (result, _) = run(ProbeKind::Email, "not an email", serde_json::Value::Null).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn phone_probe_parses_a_us_number() {
    let (result, findings) = run(ProbeKind::Phone, "+1 415 555 2671", serde_json::Value::Null).await;
    result.unwrap();
    let parsed = findings.iter().find(|f| f.kind == "number").unwrap();
    assert_eq!(parsed.data["e164"], "+14155552671");
    assert_eq!(parsed.data["region"], "US");
    assert_eq!(parsed.data["countryCode"], 1);
    assert!(findings.iter().any(|f| f.kind == "launcher" && f.url.as_deref().unwrap_or("").contains("wa.me/14155552671")));
}

#[tokio::test]
async fn phone_probe_uses_default_region_for_national_numbers() {
    let (result, findings) = run(ProbeKind::Phone, "020 7946 0018", serde_json::json!({ "region": "GB" })).await;
    result.unwrap();
    let parsed = findings.iter().find(|f| f.kind == "number").unwrap();
    assert_eq!(parsed.data["e164"], "+442079460018");
    assert_eq!(parsed.data["region"], "GB");
}

#[tokio::test]
async fn phone_probe_rejects_garbage() {
    let (result, _) = run(ProbeKind::Phone, "hello", serde_json::Value::Null).await;
    assert!(result.is_err());
}
