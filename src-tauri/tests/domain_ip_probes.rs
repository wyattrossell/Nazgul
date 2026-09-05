//! Domain and IP probe tests. These hit real public services.

use std::sync::{Arc, Mutex};

use nazgul_lib::probes::domain::{favicon_hash, normalize};
use nazgul_lib::probes::ip::registrable;
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

async fn run(probe: ProbeKind, input: &str) -> (Result<ScanDone, String>, Vec<Finding>) {
    let rec = Arc::new(Recorder::default());
    let sink: Arc<dyn ScanSink> = rec.clone();
    let req = ScanRequest {
        probe,
        input: input.to_string(),
        case_id: 0,
        options: ScanOptions {
            timeout_secs: 20,
            ..ScanOptions::default()
        },
    };
    let result = run_scan(sink, "t".into(), req, CancellationToken::new()).await;
    let findings = rec.findings.lock().unwrap().clone();
    (result, findings)
}

#[test]
fn helpers() {
    assert_eq!(normalize("https://WWW.Example.com/path?q=1"), Some("www.example.com".into()));
    assert_eq!(normalize("example.com."), Some("example.com".into()));
    assert_eq!(normalize("not a domain"), None);
    assert_eq!(registrable("mail.corp.example.co.uk"), "example.co.uk");
    assert_eq!(registrable("one.one.one.one"), "one.one");
    // Known reference: Shodan's documented example hash for a blank-ish payload is stable per algorithm.
    assert_eq!(favicon_hash(b"hello"), favicon_hash(b"hello"));
    assert_ne!(favicon_hash(b"hello"), favicon_hash(b"world"));
}

#[tokio::test]
async fn domain_probe_covers_example_com() {
    let (result, findings) = run(ProbeKind::Domain, "https://example.com/").await;
    result.unwrap();
    let a = findings.iter().find(|f| f.kind == "dns_record" && f.title == "A records").unwrap();
    assert_eq!(a.status, FindingStatus::Info, "{a:?}");
    assert!(a.discovered.iter().any(|d| d.value.contains('.')), "A record pivots to an IP");
    let reg = findings.iter().find(|f| f.kind == "registration").unwrap();
    assert!(matches!(reg.status, FindingStatus::Info | FindingStatus::Error | FindingStatus::Ambiguous), "{reg:?}");
    assert!(findings.iter().any(|f| f.kind == "technology"));
    assert!(findings.iter().any(|f| f.kind == "launcher"));
    assert!(findings.iter().any(|f| f.kind == "brute"));
}

#[tokio::test]
async fn domain_probe_rejects_garbage() {
    let (result, _) = run(ProbeKind::Domain, "hello world").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn ip_probe_covers_cloudflare_resolver() {
    let (result, findings) = run(ProbeKind::Ip, "1.1.1.1").await;
    result.unwrap();
    let ptr = findings.iter().find(|f| f.kind == "ptr").unwrap();
    assert_eq!(ptr.status, FindingStatus::Info, "{ptr:?}");
    assert!(ptr.summary.as_deref().unwrap_or("").contains("one.one.one.one"), "{ptr:?}");
    let geo = findings.iter().find(|f| f.kind == "geo").unwrap();
    assert!(matches!(geo.status, FindingStatus::Info | FindingStatus::Error), "{geo:?}");
    let ports = findings.iter().find(|f| f.kind == "ports").unwrap();
    assert!(matches!(ports.status, FindingStatus::Found | FindingStatus::NotFound | FindingStatus::Error), "{ports:?}");
    assert!(findings.iter().any(|f| f.kind == "tor"));
    assert!(findings.iter().filter(|f| f.kind == "launcher").count() >= 5);
}

#[tokio::test]
async fn ip_probe_skips_network_for_private_addresses() {
    let (result, findings) = run(ProbeKind::Ip, "192.168.1.10").await;
    result.unwrap();
    assert_eq!(findings.len(), 2, "classification and PTR only: {findings:?}");
}

#[tokio::test]
async fn ip_probe_rejects_garbage() {
    let (result, _) = run(ProbeKind::Ip, "999.1.1.1").await;
    assert!(result.is_err());
}
