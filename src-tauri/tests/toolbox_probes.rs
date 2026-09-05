//! Launcher catalog, Location and Company probes, PDF / Office metadata.

use std::sync::{Arc, Mutex};

use nazgul_lib::probes::geo::parse_coordinates;
use nazgul_lib::probes::image::{office_metadata, pdf_metadata};
use nazgul_lib::probes::launchers::{for_type, plan, render, vars_location, vars_person, vars_phone, CATALOG};
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
fn catalog_loads_and_renders() {
    assert!(CATALOG.len() > 60, "{}", CATALOG.len());
    assert!(for_type(EntityType::Location).len() >= 12);
    assert!(for_type(EntityType::Person).len() >= 15);

    let v = vars_person("John Ronald Doe");
    assert_eq!(render("https://x/{first}-{last}/{First}", &v).as_deref(), Some("https://x/john-doe/John"));
    assert!(render("https://x/{nope}", &v).is_none(), "unknown variables skip the launcher");

    let p = vars_phone("+14155552671", "4155552671");
    assert_eq!(p.get("nd").map(String::as_str), Some("415-555-2671"));
    assert_eq!(p.get("digits").map(String::as_str), Some("14155552671"));

    let l = vars_location(-33.8688, 151.2093);
    assert_eq!(l.get("ns").map(String::as_str), Some("S"));
    assert_eq!(l.get("ew").map(String::as_str), Some("E"));
    let geo = plan(EntityType::Location, &l);
    assert!(geo.iter().any(|(l, u)| l.name == "GeoHack" && u.contains("33.868800_S_151.209300_E")), "{geo:?}");

    // Every catalog URL renders for its own type with representative variables.
    for l in CATALOG.iter() {
        assert!(l.url.starts_with("https://"), "{}", l.name);
        assert!(!l.types.is_empty(), "{}", l.name);
    }
}

#[test]
fn coordinates_parse_in_common_formats() {
    assert_eq!(parse_coordinates("40.7128, -74.0060"), Some((40.7128, -74.0060)));
    assert_eq!(parse_coordinates("40.7128 N 74.0060 W"), Some((40.7128, -74.0060)));
    assert_eq!(parse_coordinates("48.8584 2.2945"), Some((48.8584, 2.2945)));
    let dms = parse_coordinates("40°42'46\"N 74°00'22\"W").unwrap();
    assert!((dms.0 - 40.7128).abs() < 0.001 && (dms.1 + 74.0061).abs() < 0.001, "{dms:?}");
    assert_eq!(parse_coordinates("Eiffel Tower"), None);
    assert_eq!(parse_coordinates("95, 10"), None, "latitude out of range");
}

#[tokio::test]
async fn location_probe_reverse_geocodes_and_launches() {
    let (result, findings) = run(ProbeKind::Geo, "48.8584, 2.2945").await;
    result.unwrap();
    let c = findings.iter().find(|f| f.kind == "coordinates").unwrap();
    assert_eq!(c.status, FindingStatus::Found);
    assert!(findings.iter().filter(|f| f.kind == "launcher").count() >= 12);
    assert!(findings.iter().any(|f| f.source == "Google Earth" && f.url.as_deref().unwrap_or("").contains("48.858400")));
}

#[tokio::test]
async fn location_probe_geocodes_a_place_name() {
    let (result, findings) = run(ProbeKind::Geo, "Eiffel Tower, Paris").await;
    result.unwrap();
    let g = findings.iter().find(|f| f.kind == "geocode").unwrap();
    assert!(matches!(g.status, FindingStatus::Found | FindingStatus::Error), "{g:?}");
    if g.status == FindingStatus::Found {
        assert!(g.discovered.iter().any(|d| d.entity_type == EntityType::Location));
        assert!(findings.iter().any(|f| f.source == "Wikimapia"));
    }
}

#[tokio::test]
async fn company_probe_emits_registers_and_dorks() {
    let (result, findings) = run(ProbeKind::Org, "Microsoft Corporation").await;
    result.unwrap();
    assert!(findings.iter().any(|f| f.kind == "companies"));
    assert!(findings.iter().any(|f| f.kind == "dorks"));
    assert!(findings.iter().any(|f| f.source == "OpenCorporates" && f.kind == "launcher"));
    assert!(findings.iter().any(|f| f.source == "Companies House"));
}

#[test]
fn pdf_and_office_metadata_extract_authors() {
    let pdf = std::fs::read(format!("{}/tests/fixtures/meta.pdf", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let m = pdf_metadata(&pdf).unwrap();
    assert_eq!(m.get("Author").and_then(|v| v.as_str()), Some("Sam Fixture"));
    assert_eq!(m.get("CreationDate").and_then(|v| v.as_str()), Some("2024-01-02 03:04:05"));
    assert_eq!(m.get("pages").and_then(|v| v.as_u64()), Some(1));

    let docx = std::fs::read(format!("{}/tests/fixtures/meta.docx", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let m = office_metadata(&docx).unwrap();
    assert_eq!(m.get("creator").and_then(|v| v.as_str()), Some("Jane Analyst"));
    assert_eq!(m.get("lastModifiedBy").and_then(|v| v.as_str()), Some("Bob Reviewer"));
    assert_eq!(m.get("Company").and_then(|v| v.as_str()), Some("Acme Widgets"));
}

#[tokio::test]
async fn file_probe_handles_documents() {
    let path = format!("{}/tests/fixtures/meta.docx", env!("CARGO_MANIFEST_DIR"));
    let (result, findings) = run(ProbeKind::Image, &path).await;
    result.unwrap();
    let doc = findings.iter().find(|f| f.kind == "document").unwrap();
    assert_eq!(doc.status, FindingStatus::Found);
    assert!(doc.discovered.iter().any(|d| d.value == "Jane Analyst" && d.entity_type == EntityType::Person));
    assert!(doc.discovered.iter().any(|d| d.value == "Acme Widgets" && d.entity_type == EntityType::Org));
    assert!(findings.iter().any(|f| f.source == "PDFYeah" || f.source == "ExtractMetadata"));
}

#[tokio::test]
async fn username_probe_now_emits_dorks_and_tools() {
    let rec = Arc::new(Recorder::default());
    let sink: Arc<dyn ScanSink> = rec.clone();
    let req = ScanRequest {
        probe: ProbeKind::Username,
        input: "torvalds".to_string(),
        case_id: 0,
        options: ScanOptions {
            categories: vec!["archived".to_string()],
            timeout_secs: 10,
            ..ScanOptions::default()
        },
    };
    run_scan(sink, "u".into(), req, CancellationToken::new()).await.unwrap();
    let findings = rec.findings.lock().unwrap();
    assert!(findings.iter().any(|f| f.kind == "dorks"));
    assert!(findings.iter().any(|f| f.source == "Redective"));
    assert!(findings.iter().any(|f| f.source == "Picuki" && f.url.as_deref().unwrap_or("").ends_with("/torvalds")));
}
