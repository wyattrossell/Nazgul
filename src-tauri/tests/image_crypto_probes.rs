//! Image and crypto probe tests. Crypto balance tests hit public explorers.

use std::sync::{Arc, Mutex};

use nazgul_lib::probes::crypto::{base58check, bech32_check, classify, eip55_ok, Chain};
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
fn address_validation() {
    // Satoshi's genesis address (P2PKH).
    assert_eq!(base58check("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"), Some(0x00));
    assert_eq!(base58check("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"), None, "typo breaks the checksum");
    let c = classify("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap();
    assert_eq!(c.chain, Chain::Bitcoin);
    assert_eq!(c.format, "legacy (P2PKH)");

    // BIP-173 test vector.
    let (hrp, ver, variant) = bech32_check("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    assert_eq!((hrp.as_str(), ver, variant), ("bc", 0, "bech32"));
    assert_eq!(classify("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap().format, "native segwit (P2WPKH)");
    // BIP-350 taproot vector.
    let t = classify("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0").unwrap();
    assert_eq!(t.format, "taproot (P2TR)");

    assert_eq!(classify("LdP8Qox1VAhCzLJNqrr74YovaWYyNBUWvL").map(|c| c.chain), Some(Chain::Litecoin));

    // EIP-55 example.
    assert_eq!(eip55_ok("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"), Some(true));
    assert_eq!(eip55_ok("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"), None);
    assert_eq!(eip55_ok("0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"), Some(false));
    assert_eq!(classify("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap().chain, Chain::Ethereum);

    assert!(classify("hello").is_none());
}

#[tokio::test]
async fn crypto_probe_reads_the_genesis_address() {
    let (result, findings) = run(ProbeKind::Crypto, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").await;
    result.unwrap();
    let balance = findings.iter().find(|f| f.kind == "balance").unwrap();
    assert!(matches!(balance.status, FindingStatus::Found | FindingStatus::Error | FindingStatus::Ambiguous), "{balance:?}");
    if balance.status == FindingStatus::Found {
        assert!(balance.summary.as_deref().unwrap_or("").contains("BTC"));
    }
    assert!(findings.iter().filter(|f| f.kind == "launcher").count() >= 2);
}

#[tokio::test]
async fn crypto_probe_rejects_bad_checksum() {
    let (result, _) = run(ProbeKind::Crypto, "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn image_probe_reads_exif_fixture() {
    let path = format!("{}/tests/fixtures/exif.jpg", env!("CARGO_MANIFEST_DIR"));
    let (result, findings) = run(ProbeKind::Image, &path).await;
    result.unwrap();
    let dims = findings.iter().find(|f| f.kind == "dimensions").unwrap();
    assert_eq!(dims.summary.as_deref(), Some("64 × 48 px"));
    let exif = findings.iter().find(|f| f.kind == "exif").unwrap();
    assert_eq!(exif.status, FindingStatus::Found, "{exif:?}");
    let camera = findings.iter().find(|f| f.kind == "camera").unwrap();
    assert!(camera.summary.as_deref().unwrap_or("").contains("TestCam"), "{camera:?}");
    let ts = findings.iter().find(|f| f.kind == "timestamp").unwrap();
    assert!(ts.summary.as_deref().unwrap_or("").starts_with("2024"), "{ts:?}");
    let gps = findings.iter().find(|f| f.kind == "gps").unwrap();
    assert_eq!(gps.status, FindingStatus::NotFound);
    assert!(findings.iter().any(|f| f.kind == "hashes"));
    assert!(findings.iter().filter(|f| f.kind == "launcher").count() >= 4, "reverse-image plus catalog tools");
    assert!(findings.iter().any(|f| f.source == "TinEye"));
}

#[tokio::test]
async fn image_probe_rejects_missing_file() {
    let (result, _) = run(ProbeKind::Image, "C:/definitely/not/here.jpg").await;
    assert!(result.is_err());
}
