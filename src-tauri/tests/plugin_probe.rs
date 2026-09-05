//! Plugin bridge test using the Windows command shell as a stand-in external tool.

use std::sync::{Arc, Mutex};

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

fn request(manifest: serde_json::Value, input: &str) -> ScanRequest {
    ScanRequest {
        probe: ProbeKind::Plugin,
        input: input.to_string(),
        case_id: 0,
        options: ScanOptions {
            extra: serde_json::json!({ "plugin": manifest["name"], "manifest": manifest }),
            ..ScanOptions::default()
        },
    }
}

#[cfg(windows)]
#[tokio::test]
async fn echo_plugin_lines_become_findings() {
    let manifest = serde_json::json!({
        "name": "echo",
        "description": "test",
        "inputTypes": ["username"],
        "command": "cmd",
        "args": ["/C", "echo [+] {input} on https://example.com/{input} && echo plain line"],
        "parse": "lines",
        "foundMarker": "[+]",
        "timeoutSecs": 30
    });
    let rec = Arc::new(Recorder::default());
    let sink: Arc<dyn ScanSink> = rec.clone();
    run_scan(sink, "p1".into(), request(manifest, "jdoe"), CancellationToken::new())
        .await
        .unwrap();
    let findings = rec.findings.lock().unwrap();
    let hit = findings.iter().find(|f| f.status == FindingStatus::Found).expect("a [+] line");
    assert_eq!(hit.url.as_deref(), Some("https://example.com/jdoe"));
    assert!(findings.iter().any(|f| f.kind == "plugin" && f.status == FindingStatus::Info && f.title == "plain line"));
    let run = findings.iter().find(|f| f.kind == "plugin-run").expect("run summary");
    assert_eq!(run.status, FindingStatus::Info, "{run:?}");
    assert_eq!(run.data["exitCode"], 0);
}

#[tokio::test]
async fn missing_plugin_command_is_a_clear_error() {
    let manifest = serde_json::json!({
        "name": "ghost",
        "command": "definitely-not-a-real-binary-9f3k2q8x",
        "args": ["{input}"],
        "parse": "lines"
    });
    let rec = Arc::new(Recorder::default());
    let sink: Arc<dyn ScanSink> = rec.clone();
    let result = run_scan(sink, "p2".into(), request(manifest, "x"), CancellationToken::new()).await;
    let err = result.err().expect("spawn failure surfaces as an error");
    assert!(err.contains("Could not start"), "{err}");
}
