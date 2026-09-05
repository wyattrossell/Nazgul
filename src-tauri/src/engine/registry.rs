//! Tracks running scans so the UI can cancel them.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct ScanRegistry {
    inner: Mutex<HashMap<String, CancellationToken>>,
}

impl ScanRegistry {
    pub fn register(&self, scan_id: &str) -> CancellationToken {
        let token = CancellationToken::new();
        self.inner
            .lock()
            .expect("registry lock")
            .insert(scan_id.to_string(), token.clone());
        token
    }

    /// Returns true if a scan with this id was running.
    pub fn cancel(&self, scan_id: &str) -> bool {
        match self.inner.lock().expect("registry lock").get(scan_id) {
            Some(token) => {
                token.cancel();
                true
            }
            None => false,
        }
    }

    pub fn remove(&self, scan_id: &str) {
        self.inner.lock().expect("registry lock").remove(scan_id);
    }

    #[allow(dead_code)] // surfaced in the top bar once the cases UI lands
    pub fn running(&self) -> usize {
        self.inner.lock().expect("registry lock").len()
    }
}
