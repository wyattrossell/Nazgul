//! Shared engine pieces: HTTP client construction and the running-scan registry.

pub mod dns;
pub mod http;
pub mod registry;
pub mod secrets;

pub use registry::ScanRegistry;
