//! DNS lookups shared by the email and domain probes.

use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;

pub fn resolver() -> TokioAsyncResolver {
    let mut opts = ResolverOpts::default();
    opts.timeout = std::time::Duration::from_secs(5);
    opts.attempts = 2;
    TokioAsyncResolver::tokio_from_system_conf()
        .unwrap_or_else(|_| TokioAsyncResolver::tokio(ResolverConfig::default(), opts))
}

#[derive(Debug, Clone)]
pub struct MxRecord {
    pub preference: u16,
    pub exchange: String,
}

pub async fn mx(resolver: &TokioAsyncResolver, domain: &str) -> Result<Vec<MxRecord>, String> {
    match resolver.mx_lookup(domain).await {
        Ok(lookup) => {
            let mut out: Vec<MxRecord> = lookup
                .iter()
                .map(|r| MxRecord {
                    preference: r.preference(),
                    exchange: r.exchange().to_utf8().trim_end_matches('.').to_string(),
                })
                .collect();
            out.sort_by_key(|r| r.preference);
            Ok(out)
        }
        Err(e) if is_no_records(&e) => Ok(Vec::new()),
        Err(e) => Err(short(&e)),
    }
}

pub async fn txt(resolver: &TokioAsyncResolver, name: &str) -> Result<Vec<String>, String> {
    match resolver.txt_lookup(name).await {
        Ok(lookup) => Ok(lookup
            .iter()
            .map(|t| {
                t.txt_data()
                    .iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .collect()),
        Err(e) if is_no_records(&e) => Ok(Vec::new()),
        Err(e) => Err(short(&e)),
    }
}

/// Generic record lookup returning display strings.
pub async fn records(resolver: &TokioAsyncResolver, name: &str, rtype: RecordType) -> Result<Vec<String>, String> {
    match resolver.lookup(name, rtype).await {
        Ok(lookup) => Ok(lookup
            .iter()
            .map(|r| r.to_string().trim_end_matches('.').to_string())
            .collect()),
        Err(e) if is_no_records(&e) => Ok(Vec::new()),
        Err(e) => Err(short(&e)),
    }
}

pub async fn reverse(resolver: &TokioAsyncResolver, ip: std::net::IpAddr) -> Result<Vec<String>, String> {
    match resolver.reverse_lookup(ip).await {
        Ok(lookup) => Ok(lookup
            .iter()
            .map(|n| n.to_utf8().trim_end_matches('.').to_string())
            .collect()),
        Err(e) if is_no_records(&e) => Ok(Vec::new()),
        Err(e) => Err(short(&e)),
    }
}

fn is_no_records(e: &hickory_resolver::error::ResolveError) -> bool {
    matches!(
        e.kind(),
        hickory_resolver::error::ResolveErrorKind::NoRecordsFound { .. }
    )
}

fn short(e: &hickory_resolver::error::ResolveError) -> String {
    let text = e.to_string();
    text.chars().take(140).collect()
}
