//! HTTP client factory. One client per scan so proxy / UA / timeout can differ per run.

use std::time::Duration;

pub const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36";

/// Desktop browser strings for rotation. One is picked per scan.
pub const USER_AGENT_POOL: &[&str] = &[
    DEFAULT_USER_AGENT,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
];

pub fn random_user_agent() -> &'static str {
    USER_AGENT_POOL[rand::random::<usize>() % USER_AGENT_POOL.len()]
}

#[derive(Debug, Clone)]
pub struct HttpOptions {
    pub user_agent: String,
    pub timeout_secs: u64,
    /// e.g. `socks5h://127.0.0.1:9050` for Tor, `http://127.0.0.1:8080` for a proxy.
    pub proxy: Option<String>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            user_agent: DEFAULT_USER_AGENT.to_string(),
            timeout_secs: 15,
            proxy: None,
        }
    }
}

pub fn build_client(opts: &HttpOptions) -> reqwest::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(opts.user_agent.as_str())
        .timeout(Duration::from_secs(opts.timeout_secs))
        // Site definitions rely on seeing 3xx codes, so never follow redirects.
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(4);

    if let Some(proxy) = opts.proxy.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    }

    builder.build()
}

/// Short, user-facing description of a request failure.
pub fn describe_error(err: reqwest::Error) -> String {
    if err.is_timeout() {
        "timeout".to_string()
    } else if err.is_connect() {
        "connection failed".to_string()
    } else if err.is_redirect() {
        "redirect loop".to_string()
    } else {
        let text = err.without_url().to_string();
        text.chars().take(120).collect()
    }
}

/// Outcome of a simple request: status, body text, elapsed milliseconds.
pub struct Fetched {
    pub status: u16,
    pub body: String,
    pub elapsed_ms: u64,
}

/// Sends a prepared request and reads the body as text.
pub async fn fetch(request: reqwest::RequestBuilder) -> Result<Fetched, (String, u64)> {
    let started = std::time::Instant::now();
    match request.send().await {
        Err(e) => Err((describe_error(e), started.elapsed().as_millis() as u64)),
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Ok(Fetched {
                status,
                body,
                elapsed_ms: started.elapsed().as_millis() as u64,
            })
        }
    }
}

/// Client that follows redirects, for APIs like RDAP and archive.org that bounce you around.
pub fn build_following_client(opts: &HttpOptions) -> reqwest::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .user_agent(opts.user_agent.as_str())
        .timeout(Duration::from_secs(opts.timeout_secs))
        .redirect(reqwest::redirect::Policy::limited(6));
    if let Some(proxy) = opts.proxy.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
        builder = builder.proxy(reqwest::Proxy::all(proxy)?);
    }
    builder.build()
}
