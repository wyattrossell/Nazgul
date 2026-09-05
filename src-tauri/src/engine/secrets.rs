//! API keys live in the OS keychain (Windows Credential Manager), never in plaintext files.

use std::collections::HashMap;

use serde::Serialize;

const SERVICE: &str = "nazgul";

/// (name, label, what it unlocks, where to get one, free-tier note)
pub const KEYS: &[(&str, &str, &str, &str, &str)] = &[
    ("github", "GitHub token", "Profile cards and commit-author emails at 5,000 requests/hour instead of 60", "https://github.com/settings/tokens", "Free · no scopes needed"),
    ("shodan", "Shodan", "IP host details, CVEs, and Shodan DNS data for domains", "https://account.shodan.io/register", "Free account · limited credits"),
    ("censys_id", "Censys API ID", "Host services and certificates (pair with the secret)", "https://search.censys.io/account/api", "Free · 250 queries/month"),
    ("censys_secret", "Censys API secret", "Second half of the Censys credential", "https://search.censys.io/account/api", "Free · same account"),
    ("ipinfo", "ipinfo.io", "Geolocation, ASN and hostnames for an IP", "https://ipinfo.io/signup", "Free · 50,000 lookups/month"),
    ("abuseipdb", "AbuseIPDB", "Abuse confidence score and report counts", "https://www.abuseipdb.com/account/api", "Free · 1,000 checks/day"),
    ("greynoise", "GreyNoise", "Is this IP a known internet scanner or a benign service", "https://viz.greynoise.io/signup", "Free community API"),
    ("ipqs", "IPQualityScore", "Fraud score, proxy/VPN/Tor flags for IPs; validity and leak flags for emails and phones", "https://www.ipqualityscore.com/create-account", "Free · 5,000 lookups/month"),
    ("pulsedive", "Pulsedive", "Threat-intel risk and feeds for domains and IPs", "https://pulsedive.com/register", "Free · community tier"),
    ("otx", "AlienVault OTX", "Higher quota for passive DNS on domains and IPs (works without a key)", "https://otx.alienvault.com/", "Free"),
    ("securitytrails", "SecurityTrails", "Historical subdomain inventory for a domain", "https://securitytrails.com/app/signup", "Free · 50 queries/month"),
    ("urlscan", "urlscan.io", "Higher quota for scan history of a domain (works without a key)", "https://urlscan.io/user/signup", "Free"),
    ("virustotal", "VirusTotal", "Reputation for domains and IPs", "https://www.virustotal.com/gui/join-us", "Free · 500 requests/day"),
    ("hunter", "Hunter.io", "Email addresses and patterns for a domain", "https://hunter.io/users/sign_up", "Free · 25 searches/month"),
    ("emailrep", "EmailRep", "Raises the emailrep.io quota (works without a key at a few queries per day)", "https://emailrep.io/key", "Free key on request"),
    ("hibp", "Have I Been Pwned", "Breach and paste lookups for an email", "https://haveibeenpwned.com/API/Key", "Paid · about $4/month"),
    ("numverify", "NumVerify", "Carrier, line type and location for a phone number", "https://numverify.com/product", "Free · 100 requests/month"),
    ("veriphone", "Veriphone", "Carrier, type and region for a phone number", "https://veriphone.io/signup", "Free · 1,000 requests/month"),
    ("steam", "Steam Web API", "Steam profile card for a handle (real name, country, account age)", "https://steamcommunity.com/dev/apikey", "Free"),
    ("youtube", "YouTube Data API", "Channel card for a handle (subscribers, country, description links)", "https://console.cloud.google.com/apis/library/youtube.googleapis.com", "Free · 10,000 units/day"),
    ("etherscan", "Etherscan", "Ethereum balance and transaction history", "https://etherscan.io/register", "Free · 5 calls/second"),
    ("opencorporates", "OpenCorporates", "Company search without the anonymous rate limit", "https://opencorporates.com/api_accounts/new", "Free for non-commercial use on request"),
];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretStatus {
    pub name: String,
    pub label: String,
    pub description: String,
    pub url: String,
    pub free: String,
    pub set: bool,
}

fn entry(name: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, name).map_err(|e| format!("keychain: {e}"))
}

pub fn known(name: &str) -> bool {
    KEYS.iter().any(|(n, ..)| *n == name)
}

pub fn set(name: &str, value: &str) -> Result<(), String> {
    if !known(name) {
        return Err(format!("Unknown key name {name}"));
    }
    let value = value.trim();
    if value.is_empty() {
        return delete(name);
    }
    entry(name)?.set_password(value).map_err(|e| format!("keychain: {e}"))
}

pub fn get(name: &str) -> Option<String> {
    entry(name).ok()?.get_password().ok().filter(|v| !v.trim().is_empty())
}

pub fn delete(name: &str) -> Result<(), String> {
    match entry(name)?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("keychain: {e}")),
    }
}

pub fn load_all() -> HashMap<String, String> {
    KEYS.iter()
        .filter_map(|(name, ..)| get(name).map(|v| (name.to_string(), v)))
        .collect()
}

pub fn status() -> Vec<SecretStatus> {
    KEYS.iter()
        .map(|(name, label, description, url, free)| SecretStatus {
            name: name.to_string(),
            label: label.to_string(),
            description: description.to_string(),
            url: url.to_string(),
            free: free.to_string(),
            set: get(name).is_some(),
        })
        .collect()
}
