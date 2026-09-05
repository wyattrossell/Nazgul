//! API keys live in the OS keychain (Windows Credential Manager), never in plaintext files.

use std::collections::HashMap;

use serde::Serialize;

const SERVICE: &str = "nazgul";

/// (name, label, what it unlocks)
pub const KEYS: &[(&str, &str, &str)] = &[
    ("shodan", "Shodan", "IP host details, CVEs, and Shodan's DNS data for domains"),
    ("censys_id", "Censys API ID", "Host services and certificates (pair with the secret)"),
    ("censys_secret", "Censys API secret", "Second half of the Censys credential"),
    ("hibp", "Have I Been Pwned", "Breach and paste lookups for an email (paid key)"),
    ("ipinfo", "ipinfo.io", "Geolocation, ASN and hostnames for an IP"),
    ("abuseipdb", "AbuseIPDB", "Abuse confidence score and report counts"),
    ("hunter", "Hunter.io", "Email addresses and patterns for a domain"),
    ("numverify", "NumVerify", "Carrier, line type and location for a phone number"),
    ("virustotal", "VirusTotal", "Reputation for domains and IPs"),
];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretStatus {
    pub name: String,
    pub label: String,
    pub description: String,
    pub set: bool,
}

fn entry(name: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, name).map_err(|e| format!("keychain: {e}"))
}

pub fn known(name: &str) -> bool {
    KEYS.iter().any(|(n, _, _)| *n == name)
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
        .filter_map(|(name, _, _)| get(name).map(|v| (name.to_string(), v)))
        .collect()
}

pub fn status() -> Vec<SecretStatus> {
    KEYS.iter()
        .map(|(name, label, description)| SecretStatus {
            name: name.to_string(),
            label: label.to_string(),
            description: description.to_string(),
            set: get(name).is_some(),
        })
        .collect()
}
