//! Crypto probe: validate BTC / ETH / LTC addresses locally, then pull balance and activity
//! from public explorers and offer explorer launchers.

use std::sync::Arc;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use super::launchers;
use super::{EntityType, FindingStatus, ScanContext};
use crate::engine::http::{build_following_client, fetch};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chain {
    Bitcoin,
    Litecoin,
    Ethereum,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub chain: Chain,
    pub format: &'static str,
    pub checksum_ok: bool,
    pub note: Option<String>,
}

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_decode(s: &str) -> Option<Vec<u8>> {
    let mut num: Vec<u8> = vec![0];
    for c in s.bytes() {
        let digit = B58.iter().position(|&b| b == c)? as u32;
        let mut carry = digit;
        for byte in num.iter_mut().rev() {
            let v = (*byte as u32) * 58 + carry;
            *byte = (v & 0xff) as u8;
            carry = v >> 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let leading = s.bytes().take_while(|&b| b == b'1').count();
    let mut out = vec![0u8; leading];
    let start = num.iter().position(|&b| b != 0).unwrap_or(num.len());
    out.extend_from_slice(&num[start..]);
    Some(out)
}

/// Base58Check: payload + 4-byte double-SHA256 checksum. Returns the version byte.
pub fn base58check(s: &str) -> Option<u8> {
    let bytes = base58_decode(s)?;
    if bytes.len() < 5 {
        return None;
    }
    let (payload, check) = bytes.split_at(bytes.len() - 4);
    let hash = Sha256::digest(Sha256::digest(payload));
    if hash[..4] == check[..] {
        Some(payload[0])
    } else {
        None
    }
}

const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    let gen = [0x3b6a_57b2u32, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ v as u32;
        for (i, g) in gen.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// Validates bech32 (const 1) or bech32m (const 0x2bc830a3). Returns (hrp, witness version).
pub fn bech32_check(s: &str) -> Option<(String, u8, &'static str)> {
    let lower = s.to_lowercase();
    if lower != s && s.to_uppercase() != s {
        return None;
    }
    let pos = lower.rfind('1')?;
    let (hrp, data) = (&lower[..pos], &lower[pos + 1..]);
    if hrp.is_empty() || data.len() < 6 {
        return None;
    }
    let mut values: Vec<u8> = Vec::new();
    for b in hrp.bytes() {
        values.push(b >> 5);
    }
    values.push(0);
    for b in hrp.bytes() {
        values.push(b & 31);
    }
    let mut payload = Vec::new();
    for c in data.bytes() {
        let v = BECH32_CHARSET.iter().position(|&x| x == c)? as u8;
        payload.push(v);
    }
    values.extend_from_slice(&payload);
    let variant = match bech32_polymod(&values) {
        1 => "bech32",
        0x2bc8_30a3 => "bech32m",
        _ => return None,
    };
    Some((hrp.to_string(), payload[0], variant))
}

/// EIP-55 mixed-case checksum. Returns None when the address is all one case (no checksum to verify).
pub fn eip55_ok(addr: &str) -> Option<bool> {
    let hex = addr.trim_start_matches("0x");
    if hex.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) || hex.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return None;
    }
    let hash = Keccak256::digest(hex.to_lowercase().as_bytes());
    let hash_hex = format!("{hash:x}");
    Some(hex.chars().zip(hash_hex.chars()).all(|(c, h)| {
        if c.is_ascii_digit() {
            true
        } else {
            let upper = h.to_digit(16).unwrap_or(0) >= 8;
            c.is_ascii_uppercase() == upper
        }
    }))
}

pub fn classify(input: &str) -> Option<Classified> {
    let s = input.trim();
    if s.len() == 42 && s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        let checksum = eip55_ok(s);
        return Some(Classified {
            chain: Chain::Ethereum,
            format: "hex (EVM)",
            checksum_ok: checksum.unwrap_or(true),
            note: match checksum {
                Some(true) => Some("EIP-55 checksum valid".into()),
                Some(false) => Some("EIP-55 checksum does NOT match: possible typo".into()),
                None => Some("no mixed-case checksum to verify".into()),
            },
        });
    }
    if let Some((hrp, ver, variant)) = bech32_check(s) {
        let chain = match hrp.as_str() {
            "bc" => Chain::Bitcoin,
            "ltc" => Chain::Litecoin,
            _ => return None,
        };
        let format = match (variant, ver) {
            ("bech32m", 1) => "taproot (P2TR)",
            ("bech32", 0) if s.len() == 42 || s.len() == 43 => "native segwit (P2WPKH)",
            ("bech32", 0) => "native segwit (P2WSH)",
            _ => "segwit",
        };
        return Some(Classified { chain, format, checksum_ok: true, note: None });
    }
    if let Some(version) = base58check(s) {
        return match version {
            0x00 => Some(Classified { chain: Chain::Bitcoin, format: "legacy (P2PKH)", checksum_ok: true, note: None }),
            0x05 => Some(Classified { chain: Chain::Bitcoin, format: "script (P2SH)", checksum_ok: true, note: None }),
            0x30 => Some(Classified { chain: Chain::Litecoin, format: "legacy (P2PKH)", checksum_ok: true, note: None }),
            0x32 => Some(Classified { chain: Chain::Litecoin, format: "script (P2SH)", checksum_ok: true, note: None }),
            _ => None,
        };
    }
    None
}

fn sats(v: &Value) -> f64 {
    v.as_f64().unwrap_or(0.0) / 1e8
}

pub async fn run(ctx: Arc<ScanContext>) -> Result<(), String> {
    let addr = ctx.input.trim().to_string();
    let Some(info) = classify(&addr) else {
        return Err("Not a recognised Bitcoin, Litecoin or Ethereum address (checksum failed or unknown format).".to_string());
    };
    let follower = build_following_client(&ctx.options.http_options()).map_err(|e| e.to_string())?;

    // classification, balance, (ens), launchers x2, catalog
    let catalog = launchers::plan(EntityType::Wallet, &launchers::vars_wallet(&addr));
    ctx.start(match info.chain {
        Chain::Ethereum => 5,
        _ => 4,
    } + catalog.len());

    let chain_name = match info.chain {
        Chain::Bitcoin => "Bitcoin",
        Chain::Litecoin => "Litecoin",
        Chain::Ethereum => "Ethereum",
    };
    ctx.emit(
        ctx.finding("parser", "address", "Address type")
            .category("address")
            .status(if info.checksum_ok { FindingStatus::Found } else { FindingStatus::Ambiguous })
            .summary(format!("{chain_name} · {}{}", info.format, info.note.as_ref().map(|n| format!(" · {n}")).unwrap_or_default()))
            .data(json!({ "chain": chain_name, "format": info.format, "checksumOk": info.checksum_ok })),
    );

    match info.chain {
        Chain::Bitcoin => {
            let mut f = ctx.finding("mempool.space", "balance", "Balance and activity").category("chain")
                .url(format!("https://mempool.space/address/{addr}"));
            match fetch(follower.get(format!("https://mempool.space/api/address/{addr}"))).await {
                Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
                Ok(res) => {
                    f.elapsed_ms = res.elapsed_ms;
                    f.http_status = Some(res.status);
                    let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                    if res.status == 200 && v["chain_stats"].is_object() {
                        let cs = &v["chain_stats"];
                        let funded = sats(&cs["funded_txo_sum"]);
                        let spent = sats(&cs["spent_txo_sum"]);
                        let txs = cs["tx_count"].as_u64().unwrap_or(0);
                        f = f.status(if txs > 0 { FindingStatus::Found } else { FindingStatus::NotFound })
                            .summary(format!("{:.8} BTC balance · {txs} tx · {funded:.4} BTC received in total", funded - spent))
                            .data(v.clone());
                    } else {
                        f = f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}", res.status));
                    }
                }
            }
            ctx.emit(f);
            for (source, title, url) in [
                ("Blockchair", "Blockchair explorer", format!("https://blockchair.com/bitcoin/address/{addr}")),
                ("OXT", "OXT address analysis", format!("https://oxt.me/address/{addr}")),
            ] {
                ctx.emit(ctx.finding(source, "launcher", title).category("launchers").status(FindingStatus::Info).url(url).summary("Transaction graph, clustering hints, labels"));
            }
        }
        Chain::Litecoin => {
            let mut f = ctx.finding("BlockCypher", "balance", "Balance and activity").category("chain")
                .url(format!("https://live.blockcypher.com/ltc/address/{addr}/"));
            match fetch(follower.get(format!("https://api.blockcypher.com/v1/ltc/main/addrs/{addr}/balance"))).await {
                Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
                Ok(res) => {
                    f.elapsed_ms = res.elapsed_ms;
                    f.http_status = Some(res.status);
                    let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                    if res.status == 200 && v["final_balance"].is_number() {
                        let txs = v["n_tx"].as_u64().unwrap_or(0);
                        f = f.status(if txs > 0 { FindingStatus::Found } else { FindingStatus::NotFound })
                            .summary(format!("{:.8} LTC balance · {txs} tx · {:.4} LTC received in total", sats(&v["final_balance"]), sats(&v["total_received"])))
                            .data(v.clone());
                    } else {
                        f = f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}: {}", res.status, v["error"].as_str().unwrap_or("")));
                    }
                }
            }
            ctx.emit(f);
            for (source, title, url) in [
                ("Blockchair", "Blockchair explorer", format!("https://blockchair.com/litecoin/address/{addr}")),
                ("Litecoin Space", "litecoinspace.org", format!("https://litecoinspace.org/address/{addr}")),
            ] {
                ctx.emit(ctx.finding(source, "launcher", title).category("launchers").status(FindingStatus::Info).url(url).summary("Transactions and balance history"));
            }
        }
        Chain::Ethereum => {
            let mut f = ctx.finding("BlockCypher", "balance", "Balance and activity").category("chain")
                .url(format!("https://etherscan.io/address/{addr}"));
            match fetch(follower.get(format!("https://api.blockcypher.com/v1/eth/main/addrs/{}/balance", addr.trim_start_matches("0x")))).await {
                Err((e, ms)) => { f.elapsed_ms = ms; f = f.error(e); }
                Ok(res) => {
                    f.elapsed_ms = res.elapsed_ms;
                    f.http_status = Some(res.status);
                    let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                    if res.status == 200 && v["final_balance"].is_number() {
                        let txs = v["n_tx"].as_u64().unwrap_or(0);
                        let eth = v["final_balance"].as_f64().unwrap_or(0.0) / 1e18;
                        f = f.status(if txs > 0 { FindingStatus::Found } else { FindingStatus::NotFound })
                            .summary(format!("{eth:.6} ETH balance · {txs} tx"))
                            .data(v.clone());
                    } else {
                        f = f.status(FindingStatus::Ambiguous).detail(format!("HTTP {}: {}", res.status, v["error"].as_str().unwrap_or("")));
                    }
                }
            }
            ctx.emit(f);

            let mut ens = ctx.finding("ENS", "ens", "ENS name").category("chain");
            match fetch(follower.get(format!("https://api.ensideas.com/ens/resolve/{addr}"))).await {
                Err((e, ms)) => { ens.elapsed_ms = ms; ens = ens.error(e); }
                Ok(res) => {
                    ens.elapsed_ms = res.elapsed_ms;
                    ens.http_status = Some(res.status);
                    let v: Value = serde_json::from_str(&res.body).unwrap_or(Value::Null);
                    match v["name"].as_str().filter(|n| !n.is_empty()) {
                        Some(name) => {
                            ens = ens.status(FindingStatus::Found)
                                .summary(format!("reverse record: {name}"))
                                .url(format!("https://app.ens.domains/{name}"))
                                .data(v.clone())
                                .discover(EntityType::Username, name.trim_end_matches(".eth"), Some("ENS name"));
                        }
                        None => ens = ens.status(FindingStatus::NotFound).summary("no reverse ENS record"),
                    }
                }
            }
            ctx.emit(ens);
            for (source, title, url) in [
                ("Etherscan", "Etherscan", format!("https://etherscan.io/address/{addr}")),
                ("Arkham", "Arkham Intelligence", format!("https://intel.arkm.com/explorer/address/{addr}")),
            ] {
                ctx.emit(ctx.finding(source, "launcher", title).category("launchers").status(FindingStatus::Info).url(url).summary("Transactions, tokens, labels and counterparties"));
            }
        }
    }

    launchers::emit(&ctx, &catalog);
    Ok(())
}
