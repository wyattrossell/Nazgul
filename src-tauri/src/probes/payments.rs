//! Payment-app helpers shared by the name, email and phone probes.
//!
//! Venmo, PayPal, Cash App and Zelle do not expose phone, email or name search without a
//! login, so we do two honest things: check public *handle* pages for candidate handles, and
//! hand the user launchers that open their own logged-in app with the identifier prefilled.

use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::username::{check_site, CATALOG};
use super::{EntityType, Finding, FindingStatus, ScanContext};

/// WhatsMyName entries whose profile pages double as payment identities.
pub const HANDLE_SITES: &[&str] = &["Venmo", "PayPal.Me", "Revolut"];

pub fn handle_sites() -> Vec<&'static super::username::WmnSite> {
    CATALOG
        .sites
        .iter()
        .filter(|s| HANDLE_SITES.contains(&s.name.as_str()))
        .collect()
}

/// Number of findings `check_handles` will emit for `n` handles.
pub fn handle_check_count(n: usize) -> usize {
    handle_sites().len() * n
}

/// Checks every handle against every payment site. Found handles are discovered as usernames.
pub async fn check_handles(ctx: &Arc<ScanContext>, handles: &[String]) {
    let semaphore = Arc::new(Semaphore::new(8));
    let mut tasks: JoinSet<()> = JoinSet::new();
    for site in handle_sites() {
        for handle in handles {
            let ctx = ctx.clone();
            let handle = handle.clone();
            let semaphore = semaphore.clone();
            tasks.spawn(async move {
                let Ok(_permit) = semaphore.acquire_owned().await else { return };
                if ctx.cancelled() {
                    return;
                }
                let template = ctx
                    .finding(&site.name, "payment_profile", &format!("{} · {}", site.name, handle))
                    .category("payments");
                tokio::select! {
                    _ = ctx.cancel.cancelled() => {},
                    mut f = check_site(&ctx.client, site, &handle, template) => {
                        if f.status == FindingStatus::Found {
                            f.summary = Some(format!("public {} page exists for the handle \"{handle}\"", site.name));
                            f = f.discover(EntityType::Username, handle.clone(), Some(&format!("{} handle", site.name)));
                        }
                        ctx.emit(f);
                    }
                }
            });
        }
    }
    while tasks.join_next().await.is_some() {}
}

/// Launchers that open the user's own payment apps with an identifier prefilled, plus notes
/// on where no lookup exists. `identifier` is a phone (digits with country code) or an email.
pub fn manual_launchers(ctx: &ScanContext, identifier: &str, what: &str) -> Vec<Finding> {
    let venmo_recipient = identifier.replace('+', "").replace('@', "%40");
    vec![
        ctx.finding("Venmo", "manual", "Venmo: pay flow with this recipient")
            .category("payments")
            .status(FindingStatus::Info)
            .url(format!("https://venmo.com/?txn=pay&audience=private&recipients={venmo_recipient}&note="))
            .summary(format!(
                "Opens your Venmo pay screen with the {what} prefilled. If it belongs to a Venmo user who allows lookup by {what}, their name and handle appear. Nothing is sent unless you confirm a payment."
            )),
        ctx.finding("PayPal", "manual", "PayPal: send money lookup")
            .category("payments")
            .status(FindingStatus::Info)
            .url("https://www.paypal.com/myaccount/transfer/homepage/pay")
            .summary(format!(
                "Paste the {what} into the recipient field of your own PayPal. A registered account shows its display name before any payment step."
            )),
        ctx.finding("Cash App", "manual", "Cash App: in-app search only")
            .category("payments")
            .status(FindingStatus::Info)
            .url("https://cash.app/")
            .summary(format!("Cash App resolves a {what} to a $cashtag only inside the mobile app (Pay → enter the {what}). No web lookup exists.")),
        ctx.finding("Zelle", "manual", "Zelle: bank app only")
            .category("payments")
            .status(FindingStatus::Info)
            .summary(format!("Zelle enrolment for a {what} is only visible from a participating bank app when you start a transfer. There is no public directory.")),
    ]
}

pub const MANUAL_LAUNCHER_COUNT: usize = 4;
