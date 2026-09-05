# Nazgul

Retro-terminal desktop OSINT workbench for Windows. Give it a username, email, phone number,
domain, IP address, image or crypto address and it fans out across public sources in parallel,
streaming findings into a local case file with a link graph, notes, history and reports.

Public data only. No CAPTCHA solving, no login bypass, no scraping behind authentication.

## Probes

| Probe | What it does |
|---|---|
| **Username** | 700+ sites from the WhatsMyName list, checked in parallel. Category filters, handle variants, sequential queue. |
| **Email** | Syntax and username candidates, disposable-domain check, MX / SPF / DMARC posture with provider guess, Gravatar profile, EmailRep reputation, registration checks that never email the target (Duolingo, Mozilla, Spotify, Pinterest, Twitter, Imgur, Proton, Keybase, openpgp), payment handles on Venmo / PayPal.Me / Revolut for the candidates plus Venmo and PayPal launchers, Epieos and IntelligenceX launchers, HIBP breaches and pastes with a key, dorks. |
| **Phone** | libphonenumber parse (country, line type, every format), WhatsApp and Telegram links, payment-app launchers (Venmo pay flow prefilled with the number, PayPal, Cash App, Zelle notes), reverse-lookup and dork launchers, NumVerify carrier data with a key. |
| **Name** | Handle candidates from a full name (johndoe, john.doe, jdoe...) checked on Venmo, PayPal.Me and Revolut, people-search launchers (TruePeopleSearch, FastPeopleSearch, Whitepages, Spokeo, ThatsThem), social searches (LinkedIn, Facebook, X, TikTok), and payment-site dorks. Top candidates pivot into the username probe. |
| **Domain** | RDAP registration, A / AAAA / CNAME / NS / MX / TXT / SOA / CAA, SPF / DMARC / DKIM selectors, subdomains from crt.sh, Wayback CDX and a DNS brute-force list, web technology fingerprint, Shodan-compatible favicon hash, robots / sitemap / security.txt, launchers, plus Shodan DNS, Hunter.io and VirusTotal with keys. |
| **IP** | Classification, reverse DNS, geolocation and ASN, Shodan InternetDB ports and CVEs, Tor exit check, RDAP allocation, launchers, plus Shodan, ipinfo, AbuseIPDB, Censys and VirusTotal with keys. |
| **Location** | Coordinates (decimal or DMS) or a place name. Nominatim geocoding both ways, then Google Maps / Earth, Dual Maps, Zoom Earth, Wikimapia, Bing, Yandex, Mapillary, ADS-B Exchange, WiGLE, GeoHack, Snap Map and more, all centred on the point. |
| **Company** | OpenCorporates search plus SAM.gov, USASpending, ProPublica nonprofits, Companies House, CompanyCheck, Moneyhouse, Crunchbase, LinkedIn companies, state public-records directory, and filing / document dorks. |
| **File** | Images: EXIF / camera / timestamp / GPS / authoring tags, dimensions. PDFs: Info dictionary (author, creator, producer, dates). Office documents: creator, last modified by, company, application. MD5 and SHA-256, reverse-image launchers, a one-click flipped copy for defeating exact-match image indexes. Files never leave the machine. |
| **Crypto** | Bitcoin, Litecoin and Ethereum address validation (Base58Check, bech32/bech32m, EIP-55), balance and activity from public explorers, ENS reverse lookup, explorer launchers. |
| **Plugins** | Run external tools (Sherlock, holehe, Maigret, theHarvester, your own) from JSON manifests and capture their output as findings. |

Everything a probe discovers (an email in a bio, a subdomain, a hostname behind an IP, the
author of a PDF, the GPS point in a photo) becomes an **entity** in the case with a **Pivot**
button, so one identifier leads to the next.

## Toolbox

The Toolbox view (`Ctrl+5`) holds the hand-operated side of the craft:

- **Launchers** for every identifier type, drawn from `data/launchers.json`: people-search
  (TruePeopleSearch, ZabaSearch, FamilyTreeNow, TruthFinder, 192.com...), records (NSOPW,
  Europol, Interpol, Black Book Online), reverse phone directories, Reddit and Instagram
  viewers, Facebook tools, IntelligenceX, Epieos, Haveibeenzuckered, geolocation tools,
  company registers, metadata viewers and face search. Sites without a query URL are marked
  "paste". Open one at a time or a whole category at once.
- **Dork builder**: exact phrase, OR groups, exclusions, `site:` and country TLD scoping,
  `filetype:`, `inurl:`, `intitle:`, number ranges and `@`/`#` social prefixes, sent to Google,
  Bing, DuckDuckGo, Yandex, Carrot2 or Google Images, with an operator cheat sheet.

The probes emit the same launchers automatically as findings, so a scan already carries them.

## Cases, graph, history, reports

- Cases hold entities, findings, tags and notes in a local SQLite file under `%APPDATA%\com.nazgul.app`.
- The Graph view draws entities and found profiles with Cytoscape. Click a node to pivot.
- History logs every query with time, status and outcome. Open any past scan to bring its results back.
- Export a scan as JSON or CSV, or a whole case as a self-contained HTML report (print to PDF from a browser).

## OPSEC

- Route traffic direct, through Tor (`socks5h://127.0.0.1:9050`) or a custom SOCKS5 / HTTP proxy, with a one-click route check.
- Airgap mode refuses every network probe. Phone and image parsing keep working.
- Rotate the desktop browser user agent per scan, or pin your own.
- API keys live in Windows Credential Manager, never in a file, and are never sent to the UI.

## API keys

Settings lists every supported service with a **Get a key** link to its sign-up or token page
and its free-tier limit. All but one have a free tier. Probes use a key only when present and
fall back to a launcher otherwise.

| Service | Used by | Free tier |
|---|---|---|
| GitHub token | username cards, commit-author emails | 5,000 requests/hour |
| Shodan | IP host details, domain DNS | free account credits |
| Censys | IP services and certificates | 250 queries/month |
| ipinfo.io | IP geolocation and ASN | 50,000/month |
| AbuseIPDB | IP abuse reports | 1,000/day |
| GreyNoise | IP scanner classification | community API |
| IPQualityScore | IP fraud score, email and phone validation | 5,000/month |
| Pulsedive | domain and IP threat risk | community tier |
| AlienVault OTX | passive DNS (works keyless) | free |
| SecurityTrails | subdomain inventory | 50/month |
| urlscan.io | domain scan history (works keyless) | free |
| VirusTotal | domain and IP verdicts | 500/day |
| Hunter.io | domain email addresses | 25/month |
| EmailRep | email reputation (works keyless) | key on request |
| Have I Been Pwned | breaches and pastes | paid, about $4/month |
| NumVerify, Veriphone | phone carrier and type | 100/month, 1,000/month |
| Steam Web API | Steam profile card | free |
| YouTube Data API | YouTube channel card | 10,000 units/day |
| Etherscan | Ethereum balance and transactions | 5 calls/second |
| OpenCorporates | company search quota | free for non-commercial use |

Keyless enrichments that always run: GitHub profile and public commit emails (60/hour without a
token), Hacker News, Keybase proofs, Gravatar by handle, LeakCheck public breach summary,
urlscan.io and OTX passive DNS.
- Concurrency and timeout sliders, jitter between requests, no redirects followed during detection.

## Run it

Requirements: Node 18+, Rust with the MSVC toolchain (`rustup default stable-x86_64-pc-windows-msvc`),
Visual Studio Build Tools with C++, WebView2 (ships with Windows 11).

```
npm install
npm run tauri dev
```

Build an installer (NSIS and MSI land in `src-tauri/target/release/bundle/`):

```
npm run tauri build
```

Run the Rust test suite (most tests hit real public services):

```
cd src-tauri
cargo test
```

## Keyboard

`Ctrl+1` to `Ctrl+6` switch between Probes, Cases, Graph, History, Toolbox and Settings. `Esc`
clears the selection. `Enter` in any probe form runs it.

## Layout

```
src/                  React + TypeScript UI
  components/         top bar, rail, inspector, log strip, boot splash
  features/probes/    probe tab strip, per-probe forms, results board, batch panel
  features/cases/     cases, entities, tags, notes, report export
  features/graph/     Cytoscape link graph
  features/history/   scan history
  features/settings/  themes, route, keys, plugins
  lib/                API bindings, store helpers, exports, variants, report builder
src-tauri/src/
  engine/             HTTP client factory, DNS resolver, keychain, scan registry
  probes/             username email phone domain ip image crypto plugin
  db/                 SQLite schema and queries
  commands.rs         Tauri commands exposed to the UI
data/                 site list, disposable domains
plugins/              external tool manifests
```

## Updating data

- Replace `data/sites/wmn-data.json` with the latest WhatsMyName release and rebuild.
- Replace `data/disposable-domains.txt` with the latest disposable-email-domains blocklist and rebuild.

## Credits

- Site definitions: [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) by Micah Hoffman and contributors, CC BY-SA 4.0.
- Disposable domains: [disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains).
- Phone metadata: libphonenumber via the `phonenumber` crate.
- Free data services: ip-api.com, Shodan InternetDB, crt.sh, Wayback Machine, rdap.org, mempool.space, BlockCypher, ensideas, Tor Project.
