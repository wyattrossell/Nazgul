# NAZGUL — Desktop OSINT Workbench

> Retro-terminal desktop app for open-source intelligence: usernames, emails,
> phones, domains, IPs, images. Inspired by fingerprint.to's fan-out + recursive pivot model.

## Decisions (2026-09-05)

| Question | Decision |
|---|---|
| Stack | Tauri 2 + Rust engine + React/TypeScript. Chosen for "usable, efficient, easy to update". |
| Name | **Nazgul** |
| Themes | Phosphor (default), Amber, Paper. Opt-in CRT effects. |
| Python sidecar | Deferred. Rust-only until phase 6. |
| v1 username results | Exists + URL for every site; full profile cards only for sites with public APIs. |
| Influences to fold in | Sherlock, Maigret, Maltego, Shodan, theHarvester (see section 10). |

## Status

- [x] Phase 0: scaffold, tokens, three themes, shell layout, CRT toggle
- [x] Phase 1: username probe (WhatsMyName list, streaming results, cards/table, JSON/CSV export, cancel)
- [x] Phase 2: SQLite cases, entities, findings, links, history, notes/tags, generic finding model
- [x] Phase 3: email + phone probes, username variants, scan queue, pivots from discovered entities
- [x] Phase 4: domain + IP probes (RDAP, DNS, mail posture, crt.sh, Wayback, brute, tech fingerprint, favicon hash, InternetDB, Tor exit)
- [x] Phase 5: image + crypto probes, Cytoscape link graph, HTML case report
- [x] Phase 6: keychain API keys (Shodan, Censys, HIBP, ipinfo, AbuseIPDB, Hunter, NumVerify, VirusTotal), Tor / custom route with check, airgap, UA rotation, plugin bridge for external tools (replaces the Python sidecar idea)
- [x] Phase 7: app icon, boot splash, batch import, keyboard shortcuts, NSIS/MSI build

- [x] Follow-up: payment apps. Name probe (handle candidates checked on Venmo / PayPal.Me / Revolut, people-search and social launchers, dorks); phone and email probes gained Venmo pay-flow and PayPal launchers and payment-handle checks. Venmo, PayPal, Cash App and Zelle expose no public phone / email / name search, so lookups by those identifiers run through the user's own logged-in app; Cash App serves a 404 shell to non-browsers, so it stays a launcher.

- [x] Follow-up: class-notes sweep (NW3C CI133 / CI134 guides + Google module). Added a shared launcher catalog (data/launchers.json, ~80 tools) that every probe emits and a Toolbox view browses; a dork builder with the full operator set; Location probe (Nominatim + 16 geolocation tools); Company probe (OpenCorporates + registers); File probe now reads PDF and Office metadata and can save a flipped image copy; EmailRep reputation in the email probe; Reddit, Instagram, Facebook, people-search, records and reverse-phone tools wired into the matching probes. Not included on purpose: AI writing tools, Android emulators, Zotero/SingleFile/PDF Mage (workflow utilities), Grabify/IP Logger (tracking links), Hash Toolkit, Proton VPN / I2P (infrastructure, not lookups).

- [x] Follow-up: API keys. Every key in Settings now carries a "Get a key" link and a free-tier note (21 services, only HIBP paid). New keyed integrations: GitHub token, GreyNoise, IPQualityScore (IP, email, phone), Pulsedive, AlienVault OTX, SecurityTrails, urlscan.io, Veriphone, Steam, YouTube, Etherscan, OpenCorporates. New keyless enrichments: GitHub profile + commit-author emails, Hacker News, Keybase proofs, Gravatar by handle, LeakCheck public breach summary, urlscan and OTX passive DNS. Skipped: BGPView (DNS does not resolve), Reddit about.json (serves HTML to non-browsers).

Deferred: auto-update needs a signing key and a hosted update manifest, so it is documented but not wired.

---

## 1. What we are building

A local, offline-first desktop app that takes an identifier (username, email, phone, domain,
IP, image) and fans out to hundreds of public sources in parallel, streaming hits into a
results board as they arrive. Every new identifier found (an email in a GitHub commit, a
username in a bio) can be queued as a new pivot. Everything lands in a local case file with
notes, tags, a link graph, and exportable reports.

**Non-goals (v1):** scraping behind logins, bypassing rate limits/CAPTCHAs, anything that
requires credentials for the target's accounts. Public data only.

---

## 2. Recommended stack

| Layer | Choice | Why |
|---|---|---|
| Shell | **Tauri 2** | ~10 MB binary, native window, Windows installer (MSI/NSIS), secure IPC. |
| Core engine | **Rust** (tokio + reqwest) | 700+ concurrent HTTP checks with a semaphore is trivial and fast. Proxy/SOCKS5 built in. |
| Frontend | **React + TypeScript + Vite** | Retro CRT look is just CSS. Huge ecosystem for tables/graphs. |
| State | Zustand | Small, fits streaming updates. |
| Storage | **SQLite** (rusqlite) | Single-file cases, easy backup/export. |
| Secrets | OS keychain (`keyring` crate) | API keys never sit in plaintext. |
| Plugins | **Python sidecar** (phase 6) | Most OSINT tooling is Python (holehe, maigret, exiftool wrappers). Spawned as a child process, JSON over stdio. |

Alternatives considered: Electron (easier, 150 MB+, slower fan-out in Node); pure Python +
PySide (best OSINT libs, but the retro web UI is far harder to build and package).

---

## 3. Feature modules ("Probes")

Each probe is a self-contained unit: `input type -> async job -> stream of Findings`.

### 3.1 Username probe (MVP, the fingerprint.to core)
- Site list in **WhatsMyName JSON format** (600+ sites, community maintained) plus our own additions.
- Detection methods per site: HTTP status, body-contains / body-absent, redirect URL, JSON field.
- Streams results as `found / not found / error / rate-limited`.
- Per-site enrichment when a public API exists: GitHub (repos, orgs, commit emails), Reddit
  (karma, created, recent subs), Mastodon, Steam, Keybase, Gravatar, HackerNews, Lichess, Chess.com.
- Username variants generator: `john.doe`, `johndoe`, `john_doe`, `jdoe`, leet, year suffixes.

### 3.2 Email probe
- Syntax + MX / SPF / DMARC lookup, disposable-domain detection, role-account detection.
- Gravatar hash lookup (avatar + profile).
- holehe-style "is this email registered on X?" checks (via sidecar or Rust port of the safe subset).
- Breach data: Have I Been Pwned (API key, paid), EmailRep (free tier).
- Derive username candidates from the local part, then auto-pivot to 3.1.

### 3.3 Phone probe
- libphonenumber parse: country, region, carrier, line type, all formats.
- Optional API enrichment: NumVerify / Twilio Lookup / Veriphone (keys).
- Messaging-app presence where public (Telegram t.me, WhatsApp click-to-chat link check).
- Reverse lookup dork generator (quoted number in multiple formats).

### 3.4 Domain probe
- RDAP/WHOIS, full DNS record set, DNSSEC, mail posture (SPF/DMARC/DKIM selectors).
- Subdomains: crt.sh certificate transparency, common-prefix brute (rate limited), Wayback CDX.
- Tech fingerprint: headers, cookies, JS libs, favicon mmh3 hash (Shodan-compatible).
- Wayback Machine snapshot timeline, robots.txt / sitemap.xml / security.txt.
- Related: reverse IP, shared nameservers, same registrant email pivot.

### 3.5 IP probe
- Geo + ASN (ipinfo / ip-api), reverse DNS, open ports & banners via Shodan / Censys (keys).
- Tor exit / VPN / datacenter classification, abuse contacts, AbuseIPDB score.

### 3.6 Image probe
- EXIF/XMP/IPTC extraction (GPS to map link), thumbnail extraction, perceptual hash (pHash).
- One-click reverse image search launchers: Google Lens, Yandex, Bing, TinEye.
- Face/blur detection is out of scope.

### 3.7 Crypto probe
- BTC / ETH / LTC address validation, balance + tx count via public explorers, ENS reverse lookup.

### 3.8 Dork & pivot toolkit
- Google/Bing/DDG dork generator per identifier type (site:, intext:, filetype:).
- Paste-site and code-search launchers (GitHub code search, grep.app, Pastebin via Google).
- Every finding exposes "pivot" actions that queue a new probe run inside the same case.

---

## 4. Case management
- **Cases** contain **Entities** (person, username, email, phone, domain, ip, image, wallet, org),
  which contain **Findings** (source, url, confidence, raw JSON, screenshot later), plus **Notes** / **Tags**.
- **Link graph** (Cytoscape.js) showing entity relationships; click to pivot.
- **Timeline** view from any dated data (account creation, snapshots, breaches).
- **History & audit log** of every query with timestamp (fingerprint.to has this).
- **Export**: JSON, CSV, Markdown, self-contained HTML report, optional PDF.
- **Import**: paste a list of identifiers for batch runs.

---

## 5. OPSEC & safety
- Global rate limiter + per-host limiter; jittered delays; exponential backoff on 429.
- User-agent rotation, optional HTTP/SOCKS5 proxy, **Tor mode** (route via 127.0.0.1:9050).
- "Airgap" toggle: disables all network probes, only local parsing (EXIF, phone parse, dorks).
- API keys in OS keychain; app-level export never includes keys.
- Clear per-probe legal note (ToS varies per site); no CAPTCHA solving, no auth bypass.

---

## 6. Retro UI direction (readable first)

Concept: **a phosphor terminal that grew a proper UI**. Terminal texture, modern ergonomics.

- **Themes:** `PHOSPHOR` (green #33ff66 on #0b0f0c), `AMBER` (#ffb000 on #100c02),
  `PAPER` (light mode: dark ink on warm off-white). All AA contrast or better.
- **Type:** IBM Plex Mono for data/tables, IBM Plex Sans for prose & notes. Base 15-16 px.
- **Texture, opt-in:** scanline overlay (low opacity), slight text glow, CRT vignette, all
  toggleable with a single "CRT effects" switch. Off by default in PAPER.
- **Chrome:** ASCII-style box borders drawn with CSS (not real box characters, so they scale),
  top status bar (case name, probe count, proxy state, clock), bottom log strip streaming
  probe events like a terminal.
- **Motion:** results typewriter in; blinking block cursor in inputs; "boot sequence" splash on
  first launch (skippable, remembers).
- **Layout:** left rail (Cases / Probes / Graph / History / Settings), center results board
  (card / table toggle like fingerprint.to), right inspector drawer for the selected finding.
- **Readability rules:** never rely on glow for legibility; min 4.5:1 contrast; line length
  under 80ch for prose; tables get zebra rows at 4% tint; reduce-motion respected.

---

## 7. Architecture

```
specter/
|- src-tauri/                 Rust core
|  |- src/
|  |  |- main.rs              Tauri setup, commands, event bus
|  |  |- engine/              scheduler, rate limiter, http client (reqwest+proxy)
|  |  |- probes/              username.rs email.rs phone.rs domain.rs ip.rs image.rs crypto.rs
|  |  |- db/                  sqlite schema + queries (cases, entities, findings, history)
|  |  |- secrets.rs           keyring wrapper
|  |  |- sidecar.rs           Python plugin bridge (phase 6)
|  |- tauri.conf.json
|- src/                       React + TS
|  |- app/                    routes, layout shell, theme provider
|  |- features/               cases/ probes/ results/ graph/ history/ settings/
|  |- components/             CRT frame, terminal log, data table, cards, inspector
|  |- styles/                 tokens.css, themes/, crt.css
|- data/
|  |- sites/wmn-data.json     WhatsMyName site list (+ our overrides)
|  |- disposable-domains.txt
|  |- dorks.yaml
|- plugins/                   Python sidecar plugins (phase 6)
|- PLAN.md
```

**Data flow:** UI calls `invoke("run_probe", {case, entity})`. The Rust scheduler spawns tasks
under a semaphore. Each result emits a `probe://finding` event. The UI appends it to the store
and SQLite persists it.

---

## 8. Roadmap

| Phase | Deliverable | Notes |
|---|---|---|
| **0** | Scaffold: Tauri 2 + React + TS, design tokens, 3 themes, shell layout, CRT toggle | Get the vibe right before features. |
| **1** | Username probe MVP: WMN site list, streaming results, card/table view, JSON/CSV export | This is fingerprint.to's core. Usable on day one. |
| **2** | SQLite cases + entities + findings, search history, notes/tags | Persistence and audit trail. |
| **3** | Email + Phone probes, username-variant generator, auto-pivot suggestions | Recursive discovery lands here. |
| **4** | Domain + IP probes (DNS, RDAP, crt.sh, Wayback, tech fingerprint) | Mostly free public sources. |
| **5** | Image + Crypto probes; link graph; HTML/PDF report | Visual payoff. |
| **6** | API-key integrations (Shodan, Censys, HIBP, ipinfo), proxy/Tor mode, Python sidecar | Power-user tier. |
| **7** | Packaging (MSI/NSIS), auto-update, batch import, polish pass | Ship. |

---

## 9. Open decisions

All five v1 decisions are settled (see top of file). Remaining open items surface per phase.

---

## 10. Integration map: what we borrow from each tool

| Tool | What it does well | What Nazgul takes from it | Phase |
|---|---|---|---|
| **Sherlock** | Username across ~400 sites, simple JSON site manifest, error-type detection (status / message / redirect) | Same detection model. We use the larger WhatsMyName list, which Sherlock's data can be merged into for sites WMN lacks. | 1 (done) |
| **Maigret** | Sherlock + profile parsing: pulls names, bios, links, IDs out of found pages and *recurses* on them. Tags sites, HTML/PDF reports | Recursive pivoting (phase 3), per-site extractors for the API-backed sites, tag filters, report export (phase 5). Maigret's site DB is another merge source. | 3, 5 |
| **Maltego** | Entity/transform model, link graph, everything is a pivot | Cases hold typed **entities**; each probe is a **transform** from one entity type to findings/new entities; Cytoscape link graph with click-to-pivot. | 2, 5 |
| **Shodan** | Internet-wide host/port/banner data, favicon hash search, keyed API | IP and domain probes call Shodan with the user's key; favicon mmh3 hash computed locally so it can be pasted into Shodan/Censys. InternetDB (free, no key) for basic port data. | 4, 6 |
| **theHarvester** | Domain to emails / subdomains / hosts via search engines, crt.sh, DNS brute, Hunter etc. | Domain probe: crt.sh, DNS brute with wordlist, Wayback CDX, search-engine dorks, Hunter.io with key. Emails found feed the email probe automatically. | 4 |
| **holehe** | Email to "registered on site X?" via password-reset flows | Safe subset ported to Rust for the email probe (sites that answer without sending mail to the target). | 3 |
| **SpiderFoot** | Module marketplace, everything-to-everything automation | Long-term: a probe registry where each probe declares input/output entity types, so auto-pivot can chain them like SpiderFoot does. | 3+ |
| **ExifTool** | Metadata from images/documents | Image probe uses a Rust EXIF crate; optional ExifTool sidecar later for exotic formats. | 5 |

Merge policy for site lists: WhatsMyName is the base. Sherlock / Maigret entries are imported
only where WMN has no entry for the same host, converted into the WMN schema, and kept in
`data/sites/extra.json` so upstream updates stay a drop-in replacement.
