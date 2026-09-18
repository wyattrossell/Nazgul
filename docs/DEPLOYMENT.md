# Nazgul — deployment and allowlisting

This page is written for an IT or security team asked to allow Nazgul on a managed
Windows endpoint (Microsoft Defender, SentinelOne, or similar). It states what the
program is, what it does on the network, and how to trust it.

## What Nazgul is

Nazgul is an open-source-intelligence (OSINT) research workbench: a desktop app that
looks up **public** information about identifiers a user already has (a username,
email, phone number, domain, IP address, company name, coordinates, or a local file's
metadata). It queries public web APIs and search services and shows the results.

- It reads public data only. It does not attempt to access anyone's private accounts,
  and it performs no credential access, authentication bypass, or exploitation.
- Source code, in full, is at https://github.com/wyattrossell/Nazgul
- Built with Tauri 2 (Rust core, WebView2 UI). No bundled browser, no telemetry.

## Why endpoint protection may flag it

Nazgul is an independently published desktop app. Until its code-signing certificate is
trusted on the endpoint, it is an *unknown publisher* that opens many outbound HTTPS
connections, which is the generic profile heuristic engines treat with suspicion. The
behaviour is benign; the flag is a reputation gap, not a detection of malicious code.

## How to trust it (pick one)

**1. Trust the publisher certificate (recommended).**
Nazgul releases are Authenticode-signed. Add the signing certificate to the machine's
Trusted Publishers store so both the installer and `nazgul.exe` are recognised.

- The public certificate is `certs/nazgul-codesign.cer` from the build, or export it
  from a signed binary: right-click the exe, Digital Signatures, view, Copy to File.
- Deploy via GPO: *Computer Configuration > Windows Settings > Security Settings >
  Public Key Policies > Trusted Publishers*, import the `.cer`.
- SentinelOne: add the publisher/certificate as an allow in the console policy, or
  allow by the file hash below.

**2. Allow by file hash.**
Each release lists the SHA-256 of the installer and of `nazgul.exe` (see the release
notes, or compute with `Get-FileHash`). Allowlist those hashes. Note that hashes change
every version, so certificate trust (option 1) is less work over time.

**3. Allow by install path.**
Per-user install location: `%LOCALAPPDATA%\Nazgul\nazgul.exe`. Case data lives in
`%APPDATA%\com.nazgul.app`. Scope any path exclusion as narrowly as your policy allows.

## Network destinations

All traffic is outbound HTTPS the user initiates by running a lookup. There is no
inbound listener and no background beaconing. Destinations are public APIs, grouped:

- **Update check on launch:** `github.com` / `objects.githubusercontent.com`
  (reads the latest release manifest; downloads an update only when the user clicks).
- **Public profile and data APIs:** e.g. api.github.com, gitlab.com, mastodon.social,
  public.api.bsky.app, lichess.org, api.chess.com, hub.docker.com, api.stackexchange.com,
  crates.io, keybase.io, gravatar.com, hacker-news.firebaseio.com.
- **Network / domain intelligence:** crt.sh, api.certspotter.com, api.hackertarget.com,
  observatory-api.mdn.mozilla.net, rdap.org, ip-api.com, ipwho.is,
  internetdb.shodan.io, otx.alienvault.com, urlscan.io, web.archive.org.
- **Records and reference:** wikidata.org, en.wikipedia.org, api.fbi.gov,
  courtlistener.com, npiregistry.cms.hhs.gov, api.open.fec.gov,
  projects.propublica.org, nominatim.openstreetmap.org, opensky-network.org.
- **Optional, only if the user adds an API key** (Settings > API keys): Shodan, Censys,
  VirusTotal, AbuseIPDB, GreyNoise, and similar vendor endpoints.

A full, current list is derivable from the source in `src-tauri/src/probes/`. API keys,
when present, are stored in Windows Credential Manager, never in a file, and are sent
only to their own vendor.

## Reducing exposure for evaluation

An analyst can set **Airgap mode** (Settings) to disable every network probe; the app
then only parses local input (file metadata, phone-number formatting). This is a useful
state for reviewing the app before allowing network access.

## Reporting a false positive

- **Microsoft Defender:** submit the file at https://www.microsoft.com/en-us/wdsi/filesubmission
  (choose "I'm an IT professional" or the home option; attach the installer). Microsoft
  typically re-scores within a day.
- **SentinelOne:** raise a false-positive through your SentinelOne console or vendor
  support with the file hash and this document.
