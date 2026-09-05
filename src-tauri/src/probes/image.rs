//! File probe: local metadata for images (EXIF, GPS, camera), PDFs (Info dictionary) and
//! Office documents (docProps), plus hashes, geolocation launchers for GPS points and
//! reverse-image launchers. Nothing about the file leaves the machine.

use std::io::{BufReader, Cursor, Read};
use std::path::Path;
use std::sync::Arc;

use exif::{In, Tag, Value};
use md5::{Digest as Md5Digest, Md5};
use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::json;
use sha2::Sha256;

use super::launchers;
use super::{EntityType, FindingStatus, ScanContext};

fn rational_to_deg(v: &Value) -> Option<f64> {
    match v {
        Value::Rational(r) if r.len() >= 3 => Some(r[0].to_f64() + r[1].to_f64() / 60.0 + r[2].to_f64() / 3600.0),
        Value::Rational(r) if !r.is_empty() => Some(r[0].to_f64()),
        _ => None,
    }
}

fn ascii(v: &Value) -> Option<String> {
    match v {
        Value::Ascii(parts) => parts.first().map(|p| String::from_utf8_lossy(p).trim().to_string()),
        _ => None,
    }
}

pub fn gps_from(exif: &exif::Exif) -> Option<(f64, f64)> {
    let lat = rational_to_deg(&exif.get_field(Tag::GPSLatitude, In::PRIMARY)?.value)?;
    let lon = rational_to_deg(&exif.get_field(Tag::GPSLongitude, In::PRIMARY)?.value)?;
    let lat_ref = exif.get_field(Tag::GPSLatitudeRef, In::PRIMARY).and_then(|f| ascii(&f.value)).unwrap_or_default();
    let lon_ref = exif.get_field(Tag::GPSLongitudeRef, In::PRIMARY).and_then(|f| ascii(&f.value)).unwrap_or_default();
    let lat = if lat_ref.starts_with('S') { -lat } else { lat };
    let lon = if lon_ref.starts_with('W') { -lon } else { lon };
    Some((lat, lon))
}

// ---------------------------------------------------------------------------
// PDF and Office metadata
// ---------------------------------------------------------------------------

fn pdf_text(obj: &lopdf::Object, doc: &lopdf::Document) -> Option<String> {
    let obj = match obj {
        lopdf::Object::Reference(id) => doc.get_object(*id).ok()?,
        other => other,
    };
    match obj {
        lopdf::Object::String(bytes, _) => {
            if bytes.starts_with(&[0xFE, 0xFF]) {
                let units: Vec<u16> = bytes[2..].chunks(2).filter(|c| c.len() == 2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
                Some(String::from_utf16_lossy(&units))
            } else {
                Some(String::from_utf8_lossy(bytes).to_string())
            }
        }
        lopdf::Object::Name(n) => Some(String::from_utf8_lossy(n).to_string()),
        _ => None,
    }
}

/// "D:20240102030405+01'00'" -> "2024-01-02 03:04:05"
fn pdf_date(s: &str) -> String {
    let d = s.trim_start_matches("D:");
    if d.len() >= 14 && d[..14].chars().all(|c| c.is_ascii_digit()) {
        format!("{}-{}-{} {}:{}:{}", &d[..4], &d[4..6], &d[6..8], &d[8..10], &d[10..12], &d[12..14])
    } else if d.len() >= 8 && d[..8].chars().all(|c| c.is_ascii_digit()) {
        format!("{}-{}-{}", &d[..4], &d[4..6], &d[6..8])
    } else {
        s.to_string()
    }
}

pub fn pdf_metadata(bytes: &[u8]) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let doc = lopdf::Document::load_mem(bytes).map_err(|e| format!("not a readable PDF: {e}"))?;
    let mut out = serde_json::Map::new();
    out.insert("pages".into(), json!(doc.get_pages().len()));
    out.insert("version".into(), json!(doc.version));
    if let Ok(info) = doc.trailer.get(b"Info") {
        let dict = match info {
            lopdf::Object::Reference(id) => doc.get_dictionary(*id).ok(),
            lopdf::Object::Dictionary(d) => Some(d),
            _ => None,
        };
        if let Some(dict) = dict {
            for (k, v) in dict.iter() {
                let key = String::from_utf8_lossy(k).to_string();
                if let Some(text) = pdf_text(v, &doc) {
                    let text = if key.ends_with("Date") { pdf_date(&text) } else { text };
                    out.insert(key, json!(text.trim()));
                }
            }
        }
    }
    Ok(out)
}

static RE_XML_TAG: Lazy<Regex> = Lazy::new(|| Regex::new(r"<(?:dc|cp|dcterms):(\w+)[^>]*>([^<]*)</").unwrap());
static RE_APP_TAG: Lazy<Regex> = Lazy::new(|| Regex::new(r"<(Application|Company|TotalTime|Pages|Words|AppVersion|Template|Manager)>([^<]*)</").unwrap());

pub fn office_metadata(bytes: &[u8]) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).map_err(|e| format!("not an Office (zip) document: {e}"))?;
    let mut out = serde_json::Map::new();
    let mut read = |name: &str| -> Option<String> {
        let mut file = zip.by_name(name).ok()?;
        let mut s = String::new();
        file.read_to_string(&mut s).ok()?;
        Some(s)
    };
    if let Some(core) = read("docProps/core.xml") {
        for cap in RE_XML_TAG.captures_iter(&core) {
            let val = cap[2].trim();
            if !val.is_empty() {
                out.insert(cap[1].to_string(), json!(val));
            }
        }
    }
    if let Some(app) = read("docProps/app.xml") {
        for cap in RE_APP_TAG.captures_iter(&app) {
            let val = cap[2].trim();
            if !val.is_empty() {
                out.insert(cap[1].to_string(), json!(val));
            }
        }
    }
    if out.is_empty() {
        return Err("no docProps metadata inside the document".to_string());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Probe
// ---------------------------------------------------------------------------

const OFFICE_EXT: &[&str] = &["docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "odt", "ods", "odp"];

pub async fn run(ctx: Arc<ScanContext>) -> Result<(), String> {
    let path = Path::new(ctx.input.trim());
    if !path.is_file() {
        return Err(format!("\"{}\" is not a file I can open.", ctx.input.trim()));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("Could not read the file: {e}"))?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    let is_pdf = ext == "pdf" || bytes.starts_with(b"%PDF");
    let is_office = OFFICE_EXT.contains(&ext.as_str());

    let file_launchers = launchers::plan(EntityType::Image, &launchers::vars_image(&ctx.input));
    // file + hashes + (dimensions + exif + camera + timestamp + gps + authoring | pdf | office) + reverse-image x4 + catalog
    let core = if is_pdf || is_office { 1 } else { 6 };
    ctx.start(2 + core + 4 + file_launchers.len());

    let size_kb = bytes.len() as f64 / 1024.0;
    ctx.emit(
        ctx.finding("file", "file", &name)
            .category("file")
            .status(FindingStatus::Info)
            .summary(format!("{size_kb:.1} KB · .{ext}{}", if is_pdf { " · PDF" } else if is_office { " · Office document" } else { "" }))
            .data(json!({ "path": path.display().to_string(), "bytes": bytes.len(), "extension": ext })),
    );

    let md5 = format!("{:x}", Md5::digest(&bytes));
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    ctx.emit(
        ctx.finding("hash", "hashes", "File hashes")
            .category("file")
            .status(FindingStatus::Info)
            .summary(format!("sha256 {}…", &sha256[..16]))
            .url(format!("https://www.virustotal.com/gui/file/{sha256}"))
            .data(json!({ "md5": md5, "sha256": sha256 })),
    );

    let mut gps: Option<(f64, f64)> = None;

    if is_pdf {
        match pdf_metadata(&bytes) {
            Ok(meta) => {
                let mut f = ctx.finding("pdf", "document", "PDF metadata").category("metadata").status(FindingStatus::Found);
                let mut parts = Vec::new();
                for key in ["Author", "Creator", "Producer", "CreationDate", "ModDate", "Title"] {
                    if let Some(v) = meta.get(key).and_then(|v| v.as_str()) {
                        parts.push(format!("{key}: {v}"));
                    }
                }
                if let Some(author) = meta.get("Author").and_then(|v| v.as_str()).filter(|a| a.len() > 1) {
                    f = f.discover(EntityType::Person, author, Some("PDF author"));
                }
                f = f.summary(if parts.is_empty() { format!("{} page(s), no Info dictionary", meta.get("pages").cloned().unwrap_or(json!(0))) } else { parts.join(" · ") })
                    .data(serde_json::Value::Object(meta));
                ctx.emit(f);
            }
            Err(e) => ctx.emit(ctx.finding("pdf", "document", "PDF metadata").category("metadata").error(e)),
        }
    } else if is_office {
        match office_metadata(&bytes) {
            Ok(meta) => {
                let mut f = ctx.finding("office", "document", "Office document metadata").category("metadata").status(FindingStatus::Found);
                let mut parts = Vec::new();
                for key in ["creator", "lastModifiedBy", "created", "modified", "Application", "Company", "revision", "title"] {
                    if let Some(v) = meta.get(key).and_then(|v| v.as_str()) {
                        parts.push(format!("{key}: {v}"));
                    }
                }
                for key in ["creator", "lastModifiedBy"] {
                    if let Some(who) = meta.get(key).and_then(|v| v.as_str()).filter(|a| a.len() > 1) {
                        f = f.discover(EntityType::Person, who, Some(&format!("document {key}")));
                    }
                }
                if let Some(company) = meta.get("Company").and_then(|v| v.as_str()).filter(|a| a.len() > 1) {
                    f = f.discover(EntityType::Org, company, Some("document Company field"));
                }
                f = f.summary(parts.join(" · ")).data(serde_json::Value::Object(meta));
                ctx.emit(f);
            }
            Err(e) => ctx.emit(ctx.finding("office", "document", "Office document metadata").category("metadata").error(e)),
        }
    } else {
        match imagesize::blob_size(&bytes) {
            Ok(dim) => ctx.emit(
                ctx.finding("imagesize", "dimensions", "Dimensions")
                    .category("file")
                    .status(FindingStatus::Info)
                    .summary(format!("{} × {} px", dim.width, dim.height))
                    .data(json!({ "width": dim.width, "height": dim.height })),
            ),
            Err(e) => ctx.emit(ctx.finding("imagesize", "dimensions", "Dimensions").category("file").error(e.to_string())),
        }

        let exif_result = exif::Reader::new().read_from_container(&mut BufReader::new(Cursor::new(&bytes)));
        match exif_result {
            Err(e) => {
                ctx.emit(
                    ctx.finding("exif", "exif", "EXIF metadata")
                        .category("metadata")
                        .status(FindingStatus::NotFound)
                        .summary(format!("no EXIF block ({e}). Social platforms strip metadata on upload.")),
                );
            }
            Ok(exif) => {
                let mut fields = serde_json::Map::new();
                let mut count = 0;
                for f in exif.fields() {
                    if f.ifd_num == In::PRIMARY || f.ifd_num == In::THUMBNAIL {
                        let key = format!("{}", f.tag);
                        let val = f.display_value().with_unit(&exif).to_string();
                        fields.insert(key, serde_json::Value::String(val.chars().take(200).collect()));
                        count += 1;
                    }
                }
                ctx.emit(
                    ctx.finding("exif", "exif", "EXIF metadata")
                        .category("metadata")
                        .status(FindingStatus::Found)
                        .summary(format!("{count} tags present"))
                        .data(serde_json::Value::Object(fields)),
                );

                let get = |tag: Tag| exif.get_field(tag, In::PRIMARY).map(|f| f.display_value().with_unit(&exif).to_string().trim_matches('"').to_string());
                let make = get(Tag::Make);
                let model = get(Tag::Model);
                let lens = get(Tag::LensModel);
                if make.is_some() || model.is_some() {
                    ctx.emit(
                        ctx.finding("exif", "camera", "Camera")
                            .category("metadata")
                            .status(FindingStatus::Found)
                            .summary(format!("{} {}{}", make.clone().unwrap_or_default(), model.clone().unwrap_or_default(), lens.as_ref().map(|l| format!(" · {l}")).unwrap_or_default()).trim().to_string())
                            .data(json!({ "make": make, "model": model, "lens": lens, "exposure": get(Tag::ExposureTime), "fNumber": get(Tag::FNumber), "iso": get(Tag::PhotographicSensitivity), "focalLength": get(Tag::FocalLength) })),
                    );
                } else {
                    ctx.emit(ctx.finding("exif", "camera", "Camera").category("metadata").status(FindingStatus::NotFound).summary("no camera make/model"));
                }

                let taken = get(Tag::DateTimeOriginal).or_else(|| get(Tag::DateTime));
                ctx.emit(match &taken {
                    Some(t) => ctx
                        .finding("exif", "timestamp", "Capture time")
                        .category("metadata")
                        .status(FindingStatus::Found)
                        .summary(t.clone())
                        .data(json!({ "dateTimeOriginal": get(Tag::DateTimeOriginal), "dateTime": get(Tag::DateTime), "digitized": get(Tag::DateTimeDigitized), "offset": get(Tag::OffsetTimeOriginal) })),
                    None => ctx.finding("exif", "timestamp", "Capture time").category("metadata").status(FindingStatus::NotFound).summary("no timestamp"),
                });

                match gps_from(&exif) {
                    Some((lat, lon)) => {
                        gps = Some((lat, lon));
                        ctx.emit(
                            ctx.finding("exif", "gps", "GPS position")
                                .category("metadata")
                                .status(FindingStatus::Found)
                                .summary(format!("{lat:.6}, {lon:.6} · pivot to the Location probe for every map tool"))
                                .url(format!("https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"))
                                .data(json!({ "lat": lat, "lon": lon, "altitude": get(Tag::GPSAltitude), "googleMaps": format!("https://www.google.com/maps?q={lat},{lon}") }))
                                .discover(EntityType::Location, format!("{lat:.6},{lon:.6}"), Some("EXIF GPS")),
                        )
                    }
                    None => ctx.emit(ctx.finding("exif", "gps", "GPS position").category("metadata").status(FindingStatus::NotFound).summary("no GPS tags")),
                }

                let software = get(Tag::Software);
                let artist = get(Tag::Artist);
                let copyright = get(Tag::Copyright);
                let comment = get(Tag::UserComment).or_else(|| get(Tag::ImageDescription));
                let any = software.is_some() || artist.is_some() || copyright.is_some() || comment.is_some();
                let mut f = ctx
                    .finding("exif", "authoring", "Software and authorship")
                    .category("metadata")
                    .status(if any { FindingStatus::Found } else { FindingStatus::NotFound })
                    .summary(if any {
                        [software.clone(), artist.clone(), copyright.clone()].into_iter().flatten().collect::<Vec<_>>().join(" · ")
                    } else {
                        "no software, artist or copyright tags".to_string()
                    })
                    .data(json!({ "software": software, "artist": artist, "copyright": copyright, "comment": comment }));
                if let Some(a) = &artist {
                    f = f.discover(EntityType::Person, a.clone(), Some("EXIF artist"));
                }
                ctx.emit(f);
            }
        }
    }

    // Reverse image launchers. Local files cannot be uploaded from a link, so these open the
    // search pages where the file can be dropped in. Run the original AND a flipped copy: a
    // horizontal flip defeats many exact-match indexes (see "Save flipped copy" in the form).
    if !is_pdf && !is_office {
        for (source, title, url, summary) in [
            ("Google Lens", "Google Lens", "https://lens.google.com/upload", "Drop the file into Lens. Try the flipped copy too."),
            ("Yandex", "Yandex Images", "https://yandex.com/images/", "Camera icon accepts a file; strong on faces and places"),
            ("Bing", "Bing Visual Search", "https://www.bing.com/visualsearch", "Upload or drag the image"),
            ("TinEye", "TinEye", "https://tineye.com/", "Exact and edited copies with first-seen dates. Never upload contraband imagery."),
        ] {
            ctx.emit(ctx.finding(source, "launcher", title).category("reverse-image").status(FindingStatus::Info).url(url).summary(summary));
        }
    }

    launchers::emit(&ctx, &file_launchers);

    if let Some((lat, lon)) = gps {
        let geo = launchers::plan(EntityType::Location, &launchers::vars_location(lat, lon));
        launchers::emit(&ctx, &geo);
    }
    Ok(())
}

/// Writes a horizontally flipped copy next to the original and returns its path.
pub fn save_flipped(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("Could not read the file: {e}"))?;
    let img = image::load_from_memory(&bytes).map_err(|e| format!("Could not decode the image: {e}"))?;
    let flipped = img.fliph();
    let stem = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "image".into());
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_else(|| "png".into());
    let ext = if ["jpg", "jpeg", "png", "webp", "bmp", "tiff", "tif", "gif"].contains(&ext.as_str()) { ext } else { "png".to_string() };
    let out = path.with_file_name(format!("{stem}.flipped.{ext}"));
    flipped.save(&out).map_err(|e| format!("Could not save the flipped copy: {e}"))?;
    Ok(out.display().to_string())
}
