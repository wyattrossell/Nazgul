//! Image probe: local metadata extraction (EXIF / XMP-ish), dimensions, file hashes, GPS,
//! and reverse-image search launchers. Nothing about the file leaves the machine.

use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use exif::{In, Tag, Value};
use md5::{Digest as Md5Digest, Md5};
use serde_json::json;
use sha2::Sha256;

use super::{FindingStatus, ScanContext};

fn rational_to_deg(v: &Value) -> Option<f64> {
    match v {
        Value::Rational(r) if r.len() >= 3 => {
            Some(r[0].to_f64() + r[1].to_f64() / 60.0 + r[2].to_f64() / 3600.0)
        }
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

pub async fn run(ctx: Arc<ScanContext>) -> Result<(), String> {
    let path = Path::new(ctx.input.trim());
    if !path.is_file() {
        return Err(format!("\"{}\" is not a file I can open.", ctx.input.trim()));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("Could not read the file: {e}"))?;
    let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

    // file, dimensions, hashes, exif, camera, timestamp, gps, software, launchers x4
    ctx.start(12);

    let size_kb = bytes.len() as f64 / 1024.0;
    let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    ctx.emit(
        ctx.finding("file", "file", &name)
            .category("file")
            .status(FindingStatus::Info)
            .summary(format!("{size_kb:.1} KB · .{ext}"))
            .data(json!({ "path": path.display().to_string(), "bytes": bytes.len(), "extension": ext })),
    );

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

    // EXIF.
    let exif_result = exif::Reader::new().read_from_container(&mut BufReader::new(std::io::Cursor::new(&bytes)));
    match exif_result {
        Err(e) => {
            ctx.emit(
                ctx.finding("exif", "exif", "EXIF metadata")
                    .category("metadata")
                    .status(FindingStatus::NotFound)
                    .summary(format!("no EXIF block ({e}). Social platforms strip metadata on upload.")),
            );
            for _ in 0..4 {
                // keep progress honest: camera, timestamp, gps, software are unavailable
            }
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
                Some((lat, lon)) => ctx.emit(
                    ctx.finding("exif", "gps", "GPS position")
                        .category("metadata")
                        .status(FindingStatus::Found)
                        .summary(format!("{lat:.6}, {lon:.6}"))
                        .url(format!("https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=16/{lat}/{lon}"))
                        .data(json!({ "lat": lat, "lon": lon, "altitude": get(Tag::GPSAltitude), "googleMaps": format!("https://www.google.com/maps?q={lat},{lon}") })),
                ),
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
                f = f.discover(super::EntityType::Person, a.clone(), Some("EXIF artist"));
            }
            ctx.emit(f);
        }
    }

    // Reverse image launchers. Local files cannot be uploaded from a link, so these open the
    // search pages where the file can be dropped in.
    for (source, title, url, summary) in [
        ("Google Lens", "Google Lens", "https://lens.google.com/upload", "Drop the file into Lens"),
        ("Yandex", "Yandex Images", "https://yandex.com/images/", "Camera icon accepts a file; strong on faces and places"),
        ("Bing", "Bing Visual Search", "https://www.bing.com/visualsearch", "Upload or drag the image"),
        ("TinEye", "TinEye", "https://tineye.com/", "Finds exact and edited copies with first-seen dates"),
    ] {
        ctx.emit(
            ctx.finding(source, "launcher", title)
                .category("reverse-image")
                .status(FindingStatus::Info)
                .url(url)
                .summary(summary),
        );
    }

    Ok(())
}
