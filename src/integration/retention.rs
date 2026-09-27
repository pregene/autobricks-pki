use crate::Result;
use std::path::Path;

pub fn days(path: &Path) -> Result<u32> {
    let configuration = std::fs::read_to_string(path)?;
    let mut result = None;
    for line in configuration.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() != "AB_WORM_RETAIN_DAYS" {
            continue;
        }
        if result.is_some() {
            return Err("duplicate TrueLog retention setting".into());
        }
        let value = value.split('#').next().unwrap_or("").trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        result = Some(value.parse::<u32>()?);
    }
    result.ok_or_else(|| {
        "TrueLog AB_WORM_RETAIN_DAYS is missing; cannot initialize CA validity".into()
    })
}
