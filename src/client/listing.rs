use crate::{Result, storage::listing::CertificateListEntry};
use std::fmt::Write;

pub fn render(response: &[u8]) -> Result<String> {
    let entries: Vec<CertificateListEntry> = serde_json::from_slice(response)?;
    let mut rows = vec![vec![
        "Index".to_owned(),
        "Common Name".to_owned(),
        "Status".to_owned(),
        "IssuedAt".to_owned(),
        "remain".to_owned(),
        "Fingerprint".to_owned(),
    ]];
    for entry in entries {
        let date = chrono::DateTime::from_timestamp(entry.issue_at, 0)
            .ok_or("invalid certificate issue time")?;
        rows.push(vec![
            entry.idx.to_string(),
            clean(&entry.cn),
            clean(&entry.valid),
            date.format("%Y-%m-%d %H:%M:%S").to_string(),
            entry.remain.to_string(),
            clean(&entry.fingerprint),
        ]);
    }
    let mut widths = [0; 6];
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let mut output = String::new();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i == 5 {
                writeln!(output, "{cell}")?;
            } else {
                write!(output, "{cell:width$}  ", width = widths[i])?;
            }
        }
    }
    Ok(output)
}

fn clean(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}
