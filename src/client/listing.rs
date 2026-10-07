use crate::{Result, client::models::CertificateListEntry};
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

pub fn print_all(
    socket: &std::path::Path,
    command: &str,
    filter: crate::client::models::ListFilter,
    output: &mut impl std::io::Write,
) -> Result<()> {
    stream_pages(
        |after, through| {
            let mut path = format!("/api/{command}?after={after}");
            path.push_str(&format!("&status={}", filter.name()));
            if let Some(through) = through {
                path.push_str(&format!("&through={through}"));
            }
            let bytes = super::daemon::call(
                socket,
                &crate::transport::management::Message {
                    method: "GET".into(),
                    path,
                    content_type: "application/json".into(),
                    credential: None,
                    body: vec![],
                },
            )?;
            Ok(serde_json::from_slice(&bytes)?)
        },
        output,
    )
}

pub fn stream_pages(
    mut fetch: impl FnMut(i64, Option<i64>) -> Result<crate::client::models::CertificatePage>,
    output: &mut impl std::io::Write,
) -> Result<()> {
    let mut after = 0;
    let mut through = None;
    let mut header = true;
    loop {
        let page = fetch(after, through)?;
        if page.entries.len() > crate::client::models::PAGE_SIZE
            || page.through < after
            || through.is_some_and(|upper| upper != page.through)
        {
            return Err("invalid list page".into());
        }
        let mut last = after;
        for entry in &page.entries {
            if entry.idx <= last || entry.idx > page.through {
                return Err("invalid list order".into());
            }
            last = entry.idx;
        }
        if page
            .next_after
            .is_some_and(|next| next != last || next <= after)
        {
            return Err("invalid next cursor".into());
        }
        if header {
            writeln!(
                output,
                "{:<5}  {:<41}  {:<10}  {:<19}  {:<6}  Fingerprint",
                "Index", "Common Name", "Status", "IssuedAt", "remain"
            )?;
            header = false;
        }
        for entry in &page.entries {
            let date = chrono::DateTime::from_timestamp(entry.issue_at, 0)
                .ok_or("invalid certificate issue time")?;
            writeln!(
                output,
                "{:<5}  {:<41}  {:<10}  {:<19}  {:<6}  {}",
                entry.idx,
                clean(&entry.cn),
                clean(&entry.valid),
                date.format("%Y-%m-%d %H:%M:%S"),
                entry.remain,
                clean(&entry.fingerprint)
            )?;
        }
        output.flush()?;
        let Some(next) = page.next_after else {
            return Ok(());
        };
        after = next;
        through = Some(page.through);
    }
}
