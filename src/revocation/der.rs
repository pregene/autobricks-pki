use crate::Result;
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else {
        let raw = content.len().to_be_bytes();
        let first = raw.iter().position(|b| *b != 0).unwrap_or(raw.len() - 1);
        out.push(0x80 | (raw.len() - first) as u8);
        out.extend_from_slice(&raw[first..]);
    }
    out.extend_from_slice(content);
    out
}
pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}
pub fn read<'a>(input: &mut &'a [u8]) -> Result<(u8, &'a [u8], &'a [u8])> {
    let original = *input;
    if original.len() < 2 {
        return Err("truncated DER".into());
    }
    let tag = original[0];
    let n = original[1];
    let mut offset = 2;
    let len = if n & 0x80 == 0 {
        usize::from(n)
    } else {
        let count = usize::from(n & 0x7f);
        if count == 0 || count > 8 || original.len() < 2 + count {
            return Err("invalid DER length".into());
        }
        offset += count;
        let mut size = 0usize;
        for b in &original[2..offset] {
            size = size
                .checked_mul(256)
                .and_then(|v| v.checked_add(usize::from(*b)))
                .ok_or("DER overflow")?;
        }
        size
    };
    let end = offset.checked_add(len).ok_or("DER overflow")?;
    if end > original.len() {
        return Err("truncated DER value".into());
    }
    *input = &original[end..];
    Ok((tag, &original[offset..end], &original[..end]))
}
pub fn content(data: &[u8], tag: u8) -> Result<&[u8]> {
    let mut data = data;
    let (t, c, _) = read(&mut data)?;
    if t != tag || !data.is_empty() {
        return Err("unexpected DER type".into());
    }
    Ok(c)
}
pub fn time(timestamp: i64) -> Result<Vec<u8>> {
    let d = chrono::DateTime::from_timestamp(timestamp, 0).ok_or("invalid timestamp")?;
    Ok(tlv(0x18, d.format("%Y%m%d%H%M%SZ").to_string().as_bytes()))
}
