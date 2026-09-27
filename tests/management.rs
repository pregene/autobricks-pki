use autobricks_pki::transport::management::{Message, read_frame};

#[test]
fn rejects_truncated_oversized_and_http_frames() {
    let complete =
        br#"{"method":"GET","path":"/api/list","content_type":"application/json","body":[]}
"#;
    assert!(read_frame::<Message>(&mut &complete[..complete.len() - 1], 1024).is_err());
    assert!(read_frame::<Message>(&mut &complete[..], complete.len() - 1).is_err());
    assert!(read_frame::<Message>(&mut &b"GET /api/list HTTP/1.1\r\n"[..], 1024).is_err());
    let message = read_frame::<Message>(&mut &complete[..], complete.len()).unwrap();
    assert!(message.into_request().is_ok());
}

#[test]
fn rejects_public_paths_and_unknown_fields() {
    let public = br#"{"method":"GET","path":"/root","content_type":"application/json","body":[]}
"#;
    let message = read_frame::<Message>(&mut &public[..], 1024).unwrap();
    assert!(message.into_request().is_err());
    let extra = br#"{"method":"GET","path":"/api/list","content_type":"application/json","body":[],"admin":true}
"#;
    assert!(read_frame::<Message>(&mut &extra[..], 1024).is_err());
}

#[test]
fn binary_frames_round_trip_bytes_without_json_expansion() {
    use autobricks_pki::transport::management::{Reply, write_frame};
    let body: Vec<u8> = (0..65536).map(|n| (n % 256) as u8).collect();
    let reply = Reply {
        status: "200 OK".into(),
        content_type: "application/octet-stream".into(),
        body: body.clone(),
    };
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &reply, 100_000).unwrap();
    assert!(bytes.starts_with(b"ABP1"));
    assert!(bytes.len() < body.len() + 256);
    let restored: Reply = read_frame(&mut bytes.as_slice(), 100_000).unwrap();
    assert_eq!(restored.body, body);
    assert!(read_frame::<Reply>(&mut &bytes[..bytes.len() - 1], 100_000).is_err());
    assert!(read_frame::<Reply>(&mut bytes.as_slice(), bytes.len() - 1).is_err());
    let mut malicious = b"ABP1".to_vec();
    malicious.extend(1u32.to_be_bytes());
    malicious.extend(u32::MAX.to_be_bytes());
    assert!(read_frame::<Reply>(&mut malicious.as_slice(), 1024).is_err());
}

#[test]
fn legacy_frames_keep_response_format_and_binary_frames_do_not_consume_next() {
    use autobricks_pki::transport::management::{
        Format, Reply, read_frame_with_format, write_frame, write_frame_with_format,
    };
    let legacy=b"{\"method\":\"GET\",\"path\":\"/api/list\",\"content_type\":\"application/json\",\"body\":[]}\n";
    let (_, format) = read_frame_with_format::<Message>(&mut legacy.as_slice(), 1024).unwrap();
    assert!(matches!(format, Format::Legacy));
    let reply = Reply {
        status: "200 OK".into(),
        content_type: "text/plain".into(),
        body: b"ok".to_vec(),
    };
    let mut old = Vec::new();
    write_frame_with_format(&mut old, &reply, 1024, format).unwrap();
    assert!(old.starts_with(b"{") && old.ends_with(b"\n"));
    assert_eq!(serde_json::from_slice::<Reply>(&old).unwrap().body, b"ok");
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &reply, 1024).unwrap();
    write_frame(&mut bytes, &reply, 1024).unwrap();
    let mut input = bytes.as_slice();
    assert_eq!(read_frame::<Reply>(&mut input, 1024).unwrap().body, b"ok");
    assert_eq!(read_frame::<Reply>(&mut input, 1024).unwrap().body, b"ok");
    assert!(input.is_empty());
}
