use autobricks_pki::transport::management::{Message, read_frame};

#[test]
fn rejects_truncated_oversized_and_http_frames() {
    use autobricks_pki::transport::management::write_frame;
    let message = Message {
        method: "GET".into(),
        path: "/api/list".into(),
        content_type: "application/json".into(),
        credential: None,
        body: Vec::new(),
    };
    let mut complete = Vec::new();
    write_frame(&mut complete, &message, 1024).unwrap();
    assert!(read_frame::<Message>(&mut &complete[..complete.len() - 1], 1024).is_err());
    assert!(read_frame::<Message>(&mut &complete[..], complete.len() - 1).is_err());
    assert!(read_frame::<Message>(&mut &b"GET /api/list HTTP/1.1\r\n"[..], 1024).is_err());
    let message = read_frame::<Message>(&mut &complete[..], complete.len()).unwrap();
    assert!(message.into_request().is_ok());
}

#[test]
fn rejects_public_paths_and_unknown_fields() {
    use autobricks_pki::transport::management::write_frame;
    let message = Message {
        method: "GET".into(),
        path: "/root".into(),
        content_type: "application/json".into(),
        credential: None,
        body: Vec::new(),
    };
    let mut public = Vec::new();
    write_frame(&mut public, &message, 1024).unwrap();
    let message = read_frame::<Message>(&mut &public[..], 1024).unwrap();
    assert!(message.into_request().is_err());
    let mut extra = b"ABP1".to_vec();
    let header = br#"{"method":"GET","path":"/api/list","content_type":"application/json","credential":null,"admin":true}"#;
    extra.extend(u32::try_from(header.len()).unwrap().to_be_bytes());
    extra.extend(0_u32.to_be_bytes());
    extra.extend(header);
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
fn binary_frames_do_not_consume_the_next_frame() {
    use autobricks_pki::transport::management::{Reply, write_frame};
    let reply = Reply {
        status: "200 OK".into(),
        content_type: "text/plain".into(),
        body: b"ok".to_vec(),
    };
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &reply, 1024).unwrap();
    write_frame(&mut bytes, &reply, 1024).unwrap();
    let mut input = bytes.as_slice();
    assert_eq!(read_frame::<Reply>(&mut input, 1024).unwrap().body, b"ok");
    assert_eq!(read_frame::<Reply>(&mut input, 1024).unwrap().body, b"ok");
    assert!(input.is_empty());
}

#[test]
fn structured_message_round_trips_without_protocol_selection() {
    use autobricks_pki::transport::management::{read_structured, write_structured};
    let message = Message {
        method: "GET".into(),
        path: "/api/list-ca?after=0&status=valid".into(),
        content_type: "application/json".into(),
        credential: None,
        body: Vec::new(),
    };
    let mut bytes = Vec::new();
    write_structured(&mut bytes, &message, 4096).unwrap();
    let restored: Message = read_structured(&mut bytes.as_slice(), 4096).unwrap();
    assert_eq!(restored.path, message.path);
}
