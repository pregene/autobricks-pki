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
