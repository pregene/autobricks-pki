use autobricks_pki::transport::request::Request;
#[test]
fn binary_post_and_chunking() {
    for raw in [b"POST /ocsp/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n\x30\x02\x00\xff".as_slice(),b"POST /ocsp/ HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n\x30\x02\x00\xff\r\n0\r\n\r\n".as_slice()]{let r=Request::read(&mut std::io::Cursor::new(raw)).unwrap();assert_eq!(r.body,b"\x30\x02\x00\xff");}
}
#[test]
fn rejects_ambiguous_and_truncated_requests() {
    for raw in [
        "POST /ocsp/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n",
        "POST /ocsp/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST /ocsp/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nabc",
        "GET / HTTP/1.1\r\nBad Header: x\r\n\r\n",
    ] {
        assert!(Request::read(&mut std::io::Cursor::new(raw)).is_err());
    }
}
