use autobricks_pki::{
    certificate::{access::Access, profile::Distribution, validity::Validity},
    client,
    revocation::ocsp,
    transport::{
        management::{self, Message},
        request::Request,
    },
};
use std::io::Cursor;

fn parse_external_bytes(bytes: &[u8]) {
    let _ = Request::read(&mut Cursor::new(bytes));
    let _ = management::read_frame::<Message>(&mut Cursor::new(bytes), 1024);
    let _ = ocsp::respond(bytes, &[], 0);
}

#[test]
fn external_input_truncations_and_byte_corpus_do_not_panic() {
    let seeds: &[&[u8]] = &[
        b"GET /root HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"POST /ocsp/ HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n00\r\n0\r\n\r\n",
        b"POST /ocsp/ HTTP/1.1\r\nHost: localhost\r\nContent-Length: 18446744073709551615\r\n\r\n",
        b"{\"method\":\"GET\",\"path\":\"/api/list\",\"content_type\":\"application/json\",\"body\":[]}\n",
        b"\x30\x88\xff\xff\xff\xff\xff\xff\xff\xff",
        b"\x30\x03\x30\x01\x00",
    ];
    for seed in seeds {
        for length in 0..=seed.len() {
            parse_external_bytes(&seed[..length]);
        }
        for offset in 0..seed.len() {
            for byte in [0, 10, 13, 0x7f, 0x80, 0xff] {
                let mut input = seed.to_vec();
                input[offset] = byte;
                parse_external_bytes(&input);
            }
        }
    }
    let mut state = 0x1234_5678_u32;
    for length in 0..512 {
        let mut input = Vec::with_capacity(length);
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            input.push(state as u8);
        }
        parse_external_bytes(&input);
    }
}

#[test]
fn frame_limit_boundary_does_not_overflow() {
    let mut input = Cursor::new(b"{}\n");
    assert!(management::read_frame::<Message>(&mut input, usize::MAX).is_err());
}

#[test]
fn text_and_validity_boundaries_do_not_panic() {
    for value in [
        "",
        ".",
        "..",
        "%",
        "%ff",
        "/",
        "a/b",
        "\0",
        "日本語",
        "😀",
        "https://[",
        "::/129",
    ] {
        let _ = client::segment(value);
        let _ = client::public_origin(value, 5546);
        let _ = Access::parse(value);
        let _ = Distribution::new(value);
    }
    let parent = Validity {
        not_before: i64::MIN,
        not_after: i64::MAX,
    };
    let huge = parent;
    assert!(huge.renewed(0, parent).is_err());
    let leaf = Validity {
        not_before: 0,
        not_after: 7 * 86400,
    };
    assert!(leaf.renewed(i64::MAX, parent).is_err());
    for timestamp in [i64::MIN, -1, 0, i64::MAX] {
        let _ = Validity::new(timestamp, u32::MAX, Some(parent));
        let _ = leaf.renewable(timestamp);
    }
}
