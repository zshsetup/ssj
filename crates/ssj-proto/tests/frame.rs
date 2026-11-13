mod common;

use common::{client_frames, server_frames};
use ssj_proto::frame::{MAX_DATA_LEN, MAX_FRAME_LEN};
use ssj_proto::{ClientFrame, DecodeError, ServerFrame, decode_client, decode_server};

/// Feeds `stream` in chunks of `step` bytes, like a socket would, and collects all frames.
type Decode<F> = fn(&[u8]) -> Result<Option<(F, usize)>, DecodeError>;

fn decode_in_chunks<F>(stream: &[u8], step: usize, decode: Decode<F>) -> Vec<F> {
    let (mut buf, mut frames) = (Vec::new(), Vec::new());
    for chunk in stream.chunks(step) {
        buf.extend_from_slice(chunk);
        while let Some((frame, used)) = decode(&buf).unwrap() {
            frames.push(frame);
            buf.drain(..used);
        }
    }
    assert!(buf.is_empty(), "{} bytes left over", buf.len());
    frames
}

#[test]
fn client_frames_survive_any_chunking_of_the_stream() {
    let frames = client_frames();
    let mut stream = Vec::new();
    for frame in &frames {
        frame.encode(&mut stream).unwrap();
    }
    for step in [1, 2, 3, 5, 7, 1000, stream.len()] {
        assert_eq!(
            decode_in_chunks(&stream, step, decode_client),
            frames,
            "step {step}"
        );
    }
}

#[test]
fn server_frames_survive_any_chunking_of_the_stream() {
    let frames = server_frames();
    let mut stream = Vec::new();
    for frame in &frames {
        frame.encode(&mut stream).unwrap();
    }
    for step in [1, 2, 3, 5, 7, 1000, stream.len()] {
        assert_eq!(
            decode_in_chunks(&stream, step, decode_server),
            frames,
            "step {step}"
        );
    }
}

// the announced length is judged from the 4 header bytes, before any body is buffered.
#[test]
fn bad_length_is_rejected_from_the_header_alone() {
    for len in [0u32, MAX_FRAME_LEN as u32 + 1, u32::MAX] {
        let header = len.to_be_bytes();
        assert_eq!(
            decode_client(&header).unwrap_err(),
            DecodeError::BadLength,
            "{len}"
        );
        assert_eq!(
            decode_server(&header).unwrap_err(),
            DecodeError::BadLength,
            "{len}"
        );
    }
    // the largest allowed frame just waits for its body.
    let header = (MAX_FRAME_LEN as u32).to_be_bytes();
    assert_eq!(decode_client(&header), Ok(None));
}

fn raw(body: &[u8]) -> Vec<u8> {
    let mut out = (body.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(body);
    out
}

fn varint(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    while n >= 0x80 {
        out.push(n as u8 | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
    out
}

// the bodies in the layout of postcard: the index of the variant, then its fields. The window
// size is 24 by 80, and a start has its environment and then the flag of the agent.
#[test]
fn malformed_client_frames_are_rejected() {
    let oversized = [&[1][..], &varint(MAX_DATA_LEN + 1), &[0; MAX_DATA_LEN + 1]].concat();
    let cases: Vec<(&str, &[u8])> = vec![
        ("unknown type", &[12]),
        ("close with a body", &[4, 0]),
        ("ping with a body", &[7, 0]),
        ("ack cut in its varint", &[3, 0x80]),
        ("ack with trailing bytes", &[3, 1, 0]),
        ("empty input", &[1, 0]),
        ("input shorter than its length", &[1, 5, b'a']),
        ("oversized input", &oversized),
        ("zero rows", &[2, 0, 80]),
        ("zero cols", &[2, 24, 0]),
        ("huge cols", &[2, 24, 0xff, 0xff, 0x03]),
        ("unknown hello kind", &[0, 9, 24, 80]),
        ("attach with trailing bytes", &[0, 2, 24, 80, 1]),
        ("resume without offset", &[0, 1, 24, 80]),
        // the count is not trusted for the allocation.
        (
            "env count without entries",
            &[0, 0, 24, 80, 0xff, 0xff, 0x03],
        ),
        ("env missing entries", &[0, 0, 24, 80, 2, 1, b'A', 0]),
        ("env name is not utf-8", &[0, 0, 24, 80, 1, 1, 0xff, 0, 0]),
        (
            "env name with equals",
            &[0, 0, 24, 80, 1, 3, b'A', b'=', b'B', 0, 0],
        ),
        ("env value with NUL", &[0, 0, 24, 80, 1, 1, b'A', 1, 0, 0]),
        (
            "env duplicate",
            &[0, 0, 24, 80, 2, 1, b'A', 0, 1, b'A', 0, 0],
        ),
        ("agent flag out of range", &[0, 0, 24, 80, 0, 2]),
        ("agent data without bytes", &[10, 1, 0]),
        ("agent close with a body", &[11, 1, 0]),
    ];
    for (name, body) in cases {
        assert_eq!(
            decode_client(&raw(body)).unwrap_err(),
            DecodeError::Invalid,
            "{name}"
        );
    }
    assert_eq!(decode_client(&raw(&[7])), Ok(Some((ClientFrame::Ping, 5))));
}

#[test]
fn malformed_server_frames_are_rejected() {
    let cases: Vec<(&str, &[u8])> = vec![
        ("unknown type", &[12]),
        ("pong with a body", &[5, 0]),
        ("welcome too short", &[1, 3]),
        ("empty output", &[0, 0]),
        ("unknown exit kind", &[3, 2, 0]),
        ("unknown error code", &[4, 6]),
        ("unknown error code, high", &[4, 200]),
        ("empty gap", &[6, 0]),
    ];
    for (name, body) in cases {
        assert_eq!(
            decode_server(&raw(body)).unwrap_err(),
            DecodeError::Invalid,
            "{name}"
        );
    }
    assert_eq!(decode_server(&raw(&[5])), Ok(Some((ServerFrame::Pong, 5))));
}

#[test]
fn encoding_bad_data_leaves_the_buffer_unchanged() {
    for frame in [
        ClientFrame::Input(vec![]),
        ClientFrame::Input(vec![0; MAX_DATA_LEN + 1]),
    ] {
        let mut out = b"keep".to_vec();
        assert!(frame.encode(&mut out).is_err());
        assert_eq!(out, b"keep");
    }
    for frame in [ServerFrame::Output(vec![]), ServerFrame::Gap(0)] {
        let mut out = b"keep".to_vec();
        assert!(frame.encode(&mut out).is_err());
        assert_eq!(out, b"keep");
    }
}

/// xorshift, so the test needs no dependency and is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

// cheap stand-in for the real fuzzer, which runs on a single platform only.
#[test]
fn decoders_do_not_panic_on_random_or_mutated_input() {
    let mut rng = Rng(0x9e3779b97f4a7c15);
    let mut seeds = Vec::new();
    for frame in client_frames() {
        let mut bytes = Vec::new();
        frame.encode(&mut bytes).unwrap();
        seeds.push((bytes, true));
    }
    for frame in server_frames() {
        let mut bytes = Vec::new();
        frame.encode(&mut bytes).unwrap();
        seeds.push((bytes, false));
    }

    for round in 0..200_000u64 {
        let (mut bytes, _) = seeds[(rng.next() % seeds.len() as u64) as usize].clone();
        match round % 3 {
            // flip a few bits.
            0 => {
                for _ in 0..1 + rng.next() % 4 {
                    let at = (rng.next() % bytes.len() as u64) as usize;
                    bytes[at] ^= 1 << (rng.next() % 8);
                }
            }
            // cut off
            1 => bytes.truncate((rng.next() % (bytes.len() as u64 + 1)) as usize),
            // pure noise behind a plausible header.
            _ => {
                let len = (rng.next() % 64) as usize;
                bytes = (1 + len as u32).to_be_bytes().to_vec();
                bytes.extend((0..=len).map(|_| rng.next() as u8));
            }
        }
        for result in [
            decode_client(&bytes).map(|r| r.map(|(_, n)| n)),
            decode_server(&bytes).map(|r| r.map(|(_, n)| n)),
        ] {
            if let Ok(Some(used)) = result {
                assert!(used <= bytes.len());
            }
        }
    }
}

// looking at a frame must agree with decoding it, for every frame and every cut of the stream.
#[test]
fn peeking_agrees_with_decoding() {
    use ssj_proto::{Peek, peek_server};

    for frame in server_frames() {
        let mut bytes = Vec::new();
        frame.encode(&mut bytes).unwrap();
        for cut in 0..bytes.len() {
            assert_eq!(
                peek_server(&bytes[..cut]),
                Ok(Peek::Incomplete),
                "{frame:?} cut {cut}"
            );
        }
        let (decoded, used) = decode_server(&bytes).unwrap().unwrap();
        match (peek_server(&bytes).unwrap(), &decoded) {
            (Peek::Output { data, used: peeked }, ServerFrame::Output(expected)) => {
                assert_eq!(&bytes[data], expected.as_slice());
                assert_eq!(peeked, used);
            }
            (Peek::Other, other) => assert!(!matches!(other, ServerFrame::Output(_))),
            (peeked, decoded) => panic!("{peeked:?} for {decoded:?}"),
        }
    }
    // a frame of one kind followed by another: only the first counts.
    let mut two = Vec::new();
    ServerFrame::Pong.encode(&mut two).unwrap();
    ServerFrame::Output(b"x".to_vec()).encode(&mut two).unwrap();
    assert_eq!(peek_server(&two), Ok(Peek::Other));
    // an output frame without data, one without its length, and a header that is too large, are
    // errors.
    assert!(peek_server(&raw(&[0, 0])).is_err());
    assert!(peek_server(&raw(&[0])).is_err());
    assert!(peek_server(&[0xff, 0xff, 0xff, 0xff]).is_err());
}

// postcard takes a number that is written longer than it needs to be, so a frame can decode from
// bytes that it does not encode to. The server input was found by the fuzzer; the client input
// is a resize with a row count of 24 written in two bytes (the fuzzer input of protocol 2 had
// the layout of the old window size). The frame has to survive the round trip all the same.
#[test]
fn a_number_written_too_long_decodes_and_the_frame_survives_a_round_trip() {
    let client = [0, 0, 0, 6, 2, 152, 0, 80, 0, 0, 7];
    let (frame, used) = decode_client(&client).unwrap().unwrap();
    assert_eq!(used, 10);
    let mut again = Vec::new();
    frame.encode(&mut again).unwrap();
    assert_ne!(again, &client[..used]);
    assert_eq!(decode_client(&again), Ok(Some((frame, again.len()))));

    let server = [0, 0, 0, 7, 1, 0, 255, 255, 255, 255, 0];
    let (frame, used) = decode_server(&server).unwrap().unwrap();
    assert_eq!(used, server.len());
    let mut again = Vec::new();
    frame.encode(&mut again).unwrap();
    assert_eq!(decode_server(&again), Ok(Some((frame, again.len()))));
}
