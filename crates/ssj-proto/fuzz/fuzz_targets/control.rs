// fuzz target. The first line is a comment, so that the file does not look like a script.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ssj_proto::control::{Reply, format_reply, format_request, parse_reply, parse_request};

// whatever parses must format back to the same line, or to the same value for a connect line.
fuzz_target!(|data: &[u8]| {
    if let Ok(request) = parse_request(data) {
        let line = format_request(&request);
        assert_eq!(line.as_bytes(), data.strip_suffix(b"\n").map_or(data, |d| d).iter().chain(b"\n").copied().collect::<Vec<u8>>());
    }
    if let Ok(reply) = parse_reply(data) {
        let line = format_reply(&reply);
        // a connect line may carry the port of TCP from earlier servers, which formatting drops.
        if matches!(reply, Reply::Connect(_)) {
            assert_eq!(parse_reply(line.as_bytes()), Ok(reply));
        } else {
            let mut expected = data.to_vec();
            if !expected.ends_with(b"\n") {
                expected.push(b'\n');
            }
            assert_eq!(line.as_bytes(), expected);
        }
    }
});
