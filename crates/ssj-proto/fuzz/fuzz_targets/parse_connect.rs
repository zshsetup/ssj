// fuzz target. The first line is a comment, so that the file does not look like a script.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ssj_proto::bootstrap::{format_pin, parse_connect, parse_pin, sanitize, format_connect};

// A parsed line must parse back to the same value once formatted. The text itself may differ, since
// the port of TCP from earlier servers is read and dropped.
fuzz_target!(|data: &[u8]| {
    if let Ok(Some(connect)) = parse_connect(data) {
        let line = format_connect(&connect);
        assert_eq!(parse_connect(line.as_bytes()), Ok(Some(connect)));
    }
    if let Ok(pin) = parse_pin(data) {
        let line = format_pin(&pin);
        assert!(data.starts_with(line.trim_end().as_bytes()));
    }
    let shown = sanitize(data, 80);
    assert!(!shown.chars().any(|c| c.is_control()));
    assert!(shown.chars().count() <= 83);
});
