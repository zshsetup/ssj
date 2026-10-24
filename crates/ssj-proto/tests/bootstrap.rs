use ssj_proto::bootstrap::{
    BootstrapError, Connect, format_connect, format_leg, format_pin, format_relay_port,
    format_relay_secret, parse_connect, parse_leg, parse_pin, parse_relay_port, parse_relay_secret,
    sanitize,
};
use ssj_proto::{SessionId, SessionName};

fn connect() -> Connect {
    let mut fingerprint = [0u8; 32];
    for (i, byte) in fingerprint.iter_mut().enumerate() {
        *byte = (i * 8 + 3) as u8;
    }
    Connect {
        id: SessionId::parse("abcdef012345").unwrap(),
        udp: Some(60123),
        fingerprint,
        new: false,
        name: None,
        socket: None,
    }
}

const BODY: &str =
    "abcdef012345 udp:1 tcp:2 030b131b232b333b434b535b636b737b838b939ba3abb3bbc3cbd3dbe3ebf3fb";
const HEX: &str = "030b131b232b333b434b535b636b737b838b939ba3abb3bbc3cbd3dbe3ebf3fb";

#[test]
fn line_has_a_fixed_shape() {
    assert_eq!(
        format_connect(&connect()),
        format!("SSJ CONNECT abcdef012345 udp:60123 none {HEX}\n")
    );
}

#[test]
fn finds_the_line_between_banners_and_noise() {
    let line = format_connect(&connect());
    let output = format!("Welcome to host\r\nlast login: today\n{line}some trailing text\n");
    assert_eq!(parse_connect(output.as_bytes()), Ok(Some(connect())));
    // windows line ending, as some shells and wrappers produce.
    let crlf = line.replace('\n', "\r\n");
    assert_eq!(parse_connect(crlf.as_bytes()), Ok(Some(connect())));
}

#[test]
fn waits_for_the_complete_line() {
    let line = format_connect(&connect());
    for cut in 0..line.len() - 1 {
        assert_eq!(
            parse_connect(&line.as_bytes()[..cut]),
            Ok(None),
            "cut at {cut}"
        );
    }
    assert_eq!(parse_connect(b""), Ok(None));
    assert_eq!(parse_connect(b"just a banner\n"), Ok(None));
}

// text that merely contains the prefix, such as an echoed command, is not the line.
#[test]
fn prefix_must_be_at_the_start_of_the_line() {
    for text in [
        format!(" SSJ CONNECT {BODY}\n"),
        format!("echo SSJ CONNECT {BODY}\n"),
        format!("ssj CONNECT {BODY}\n"),
        format!("SSJ  CONNECT {BODY}\n"),
    ] {
        assert_eq!(parse_connect(text.as_bytes()), Ok(None), "{text:?}");
    }
}

#[test]
fn malformed_lines_are_errors_and_not_ignored() {
    let upper = HEX.to_uppercase();
    let id = "abcdef012345";
    let cases = [
        // the port
        format!("SSJ CONNECT {id} udp:0 tcp:2 {HEX}\n"),
        format!("SSJ CONNECT {id} udp:65536 tcp:2 {HEX}\n"),
        format!("SSJ CONNECT {id} udp:080 tcp:2 {HEX}\n"),
        format!("SSJ CONNECT {id} udp:+80 tcp:2 {HEX}\n"),
        format!("SSJ CONNECT {id} udp:-1 tcp:2 {HEX}\n"),
        format!("SSJ CONNECT {id} udp:123456 tcp:2 {HEX}\n"),
        format!("SSJ CONNECT {id} udp: tcp:2 {HEX}\n"),
        format!("SSJ CONNECT {id} udp:1 tcp:0 {HEX}\n"),
        // the kind of the transport.
        format!("SSJ CONNECT {id} tcp:1 udp:2 {HEX}\n"),
        format!("SSJ CONNECT {id} 80 tcp:2 {HEX}\n"),
        format!("SSJ CONNECT {id} UDP:80 tcp:2 {HEX}\n"),
        format!("SSJ CONNECT {id} None tcp:2 {HEX}\n"),
        format!("SSJ CONNECT {id} - tcp:2 {HEX}\n"),
        // the id
        format!("SSJ CONNECT short udp:1 tcp:2 {HEX}\n"),
        format!("SSJ CONNECT ABCDEF012345 udp:1 tcp:2 {HEX}\n"),
        format!("SSJ CONNECT ../etc/passwd udp:1 tcp:2 {HEX}\n"),
        format!("SSJ CONNECT udp:1 tcp:2 {HEX}\n"),
        // the fingerprint
        format!("SSJ CONNECT {id} udp:1 tcp:2 {upper}\n"),
        format!("SSJ CONNECT {id} udp:1 tcp:2 {}\n", &HEX[1..]),
        format!("SSJ CONNECT {id} udp:1 tcp:2 {HEX}00\n"),
        format!("SSJ CONNECT {id} udp:1 tcp:2 {}g\n", &HEX[..63]),
        // the separators
        format!("SSJ CONNECT {id} udp:1\ttcp:2 {HEX}\n"),
        format!("SSJ CONNECT {id}  udp:1 tcp:2 {HEX}\n"),
        format!("SSJ CONNECT {id} udp:1 tcp:2 {HEX} extra\n"),
        format!("SSJ CONNECT {id} udp:1 tcp:2 {HEX} \n"),
        // the old line of one port.
        format!("SSJ CONNECT 80 {HEX}\n"),
        "SSJ CONNECT \n".to_owned(),
    ];
    for text in cases {
        assert_eq!(
            parse_connect(text.as_bytes()),
            Err(BootstrapError::Malformed),
            "{text:?}"
        );
    }
}

#[test]
fn two_lines_are_ambiguous_even_if_identical() {
    let line = format_connect(&connect());
    assert_eq!(
        parse_connect(format!("{line}{line}").as_bytes()),
        Err(BootstrapError::Ambiguous)
    );
}

#[test]
fn remote_text_cannot_carry_terminal_commands() {
    // clear screen, set title, and a fake prompt, as a hostile banner could send.
    let hostile = b"\x1b[2J\x1b]0;title\x07\x1b[31mred\r\x9b31m";
    let shown = sanitize(hostile, 100);
    assert!(!shown.chars().any(|c| c.is_control()), "{shown:?}");
    assert!(shown.contains("red"));

    // right-to-left override can reorder what the user reads.
    assert_eq!(sanitize("a\u{202e}b\u{2066}c".as_bytes(), 100), "a?b?c");
    assert_eq!(sanitize(b"\xff\xfe", 100), "\u{fffd}\u{fffd}");
}

#[test]
fn sanitized_text_is_cut_to_the_limit() {
    assert_eq!(sanitize(b"abcdef", 6), "abcdef");
    assert_eq!(sanitize(b"abcdefg", 6), "abcdef...");
    assert_eq!(sanitize("äöüäöüx".as_bytes(), 6), "äöüäöü...");
}

#[test]
fn pin_line_round_trips_and_rejects_everything_else() {
    let fingerprint = connect().fingerprint;
    assert_eq!(format_pin(&fingerprint), format!("SSJ PIN {HEX}\n"));
    assert_eq!(
        parse_pin(format_pin(&fingerprint).as_bytes()),
        Ok(fingerprint)
    );
    assert_eq!(
        parse_pin(format!("SSJ PIN {HEX}\r\n").as_bytes()),
        Ok(fingerprint)
    );
    assert_eq!(
        parse_pin(format!("SSJ PIN {HEX}").as_bytes()),
        Ok(fingerprint)
    );

    for bad in [
        format!("SSJ CONNECT {BODY}\n"),
        format!("SSJ PIN {}\n", HEX.to_uppercase()),
        format!("SSJ PIN {}\n", &HEX[2..]),
        format!("SSJ PIN {HEX}00\n"),
        format!(" SSJ PIN {HEX}\n"),
        format!("SSJ PIN {HEX} \n"),
        "SSJ PIN \n".to_owned(),
        String::new(),
    ] {
        assert_eq!(
            parse_pin(bad.as_bytes()),
            Err(BootstrapError::Malformed),
            "{bad:?}"
        );
    }
}

#[test]
fn udp_may_be_off() {
    for (udp, text) in [
        (Some(1), "udp:1"),
        (None, "none"),
        (Some(65535), "udp:65535"),
    ] {
        let mut connect = connect();
        connect.udp = udp;
        let line = format!("SSJ CONNECT abcdef012345 {text} none {HEX}\n");
        assert_eq!(format_connect(&connect), line);
        assert_eq!(parse_connect(line.as_bytes()), Ok(Some(connect)));
    }
}

// earlier servers put the port of TCP in the third field, and it is read and left alone.
#[test]
fn the_tcp_field_of_earlier_servers_is_accepted() {
    let line = format!("SSJ CONNECT abcdef012345 udp:60123 tcp:40123 {HEX}\n");
    assert_eq!(parse_connect(line.as_bytes()), Ok(Some(connect())));
}

#[test]
fn the_stream_of_stdio_starts_after_the_sync_header_whatever_came_before() {
    use ssj_proto::bootstrap::{SYNC_HEADER, find_sync};

    assert_eq!(find_sync(SYNC_HEADER), Some(SYNC_HEADER.len()));
    let noisy = [
        b"Welcome to host\r\nlast login: today\n".as_slice(),
        SYNC_HEADER,
        b"\x01\x02",
    ]
    .concat();
    let end = find_sync(&noisy).unwrap();
    assert_eq!(&noisy[end..], b"\x01\x02");
    // the first header counts.
    let twice = [SYNC_HEADER, b"x", SYNC_HEADER].concat();
    assert_eq!(find_sync(&twice), Some(SYNC_HEADER.len()));

    // an incomplete header, or the text of it without the leading NUL, is not the header.
    for cut in 0..SYNC_HEADER.len() {
        assert_eq!(find_sync(&SYNC_HEADER[..cut]), None, "cut at {cut}");
    }
    assert_eq!(find_sync(&SYNC_HEADER[1..]), None);
    assert_eq!(find_sync(b"SSJ_SYNC_STREAM\n"), None);
    assert_eq!(find_sync(b""), None);
}

mod start_line {
    use ssj_proto::bootstrap::{
        BootstrapError, MAX_START_LINE, Prestart, format_start, parse_start,
    };
    use ssj_proto::{Env, WindowSize};

    fn start(vars: Vec<(String, String)>) -> Prestart {
        Prestart {
            size: WindowSize::new(30, 100).unwrap(),
            env: Env::new(vars).unwrap(),
            agent: true,
        }
    }

    #[test]
    fn a_start_line_round_trips_with_the_size_the_environment_and_the_agent() {
        let wanted = start(vec![
            ("TERM".into(), "xterm-256color".into()),
            ("LANG".into(), "de_DE.UTF-8".into()),
            ("EMPTY".into(), String::new()),
        ]);
        let line = format_start(&wanted).unwrap();
        assert!(line.starts_with("SSJ START ") && line.ends_with('\n'));
        assert_eq!(line.matches('\n').count(), 1);
        assert_eq!(parse_start(line.as_bytes()), Ok(wanted.clone()));
        // a carriage return before the newline is accepted.
        let crlf = line.replace('\n', "\r\n");
        assert_eq!(parse_start(crlf.as_bytes()), Ok(wanted));
    }

    #[test]
    fn an_environment_with_odd_values_cannot_break_the_line() {
        let wanted = start(vec![(
            "NOTE".into(),
            "a b\nc\u{e4}\u{1f600} 'q' \"d\"".into(),
        )]);
        let line = format_start(&wanted).unwrap();
        assert_eq!(line.matches('\n').count(), 1);
        assert_eq!(parse_start(line.as_bytes()), Ok(wanted));
    }

    #[test]
    fn the_largest_environment_fits_in_the_line() {
        // seven values of the largest size, close to the limit of the total.
        let vars: Vec<(String, String)> = (0..7)
            .map(|i| (format!("BIG{i}"), "x".repeat(Env::MAX_VALUE)))
            .collect();
        let line = format_start(&start(vars)).unwrap();
        assert!(line.len() <= MAX_START_LINE, "{}", line.len());
    }

    #[test]
    fn broken_start_lines_are_refused() {
        let good = format_start(&start(vec![])).unwrap();
        let hex = good.trim_end().strip_prefix("SSJ START ").unwrap();
        for bad in [
            String::new(),
            "SSJ START \n".to_owned(),
            "SSJ START zz\n".to_owned(),
            "SSJ START abc\n".to_owned(),
            format!("SSJ START {}\n", hex.to_uppercase()),
            format!("SSJ START {}00\n", hex),
            format!("SSJ START {}\n", &hex[..hex.len() - 2]),
            // a frame that is not a start.
            "SSJ START 0000000105\n".to_owned(),
            format!("SSJ PIN {hex}\n"),
        ] {
            assert_eq!(
                parse_start(bad.as_bytes()),
                Err(BootstrapError::Malformed),
                "{bad:?}"
            );
        }
    }
}

#[test]
fn the_new_flag_is_an_optional_fifth_field_and_nothing_else_is() {
    let mut connect = connect();
    assert!(!connect.new);
    let plain = format_connect(&connect);
    assert!(!plain.contains(" new"), "{plain:?}");
    assert_eq!(parse_connect(plain.as_bytes()), Ok(Some(connect.clone())));

    connect.new = true;
    let flagged = format_connect(&connect);
    assert!(flagged.ends_with(" new\n"), "{flagged:?}");
    assert_eq!(parse_connect(flagged.as_bytes()), Ok(Some(connect)));
    assert_eq!(flagged.matches('\n').count(), 1, "one line");

    // any other fifth field, and a sixth, are errors
    for tail in [" old", " NEW", " new new", " new x", " "] {
        let line = format!("{}{tail}\n", plain.trim_end());
        assert_eq!(
            parse_connect(line.as_bytes()),
            Err(BootstrapError::Malformed),
            "{tail:?}"
        );
    }
}

#[test]
fn the_name_is_an_optional_field_after_new() {
    let plain = format_connect(&connect());
    let mut connect = connect();
    connect.name = SessionName::parse("work");
    let named = format_connect(&connect);
    assert!(named.ends_with(" name=work\n"), "{named:?}");
    assert_eq!(parse_connect(named.as_bytes()), Ok(Some(connect.clone())));

    connect.new = true;
    let both = format_connect(&connect);
    assert!(both.ends_with(" new name=work\n"), "{both:?}");
    assert_eq!(parse_connect(both.as_bytes()), Ok(Some(connect)));

    // a name must be a valid one, stand once, and come after `new`
    for tail in [
        " name=",
        " name=a b",
        " name=wo/rk",
        " name=work name=work",
        " name=work new",
        " name=work x",
        " name=0123456789012345678901234567890123",
    ] {
        let line = format!("{}{tail}\n", plain.trim_end());
        assert_eq!(
            parse_connect(line.as_bytes()),
            Err(BootstrapError::Malformed),
            "{tail:?}"
        );
    }
}

#[test]
fn the_socket_is_an_optional_field_after_the_name() {
    let plain = format_connect(&connect());
    let mut connect = connect();
    connect.new = true;
    connect.name = SessionName::parse("work");
    connect.socket = Some("/run/user/1000/ssj/abcdef012345.sock".to_owned());
    let line = format_connect(&connect);
    assert!(
        line.ends_with(" new name=work socket=/run/user/1000/ssj/abcdef012345.sock\n"),
        "{line:?}"
    );
    assert_eq!(parse_connect(line.as_bytes()), Ok(Some(connect)));

    // a path must be absolute, have nothing that `ssh -W` reads otherwise, stand once, and come
    // last.
    for tail in [
        " socket=",
        " socket=run/x.sock",
        " socket=/run/a b.sock",
        " socket=/run/x.sock:22",
        " socket=/run/\u{1b}x.sock",
        " socket=/a socket=/b",
        " socket=/a name=work",
        " socket=/a new",
    ] {
        let line = format!("{}{tail}\n", plain.trim_end());
        assert_eq!(
            parse_connect(line.as_bytes()),
            Err(BootstrapError::Malformed),
            "{tail:?}"
        );
    }
}

#[test]
fn the_relay_secret_line_has_a_fixed_shape_and_survives_a_round_trip() {
    let secret: [u8; 32] = core::array::from_fn(|i| (i * 8 + 3) as u8);
    let line = format_relay_secret(&secret);
    assert_eq!(line, format!("SSJ RELAY {HEX}\n"));
    assert_eq!(parse_relay_secret(line.as_bytes()), Ok(secret));
    assert_eq!(parse_relay_secret(line.trim_end().as_bytes()), Ok(secret));
    for bad in [
        "SSJ RELAY \n".to_owned(),
        format!("SSJ RELAY {}\n", HEX.to_uppercase()),
        format!("SSJ RELAY {}\n", &HEX[2..]),
        format!("SSJ RELAY {HEX}00\n"),
        format!("SSJ PIN {HEX}\n"),
    ] {
        assert!(parse_relay_secret(bad.as_bytes()).is_err(), "{bad:?}");
    }
}

#[test]
fn the_relay_port_is_found_after_other_text() {
    assert_eq!(format_relay_port(60123), "SSJ RELAY-PORT 60123\n");
    assert_eq!(parse_relay_port(b"SSJ RELAY-PORT 60123\n"), Ok(Some(60123)));
    assert_eq!(
        parse_relay_port(b"Welcome\r\nSSJ RELAY-PORT 7\r\nmore"),
        Ok(Some(7))
    );
    // not complete yet, or not there
    assert_eq!(parse_relay_port(b"SSJ RELAY-PORT 60123"), Ok(None));
    assert_eq!(parse_relay_port(b"nothing\n"), Ok(None));
    assert_eq!(parse_relay_port(b""), Ok(None));
    for bad in [
        &b"SSJ RELAY-PORT \n"[..],
        b"SSJ RELAY-PORT 65536\n",
        b"SSJ RELAY-PORT 007\n",
        b"SSJ RELAY-PORT -1\n",
        b"SSJ RELAY-PORT 1 2\n",
    ] {
        assert!(parse_relay_port(bad).is_err(), "{bad:?}");
    }
}

#[test]
fn the_command_of_the_leg_survives_any_words() {
    let command: Vec<String> = ["ssh", "-o", "A=b c", "--", "me@host", "it's \"x\"\n,"]
        .map(str::to_owned)
        .to_vec();
    let line = format_leg(&command).unwrap();
    assert!(line.starts_with("SSJ LEG "));
    assert_eq!(line.matches('\n').count(), 1);
    assert_eq!(parse_leg(line.as_bytes()), Ok(command));
    assert_eq!(format_leg(&[]), None);
    assert_eq!(format_leg(&["x".repeat(10_000)]), None);
    for bad in [
        "SSJ LEG \n",
        "SSJ LEG zz\n",
        "SSJ LEG 41,\n",
        "SSJ LEG 4G\n",
        "SSJ LEG 41 42\n",
        "SSJ LEG ff\n",
        "LEG 41\n",
    ] {
        assert!(parse_leg(bad.as_bytes()).is_err(), "{bad:?}");
    }
}
