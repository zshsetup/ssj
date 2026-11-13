// each test crate uses a different subset of these helpers.
#![allow(dead_code)]

use ssj_proto::frame::MAX_DATA_LEN;
use ssj_proto::{ClientFrame, Env, ErrorCode, ExitStatus, Hello, ServerFrame, Welcome, WindowSize};

pub fn size() -> WindowSize {
    WindowSize::new(24, 80).unwrap().with_pixels(640, 384)
}

pub fn client_frames() -> Vec<ClientFrame> {
    let env = Env::new(vec![
        ("TERM".into(), "xterm".into()),
        ("LANG".into(), "".into()),
    ])
    .unwrap();
    vec![
        ClientFrame::Hello(Hello::Start {
            size: size(),
            env,
            agent: false,
        }),
        ClientFrame::Hello(Hello::Start {
            size: size(),
            env: Env::default(),
            agent: true,
        }),
        ClientFrame::Hello(Hello::Resume {
            size: size(),
            output_offset: u64::MAX,
        }),
        ClientFrame::Hello(Hello::Attach { size: size() }),
        ClientFrame::Input(b"ls\r".to_vec()),
        ClientFrame::Input(vec![7; MAX_DATA_LEN]),
        ClientFrame::Compressed(vec![0x4b, 0x4c, 0x4a, 0x06, 0x00]),
        ClientFrame::Resize(
            WindowSize::new(1, WindowSize::MAX)
                .unwrap()
                .with_pixels(u16::MAX, u16::MAX),
        ),
        ClientFrame::OutputAck(12345),
        ClientFrame::Close,
        ClientFrame::Detach,
        ClientFrame::Ping,
        ClientFrame::AgentOffer,
        ClientFrame::Hangup,
        ClientFrame::Agent(7, b"\0\0\0\x01\x0b".to_vec()),
        ClientFrame::Agent(u32::MAX, vec![1; MAX_DATA_LEN]),
        ClientFrame::AgentClose(7),
    ]
}

pub fn server_frames() -> Vec<ServerFrame> {
    vec![
        ServerFrame::Welcome(Welcome {
            input_offset: 3,
            output_offset: u64::MAX,
        }),
        ServerFrame::Output(b"\x1b[1mhi\x1b[0m".to_vec()),
        ServerFrame::Output(vec![9; MAX_DATA_LEN]),
        ServerFrame::InputAck(77),
        ServerFrame::Exit(ExitStatus::Code(3)),
        ServerFrame::Exit(ExitStatus::Signal(9)),
        ServerFrame::Error(ErrorCode::ReplayGap),
        ServerFrame::Pong,
        ServerFrame::Gap(1 << 40),
        ServerFrame::Compressed(vec![0x4b, 0x4c, 0x4a, 0x06, 0x00]),
        ServerFrame::AgentOpen(7),
        ServerFrame::Agent(7, b"\0\0\0\x05\x0c\0\0\0\0".to_vec()),
        ServerFrame::AgentClose(u32::MAX),
        ServerFrame::Detached,
    ]
}
