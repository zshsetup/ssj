//! Entry point of `ssj-server`.

use std::process::ExitCode;

use ssj_server::cli::{self, Mode};
use ssj_server::{control_cli, launch, relay};

/// `ssj edit` asks the server to judge a new `server.toml` before it replaces the old one.
fn check_config() -> ExitCode {
    use std::io::Read;
    let mut text = String::new();
    // a config file is small, and a larger one is not one.
    if std::io::stdin()
        .take(1 << 20)
        .read_to_string(&mut text)
        .is_err()
    {
        eprintln!("ssj-server: the file is not text");
        return ExitCode::from(2);
    }
    match ssj_server::config::Config::from_text(&text) {
        Ok(_) => {
            println!("OK");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}

fn main() -> ExitCode {
    match cli::parse(std::env::args_os().skip(1)) {
        Ok(args) if args.mode == Mode::Version => {
            println!(
                "ssj-server {} protocol {}",
                env!("CARGO_PKG_VERSION"),
                ssj_proto::PROTOCOL
            );
            ExitCode::SUCCESS
        }
        Ok(args) if args.mode == Mode::CheckConfig => check_config(),
        Ok(args) if args.mode == Mode::ConfigTemplate => {
            print!("{}", ssj_server::config::Config::template());
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("ssj-server: {message}");
            ExitCode::from(2)
        }
        Ok(args) if args.mode == Mode::Relay && args.daemon_child => relay::run_child(&args),
        Ok(args) if args.mode == Mode::Relay => relay::run_parent(),
        Ok(args) if args.mode != Mode::Serve => control_cli::run(&args),
        Ok(args) if args.daemon_child => launch::run_child(args),
        Ok(args) => launch::run_parent(&args),
    }
}
