use ssj_client::cli::Transport;
use ssj_client::tunnel::{Kind, SshConfig, jump_in_config, parse_ssh_config, tier_order};

#[test]
fn a_jump_host_or_proxy_command_is_found_in_the_ssh_configuration() {
    let config =
        |extra: &str| format!("host example\nhostname 192.0.2.7\nport 22\n{extra}user tim\n");
    assert!(!jump_in_config(&config("")));
    assert!(!jump_in_config(&config("proxyjump none\n")));
    assert!(!jump_in_config(&config("proxycommand none\n")));
    assert!(jump_in_config(&config("proxyjump bastion.example.com\n")));
    assert!(jump_in_config(&config("proxyjump tim@bastion:2222\n")));
    assert!(jump_in_config(&config(
        "proxycommand nc -X 5 -x proxy %h %p\n"
    )));
    // only whole keys count.
    assert!(!jump_in_config(&config("identityfile ~/.ssh/proxyjump\n")));
    assert!(!jump_in_config("proxyjumper bastion\n"));
    assert!(!jump_in_config("proxyjump \n"));
    assert!(!jump_in_config(""));
}

#[test]
fn the_order_of_transports_follows_the_choice_the_path_and_the_server() {
    use Kind::{Stdio, Udp};

    // automatic: the fastest first, the one that always works last.
    assert_eq!(tier_order(Transport::Auto, false, true), [Udp, Stdio]);
    // a jump host leaves out UDP.
    assert_eq!(tier_order(Transport::Auto, true, true), [Stdio]);
    // what the server does not offer is left out.
    assert_eq!(tier_order(Transport::Auto, false, false), [Stdio]);

    // a choice is kept, and an unavailable one gives nothing.
    assert_eq!(tier_order(Transport::Udp, true, true), [Udp]);
    assert_eq!(tier_order(Transport::Stdio, false, true), [Stdio]);
    assert!(tier_order(Transport::Udp, false, false).is_empty());
}

#[test]
fn the_host_name_is_taken_from_the_ssh_configuration() {
    let config = parse_ssh_config(
        "host work\nuser tim\nhostname server.example.org\nport 22\nproxyjump none\n\
         hostname second.example.org\n",
    );
    assert_eq!(
        config,
        SshConfig {
            hostname: Some("server.example.org".to_owned()),
            user: Some("tim".to_owned()),
            port: Some(22),
            ..SshConfig::default()
        }
    );
    let jump = parse_ssh_config("hostname 10.0.0.5\nproxyjump bastion\n");
    assert!(jump.jump);
    assert_eq!(jump.hostname.as_deref(), Some("10.0.0.5"));
    assert_eq!(parse_ssh_config(""), SshConfig::default());
    // no value, no host.
    assert_eq!(parse_ssh_config("hostname \nhostname\n").hostname, None);
}

#[test]
fn the_sendenv_lines_of_ssh_are_the_patterns() {
    let text = "host example\nsendenv LC_THEME\nsendenv LANG\nsendenv LC_*\nsendenv bad-name\n\
                setenv A=b\nsendenv  \n";
    assert_eq!(
        parse_ssh_config(text).send_env,
        ["LC_THEME", "LANG", "LC_*"]
    );
}

#[test]
fn the_jump_hosts_user_port_and_agent_are_taken_from_the_ssh_configuration() {
    let config = parse_ssh_config(
        "user tim\nport 2222\nproxyjump a@jump:22, b@second\nforwardagent yes\n\
         user other\n",
    );
    assert_eq!(config.proxy_jump, ["a@jump:22", "b@second"]);
    assert!(config.jump && !config.proxy_command && config.forward_agent);
    assert_eq!(
        (config.user.as_deref(), config.port),
        (Some("tim"), Some(2222))
    );

    let command = parse_ssh_config("proxycommand nc %h %p\nforwardagent no\n");
    assert!(command.jump && command.proxy_command && !command.forward_agent);
    assert!(command.proxy_jump.is_empty());
    assert_eq!(parse_ssh_config("port x\n").port, None);
}
