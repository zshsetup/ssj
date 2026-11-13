//! The completion scripts, run in the shells they are for.
//!
//! A fake `ssj` stands in for `ssj --complete HOST`, which lists the session names that are cached
//! for a host. A shell that is not installed is skipped, unless `SSJ_REQUIRE_SHELLS` is set, as in
//! CI, where a missing shell would otherwise hide a broken script.

use std::path::{Path, PathBuf};
use std::process::Command;

/// A generated file, written once for all tests of the process.
fn generated(name: &str) -> PathBuf {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("ssj-assets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        ssj_assets::write(&dir).unwrap();
        dir
    })
    .join(name)
}

/// A directory with a fake `ssj`: `--complete` prints the names of a host.
fn fake_ssj() -> PathBuf {
    // one directory for each call, since tests of one process run at the same time and a file
    // that is being written cannot be run.
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ssj-completions-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ssj");
    std::fs::write(
        &path,
        "#!/bin/sh\n\
         if [ \"$1\" = \"--complete\" ]; then\n\
           case \"$2\" in\n\
             me@box) if [ \"$3\" = \"--connected\" ]; then printf 'work\\n'; else printf 'work\\nbuild\\n'; fi ;;\n\
             \"\") printf 'work\\nbuild\\nother\\n' ;;\n\
           esac\n\
         fi\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&path, permissions).unwrap();
    dir
}

fn installed(shell: &str) -> bool {
    let found = Command::new(shell)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !found && std::env::var_os("SSJ_REQUIRE_SHELLS").is_some() {
        panic!("{shell} is not installed, and SSJ_REQUIRE_SHELLS is set");
    }
    found
}

fn run(shell: &str, args: &[&str], path_dir: &Path) -> String {
    let path = format!(
        "{}:{}",
        path_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(shell)
        .args(args)
        .env("PATH", path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{shell} {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn bash_offers_the_sessions_of_the_host_after_attach_and_kill() {
    if !installed("bash") {
        return;
    }
    let file = generated("ssj.bash");
    let case = |words: &str, cword: usize| {
        let code = format!(
            "source '{}'\nCOMP_WORDS=({words}); COMP_CWORD={cword}; \
             _ssj_sessions ssj \"${{COMP_WORDS[COMP_CWORD]}}\" \"${{COMP_WORDS[COMP_CWORD-1]}}\"; \
             echo \"${{COMPREPLY[*]}}\"",
            file.display()
        );
        run("bash", &["-c", &code], &fake_ssj()).trim().to_owned()
    };
    // the sessions of that host, filtered by what is typed.
    assert_eq!(case("ssj attach me@box w", 3), "work");
    assert_eq!(case("ssj kill me@box ''", 3), "work build");
    // kill takes more than one, the others do not.
    assert_eq!(case("ssj kill me@box work ''", 4), "work build");
    assert_eq!(case("ssj attach me@box work ''", 4), "");
    // detach offers only the sessions that have a client, and more than one.
    assert_eq!(case("ssj detach me@box ''", 3), "work");
    assert_eq!(case("ssj detach me@box work ''", 4), "work");
    // another host has none.
    assert_eq!(case("ssj attach other@host ''", 3), "");
    // --name offers the names of all hosts.
    assert_eq!(case("ssj connect --name ''", 3), "work build other");

    // hosts: the word after a command, when bash-completion is loaded.
    let hosts = |words: &str, cword: usize| {
        let code = format!(
            "source '{}'\n_known_hosts_real() {{ COMPREPLY=(boxa boxb); }}\n\
             COMP_WORDS=({words}); COMP_CWORD={cword}; \
             _ssj_sessions ssj \"${{COMP_WORDS[COMP_CWORD]}}\" \"${{COMP_WORDS[COMP_CWORD-1]}}\"; \
             echo \"${{COMPREPLY[*]}}\"",
            file.display()
        );
        run("bash", &["-c", &code], &fake_ssj()).trim().to_owned()
    };
    assert_eq!(hosts("ssj attach ''", 2), "boxa boxb");
    assert_eq!(hosts("ssj list ''", 2), "boxa boxb");
    // not for the session, nor for a second word after a host, nor for an option.
    assert_eq!(hosts("ssj attach me@box ''", 3), "work build");
    // the same as in zsh: the commands first, the options of a command after its host, and the
    // values of options are not destinations.
    let first = hosts("ssj ''", 1);
    assert!(
        first.starts_with("connect list attach kill detach install edit")
            && !first.contains("boxa"),
        "{first}"
    );
    assert!(hosts("ssj install me@box --ser", 3).contains("--server-binary"));
    assert!(hosts("ssj kill me@box --fo", 3).contains("--force"));
    assert_eq!(hosts("ssj connect me@box ls --ser", 4), "");
    // only the options that the command reads
    let edit = hosts("ssj edit me@box -", 3);
    assert!(
        edit.contains("--server-path") && !edit.contains("--json"),
        "{edit}"
    );
    assert!(!hosts("ssj kill me@box -", 3).contains("--json"));
    // `connect`: the hosts, the options of the connection before the host, and files for the
    // command on the host after it.
    assert_eq!(hosts("ssj connect ''", 2), "boxa boxb");
    assert_eq!(hosts("ssj connect --transport udp ''", 4), "boxa boxb");
    assert!(hosts("ssj connect --tr", 2).contains("--transport"));
    assert_eq!(hosts("ssj connect me@box ''", 3), "");
    // the values of options: the fixed ones, files, and the hosts of the ssh config
    assert_eq!(hosts("ssj connect --transport ''", 3), "auto udp stdio");
    assert_eq!(hosts("ssj attach me@box --compress ''", 4), "off auto");
    assert_eq!(hosts("ssj connect --udp-host ''", 3), "boxa boxb");
    assert_eq!(hosts("ssj attach me@box --udp-host ''", 4), "boxa boxb");
    // an option that the command does not read has no values
    assert_eq!(hosts("ssj install me@box --udp-host ''", 4), "");
    assert_eq!(hosts("ssj connect me@box -l", 3), "");
    assert!(hosts("ssj list me@box -", 3).contains("--json"));
    assert_eq!(hosts("ssj attach --transport udp ''", 4), "boxa boxb");
    assert_eq!(hosts("ssj list -v ''", 3), "boxa boxb");
}

/// Completes each line in a zsh that runs the completion system in a pseudo terminal, as a
/// person does: the line is typed, and the tab key pressed once (a second press would complete the
/// next word after a match that was inserted). What zsh shows is returned
/// for each line. The fake `ssj` is found first, `_ssh_hosts` offers two hosts, and the working
/// directory has one file. `None` when this zsh has no `zpty`.
fn zsh_complete(lines: &[&str]) -> Option<Vec<String>> {
    let dir = fake_ssj();
    let work = dir.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("afile"), "").unwrap();
    let completions = generated("_ssj");
    let inner = format!(
        "export PATH='{}':$PATH\n\
         fpath=('{}' $fpath)\n\
         autoload -U compinit; compinit -u -d '{}/zcompdump'\n\
         _ssh_hosts() {{ compadd -- boxa boxb box-c }}\n\
         zstyle ':completion:*' matcher-list 'm:{{[:lower:][:upper:]}}={{[:upper:][:lower:]}}' 'r:|=*' 'l:|=* r:|=*'\n\
         LISTMAX=1000; setopt AUTO_LIST; unsetopt AUTO_MENU LIST_AMBIGUOUS; PS1='> '\n\
         _ssj_done() {{ zle -M '@@DONE@@' }}; zle -N _ssj_done; bindkey '^X^D' _ssj_done\n",
        dir.display(),
        completions.parent().unwrap().display(),
        dir.display(),
    );
    std::fs::write(dir.join("inner.zsh"), inner).unwrap();
    let outer = format!(
        r#"zmodload zsh/zpty 2>/dev/null || exit 3
zpty z "zsh -f -i"
# reads what zsh shows until it has been quiet for a while. With a marker it reads until the
# marker has come, and then until the output has been quiet for a moment: zsh answers in order, so
# the marker shows that the answer is complete, where a loaded machine can take longer than any
# quiet period to start answering.
drain() {{
  local chunk waited=0 limit=${{1:-30}} marker=$2
  buf=
  while (( waited < limit )); do
    if zpty -r -t z chunk; then
      buf+=$chunk; waited=0
      if [[ -z $marker ]]; then limit=6
      elif [[ $buf == *$marker* ]]; then limit=2; fi
    else sleep 0.05; (( waited++ )); fi
  done
}}
zpty -w z "cd '{}'; source '{}/inner.zsh'; print @@RE''ADY@@"
drain 600 @@READY@@
for line in "$@"; do
  zpty -w -n z $'\025'; drain 8
  zpty -w -n z "$line"$'\t\030\004'; drain 600 @@DONE@@
  print -r -- "@@@ $line"
  print -r -- "$buf" | sed -e 's/@@DONE@@//' -e 's/\x1b\[[0-9;?]*[a-zA-Z]//g' | tr '\r\010\007' '   ' | tr -s ' \n' ' '
done
"#,
        work.display(),
        dir.display(),
    );
    std::fs::write(dir.join("outer.zsh"), outer).unwrap();
    let output = Command::new("zsh")
        .args(["-f", dir.join("outer.zsh").to_str().unwrap()])
        .args(lines)
        .current_dir(&work)
        .output()
        .unwrap();
    if output.status.code() == Some(3) {
        assert!(
            std::env::var_os("SSJ_REQUIRE_SHELLS").is_none(),
            "this zsh has no zpty, and SSJ_REQUIRE_SHELLS is set"
        );
        return None;
    }
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let shown: Vec<String> = text
        .split("@@@ ")
        .skip(1)
        .map(|part| {
            part.split_once('\n')
                .map_or("", |(_, rest)| rest)
                .to_owned()
        })
        .collect();
    assert_eq!(shown.len(), lines.len(), "{text}");
    Some(shown)
}

#[test]
fn zsh_file_has_no_syntax_error_and_starts_with_compdef() {
    if !installed("zsh") {
        return;
    }
    let file = generated("_ssj");
    // zsh -n finds a syntax error in the whole file.
    run("zsh", &["-n", file.to_str().unwrap()], &fake_ssj());
    let first_line = std::fs::read_to_string(&file).unwrap();
    assert!(first_line.starts_with("#compdef ssj\n"));
}

#[test]
fn fish_offers_the_sessions_of_the_host_after_attach_and_kill() {
    if !installed("fish") {
        return;
    }
    let file = generated("ssj.fish");
    let case = |line: &str| {
        let code = format!("source '{}'; complete -C '{line}'", file.display());
        let out = run("fish", &["-c", &code], &fake_ssj());
        let mut names: Vec<String> = out
            .lines()
            .filter_map(|l| l.split('\t').next())
            .filter(|n| matches!(*n, "work" | "build" | "other"))
            .map(str::to_owned)
            .collect();
        names.sort();
        names.join(" ")
    };
    assert_eq!(case("ssj attach me@box "), "build work");
    assert_eq!(case("ssj kill me@box w"), "work");
    // kill takes more than one, the others do not.
    assert_eq!(case("ssj kill me@box work "), "build work");
    assert_eq!(case("ssj attach me@box work "), "");
    assert_eq!(case("ssj detach me@box "), "work");
    assert_eq!(case("ssj detach me@box work "), "work");
    // options do not count as words.
    assert_eq!(case("ssj attach -v me@box "), "build work");
    // no sessions after the other commands, or for another host, or before the host.
    assert_eq!(case("ssj list me@box "), "");
    assert_eq!(case("ssj attach other@host "), "");
    assert_eq!(case("ssj attach "), "");
    // --name offers the names of all hosts.
    assert_eq!(case("ssj connect --name "), "build other work");
}

#[test]
fn fish_offers_the_commands_and_the_hosts() {
    if !installed("fish") {
        return;
    }
    let file = generated("ssj.fish");
    let case = |line: &str| {
        // `__fish_print_hostnames` is replaced, since it reads the files of the person.
        let code = format!(
            "function __fish_print_hostnames; printf 'boxa\\nboxb\\n'; end; source '{}'; complete -C '{line}'",
            file.display()
        );
        let out = run("fish", &["-c", &code], &fake_ssj());
        let mut names: Vec<String> = out
            .lines()
            .filter_map(|l| l.split('\t').next())
            .filter(|n| matches!(*n, "boxa" | "boxb" | "attach" | "list"))
            .map(str::to_owned)
            .collect();
        names.sort();
        names.join(" ")
    };
    assert_eq!(case("ssj "), "attach list");
    assert_eq!(case("ssj attach "), "boxa boxb");
    assert_eq!(case("ssj list -v "), "boxa boxb");
    // after the host the sessions follow, not the hosts.
    assert_eq!(case("ssj attach me@box "), "");
    // the values of options are not destinations.
    assert_eq!(case("ssj attach --transport udp "), "boxa boxb");
    assert_eq!(case("ssj connect --name x "), "boxa boxb");
    let options = |line: &str| {
        let code = format!("source '{}'; complete -C '{line}'", file.display());
        run("fish", &["-c", &code], &fake_ssj())
            .lines()
            .any(|l| l.starts_with("--server-binary"))
    };
    assert!(options("ssj install me@box --ser"));
    assert!(!options("ssj list me@box --ser"));
    // `connect`: the hosts, the options before the host, and the command for the host after it
    assert_eq!(case("ssj connect "), "boxa boxb");
    assert_eq!(case("ssj connect --transport udp "), "boxa boxb");
    assert!(options("ssj connect --ser"));
    // the values of options
    assert_eq!(case("ssj connect --udp-host "), "boxa boxb");
    assert_eq!(case("ssj attach me@box --udp-host "), "boxa boxb");
    // the values of an option that the command does not read are not completed
    assert_eq!(case("ssj install me@box --udp-host "), "");
    // the dashes after the destination of `connect` are for the command on the host.
    assert!(!options("ssj connect me@box --ser"));
    assert!(!options("ssj connect me@box ls --ser"));
}

/// Options with a fixed set of values, and the values.
const FIXED: [(&str, &str); 4] = [
    ("--local-echo", "auto off"),
    ("--compress", "auto off"),
    ("--congestion", "auto bbr cubic"),
    ("--transport", "auto stdio udp"),
];

#[test]
fn bash_completes_the_values_of_options_with_a_fixed_set() {
    if !installed("bash") {
        return;
    }
    let file = generated("ssj.bash");
    // what bash does: it splits the words at the `=`, and calls the function with the command,
    // the word under the cursor, and the one before it.
    let case = |words: &str, cword: usize| {
        let code = format!(
            "source '{}'\nCOMP_WORDS=({words}); COMP_CWORD={cword}; \
             _ssj_sessions ssj \"${{COMP_WORDS[COMP_CWORD]}}\" \"${{COMP_WORDS[COMP_CWORD-1]}}\"; \
             printf '%s\\n' \"${{COMPREPLY[@]}}\"",
            file.display()
        );
        let mut values: Vec<String> = run("bash", &["-c", &code], &fake_ssj())
            .lines()
            .map(str::to_owned)
            .collect();
        values.sort();
        values.join(" ")
    };
    for (option, values) in FIXED {
        // after a space
        assert_eq!(
            case(&format!("ssj connect {option} ''"), 3),
            values,
            "{option} <TAB>"
        );
        let first = &values[..1];
        let wanted: Vec<&str> = values.split(' ').filter(|v| v.starts_with(first)).collect();
        assert_eq!(
            case(&format!("ssj connect {option} {first}"), 3),
            wanted.join(" "),
            "{option} {first}<TAB>"
        );
        // after the `=`, with nothing typed and with the start of a value
        assert_eq!(
            case(&format!("ssj connect {option} ="), 3),
            values,
            "{option}=<TAB>"
        );
        assert_eq!(
            case(&format!("ssj connect {option} = {first}"), 4),
            wanted.join(" "),
            "{option}={first}<TAB>"
        );
    }
}

#[test]
fn fish_completes_the_values_of_options_with_a_fixed_set() {
    if !installed("fish") {
        return;
    }
    let file = generated("ssj.fish");
    let case = |line: &str| {
        let code = format!("source '{}'; complete -C '{line}'", file.display());
        let out = run("fish", &["-c", &code], &fake_ssj());
        let mut values: Vec<String> = out
            .lines()
            .filter_map(|l| l.split('\t').next())
            .map(|v| v.rsplit('=').next().unwrap_or(v).to_owned())
            .collect();
        values.sort();
        values.join(" ")
    };
    for (option, values) in FIXED {
        assert_eq!(
            case(&format!("ssj connect {option} ")),
            values,
            "{option} <TAB>"
        );
        assert_eq!(
            case(&format!("ssj connect {option}=")),
            values,
            "{option}=<TAB>"
        );
    }
}

#[test]
fn zsh_lists_the_values_of_options_with_a_fixed_set() {
    let text = std::fs::read_to_string(generated("_ssj")).unwrap();
    for (option, values) in FIXED {
        let mut sorted: Vec<&str> = values.split(' ').collect();
        // clap lists the values in the order of the definition, which the help also shows.
        sorted.sort_unstable();
        // a description of a value may take several lines.
        let start = text
            .find(&format!("'{option}=["))
            .unwrap_or_else(|| panic!("no line for {option}"));
        let line = &text[start..start + text[start..].find(")'").unwrap()];
        // the values are `(off auto)`, or with descriptions `((auto\:"..." udp\:"..."))`.
        let mut listed: Vec<&str> = if line.contains("((") {
            let mut words: Vec<&str> = line
                .split("\\:\"")
                .filter_map(|before| before.rsplit(['(', ' ', '\n']).next())
                .collect();
            words.pop();
            words
        } else {
            line.rsplit_once(":(").unwrap().1.split(' ').collect()
        };
        listed.sort_unstable();
        assert_eq!(listed, sorted, "{option}");
    }
}

/// The long options of `ssj connect`.
const CONNECT: &str = "verbose quiet log-file name auto-attach no-auto-attach forward-agent \
    no-forward-agent transport local-echo congestion compress ssh-command server-path server-arg \
    port-range detached-timeout install no-install download-url server-binary udp-host detach-key \
    send-env";

/// The options that each command reads, written out again and not taken from the definition that
/// the generator reads.
const READS: [(&str, &str); 6] = [
    (
        "list",
        "verbose log-file ssh-command server-path server-arg json",
    ),
    (
        "attach",
        "verbose quiet log-file transport local-echo congestion compress ssh-command server-path \
         server-arg port-range install no-install download-url server-binary udp-host \
         detach-key",
    ),
    (
        "kill",
        "verbose log-file ssh-command server-path server-arg force",
    ),
    (
        "detach",
        "verbose log-file ssh-command server-path server-arg",
    ),
    (
        "install",
        "verbose log-file ssh-command download-url server-binary",
    ),
    (
        "edit",
        "verbose log-file ssh-command server-path server-arg",
    ),
];

/// What a line must offer when the tab key is pressed at its end, and what it must not. `FILES`
/// stands for the files of the directory (`afile`; for bash an empty answer, which bash
/// completes with the files), and no word at all for nothing. The hosts are `boxa`, `boxb`, and `box-c` (a dash that a matcher could take for a typed `-`),
/// the sessions `work` and `build` (`work` when they have a client), and `other` is one more.
struct Position {
    line: String,
    must: Vec<String>,
    absent: Vec<String>,
}

fn dashed(names: &str) -> Vec<String> {
    names.split(' ').map(|n| format!("--{n}")).collect()
}

fn positions() -> Vec<Position> {
    let mut all = Vec::new();
    // words that no position offers by accident
    let stock = [
        "boxa",
        "boxb",
        "box-c",
        "work",
        "build",
        "other",
        "afile",
        "--json",
        "--force",
        "--verbose",
        "--download-url",
        "--transport",
    ];
    let mut add = |line: &str, must: Vec<String>| {
        let absent = stock
            .iter()
            .map(|w| (*w).to_owned())
            .filter(|w| !must.contains(w) && !line.contains(w.as_str()))
            .collect();
        all.push(Position {
            line: line.to_owned(),
            must,
            absent,
        });
    };
    let words = |text: &str| -> Vec<String> { text.split(' ').map(str::to_owned).collect() };
    let hosts = || words("boxa boxb box-c");
    let files = || words("FILES");
    let none = || Vec::new();
    let commands = "connect list attach kill detach install edit";

    // the start: a command
    add("ssj ", words(commands));
    // the options of a command are skipped, and so are their values
    add("ssj attach -v me@box ", words("work build"));
    add("ssj list --server-path x ", hosts());
    // the connection: the host, the options before it, files for the command on the host
    add("ssj connect ", hosts());
    add("ssj connect -", dashed(CONNECT));
    add("ssj connect --name ", words("work build other"));
    add("ssj connect --transport ", words("auto udp stdio"));
    add("ssj connect --local-echo ", words("off auto"));
    add("ssj connect --congestion ", words("auto bbr cubic"));
    add("ssj connect --compress ", words("off auto"));
    add("ssj connect --udp-host ", hosts());
    add("ssj connect --log-file ", files());
    add("ssj connect --server-path ", files());
    add("ssj connect --server-binary ", files());
    add("ssj connect --transport udp ", hosts());
    add("ssj connect me@box ", files());
    add("ssj connect me@box ls ", files());
    add("ssj connect me@box -", none());
    add("ssj connect me@box ls -", none());
    // each command: the host, the ids, its options and their values
    for (command, reads) in READS {
        add(&format!("ssj {command} "), hosts());
        add(&format!("ssj {command} me@box -"), dashed(reads));
        for (name, values) in [
            ("transport", "auto udp stdio"),
            ("compress", "off auto"),
            ("udp-host", "boxa boxb box-c"),
            ("log-file", "FILES"),
            ("server-binary", "FILES"),
            // free text: nothing, and no files either
            ("download-url", ""),
            ("ssh-command", ""),
        ] {
            let read = reads.split(' ').any(|r| r == name);
            let offered = if read && !values.is_empty() {
                words(values)
            } else {
                none()
            };
            add(&format!("ssj {command} me@box --{name} "), offered);
        }
    }
    // the ids
    add("ssj attach me@box ", words("work build"));
    add("ssj attach me@box work ", none());
    add("ssj attach me@box work -", dashed(READS[1].1));
    add("ssj attach other@host ", none());
    add("ssj kill me@box ", words("work build"));
    add("ssj kill me@box work ", words("build"));
    add("ssj detach me@box ", words("work"));
    add("ssj detach me@box work ", words("work"));
    add("ssj list me@box ", none());
    add("ssj install me@box ", none());
    add("ssj edit ", hosts());
    add("ssj edit me@box ", none());
    all
}

/// The positions of `part` out of `parts`, so that slow shells can use several tests.
fn some_positions(part: usize, parts: usize) -> Vec<Position> {
    positions()
        .into_iter()
        .enumerate()
        .filter(|(at, _)| at % parts == part)
        .map(|(_, position)| position)
        .collect()
}

/// Checks what a shell offered for a position: `offered` is the set of words, and `empty` says
/// that it offered nothing of its own (bash completes the files then).
fn check(shell: &str, position: &Position, offered: &[String], files_are_empty: bool) {
    let line = &position.line;
    let wants_files = position.must.iter().any(|w| w == "FILES");
    let others: Vec<&String> = position.must.iter().filter(|w| *w != "FILES").collect();
    // bash completes the files itself after an empty answer, and `clap` lists them after an
    // option for a file: both are files, and neither is a host, a session, or an option
    if files_are_empty && others.is_empty() && !wants_files {
        assert!(
            offered.is_empty(),
            "{shell}: {line:?} offered {offered:?}, and should leave the files"
        );
        return;
    }
    for word in &others {
        assert!(
            offered.contains(word),
            "{shell}: {line:?} lacks {word}, offered {offered:?}"
        );
    }
    if wants_files && !files_are_empty {
        assert!(
            offered.iter().any(|w| w.as_str() == "afile"),
            "{shell}: {line:?} lacks the files, offered {offered:?}"
        );
    }
    for word in &position.absent {
        if wants_files && word == "afile" {
            continue;
        }
        assert!(
            !offered.contains(word),
            "{shell}: {line:?} has {word}, offered {offered:?}"
        );
    }
}

#[test]
fn bash_offers_what_each_position_takes() {
    if !installed("bash") {
        return;
    }
    let file = generated("ssj.bash");
    for position in positions() {
        let words: Vec<String> = position.line.split(' ').map(|w| format!("'{w}'")).collect();
        let code = format!(
            "source '{}'\n_known_hosts_real() {{ COMPREPLY=(boxa boxb box-c); }}\n\
             COMP_WORDS=({}); COMP_CWORD={}; \
             _ssj_sessions ssj \"${{COMP_WORDS[COMP_CWORD]}}\" \"${{COMP_WORDS[COMP_CWORD-1]}}\"; \
             printf '%s\\n' \"${{COMPREPLY[@]}}\"",
            file.display(),
            words.join(" "),
            words.len() - 1,
        );
        let out = run("bash", &["-c", &code], &fake_ssj());
        let offered: Vec<String> = out
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect();
        // an empty answer is what bash completes with the files, and the files are the answer
        // for a position that wants them
        check("bash", &position, &offered, true);
    }
}

#[test]
fn fish_offers_what_each_position_takes() {
    if !installed("fish") {
        return;
    }
    let file = generated("ssj.fish");
    let dir = fake_ssj().join("work");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("afile"), "").unwrap();
    for position in positions() {
        let code = format!(
            "function __fish_print_hostnames; printf 'boxa\\nboxb\\nbox-c\\n'; end; source '{}'; \
             complete -C '{}'",
            file.display(),
            position.line
        );
        let output = Command::new("fish")
            .args(["-c", &code])
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    fake_ssj().display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .current_dir(&dir)
            .output()
            .unwrap();
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        let offered: Vec<String> = out
            .lines()
            .filter_map(|l| l.split('\t').next())
            .map(|n| n.trim_end_matches('/').to_owned())
            .collect();
        check("fish", &position, &offered, false);
    }
}

fn zsh_offers(part: usize, parts: usize) {
    if !installed("zsh") {
        return;
    }
    let positions = some_positions(part, parts);
    let lines: Vec<&str> = positions.iter().map(|p| p.line.as_str()).collect();
    let Some(shown) = zsh_complete(&lines) else {
        return;
    };
    for (position, text) in positions.iter().zip(&shown) {
        let offered: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
        check("zsh", position, &offered, false);
        // the `matcher-list` of oh-my-zsh has three matchers, and a completion that ends with a
        // failure is run for each of them, so that its words are shown three times: each option is shown once
        for word in position.must.iter().filter(|w| w.starts_with('-')) {
            let times = offered.iter().filter(|w| *w == word).count();
            assert_eq!(
                times, 1,
                "zsh: {:?} shows {word} {times} times",
                position.line
            );
        }
    }
}

#[test]
fn zsh_offers_what_each_position_takes_part_1() {
    zsh_offers(0, 4);
}

#[test]
fn zsh_offers_what_each_position_takes_part_2() {
    zsh_offers(1, 4);
}

#[test]
fn zsh_offers_what_each_position_takes_part_3() {
    zsh_offers(2, 4);
}

#[test]
fn zsh_offers_what_each_position_takes_part_4() {
    zsh_offers(3, 4);
}

#[test]
fn the_man_page_and_the_completions_are_built() {
    let found = generated;
    let page = std::fs::read_to_string(found("ssj.1")).unwrap();
    for word in [
        "transport",
        "client.toml",
        "server.toml",
        "port_range",
        "auto_attach",
        "forward_agent",
        "congestion",
    ] {
        assert!(page.contains(word), "{word}");
    }
    for file in ["ssj.bash", "_ssj", "ssj.fish"] {
        let text = std::fs::read_to_string(found(file)).unwrap();
        assert!(text.contains("transport"), "{file}");
    }
    // the id after the host of `attach` and `kill` is completed from the sessions of that host.
    let zsh = std::fs::read_to_string(found("_ssj")).unwrap();
    assert!(
        zsh.starts_with("#compdef ssj\n"),
        "compdef stays the first line"
    );
    assert!(zsh.contains("ssj --complete $line[1]"));
    let bash = std::fs::read_to_string(found("ssj.bash")).unwrap();
    assert!(bash.contains("ssj --complete \"${pos[1]}\""));
    let fish = std::fs::read_to_string(found("ssj.fish")).unwrap();
    assert!(fish.contains("ssj --complete $words[2]"));
}
