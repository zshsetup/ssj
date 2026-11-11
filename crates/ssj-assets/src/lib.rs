//! The man page and the shell completions of `ssj`, made from its command line. The release
//! workflow writes them with `cargo run -p ssj-assets -- DIR`.

use std::{fs, io, path::Path};

use clap_complete::Shell;
use confique::Config as _;
use confique::meta::{FieldKind, LeafKind, Meta};
use ssj_client::options;

/// What the options cannot show: a command on the host.
const COMMAND: &str = r#".SH RUNNING A COMMAND
\fBssj connect\fR \fIDESTINATION\fR \fICOMMAND\fR... runs the command in the session instead of the
shell, as \fBssh\fR does, and ends with its exit code. The shell of the host runs it with \fB-c\fR
(not as a login shell, as with \fBssh\fR), so pipes, \fB&&\fR, and \fBcd\fR work. The session
survives a lost connection like any other, and can be joined with \fBssj attach\fR.
.PP
As with \fBssh\fR, everything after the destination belongs to the command, options included:
\fBssj connect host ls \-la\fR runs \fBls \-la\fR on the host. Options of \fBssj\fR go before the
destination (\fBssj connect \-\-local\-echo auto host make \-j4\fR). A \fB\-\-\fR right after the
destination is optional. The other commands take their options before or after the destination
(\fBssj list host \-\-json\fR), and only those listed under COMMANDS.
"#;

/// The FILES section around the keys of the two config files, which come from their structs.
const FILES: &str = r#".SH FILES
All config files are flat \fIkey = value\fR lines of TOML, without tables. A typo in a key is an
error with the line number, and a file that others can write is refused. Options on the command
line override the file. \fBssj edit\fR opens a file with every key as a comment.
.TP
\fI$XDG_CONFIG_HOME/ssj/client.toml\fR
(default \fI~/.config/ssj/client.toml\fR) Settings of \fBssj\fR:
CLIENT_KEYS.TP
\fI$XDG_CONFIG_HOME/ssj/server.toml\fR
Settings of \fBssj-server\fR, read on the host:
SERVER_KEYS.TP
\fI$XDG_CACHE_HOME/ssj/sessions/\fR
The session names last seen on each host, for tab completion. Written by \fBssj list\fR and
refreshed in the background.
"#;

/// The keys of a config file for the man page: the doc comment and the default of each field.
fn keys(meta: &Meta) -> String {
    let mut out = String::from(".RS\n");
    for field in meta.fields {
        let default = match field.kind {
            FieldKind::Leaf {
                kind:
                    LeafKind::Required {
                        default: Some(value),
                    },
                ..
            } => format!(
                " (default {})",
                serde_json::to_string(&value).expect("plain values")
            ),
            _ => String::new(),
        };
        let doc: Vec<&str> = field.doc.iter().map(|line| line.trim()).collect();
        let doc = doc.join(" ").replace('\\', "\\\\");
        out.push_str(&format!(".TP\n\\fB{}\\fR{default}\n{doc}\n", field.name));
    }
    out.push_str(".RE\n");
    out
}

/// Writes `ssj.1`, `ssj.bash`, `_ssj`, and `ssj.fish` to `out`.
pub fn write(out: &Path) -> io::Result<()> {
    let tree = completion_tree();
    let mut page = Vec::new();
    let man = clap_mangen::Man::new(options::command());
    man.render_title(&mut page)?;
    man.render_name_section(&mut page)?;
    man.render_synopsis_section(&mut page)?;
    man.render_description_section(&mut page)?;
    // the options of all commands in one list; COMMANDS says which command reads which
    let all = clap::Command::new("ssj").args(every_option(&tree).into_iter().cloned());
    clap_mangen::Man::new(all).render_options_section(&mut page)?;
    man.render_version_section(&mut page)?;
    page.extend_from_slice(COMMAND.as_bytes());
    page.extend_from_slice(commands_section().as_bytes());
    let files = FILES
        .replace("CLIENT_KEYS", &keys(&ssj_client::config::Config::META))
        .replace("SERVER_KEYS", &keys(&ssj_server::config::Config::META));
    page.extend_from_slice(files.as_bytes());
    fs::write(out.join("ssj.1"), page)?;

    // the options that take a value: the word after one of them is not a destination
    let value_options = every_option(&tree)
        .into_iter()
        .filter(|arg| arg.get_action().takes_values())
        .flat_map(|arg| {
            let long = arg.get_long().map(|long| format!("--{long}"));
            let short = arg.get_short().map(|short| format!("-{short}"));
            long.into_iter().chain(short)
        })
        .collect::<Vec<_>>()
        .join(" ");
    // the options with a free text: no fixed values, no file or host, and not the session name
    let free_options: Vec<String> = every_option(&tree)
        .into_iter()
        .filter(|arg| arg.get_action().takes_values())
        .filter(|arg| arg.get_possible_values().is_empty())
        .filter(|arg| {
            !matches!(
                arg.get_value_hint(),
                clap::ValueHint::FilePath | clap::ValueHint::AnyPath | clap::ValueHint::Hostname
            )
        })
        .filter_map(|arg| arg.get_long())
        .filter(|long| *long != "name")
        .map(str::to_owned)
        .collect();
    for (shell, file) in [
        (Shell::Bash, "ssj.bash"),
        (Shell::Zsh, "_ssj"),
        (Shell::Fish, "ssj.fish"),
    ] {
        let mut text = Vec::new();
        clap_complete::generate(shell, &mut tree.clone(), "ssj", &mut text);
        let text = String::from_utf8(text).expect("the completions are text");
        let text = match shell {
            Shell::Bash => bash(&text, &value_options, &free_options),
            Shell::Zsh => zsh(&text, &value_options, &free_options),
            Shell::Fish => fish(&text, &value_options, &free_options),
            _ => text,
        };
        fs::write(out.join(file), text)?;
    }
    Ok(())
}

/// The options of all commands, each once.
fn every_option(tree: &clap::Command) -> Vec<&clap::Arg> {
    let mut all: Vec<&clap::Arg> = Vec::new();
    for arg in tree
        .get_subcommands()
        .flat_map(clap::Command::get_arguments)
    {
        if !arg.is_positional() && all.iter().all(|has| has.get_id() != arg.get_id()) {
            all.push(arg);
        }
    }
    all
}

/// The COMMANDS section of the man page: the usage of each command, what it does, and its
/// options.
fn commands_section() -> String {
    let roff = |text: &str| text.replace('\\', "\\\\").replace('-', "\\-");
    let mut command = options::command();
    command.build();
    let mut section = String::from(".SH COMMANDS\n");
    for sub in command.get_subcommands() {
        let usage = sub.clone().render_usage().to_string();
        let usage = usage.trim_start_matches("Usage: ");
        // the long text of `clap` starts with the line about the command
        let about = sub.get_about().map(ToString::to_string).unwrap_or_default();
        let long = sub
            .get_long_about()
            .map(ToString::to_string)
            .unwrap_or_default();
        let detail = long.strip_prefix(&about).unwrap_or_default().trim();
        let options = sub
            .get_arguments()
            .filter(|arg| !arg.is_positional() && !arg.is_hide_set())
            .filter_map(|arg| arg.get_long())
            .filter(|long| *long != "help")
            .map(|long| format!("\\fB\\-\\-{}\\fR", roff(long)))
            .collect::<Vec<_>>()
            .join(", ");
        section.push_str(&format!(
            ".TP\n\\fB{}\\fR\n{}. {}\n.br\nOptions: {options}\n",
            roff(usage),
            roff(&about),
            roff(detail).replace('\n', " ")
        ));
    }
    section
}

/// The tree of the commands with what only the generators need: the generators list hidden
/// options too, so only the visible ones are copied. What the hosts have and the sessions of a
/// host stay with the functions that are added in the shells.
fn completion_tree() -> clap::Command {
    let full = options::command();
    let mut tree = clap::Command::new("ssj")
        .version(env!("CARGO_PKG_VERSION"))
        .disable_help_subcommand(true);
    for sub in full.get_subcommands() {
        let mut copy = clap::Command::new(sub.get_name().to_owned())
            .disable_help_flag(true)
            .disable_version_flag(true);
        if let Some(about) = sub.get_about() {
            copy = copy.about(about.clone());
        }
        for arg in sub.get_arguments().filter(|arg| !arg.is_hide_set()) {
            // the functions added to the zsh file look for the arguments without a text.
            let arg = if arg.is_positional() {
                arg.clone().help(None::<&str>)
            } else {
                arg.clone()
            };
            copy = copy.arg(arg);
        }
        match sub.get_name() {
            // the destination, and the words after it for the command on the host.
            "connect" => {
                copy = copy
                    .mut_arg("line", |arg| {
                        arg.num_args(1)
                            .action(clap::ArgAction::Set)
                            .trailing_var_arg(false)
                            .value_names(["DESTINATION"])
                    })
                    .arg(
                        clap::Arg::new("remote")
                            .value_name("COMMAND")
                            .num_args(0..)
                            .trailing_var_arg(true)
                            .value_hint(clap::ValueHint::AnyPath),
                    );
            }
            "kill" | "detach" => {}
            // nothing is left to say after them, which `_arguments` of zsh would answer with the
            // options even before a dash is typed: a rest that completes nothing keeps them back
            _ => {
                let rest = clap::Arg::new("rest").value_name("NOTHING").num_args(0..);
                copy = copy.arg(rest);
            }
        }
        tree = tree.subcommand(copy);
    }
    tree
}

/// The words of the commands.
fn words() -> Vec<String> {
    options::command()
        .get_subcommands()
        .map(|sub| sub.get_name().to_owned())
        .collect()
}

/// The functions that the zsh file adds to what `clap` writes.
const ZSH_HELPERS: &str = r#"
# the hosts of ~/.ssh/config are known to `_ssh_hosts`, not to `_hosts`
_ssj_hosts() { if (( $+functions[_ssh_hosts] )); then _ssh_hosts; else _hosts; fi; }
# a word that nothing completes
_ssj_nothing() { return 1; }
_ssj_sessions() { local -a s; s=(${(f)"$(ssj --complete 2>/dev/null)"}); compadd -a s; }
# the sessions of the host that was typed: the first positional word of the command is it
_ssj_session_ids() {
    local -a s extra
    # the value of an option that the command does not read is not an id
    [[ " __VALUE_OPTIONS__ " == *" $words[CURRENT-1] "* ]] && return 1
    # `detach` only acts on a session that has a client; the context names the command
    [[ $curcontext == *:ssj-command-detach:* ]] && extra=(--connected)
    s=(${(f)"$(ssj --complete $line[1] $extra 2>/dev/null)"}); compadd -a s
}
"#;

/// The zsh file: the functions of `clap` with the hosts of the ssh config and the sessions.
fn zsh(text: &str, value_options: &str, free_options: &[String]) -> String {
    let mut text = text
        .replace(":_hosts'", ":_ssj_hosts'")
        .replace(":id:_default'", ":id:_ssj_session_ids'")
        // one colon: the options may still stand among the ids
        .replace("'*::id:", "'*:id:")
        // one colon: the options may still stand among the words that this rest takes
        .replace("'*::rest:_default'", "'*:rest:_ssj_nothing'")
        .replace(
            "--name=[Join the session of this name, or start it]:NAME:_default",
            "--name=[Join the session of this name, or start it]:NAME:_ssj_sessions",
        );
    let end = "        esac\n    ;;\nesac";
    assert!(text.contains(end), "the end of the case of the commands");
    text = text.replacen(
        end,
        // the status is that of the completion: with several matchers (the `matcher-list` of
        // oh-my-zsh has three) a function that ends with 1 is run again for the next matcher,
        // and the lists of all of them are shown
        "        esac\n    ;;\nesac\n    return ret",
        1,
    );
    // `#compdef` must stay the first line, or the completion is not found.
    // an option with a free text completes nothing, where the default would offer files
    let text = text
        .lines()
        .map(|line| {
            let free = free_options
                .iter()
                .any(|long| line.contains(&format!("--{long}=[")));
            if free {
                line.replace(":_default'", ":_ssj_nothing'")
            } else {
                line.to_owned()
            }
        })
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let helpers = ZSH_HELPERS.replace("__VALUE_OPTIONS__", value_options);
    match text.split_once('\n') {
        Some((first, rest)) => format!("{first}\n{helpers}{rest}"),
        None => format!("{helpers}{text}"),
    }
}

/// The bash file: the function of `clap` and, in front of it, the one that is registered. It
/// finds the words that are no options, and offers the hosts and the sessions to them, and leaves
/// the options and their values to `clap`.
fn bash(text: &str, value_options: &str, free_options: &[String]) -> String {
    let free = free_options
        .iter()
        .map(|long| format!("--{long}"))
        .collect::<Vec<_>>()
        .join(" ");
    let wrapper = BASH_WRAPPER
        .replace("__FREE_OPTIONS__", &free)
        .replace("__VALUE_OPTIONS__", value_options)
        .replace("__COMMANDS__", &words().join(" "));
    format!("{text}{wrapper}")
}

/// The function that bash calls for `ssj`.
const BASH_WRAPPER: &str = r#"
_ssj_sessions() {
    local current=${COMP_WORDS[COMP_CWORD]}
    local previous=${COMP_WORDS[COMP_CWORD-1]}
    local value_options=" __VALUE_OPTIONS__ "
    # `--option=value`: bash splits the word at the `=`, and the value is a word of its own
    if [[ $current == = ]]; then
        current=
        # bash 3 does not pass the word to the function and reads it from here
        COMP_WORDS[COMP_CWORD]=
    elif [[ $previous == = ]]; then
        previous=${COMP_WORDS[COMP_CWORD-2]}
    fi
    # the words before this one that are neither options nor the values of options
    local -a pos=()
    local word skip= i
    for ((i = 1; i < COMP_CWORD; i++)); do
        word=${COMP_WORDS[i]}
        if [[ -n $skip ]]; then
            [[ $word == = ]] || skip=
        elif [[ $word == -* ]]; then
            [[ $value_options == *" $word "* ]] && skip=1
        else
            pos+=("$word")
        fi
    done
    COMPREPLY=()
    local first=${pos[0]-}
    # after the destination of `connect` the words are for the command on the host: files
    [[ $first == connect && ${#pos[@]} -gt 1 ]] && return
    if [[ $value_options == *" $previous "* ]]; then
        # a free text has nothing to offer, and no files
        if [[ " __FREE_OPTIONS__ " == *" $previous "* ]]; then
            compopt +o default +o bashdefault 2>/dev/null
            return
        fi
        # an option that the command does not read has no values: ask `clap` for its options
        local saved=${COMP_WORDS[COMP_CWORD]}
        COMP_WORDS[COMP_CWORD]=-
        _ssj "$1" - ""
        COMP_WORDS[COMP_CWORD]=$saved
        local known=" ${COMPREPLY[*]} "
        COMPREPLY=()
        [[ $known == *" $previous "* ]] || return
        if [[ $previous == --name ]]; then
            COMPREPLY=($(compgen -W "$(ssj --complete 2>/dev/null)" -- "$current"))
        elif [[ $previous == --udp-host ]] && declare -F _known_hosts_real >/dev/null; then
            _known_hosts_real -- "$current"
        else
            _ssj "$1" "$current" "$previous"
        fi
        return
    fi
    # the commands first, as in zsh and fish, where `clap` would put its options in front
    if [[ -z $first && $current != -* ]]; then
        COMPREPLY=($(compgen -W "__COMMANDS__" -- "$current"))
        return
    fi
    # the options of a command
    if [[ -z $first || $current == -* ]]; then
        _ssj "$1" "$current" "$previous"
        return
    fi
    if [[ ${#pos[@]} -eq 1 ]]; then
        # the aliases of the ssh config are known to `_known_hosts_real` of bash-completion, as
        # for ssh
        declare -F _known_hosts_real >/dev/null && _known_hosts_real -- "$current"
        return
    fi
    # `kill` and `detach` take any number of sessions, `attach` one
    local only=
    case $first in
        attach) [[ ${#pos[@]} -eq 2 ]] || only=none ;;
        kill) ;;
        # `detach` only acts on a session that has a client
        detach) only=--connected ;;
        *) only=none ;;
    esac
    if [[ $only != none ]]; then
        COMPREPLY=($(compgen -W "$(ssj --complete "${pos[1]}" $only 2>/dev/null)" -- "$current"))
    fi
    # no file names where nothing is to be said
    [[ ${#COMPREPLY[@]} -gt 0 ]] || compopt +o default 2>/dev/null
}
complete -F _ssj_sessions -o bashdefault -o default ssj
"#;

/// The fish file: the rules of `clap`, which find the command word with `argparse`, and the rules
/// for the hosts and the sessions. The options of `connect` stand before its destination only.
fn fish(text: &str, value_options: &str, free_options: &[String]) -> String {
    let text = text.replace(
        "__fish_ssj_using_subcommand connect\"",
        "__fish_ssj_using_subcommand connect; and test (count (__ssj_words)) -le 1\"",
    );
    // the options with a free text complete nothing, files included
    let text = text
        .lines()
        .map(|line| {
            let free = free_options
                .iter()
                .any(|long| line.contains(&format!(" -l {long} ")) && line.ends_with(" -r"));
            if free {
                format!("{line} -f\n")
            } else {
                format!("{line}\n")
            }
        })
        .collect::<String>();
    let rules = FISH_RULES
        .replace("__VALUE_OPTIONS__", value_options)
        .replace("__COMMANDS__", &words().join(" "));
    format!("{text}{rules}")
}

/// What the fish file adds.
const FISH_RULES: &str = r#"
# the words that are neither options nor the values of options, without the one being typed
function __ssj_words
    set -l tokens (commandline -opc)
    set -e tokens[1]
    set -l skip 0
    for word in $tokens
        if test $skip = 1
            set skip 0
            continue
        end
        switch $word
            case __VALUE_OPTIONS__
                set skip 1
            case '-*'
            case '*'
                printf '%s\n' $word
        end
    end
end
# the word before the one being typed is an option that takes a value
function __ssj_value_pending
    set -l tokens (commandline -opc)
    contains -- $tokens[-1] __VALUE_OPTIONS__
end
function __ssj_wants_host
    set -l words (__ssj_words)
    not __ssj_value_pending; and test (count $words) -eq 1; and contains -- $words[1] __COMMANDS__
end
# the option before the word being typed is not one that the command reads: fish is asked whether
# the command completes the name of the option
function __ssj_foreign_value
    __ssj_value_pending; or return 1
    set -l tokens (commandline -opc)
    set -l offered (complete -C (string join ' ' -- $tokens[1..-2] $tokens[-1]) | string replace -r '\t.*' '')
    not contains -- $tokens[-1] $offered
end
# no file is wanted but for the values of options and for the command on the host after the
# destination of `connect`
function __ssj_no_files
    set -l words (__ssj_words)
    test (count $words) -ge 1; or return 1
    test $words[1] = connect; and test (count $words) -ge 2; and return 1
    not __ssj_value_pending; or __ssj_foreign_value
end
function __ssj_wants_sessions
    set -l words (__ssj_words)
    not __ssj_value_pending; or return 1
    test (count $words) -ge 2; or return 1
    switch $words[1]
        case attach
            test (count $words) -eq 2
        case kill detach
            true
        case '*'
            false
    end
end
function __ssj_sessions_of_host
    set -l words (__ssj_words)
    if test $words[1] = detach
        ssj --complete $words[2] --connected 2>/dev/null
    else
        ssj --complete $words[2] 2>/dev/null
    end
end
complete -c ssj -n '__ssj_no_files' -f
complete -c ssj -n '__ssj_wants_sessions' -f -a '(__ssj_sessions_of_host)'
complete -c ssj -n '__ssj_wants_host' -f -a '(__fish_print_hostnames)'
complete -c ssj -n '__fish_ssj_using_subcommand connect; and test (count (__ssj_words)) -le 1' -l name -x -a '(ssj --complete 2>/dev/null)'
"#;
