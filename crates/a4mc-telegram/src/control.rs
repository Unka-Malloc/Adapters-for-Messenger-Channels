//! Single-slash control command parser (OpenClaw-aligned subset).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlCommand {
    Help,
    Commands,
    Start,
    Status,
    Whoami,
    Pair,
    Unpair,
    Agent { agent_id: Option<String> },
    Session { selector: Option<String> },
    New,
    Reset,
    Stop,
    Unknown { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlOutcome {
    Command(ControlCommand),
    OrdinaryText(String),
}

/// Parse a full Telegram message body into a control command or ordinary text.
///
/// Whole-message commands only. Names are lowercased; Telegram `@bot` suffixes
/// are stripped (`/agent@MyBot` → `agent`). An optional trailing `:` on the
/// command token is accepted (`/status:`).
pub fn parse_control_command(text: &str) -> ControlOutcome {
    let trimmed = text.trim();
    if !trimmed.starts_with('/') {
        return ControlOutcome::OrdinaryText(trimmed.to_owned());
    }
    let without_slash = trimmed.trim_start_matches('/');
    if without_slash.is_empty() {
        return ControlOutcome::OrdinaryText(trimmed.to_owned());
    }
    let mut parts = without_slash.split_whitespace();
    let head = parts.next().unwrap_or_default();
    let command = head
        .split('@')
        .next()
        .unwrap_or(head)
        .trim_end_matches(':')
        .to_ascii_lowercase();
    let arg = parts.collect::<Vec<_>>().join(" ");
    let arg = arg.trim();
    match command.as_str() {
        "help" => ControlOutcome::Command(ControlCommand::Help),
        "commands" => ControlOutcome::Command(ControlCommand::Commands),
        "start" => ControlOutcome::Command(ControlCommand::Start),
        "status" => ControlOutcome::Command(ControlCommand::Status),
        "whoami" | "id" => ControlOutcome::Command(ControlCommand::Whoami),
        "pair" => ControlOutcome::Command(ControlCommand::Pair),
        "unpair" | "revoke" => ControlOutcome::Command(ControlCommand::Unpair),
        "agent" | "agents" => ControlOutcome::Command(ControlCommand::Agent {
            agent_id: non_empty(arg),
        }),
        "session" | "sessions" => {
            if arg.eq_ignore_ascii_case("new") {
                ControlOutcome::Command(ControlCommand::New)
            } else {
                ControlOutcome::Command(ControlCommand::Session {
                    selector: non_empty(arg),
                })
            }
        }
        "new" => ControlOutcome::Command(ControlCommand::New),
        "reset" => ControlOutcome::Command(ControlCommand::Reset),
        "stop" => ControlOutcome::Command(ControlCommand::Stop),
        other => ControlOutcome::Command(ControlCommand::Unknown {
            name: other.to_owned(),
        }),
    }
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Help text is channel UX, not host copy: it names no host product so
/// any composing host can ship the same surface.
pub fn help_text(bot_username: &str) -> String {
    format!(
        "A4MC Telegram Channel\n\
         Bot: @{bot_username}\n\n\
         Access\n\
         /start — request a pairing code\n\
         /pair — show or renew pairing code\n\
         /unpair — revoke this chat's pairing\n\
         /whoami — show your Telegram ids\n\n\
         Binding\n\
         /status — pairing, agent, session\n\
         /agent — list local agents\n\
         /agent <id> — bind an agent\n\
         /session — list conversations\n\
         /session <id|index> — bind a conversation\n\
         /new — start a new conversation\n\
         /reset — same as /new\n\
         /stop — note about in-flight turns\n\n\
         Help\n\
         /help — this message\n\
         /commands — command catalog\n\n\
         Ordinary messages go to the bound local agent.\n\
         Approve pairing in the host application's channel settings.\n\
         Telegram can read content sent through this bot."
    )
}

pub fn commands_text() -> String {
    "Commands:\n\
     /start /pair /unpair /whoami\n\
     /status /agent /session /new /reset /stop\n\
     /help /commands\n\
     Aliases: /id→/whoami, /agents→/agent, /sessions→/session, /revoke→/unpair"
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_slash_commands_and_bot_suffix() {
        assert_eq!(
            parse_control_command("/agent@MyBot cursor"),
            ControlOutcome::Command(ControlCommand::Agent {
                agent_id: Some("cursor".into())
            })
        );
        assert_eq!(
            parse_control_command("/session new"),
            ControlOutcome::Command(ControlCommand::New)
        );
        assert_eq!(
            parse_control_command("/SESSION 2"),
            ControlOutcome::Command(ControlCommand::Session {
                selector: Some("2".into())
            })
        );
        assert_eq!(
            parse_control_command("/whoami@Bot"),
            ControlOutcome::Command(ControlCommand::Whoami)
        );
        assert_eq!(
            parse_control_command("/id"),
            ControlOutcome::Command(ControlCommand::Whoami)
        );
        assert_eq!(
            parse_control_command("/reset"),
            ControlOutcome::Command(ControlCommand::Reset)
        );
        assert_eq!(
            parse_control_command("/unpair"),
            ControlOutcome::Command(ControlCommand::Unpair)
        );
        assert_eq!(
            parse_control_command("/commands"),
            ControlOutcome::Command(ControlCommand::Commands)
        );
        assert_eq!(
            parse_control_command("/status:"),
            ControlOutcome::Command(ControlCommand::Status)
        );
        assert_eq!(
            parse_control_command("hello /agent"),
            ControlOutcome::OrdinaryText("hello /agent".into())
        );
        assert_eq!(
            parse_control_command("/unknown"),
            ControlOutcome::Command(ControlCommand::Unknown {
                name: "unknown".into()
            })
        );
    }
}
