use anyhow::{Context, Result};

use crate::config;
use crate::credentials::Credentials;
use crate::crypto::signing;

pub fn run(command: &[String], dry_run: bool) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("No command provided. Usage: atomic sign -- curl ...");
    }

    let creds = Credentials::load(&config::credentials_path()?)?;
    let signing_key = creds.signing_key()?;

    // Extract the request body from the command.
    // Looks for -d/--data/--data-raw and grabs the next arg.
    let body = extract_body(command);
    let timestamp = chrono::Utc::now().timestamp();

    // Sign: "{timestamp}.{body}"
    let message = format!("{timestamp}.{body}");
    let signature = signing::sign(&signing_key, message.as_bytes());
    let sig_b64 = signing::encode_signature(&signature);

    // Build the modified command with injected headers
    let mut new_cmd = Vec::new();
    new_cmd.push(command[0].clone());
    new_cmd.extend_from_slice(&[
        "-H".to_string(),
        format!("X-Agent-Id: {}", creds.domain),
        "-H".to_string(),
        format!("X-Agent-Sig: {sig_b64}"),
        "-H".to_string(),
        format!("X-Agent-Sig-Time: {timestamp}"),
    ]);
    new_cmd.extend_from_slice(&command[1..]);

    if dry_run {
        println!("{}", shell_join(&new_cmd));
        return Ok(());
    }

    let status = std::process::Command::new(&new_cmd[0])
        .args(&new_cmd[1..])
        .status()
        .with_context(|| format!("Failed to execute: {}", new_cmd[0]))?;

    let exit_code = if let Some(code) = status.code() {
        code
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            128 + status.signal().unwrap_or(1)
        }
        #[cfg(not(unix))]
        {
            1
        }
    };
    std::process::exit(exit_code);
}

// Pull the body from -d, --data, or --data-raw flags.
// If there's no body, sign with empty string.
fn extract_body(command: &[String]) -> String {
    let mut iter = command.iter();
    while let Some(arg) = iter.next() {
        if arg == "-d" || arg == "--data" || arg == "--data-raw" {
            if let Some(value) = iter.next() {
                return value.clone();
            }
        }
        // Handle -d"value" (no space)
        if let Some(rest) = arg.strip_prefix("-d") {
            if !rest.is_empty() {
                return rest.to_string();
            }
        }
    }
    String::new()
}

// Join args into a copy-pasteable shell command
fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| {
            if a.contains(' ') || a.contains('"') || a.contains('\'') {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_body_with_d_flag() {
        let cmd = vec![
            "curl".into(), "-X".into(), "POST".into(),
            "-d".into(), r#"{"amount":100}"#.into(),
            "https://api.example.com".into(),
        ];
        assert_eq!(extract_body(&cmd), r#"{"amount":100}"#);
    }

    #[test]
    fn extract_body_with_data_flag() {
        let cmd = vec![
            "curl".into(), "--data".into(), "hello".into(),
            "https://example.com".into(),
        ];
        assert_eq!(extract_body(&cmd), "hello");
    }

    #[test]
    fn extract_body_no_data() {
        let cmd = vec!["curl".into(), "https://example.com".into()];
        assert_eq!(extract_body(&cmd), "");
    }

    #[test]
    fn extract_body_compact_d() {
        let cmd = vec!["curl".into(), "-dfoo=bar".into(), "https://example.com".into()];
        assert_eq!(extract_body(&cmd), "foo=bar");
    }

    #[test]
    fn shell_join_handles_spaces() {
        let args = vec!["curl".into(), "-H".into(), "X-Agent-Id: foo.com".into()];
        let joined = shell_join(&args);
        assert!(joined.contains("'X-Agent-Id: foo.com'"));
    }

    #[test]
    fn extract_body_with_data_raw_flag() {
        let cmd = vec![
            "curl".into(), "--data-raw".into(), "rawbody".into(),
            "https://example.com".into(),
        ];
        assert_eq!(extract_body(&cmd), "rawbody");
    }

    #[test]
    fn extract_body_d_flag_at_end_no_value() {
        let cmd = vec!["curl".into(), "https://example.com".into(), "-d".into()];
        assert_eq!(extract_body(&cmd), "");
    }

    #[test]
    fn shell_join_escapes_single_quotes() {
        let args = vec!["echo".into(), "it's".into()];
        let joined = shell_join(&args);
        assert!(joined.contains("'it'\\''s'"));
    }

    #[test]
    fn shell_join_empty_args() {
        let args: Vec<String> = vec![];
        assert_eq!(shell_join(&args), "");
    }
}
