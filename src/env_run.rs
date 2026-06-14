use std::process::Command;

/// Run a command with an environment variable set from a secret value.
///
/// The `value` is the raw secret bytes.  The `command` slice must be
/// non-empty; the first element is the program and the rest are args.
/// Returns the exit code, or an error string on failure.
pub fn run_with_env(var_name: &str, value: &[u8], command: &[String]) -> Result<i32, String> {
    if command.is_empty() {
        return Err(
            "No command specified after -- separator. \
             Usage: keybox get <domain> <account> --env VAR -- <command>"
                .into(),
        );
    }
    let value_str = std::str::from_utf8(value)
        .map_err(|_| "Secret contains non-UTF8 data, cannot set as env var".to_string())?;
    let (program, args) = command.split_first().unwrap();
    let status = Command::new(program)
        .args(args)
        .env(var_name, value_str)
        .status()
        .map_err(|e| format!("Failed to execute '{}': {}", program, e))?;
    Ok(status.code().unwrap_or(1))
}
