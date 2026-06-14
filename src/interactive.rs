use std::io::{self, Write};

/// Check if stdin is a terminal (TTY)
pub fn stdin_is_tty() -> bool {
    atty::is(atty::Stream::Stdin)
}

/// Check if KEYBOX_LLM_CALLING environment variable is set to "1"
pub fn is_llm_calling() -> bool {
    matches!(std::env::var("KEYBOX_LLM_CALLING"), Ok(v) if v == "1")
}

/// Verify the current process can accept interactive input.
/// Returns Ok(()) if interactive, Err with a helpful message if not.
pub fn check_interactive() -> Result<(), String> {
    if is_llm_calling() {
        return Err(llm_mode_error(None));
    }
    if !stdin_is_tty() {
        return Err(subprocess_error());
    }
    Ok(())
}

/// Prompt for a password (hidden input) with confirmation
pub fn prompt_password_with_confirm(prompt: &str, confirm_prompt: &str) -> Result<String, String> {
    check_interactive()?;
    let password = rpassword::prompt_password(prompt)
        .map_err(|e| format!("Failed to read password: {}", e))?;
    let confirm = rpassword::prompt_password(confirm_prompt)
        .map_err(|e| format!("Failed to read confirmation: {}", e))?;
    if password != confirm {
        return Err("Passwords do not match".into());
    }
    Ok(password)
}

/// Prompt for a single password (hidden input, no confirmation)
pub fn prompt_password(prompt: &str) -> Result<String, String> {
    check_interactive()?;
    rpassword::prompt_password(prompt)
        .map_err(|e| format!("Failed to read password: {}", e))
}

/// Prompt for a yes/no confirmation
pub fn prompt_confirm(prompt: &str) -> Result<bool, String> {
    check_interactive()?;
    print!("{} [y/N]: ", prompt);
    io::stdout().flush().map_err(|e| format!("IO error: {}", e))?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| format!("IO error: {}", e))?;
    Ok(input.trim().to_lowercase() == "y" || input.trim().to_lowercase() == "yes")
}

/// Prompt for a text input line
pub fn prompt_input(prompt: &str) -> Result<String, String> {
    check_interactive()?;
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| format!("IO error: {}", e))?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| format!("IO error: {}", e))?;
    Ok(input.trim().to_string())
}

/// Error message when KEYBOX_LLM_CALLING is detected — guides LLM agents through resolution paths
pub fn llm_mode_error(tier: Option<&str>) -> String {
    let tier_str = tier.unwrap_or("confidential");
    format!(
        "Error: keybox requires interactive input (LLM calling mode detected).\n\
         Possible resolutions (in order of preference):\n\
           1. Ask the user to unlock the daemon directly on the machine:\n\
              `keybox --{} unlock` (or `--top-secret`).\n\
              Once unlocked, all commands will work without prompts.\n\
           2. Use non-interactive mode with a credential provided by the human:\n\
              `--non-interactive --password <value>`\n\
           3. If the daemon is already running but locked, ask the user to unlock it.\n\
           4. Ask the human for the credential directly:\n\
              \"I need access to [description]. Can you provide the value or unlock keybox?\"",
        tier_str
    )
}

/// Error message when stdin is not a TTY (subprocess without KEYBOX_LLM_CALLING)
pub fn subprocess_error() -> String {
    "Error: keybox requires interactive input but stdin is not a TTY.\n\
     Use --non-interactive --password <value> for scripting, or set up a daemon\n\
     with `keybox serve` before calling from subprocesses."
        .to_string()
}
