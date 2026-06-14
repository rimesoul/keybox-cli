use keybox::interactive;

#[test]
fn test_stdin_is_tty() {
    // stdin_is_tty() should return a bool without panicking
    let result = interactive::stdin_is_tty();
    // In a terminal, this will be true; in CI/pipes, it will be false
    // We just verify it doesn't panic and returns a boolean
    let _: bool = result;
}

#[test]
fn test_is_llm_calling_env_var() {
    // Save original value
    let original = std::env::var("KEYBOX_LLM_CALLING").ok();

    // When set to "1", should return true
    std::env::set_var("KEYBOX_LLM_CALLING", "1");
    assert!(
        interactive::is_llm_calling(),
        "is_llm_calling should return true when KEYBOX_LLM_CALLING=1"
    );

    // When set to "0", should return false
    std::env::set_var("KEYBOX_LLM_CALLING", "0");
    assert!(
        !interactive::is_llm_calling(),
        "is_llm_calling should return false when KEYBOX_LLM_CALLING=0"
    );

    // When unset, should return false
    std::env::remove_var("KEYBOX_LLM_CALLING");
    assert!(
        !interactive::is_llm_calling(),
        "is_llm_calling should return false when KEYBOX_LLM_CALLING is unset"
    );

    // Restore original value
    if let Some(val) = original {
        std::env::set_var("KEYBOX_LLM_CALLING", val);
    }
}

#[test]
fn test_check_interactive() {
    // check_interactive() should not panic
    // It returns Ok(()) when interactive, Err with message when not
    let result = interactive::check_interactive();
    // In CI, stdin is not a TTY, so it should return Err
    // In terminal, it should return Ok(())
    // We just verify the function doesn't panic and returns a Result
    match result {
        Ok(()) => {} // interactive — fine
        Err(msg) => {
            // In non-interactive mode, message should be meaningful
            assert!(!msg.is_empty(), "Error message should not be empty");
        }
    }
}

#[test]
fn test_llm_mode_error_message() {
    // Test default tier (confidential)
    let msg = interactive::llm_mode_error(None);
    assert!(
        msg.contains("LLM calling mode"),
        "Message should mention LLM calling mode, got: {}",
        msg
    );
    assert!(
        msg.contains("unlock"),
        "Message should suggest unlock, got: {}",
        msg
    );
    assert!(
        msg.contains("non-interactive"),
        "Message should mention non-interactive, got: {}",
        msg
    );
    assert!(
        msg.contains("confidential"),
        "Default tier should be confidential, got: {}",
        msg
    );

    // Test with explicit tier
    let msg_top = interactive::llm_mode_error(Some("top-secret"));
    assert!(
        msg_top.contains("top-secret"),
        "Message with tier should contain 'top-secret', got: {}",
        msg_top
    );
}

#[test]
fn test_subprocess_error_message() {
    let msg = interactive::subprocess_error();
    assert!(
        msg.contains("not a TTY"),
        "Message should mention 'not a TTY', got: {}",
        msg
    );
    assert!(
        msg.contains("non-interactive"),
        "Message should mention non-interactive, got: {}",
        msg
    );
    assert!(
        msg.contains("keybox serve"),
        "Message should suggest keybox serve, got: {}",
        msg
    );
}
