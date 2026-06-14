use std::path::PathBuf;

pub fn test_config_dir() -> PathBuf {
    let dir = std::env::temp_dir()
        .join("keybox-test")
        .join(format!("{}", std::process::id()));
    dir
}
