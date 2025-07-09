use mailbot::error::{MailbotError, Result};
use mailbot::email::LeiEmail;
use mailbot::kernel::KernelVersion;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_error_types() {
    let git_err = git2::Error::from_str("test git error");
    let mailbot_err: MailbotError = git_err.into();
    assert!(matches!(mailbot_err, MailbotError::Git(_)));
    assert!(mailbot_err.to_string().contains("Git error"));
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let mailbot_err: MailbotError = io_err.into();
    assert!(matches!(mailbot_err, MailbotError::Io(_)));
    
    let json_err = serde_json::from_str::<LeiEmail>("invalid json").unwrap_err();
    let mailbot_err: MailbotError = json_err.into();
    assert!(matches!(mailbot_err, MailbotError::Json(_)));
}

#[test]
fn test_email_parse_error() {
    let err = MailbotError::EmailParse("Invalid email format".to_string());
    assert_eq!(err.to_string(), "Email parsing error: Invalid email format");
}

#[test]
fn test_patch_validation_error() {
    let err = MailbotError::PatchValidation("Patch failed to apply".to_string());
    assert_eq!(err.to_string(), "Patch validation error: Patch failed to apply");
}

#[test]
fn test_series_error() {
    let err = MailbotError::Series("Missing patch 2 of 5".to_string());
    assert_eq!(err.to_string(), "Series error: Missing patch 2 of 5");
}

#[test]
fn test_build_error() {
    let err = MailbotError::Build("Compilation failed".to_string());
    assert_eq!(err.to_string(), "Build error: Compilation failed");
}

#[test]
fn test_invalid_kernel_version_error() {
    let err = MailbotError::InvalidKernelVersion("not.a.version".to_string());
    assert_eq!(err.to_string(), "Invalid kernel version: not.a.version");
}

#[test]
fn test_worktree_error() {
    let err = MailbotError::Worktree("Failed to create worktree".to_string());
    assert_eq!(err.to_string(), "Worktree error: Failed to create worktree");
}

#[test]
fn test_result_type() {
    fn returns_result() -> Result<String> {
        Ok("success".to_string())
    }
    
    fn returns_error() -> Result<String> {
        Err(MailbotError::EmailParse("test error".to_string()))
    }
    
    assert!(returns_result().is_ok());
    assert!(returns_error().is_err());
}

#[test]
fn test_error_chaining() {
    fn read_and_parse() -> Result<LeiEmail> {
        let content = fs::read_to_string("/non/existent/file")?;
        let email: LeiEmail = serde_json::from_str(&content)?;
        Ok(email)
    }
    
    let result = read_and_parse();
    assert!(result.is_err());
    
    match result {
        Err(MailbotError::Io(_)) => {},
        _ => panic!("Expected IO error"),
    }
}

#[test]
fn test_kernel_version_parsing_errors() {
    assert!(KernelVersion::parse("5.10").is_ok());
    assert!(KernelVersion::parse("6.1.52").is_ok());
    assert!(KernelVersion::parse("invalid").is_err());
    assert!(KernelVersion::parse("5").is_err());
    assert!(KernelVersion::parse("5.").is_err());
    assert!(KernelVersion::parse(".10").is_err());
    assert!(KernelVersion::parse("").is_err());
    
    match KernelVersion::parse("not-a-version") {
        Err(MailbotError::InvalidKernelVersion(v)) => {
            assert_eq!(v, "not-a-version");
        },
        _ => panic!("Expected InvalidKernelVersion error"),
    }
}

#[test]
fn test_file_operations_errors() {
    use mailbot::config::Config;
    
    let result = Config::load("/non/existent/config.json");
    assert!(result.is_ok());
    let test_dir = tempdir().unwrap();
    let bad_config = test_dir.path().join("bad.json");
    fs::write(&bad_config, "{ invalid json").unwrap();
    
    let result = Config::load(&bad_config);
    assert!(result.is_err());
}

#[test]
fn test_email_validation_errors() {
    let result = serde_json::from_str::<LeiEmail>(r#"{
        "subject": "Test",
        "from": "test@example.com"
    }"#);
    
    assert!(result.is_err());
}

#[test]
fn test_series_error_scenarios() {
    use mailbot::series::SeriesManager;
    
    let test_dir = tempdir().unwrap();
    let manager = SeriesManager::new(test_dir.path().to_path_buf());
    
    let email = LeiEmail {
        subject: "[PATCH 1/3] Test".to_string(),
        from: "test@example.com".to_string(),
        message_id: "<nonexistent@example.com>".to_string(),
        in_reply_to: None,
        date: "2024-01-01".to_string(),
        body: "Test".to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    let result = manager.get_series_patches(&email, 3);
    assert!(result.is_err());
}