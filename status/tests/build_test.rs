use mailbot::response::{ResponseBuilder, TestResult, PatchStatus};
use mailbot::email::LeiEmail;
use mailbot::config::Config;

#[test]
fn test_response_with_build_results() {
    let email = LeiEmail {
        subject: "[PATCH] Test patch".to_string(),
        from: "test@example.com".to_string(),
        message_id: "<123@example.com>".to_string(),
        in_reply_to: None,
        date: "2024-01-01".to_string(),
        body: "Test content".to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    let config = Config::default();
    let mut builder = ResponseBuilder::new(&email, &config);
    
    // Set commit info
    builder.set_commit_info(
        Some("abc123".to_string()),
        Some("abc123".to_string()),
        None,
    );
    
    // Add test result with successful build
    builder.add_test_result(TestResult {
        branch: "stable/linux-6.1.y".to_string(),
        patch_status: PatchStatus::Success,
        build_passed: Some(true),
        error: None,
    });
    
    // Add test result with failed build
    builder.add_test_result(TestResult {
        branch: "stable/linux-5.10.y".to_string(),
        patch_status: PatchStatus::Success,
        build_passed: Some(false),
        error: Some("Build failed: undefined reference to `foo'".to_string()),
    });
    
    // Add test result with patch failure (no build)
    builder.add_test_result(TestResult {
        branch: "stable/linux-5.4.y".to_string(),
        patch_status: PatchStatus::Failed,
        build_passed: None,
        error: Some("Patch failed to apply".to_string()),
    });
    
    let response = builder.build().unwrap();
    
    // Should have issues due to build failure
    assert!(response.body.contains("❌ Build failures detected"));
    
    // Check table formatting
    assert!(response.body.contains("| Branch                    | Patch Apply | Build Test |"));
    assert!(response.body.contains("| stable/linux-6.1.y        | Success     | Success    |"));
    assert!(response.body.contains("| stable/linux-5.10.y       | Success     | Failed     |"));
    assert!(response.body.contains("| stable/linux-5.4.y        | Failed      | N/A        |"));
    
    // Check error section
    assert!(response.body.contains("Build failed: undefined reference to `foo'"));
    
    // Should not contain the old message about separate build testing
    assert!(!response.body.contains("Note: Build testing is performed separately"));
}