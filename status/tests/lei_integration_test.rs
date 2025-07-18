use mailbot::lei::{LeiClient, ensure_stable_external};
use mailbot::config::Config;
use mailbot::patch::PatchProcessor;
use tempfile::TempDir;

#[test]
#[ignore] // Run with --ignored for integration tests
fn test_lei_query_integration() {
    // Create temporary directories
    let temp_dir = TempDir::new().unwrap();
    let output_dir = temp_dir.path().join("output");
    let worktree_dir = temp_dir.path().join("worktrees");
    
    std::fs::create_dir_all(&worktree_dir).unwrap();
    
    // Create a test config
    let config = Config {
        output_dir: output_dir.clone(),
        worktree_dir,
        debug: true, // Dry run mode
        ..Default::default()
    };
    
    // Test lei external setup
    ensure_stable_external().unwrap();
    
    // Create lei client
    let client = LeiClient::new();
    
    // Query recent patches (5 minutes)
    let emails = client.query_recent_patches(5, &[]).unwrap();
    
    println!("Found {} emails in the last 5 minutes", emails.len());
    
    if !emails.is_empty() {
        // Try processing the first email
        let processor = PatchProcessor::new(config).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        
        runtime.block_on(async {
            match processor.process_email(emails[0].clone()).await {
                Ok(_) => println!("Successfully processed email"),
                Err(e) => println!("Error processing email: {e}"),
            }
        });
        
        // Check if output was created
        if output_dir.exists() {
            let entries: Vec<_> = std::fs::read_dir(&output_dir)
                .unwrap()
                .filter_map(|e| e.ok())
                .collect();
            println!("Created {} response files", entries.len());
        }
    }
}


#[test]
fn test_empty_subject_handling() {
    use mailbot::email::LeiEmail;
    
    let email = LeiEmail {
        subject: "".to_string(),
        from: "test@example.com".to_string(),
        message_id: "<test@example.com>".to_string(),
        in_reply_to: None,
        date: "2025-01-01".to_string(),
        body: "Test".to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    let config = Config::default();
    let processor = PatchProcessor::new(config).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    
    // Should not crash on empty subject
    runtime.block_on(async {
        let result = processor.process_email(email).await;
        assert!(result.is_ok());
    });
}

