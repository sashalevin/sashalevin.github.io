use mailbot::email::LeiEmail;
use mailbot::patch::PatchProcessor;
use mailbot::config::Config;
use mailbot::tracking::{PatchTracking, PatchState, MailingListActivity, TrackingStore};
use chrono::Utc;
use std::path::PathBuf;
use std::fs;
use tempfile::tempdir;

#[tokio::test]
async fn test_failed_email_processing() {
    let test_dir = tempdir().unwrap();
    
    // Create test config
    let versions_file = test_dir.path().join("versions");
    fs::write(&versions_file, "6.6\n6.1\n5.15\n").unwrap();
    
    let config = Config {
        linux_dir: PathBuf::from("/home/sasha/stable-status/linux"),
        stable_queue_dir: PathBuf::from("/home/sasha/stable-status/stable-queue"),
        active_versions_file: versions_file,
        pending_dir: test_dir.path().join("pending"),
        worktree_dir: test_dir.path().join("worktrees"),
        output_dir: test_dir.path().join("output"),
        tracking_file: test_dir.path().join("tracking.json"),
        ignored_authors: vec![],
        email: mailbot::config::EmailConfig {
            from: "Bot <bot@test.com>".to_string(),
            reply_to: None,
            smtp: None,
        },
        build_command: "true".to_string(),
        debug: true,
        dry_run: true,
        skip_build: true,
    };
    
    // First, simulate processing a patch email by creating tracking data
    {
        let mut store = TrackingStore::new();
        let tracking = PatchTracking {
            message_id: "<patch12345@example.com>".to_string(),
            sha1: Some("1234567890abcdef1234567890abcdef12345678".to_string()),
            subject: "[PATCH 6.6] net: fix buffer overflow in driver".to_string(),
            author: "Developer <dev@example.com>".to_string(),
            from_email: "Developer <dev@example.com>".to_string(),
            first_seen: Utc::now(),
            last_updated: Utc::now(),
            state: PatchState::TestsPassed,
            processing_history: vec![],
            mailbot_results: vec![],
            mailing_list_activity: MailingListActivity {
                replies: vec![],
                reviews: vec![],
                related_patches: vec![],
                fixes_commit: None,
                fixes_cve: None,
            },
            target_versions: vec!["6.6".to_string()],
            lore_url: Some("https://lore.kernel.org/stable/patch12345@example.com".to_string()),
        };
        store.add_or_update_patch(tracking);
        store.save_to_file(&config.tracking_file).unwrap();
    }
    
    // Now create the processor after the tracking file has been saved
    let processor = PatchProcessor::new(config.clone()).unwrap();
    
    // Create a FAILED email without In-Reply-To
    let failed_email = LeiEmail {
        subject: "FAILED: patch \"net: fix buffer overflow in driver\" failed to apply to 6.6-stable tree".to_string(),
        from: "Greg Kroah-Hartman <gregkh@linuxfoundation.org>".to_string(),
        message_id: "<failed567890@kroah.com>".to_string(),
        in_reply_to: None,
        date: "Wed, 15 Jan 2025 10:30:00 +0100".to_string(),
        body: r#"The patch below does not apply to the 6.6-stable tree.
If someone wants it applied there, or to any other stable or longterm
tree, then please email the backport, including the original git commit
id to <stable@vger.kernel.org>.

thanks,

greg k-h

---------- Forwarded message ----------
From: Developer <dev@example.com>
Subject: [PATCH 6.6] net: fix buffer overflow in driver"#.to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    // Process the FAILED email
    let result = processor.process_reply_or_comment(failed_email).await.unwrap();
    assert!(result, "FAILED email should be processed as a reply");
    
    // Verify the patch state was updated
    {
        let store = TrackingStore::load_from_file(&config.tracking_file).unwrap();
        let patch = store.get_patch("<patch12345@example.com>").unwrap();
        
        // Check state is now Failed
        assert!(matches!(patch.state, PatchState::Failed(_)));
        
        // Check that the FAILED email was added to replies
        assert_eq!(patch.mailing_list_activity.replies.len(), 1);
        let reply = &patch.mailing_list_activity.replies[0];
        assert_eq!(reply.message_id, "<failed567890@kroah.com>");
        assert!(reply.subject.starts_with("FAILED: patch"));
        assert!(matches!(reply.message_type, mailbot::tracking::MessageType::FailedToApply));
    }
}

#[tokio::test]
async fn test_failed_email_with_in_reply_to() {
    let test_dir = tempdir().unwrap();
    
    // Create test config
    let versions_file = test_dir.path().join("versions");
    fs::write(&versions_file, "6.6\n").unwrap();
    
    let config = Config {
        linux_dir: PathBuf::from("/home/sasha/stable-status/linux"),
        stable_queue_dir: PathBuf::from("/home/sasha/stable-status/stable-queue"),
        active_versions_file: versions_file,
        pending_dir: test_dir.path().join("pending"),
        worktree_dir: test_dir.path().join("worktrees"),
        output_dir: test_dir.path().join("output"),
        tracking_file: test_dir.path().join("tracking.json"),
        ignored_authors: vec![],
        email: mailbot::config::EmailConfig {
            from: "Bot <bot@test.com>".to_string(),
            reply_to: None,
            smtp: None,
        },
        build_command: "true".to_string(),
        debug: true,
        dry_run: true,
        skip_build: true,
    };
    
    // Add a patch to tracking
    {
        let mut store = TrackingStore::new();
        let tracking = PatchTracking {
            message_id: "<original@example.com>".to_string(),
            sha1: None,
            subject: "[PATCH] mm: fix memory leak".to_string(),
            author: "Dev <dev@example.com>".to_string(),
            from_email: "Dev <dev@example.com>".to_string(),
            first_seen: Utc::now(),
            last_updated: Utc::now(),
            state: PatchState::OnMailingList,
            processing_history: vec![],
            mailbot_results: vec![],
            mailing_list_activity: MailingListActivity {
                replies: vec![],
                reviews: vec![],
                related_patches: vec![],
                fixes_commit: None,
                fixes_cve: None,
            },
            target_versions: vec!["6.6".to_string()],
            lore_url: None,
        };
        store.add_or_update_patch(tracking);
        store.save_to_file(&config.tracking_file).unwrap();
    }
    
    // Now create the processor after the tracking file has been saved
    let processor = PatchProcessor::new(config.clone()).unwrap();
    
    // Create FAILED email with In-Reply-To
    let failed_email = LeiEmail {
        subject: "FAILED: patch \"mm: fix memory leak\" failed to apply".to_string(),
        from: "Sasha Levin <sashal@kernel.org>".to_string(),
        message_id: "<failed999@kernel.org>".to_string(),
        in_reply_to: Some("<original@example.com>".to_string()),
        date: "2025-01-15".to_string(),
        body: "Failed to apply to stable tree.".to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    // Process the email
    let result = processor.process_reply_or_comment(failed_email).await.unwrap();
    assert!(result);
    
    // Verify patch was updated
    {
        let store = TrackingStore::load_from_file(&config.tracking_file).unwrap();
        let patch = store.get_patch("<original@example.com>").unwrap();
        assert!(matches!(patch.state, PatchState::Failed(_)));
        assert_eq!(patch.mailing_list_activity.replies.len(), 1);
    }
}