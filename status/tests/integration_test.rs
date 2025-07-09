use mailbot::email::LeiEmail;
use mailbot::config::Config;
use mailbot::patch::PatchProcessor;
use tempfile::tempdir;
use std::fs;
use std::path::PathBuf;

#[test]
fn test_full_patch_workflow() {
    let _email = LeiEmail {
        subject: "[PATCH 5.10] mm: fix memory leak".to_string(),
        from: "Developer <dev@example.com>".to_string(),
        message_id: "<patch123@example.com>".to_string(),
        in_reply_to: None,
        date: "2024-01-01T00:00:00Z".to_string(),
        body: r#"From: Developer <dev@example.com>
Subject: [PATCH 5.10] mm: fix memory leak
Date: Mon, 1 Jan 2024 00:00:00 +0000

Fix a memory leak in the mm subsystem.

commit abcdef1234567890abcdef1234567890abcdef12 upstream.

This patch fixes a memory leak that occurs when...

Signed-off-by: Developer <dev@example.com>
---
 mm/memory.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/mm/memory.c b/mm/memory.c
index 1234567..abcdefg 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -100,6 +100,8 @@ void some_function(void)
 {
     void *ptr = kmalloc(size, GFP_KERNEL);
     if (!ptr)
         return;
+    /* Fix: free allocated memory */
+    kfree(ptr);
 }
-- 
2.34.1
"#.to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    let test_dir = tempdir().unwrap();
    let pending_dir = test_dir.path().join("pending");
    let worktree_dir = test_dir.path().join("worktrees");
    let output_dir = test_dir.path().join("output");
    
    fs::create_dir_all(&pending_dir).unwrap();
    fs::create_dir_all(&worktree_dir).unwrap();
    fs::create_dir_all(&output_dir).unwrap();
    
    let versions_file = test_dir.path().join("active_versions");
    fs::write(&versions_file, "5.10\n5.15\n6.1\n").unwrap();
    
    let config = Config {
        linux_dir: PathBuf::from("/home/sasha/stable-status/linux"),
        stable_queue_dir: PathBuf::from("/home/sasha/stable-status/stable-queue"),
        active_versions_file: versions_file,
        pending_dir,
        worktree_dir,
        output_dir: output_dir.clone(),
        ignored_authors: vec![],
        email: mailbot::config::EmailConfig {
            from: "Test Bot <bot@test.com>".to_string(),
            reply_to: None,
            smtp: None,
        },
        build_command: "echo 'Build successful'".to_string(),
        debug: true,
    };
    
    let _processor = PatchProcessor::new(config).unwrap();
    assert!(output_dir.exists());
}

#[test] 
fn test_series_workflow() {
    let test_dir = tempdir().unwrap();
    let pending_dir = test_dir.path().join("pending/series");
    fs::create_dir_all(&pending_dir).unwrap();
    
    let series_emails = vec![
        LeiEmail {
            subject: "[PATCH 0/3] Fix memory issues".to_string(),
            from: "Developer <dev@example.com>".to_string(),
            message_id: "<cover@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01T00:00:00Z".to_string(),
            body: "This series fixes several memory issues...".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        },
        LeiEmail {
            subject: "[PATCH 1/3] mm: fix leak in allocator".to_string(),
            from: "Developer <dev@example.com>".to_string(),
            message_id: "<patch1@example.com>".to_string(),
            in_reply_to: Some("<cover@example.com>".to_string()),
            date: "2024-01-01T00:01:00Z".to_string(),
            body: "First patch content...".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        },
        LeiEmail {
            subject: "[PATCH 2/3] mm: fix race condition".to_string(),
            from: "Developer <dev@example.com>".to_string(),
            message_id: "<patch2@example.com>".to_string(),
            in_reply_to: Some("<cover@example.com>".to_string()),
            date: "2024-01-01T00:02:00Z".to_string(),
            body: "Second patch content...".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        },
        LeiEmail {
            subject: "[PATCH 3/3] mm: add tests".to_string(),
            from: "Developer <dev@example.com>".to_string(),
            message_id: "<patch3@example.com>".to_string(),
            in_reply_to: Some("<cover@example.com>".to_string()),
            date: "2024-01-01T00:03:00Z".to_string(),
            body: "Third patch content...".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        },
    ];
    
    assert_eq!(series_emails[0].extract_series_info(), Some((0, 3)));
    assert_eq!(series_emails[1].extract_series_info(), Some((1, 3)));
    assert_eq!(series_emails[2].extract_series_info(), Some((2, 3)));
    assert_eq!(series_emails[3].extract_series_info(), Some((3, 3)));
}

#[test]
fn test_ignored_authors() {
    let config = Config::default();
    
    let ignored_email = LeiEmail {
        subject: "[PATCH] Test".to_string(),
        from: "Greg Kroah-Hartman <gregkh@kernel.org>".to_string(),
        message_id: "<test@kernel.org>".to_string(),
        in_reply_to: None,
        date: "2024-01-01".to_string(),
        body: "Test".to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    assert!(ignored_email.should_ignore(&config));
    
    let normal_email = LeiEmail {
        subject: "[PATCH] Test".to_string(),
        from: "Random Developer <dev@example.com>".to_string(),
        message_id: "<test@example.com>".to_string(),
        in_reply_to: None,
        date: "2024-01-01".to_string(),
        body: "Test".to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    assert!(!normal_email.should_ignore(&config));
}

#[test]
fn test_email_parsing_edge_cases() {
    let email = LeiEmail {
        subject: "=?UTF-8?B?W1BBVENIXSBGaXggc29tZXRoaW5n?=".to_string(),
        from: "=?UTF-8?Q?Test_User?= <test@example.com>".to_string(),
        message_id: "<test@example.com>".to_string(),
        in_reply_to: None,
        date: "2024-01-01".to_string(),
        body: "Test".to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    let decoded_subject = LeiEmail::decode_mime_header(&email.subject);
    assert_eq!(decoded_subject, "[PATCH] Fix something");
    
    let decoded_from = LeiEmail::decode_mime_header(&email.from);
    assert_eq!(decoded_from, "Test User <test@example.com>");
}

#[test]
fn test_response_generation_scenarios() {
    use mailbot::response::{ResponseBuilder, TestResult, PatchStatus};
    
    let email = LeiEmail {
        subject: "[PATCH 5.10] Fix critical bug".to_string(),
        from: "Dev <dev@example.com>".to_string(),
        message_id: "<critical@example.com>".to_string(),
        in_reply_to: None,
        date: "2024-01-01".to_string(),
        body: "Critical fix".to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    let config = Config::default();
    
    let mut builder = ResponseBuilder::new(&email, &config);
    builder.set_commit_info(
        Some("abc123".to_string()),
        Some("abc123".to_string()),
        None,
    );
    builder.add_test_result(TestResult {
        branch: "stable/linux-5.10.y".to_string(),
        patch_status: PatchStatus::Success,
        build_status: Some(true),
        error: None,
    });
    
    let response = builder.build().unwrap();
    assert!(response.body.contains("✅"));
    assert_eq!(response.to, vec!["stable@vger.kernel.org"]);
    
    let mut builder = ResponseBuilder::new(&email, &config);
    builder.add_test_result(TestResult {
        branch: "stable/linux-5.10.y".to_string(),
        patch_status: PatchStatus::Success,
        build_status: Some(false),
        error: Some("undefined reference to `foo'".to_string()),
    });
    
    let response = builder.build().unwrap();
    assert!(response.body.contains("❌"));
    assert_eq!(response.to, vec!["dev@example.com"]);
    assert_eq!(response.cc, vec!["stable@vger.kernel.org"]);
}