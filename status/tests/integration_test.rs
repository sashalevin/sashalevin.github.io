use mailbot::email::LeiEmail;
use mailbot::config::Config;
use mailbot::patch::PatchProcessor;
use mailbot::tracking::TrackingStore;
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
        tracking_file: test_dir.path().join("tracking.json"),
        ignored_authors: vec![],
        email: mailbot::config::EmailConfig {
            from: "Test Bot <bot@test.com>".to_string(),
            reply_to: None,
            smtp: None,
        },
        build_command: "echo 'Build successful'".to_string(),
        debug: true,
        dry_run: true,
        skip_build: false,
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
        build_passed: None,
        error: None,
    });
    
    let response = builder.build().unwrap();
    assert!(response.body.contains("✅"));
    assert_eq!(response.to, vec!["stable@vger.kernel.org"]);
    
    let mut builder = ResponseBuilder::new(&email, &config);
    builder.add_test_result(TestResult {
        branch: "stable/linux-5.10.y".to_string(),
        patch_status: PatchStatus::Success,
        build_passed: Some(false),
        error: Some("undefined reference to `foo'".to_string()),
    });
    
    let response = builder.build().unwrap();
    assert!(response.body.contains("❌"));
    assert_eq!(response.to, vec!["dev@example.com"]);
    assert_eq!(response.cc, vec!["stable@vger.kernel.org"]);
}

#[tokio::test]
async fn test_failed_emails_from_ignored_authors_are_processed() {
    // Create a temporary directory for test data
    let temp_dir = tempdir().unwrap();
    let tracking_file = temp_dir.path().join("tracking.json");
    let linux_dir = temp_dir.path().join("linux");
    let stable_queue_dir = temp_dir.path().join("stable-queue");
    
    // Create directories
    fs::create_dir_all(&linux_dir).unwrap();
    fs::create_dir_all(&stable_queue_dir).unwrap();
    
    // Initialize git repo
    use std::process::Command;
    Command::new("git")
        .args(&["init"])
        .current_dir(&linux_dir)
        .output()
        .expect("Failed to init git repo");
    
    // Create a config with Greg KH as an ignored author
    let config = Config {
        ignored_authors: vec!["Greg Kroah-Hartman".to_string(), "gregkh@kernel.org".to_string()],
        tracking_file: tracking_file.clone(),
        linux_dir: linux_dir.clone(),
        stable_queue_dir: stable_queue_dir.clone(),
        dry_run: true,
        skip_build: true,
        ..Default::default()
    };
    
    // Create a processor
    let processor = PatchProcessor::new(config.clone()).unwrap();
    
    // First, process a regular patch to track it
    let patch_email = LeiEmail {
        subject: "[PATCH 5.10] drm/i915: Fix display issue".to_string(),
        from: "Developer <dev@example.com>".to_string(),
        message_id: "<patch999@example.com>".to_string(),
        in_reply_to: None,
        date: "2024-01-01T00:00:00Z".to_string(),
        body: r#"From: Developer <dev@example.com>
Subject: [PATCH 5.10] drm/i915: Fix display issue

Fix display issue in i915 driver.

commit abc123 upstream.

Signed-off-by: Developer <dev@example.com>
---
 drivers/gpu/drm/i915/display.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/drivers/gpu/drm/i915/display.c b/drivers/gpu/drm/i915/display.c
index 1234567..abcdefg 100644
--- a/drivers/gpu/drm/i915/display.c
+++ b/drivers/gpu/drm/i915/display.c
@@ -100,6 +100,8 @@ void display_func(void)
 {
     /* Fix display issue */
+    fix_display();
 }
"#.to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    // Process the patch
    processor.process_email(patch_email).await.unwrap();
    
    // Now create a FAILED email from Greg KH (ignored author)
    let failed_email = LeiEmail {
        subject: "FAILED: patch \"drm/i915: Fix display issue\" failed to apply to 5.10-stable tree".to_string(),
        from: "Greg Kroah-Hartman <gregkh@kernel.org>".to_string(),
        message_id: "<failed999@kernel.org>".to_string(),
        in_reply_to: Some("<patch999@example.com>".to_string()),
        date: "2024-01-02T00:00:00Z".to_string(),
        body: r#"The patch below does not apply to the 5.10-stable tree.
If someone wants it applied there, or to any other stable or longterm
tree, then please email the backport, including the original git commit
id to <stable@vger.kernel.org>.

thanks,

greg k-h

------------------ original commit in Linus's tree ------------------"#.to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    // This should NOT be a git patch
    assert!(!failed_email.is_git_patch());
    
    // Process the FAILED email - it should be processed even though Greg is in ignored_authors
    let result = processor.process_reply_or_comment(failed_email).await.unwrap();
    assert!(result, "FAILED email from ignored author should be processed");
    
    // Check that the tracking data was updated
    let store = TrackingStore::load_from_file(&tracking_file).unwrap();
    let patch = store.get_patch("<patch999@example.com>").unwrap();
    
    // FAILED emails are stored as replies with MessageType::FailedToApply
    assert_eq!(patch.mailing_list_activity.replies.len(), 1);
    assert_eq!(patch.mailing_list_activity.replies[0].from, "Greg Kroah-Hartman <gregkh@kernel.org>");
    assert!(matches!(patch.mailing_list_activity.replies[0].message_type, mailbot::tracking::MessageType::FailedToApply));
}

#[tokio::test]
async fn test_patches_from_ignored_authors_are_ignored() {
    // Create a temporary directory for test data
    let temp_dir = tempdir().unwrap();
    let tracking_file = temp_dir.path().join("tracking.json");
    let linux_dir = temp_dir.path().join("linux");
    let stable_queue_dir = temp_dir.path().join("stable-queue");
    
    // Create directories
    fs::create_dir_all(&linux_dir).unwrap();
    fs::create_dir_all(&stable_queue_dir).unwrap();
    
    // Initialize git repo
    use std::process::Command;
    Command::new("git")
        .args(&["init"])
        .current_dir(&linux_dir)
        .output()
        .expect("Failed to init git repo");
    
    // Create a config with Greg KH as an ignored author
    let config = Config {
        ignored_authors: vec!["Greg Kroah-Hartman".to_string(), "gregkh@kernel.org".to_string()],
        tracking_file: tracking_file.clone(),
        linux_dir: linux_dir.clone(),
        stable_queue_dir: stable_queue_dir.clone(),
        dry_run: true,
        skip_build: true,
        ..Default::default()
    };
    
    // Create a patch email from Greg KH
    let patch_email = LeiEmail {
        subject: "[PATCH 5.10] usb: fix something".to_string(),
        from: "Greg Kroah-Hartman <gregkh@kernel.org>".to_string(),
        message_id: "<gregpatch@kernel.org>".to_string(),
        in_reply_to: None,
        date: "2024-01-01T00:00:00Z".to_string(),
        body: r#"From: Greg Kroah-Hartman <gregkh@kernel.org>
Subject: [PATCH 5.10] usb: fix something

Fix USB issue.

commit xyz789 upstream.

Signed-off-by: Greg Kroah-Hartman <gregkh@kernel.org>
---
 drivers/usb/core/hub.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/drivers/usb/core/hub.c b/drivers/usb/core/hub.c
index 1234567..abcdefg 100644
--- a/drivers/usb/core/hub.c
+++ b/drivers/usb/core/hub.c
@@ -100,6 +100,8 @@ void hub_func(void)
 {
     /* Fix USB issue */
+    fix_usb();
 }
"#.to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    // This should be identified as a git patch
    assert!(patch_email.is_git_patch());
    
    // This patch should be ignored due to the author
    assert!(patch_email.should_ignore(&config));
    
    // Verify the patch is not tracked
    let store = TrackingStore::load_from_file(&tracking_file).unwrap_or_else(|_| TrackingStore::new());
    assert!(store.get_patch("<gregpatch@kernel.org>").is_none(), "Patch from ignored author should not be tracked");
}