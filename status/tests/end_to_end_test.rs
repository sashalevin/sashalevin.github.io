use mailbot::{
    config::{Config, EmailConfig},
    email::LeiEmail,
    kernel::{KernelVersion, KernelVersionManager},
    patch::PatchProcessor,
    response::{ResponseBuilder, TestResult, PatchStatus},
    series::SeriesManager,
};
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn test_complete_workflow_with_successful_patch() {
    let test_dir = tempdir().unwrap();
    
    let config = create_test_config(&test_dir);
    let email = LeiEmail {
        subject: "[PATCH 5.10] mm: Fix memory leak in allocator".to_string(),
        from: "John Developer <john@example.com>".to_string(),
        message_id: "<patch-123@example.com>".to_string(),
        in_reply_to: None,
        date: "2024-01-01T12:00:00Z".to_string(),
        body: r#"From: John Developer <john@example.com>
Subject: [PATCH 5.10] mm: Fix memory leak in allocator

This fixes a memory leak that occurs when allocation fails.

commit fedcba9876543210fedcba9876543210fedcba98 upstream.

The leak was introduced in commit abc123 and causes system
memory to be exhausted over time.

Signed-off-by: John Developer <john@example.com>
---
 mm/page_alloc.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 1234567..abcdefg 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1000,6 +1000,9 @@ void *alloc_pages(int order)
     if (!page)
         return NULL;
         
+    /* Fix: Clear the page before returning */
+    clear_page(page);
+    
     return page;
 }
-- 
2.34.1"#.to_string(),
        headers: None,
        references: None,
        cc: Some(vec!["stable@vger.kernel.org".to_string()]),
        to: Some(vec!["linux-mm@kvack.org".to_string()]),
    };
    
    assert!(email.is_git_patch());
    assert_eq!(email.extract_series_info(), None);
    assert_eq!(email.clean_subject(), "mm: Fix memory leak in allocator");
    assert_eq!(email.extract_email_address(), Some("john@example.com".to_string()));
    
    let _processor = PatchProcessor::new(config.clone()).unwrap();
    let body_contains_sha = email.body.contains("fedcba9876543210fedcba9876543210fedcba98");
    assert!(body_contains_sha);
    
    let mut response_builder = ResponseBuilder::new(&email, &config);
    
    response_builder.set_commit_info(
        Some("fedcba9876543210fedcba9876543210fedcba98".to_string()),
        Some("fedcba9876543210fedcba9876543210fedcba98".to_string()),
        None,
    );
    
    response_builder.add_test_result(TestResult {
        branch: "stable/linux-5.10.y".to_string(),
        patch_status: PatchStatus::Success,
        build_passed: None,
        error: None,
    });
    
    let response = response_builder.build().unwrap();
    
    assert_eq!(response.subject, "Re: [PATCH 5.10] mm: Fix memory leak in allocator");
    assert!(response.body.contains("✅ All tests passed successfully"));
    assert_eq!(response.to, vec!["stable@vger.kernel.org"]);
    assert!(response.cc.is_empty());
    
    let response_path = test_dir.path().join("responses");
    fs::create_dir_all(&response_path).unwrap();
    response.save(&response_path).unwrap();
    let files: Vec<_> = fs::read_dir(&response_path).unwrap().collect();
    assert_eq!(files.len(), 1);
}

#[test]
fn test_series_workflow() {
    let test_dir = tempdir().unwrap();
    let series_dir = test_dir.path().join("pending/series");
    fs::create_dir_all(&series_dir).unwrap();
    
    let manager = SeriesManager::new(series_dir.clone());
    
    let emails = vec![
        create_series_email(0, 3, None, "Cover letter"),
        create_series_email(1, 3, Some("<cover@example.com>"), "First patch"),
        create_series_email(2, 3, Some("<cover@example.com>"), "Second patch"),
        create_series_email(3, 3, Some("<cover@example.com>"), "Third patch"),
    ];
    
    for (i, email) in emails.iter().enumerate() {
        if i == 0 {
            assert_eq!(email.extract_series_info(), Some((0, 3)));
            continue;
        }
        
        let (part, total) = email.extract_series_info().unwrap();
        manager.store_patch(email, part, total).unwrap();
        
        if i < 3 {
            assert!(!manager.is_series_complete(email, total).unwrap());
        } else {
            assert!(manager.is_series_complete(email, total).unwrap());
        }
    }
    
    let patches = manager.get_series_patches(&emails[1], 3).unwrap();
    assert_eq!(patches.len(), 3);
    
    manager.cleanup_series(&emails[1]).unwrap();
    let dirs: Vec<_> = fs::read_dir(&series_dir).unwrap().collect();
    assert_eq!(dirs.len(), 0);
}

#[test]
fn test_failed_patch_workflow() {
    let test_dir = tempdir().unwrap();
    let config = create_test_config(&test_dir);
    
    let email = LeiEmail {
        subject: "[PATCH 6.1] driver: Fix null pointer dereference".to_string(),
        from: "Jane Dev <jane@example.com>".to_string(),
        message_id: "<failed-patch@example.com>".to_string(),
        in_reply_to: None,
        date: "2024-01-01T14:00:00Z".to_string(),
        body: r#"From: Jane Dev <jane@example.com>
Subject: [PATCH 6.1] driver: Fix null pointer dereference

Fix NPE in driver code.

Signed-off-by: Jane Dev <jane@example.com>
---
 drivers/misc/example.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/drivers/misc/example.c b/drivers/misc/example.c
index 1234567..abcdefg 100644
--- a/drivers/misc/example.c
+++ b/drivers/misc/example.c
@@ -100,6 +100,11 @@ static int example_probe(struct device *dev)
{
    struct example_data *data = dev_get_drvdata(dev);
    
+   if (!data) {
+       dev_err(dev, "No driver data\n");
+       return -EINVAL;
+   }
+   
    return 0;
}
-- 
2.34.1"#.to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    };
    
    let mut response_builder = ResponseBuilder::new(&email, &config);
    response_builder.set_commit_info(None, None, None);
    
    response_builder.add_test_result(TestResult {
        branch: "stable/linux-6.1.y".to_string(),
        patch_status: PatchStatus::Failed,
        build_passed: None,
        error: Some("Hunk #1 FAILED at 100.\n1 out of 1 hunk FAILED".to_string()),
    });
    
    let response = response_builder.build().unwrap();
    
    assert!(response.body.contains("❌ Build failures detected"));
    assert!(response.body.contains("⚠️ Could not find matching upstream commit"));
    assert_eq!(response.to, vec!["jane@example.com"]);
    assert_eq!(response.cc, vec!["stable@vger.kernel.org"]);
    assert!(response.body.contains("Hunk #1 FAILED"));
}

#[test]
fn test_kernel_version_extraction() {
    let test_dir = tempdir().unwrap();
    let versions_file = test_dir.path().join("versions");
    fs::write(&versions_file, "4.19\n5.4\n5.10\n5.15\n6.1\n6.6\n6.12\n").unwrap();
    
    let manager = KernelVersionManager::load(&versions_file).unwrap();
    
    let versions = manager.extract_versions_from_subject("[PATCH 5.10] Fix bug");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].to_string(), "5.10");
    
    let versions = manager.extract_versions_from_subject("[PATCH 5.4-6.1] Fix issue");
    assert_eq!(versions.len(), 4);
    assert_eq!(versions[0].to_string(), "5.4");
    assert_eq!(versions[3].to_string(), "6.1");
    
    let versions = manager.extract_versions_from_subject("[PATCH 5.10,5.15,6.6] Backport fix");
    assert!(versions.contains(&KernelVersion::parse("5.10").unwrap()));
    assert!(versions.contains(&KernelVersion::parse("5.15").unwrap()));
    assert!(versions.contains(&KernelVersion::parse("6.6").unwrap()));
    
    let versions = manager.extract_versions_from_subject("[PATCH v5.10.y-v6.1.y] Security fix");
    assert_eq!(versions.len(), 3);  // Should be 5.10, 5.15, 6.1
    
    let versions = manager.extract_versions_from_subject("[PATCH] Generic fix");
    assert_eq!(versions.len(), 0);
}

#[test]
fn test_response_with_fixes_and_reverts() {
    let test_dir = tempdir().unwrap();
    let config = create_test_config(&test_dir);
    
    let email = create_test_email();
    let mut builder = ResponseBuilder::new(&email, &config);
    
    builder.set_commit_info(
        Some("abc123".to_string()),
        Some("abc123".to_string()),
        None,
    );
    
    builder.set_fixes(vec![
        ("fix123456789012".to_string(), "mm: fix race condition in original patch".to_string()),
        ("fix234567890123".to_string(), "mm: fix another issue with the patch".to_string()),
    ]);
    
    builder.set_reverts(vec![
        ("rev345678901234".to_string(), "Revert \"mm: original patch\"".to_string()),
    ]);
    
    builder.add_test_result(TestResult {
        branch: "stable/linux-5.10.y".to_string(),
        patch_status: PatchStatus::Success,
        build_passed: None,
        error: None,
    });
    
    let response = builder.build().unwrap();
    
    assert!(response.body.contains("⚠️ Found follow-up fixes in mainline"));
    assert!(response.body.contains("❌ Commit was reverted in mainline"));
    assert!(response.body.contains("fix123456789 mm: fix race condition"));
    assert!(response.body.contains("rev345678901 Revert"));
    
    assert_eq!(response.to.len(), 1);
    assert!(response.to[0].contains("@example.com"));
}

fn create_test_config(test_dir: &tempfile::TempDir) -> Config {
    let versions_file = test_dir.path().join("versions");
    fs::write(&versions_file, "5.10\n5.15\n6.1\n6.6\n").unwrap();
    
    Config {
        linux_dir: PathBuf::from("/home/sasha/stable-status/linux"),
        stable_queue_dir: PathBuf::from("/home/sasha/stable-status/stable-queue"),
        active_versions_file: versions_file,
        pending_dir: test_dir.path().join("pending"),
        worktree_dir: test_dir.path().join("worktrees"),
        output_dir: test_dir.path().join("output"),
        tracking_file: test_dir.path().join("tracking.json"),
        ignored_authors: vec![
            "Greg Kroah-Hartman".to_string(),
            "Sasha Levin".to_string(),
        ],
        email: EmailConfig {
            from: "Test Bot <bot@test.com>".to_string(),
            reply_to: None,
            smtp: None,
        },
        build_command: "echo 'Build successful'".to_string(),
        debug: true,
        dry_run: true,
        skip_build: false,
    }
}

fn create_test_email() -> LeiEmail {
    LeiEmail {
        subject: "[PATCH] Test patch".to_string(),
        from: "Test Dev <test@example.com>".to_string(),
        message_id: "<test@example.com>".to_string(),
        in_reply_to: None,
        date: "2024-01-01".to_string(),
        body: "Test patch content".to_string(),
        headers: None,
        references: None,
        cc: None,
        to: None,
    }
}

fn create_series_email(part: u32, total: u32, reply_to: Option<&str>, desc: &str) -> LeiEmail {
    LeiEmail {
        subject: format!("[PATCH {part}/{total}] {desc}"),
        from: "Series Author <series@example.com>".to_string(),
        message_id: format!("<part-{part}@example.com>"),
        in_reply_to: reply_to.map(|s| s.to_string()),
        date: "2024-01-01".to_string(),
        body: format!("{desc} content"),
        headers: None,
        references: None,
        cc: None,
        to: None,
    }
}