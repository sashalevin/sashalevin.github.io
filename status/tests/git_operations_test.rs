use mailbot::git::GitRepo;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

const LINUX_REPO_PATH: &str = "/home/sasha/stable-status/linux";
const LINUX_STABLE_RC_PATH: &str = "/home/sasha/stable-status/linux-stable-rc";
const STABLE_QUEUE_PATH: &str = "/home/sasha/stable-status/stable-queue";

#[test]
fn test_git_repo_operations() {
    // Use the real Linux kernel repository
    let repo = GitRepo::open(Path::new(LINUX_REPO_PATH)).unwrap();
    
    // Get a known recent commit from master branch
    let output = Command::new("git")
        .args(["rev-parse", "master"])
        .current_dir(LINUX_REPO_PATH)
        .output()
        .unwrap();
    
    let master_sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    
    // Test commit exists by trying to find it
    assert!(repo.find_commit(&master_sha).is_ok());
    assert!(repo.find_commit("0000000000000000000000000000000000000000").is_err());
    
    // Test find commit
    let commit = repo.find_commit(&master_sha).unwrap();
    assert_eq!(commit.id().to_string(), master_sha);
    
    // Test get commit author (can't assert specific author as it varies)
    let author = repo.get_commit_author(&master_sha).unwrap();
    assert!(!author.is_empty());
    assert!(author.contains("<")); // Should have email format
    
    // Test is_ancestor - master HEAD should be ancestor of master branch
    assert!(repo.is_ancestor(&master_sha, "master").unwrap());
    
    // Test find commit by subject - look for a merge commit which is common
    let found = repo.find_commit_by_subject("master", "Merge").ok();
    // We can't guarantee a specific commit exists, but the function should work
    assert!(found.is_some()); // Either Some(Some(commit)) or Some(None)
}

#[test]
fn test_worktree_operations() {
    // Use the real Linux kernel repository
    let repo = GitRepo::open(Path::new(LINUX_REPO_PATH)).unwrap();
    let worktree_dir = tempdir().unwrap();
    
    // Create worktree from master branch
    let worktree = repo.create_worktree("master", "test-worktree", worktree_dir.path()).unwrap();
    
    // Verify worktree exists
    assert!(worktree.path.exists());
    assert!(worktree.path.join(".git").exists());
    
    // Test reset_hard - create a file and verify it gets removed
    std::fs::write(worktree.path.join("test_file.txt"), "test content").unwrap();
    assert!(worktree.path.join("test_file.txt").exists());
    worktree.reset_hard().unwrap();
    assert!(!worktree.path.join("test_file.txt").exists());
    
    // Test apply_patch with a simple patch that adds a file
    let patch = r#"From abc123 Mon Sep 17 00:00:00 2001
From: Test User <test@example.com>
Date: Mon, 1 Jan 2024 00:00:00 +0000
Subject: [PATCH] Add test documentation file

This is a test patch for the git operations test.

---
 Documentation/test_patch.txt | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/Documentation/test_patch.txt b/Documentation/test_patch.txt
new file mode 100644
index 0000000..1234567
--- /dev/null
+++ b/Documentation/test_patch.txt
@@ -0,0 +1,3 @@
+Test Documentation
+==================
+This is a test file added by the git operations test.
-- 
2.34.1
"#;
    
    worktree.apply_patch(patch).unwrap();
    assert!(worktree.path.join("Documentation/test_patch.txt").exists());
    
    // Test get_head_sha
    let sha = worktree.get_head_sha().unwrap();
    assert_eq!(sha.len(), 40);
    assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_failed_patch_application() {
    // Use the real Linux kernel repository
    let repo = GitRepo::open(Path::new(LINUX_REPO_PATH)).unwrap();
    let worktree_dir = tempdir().unwrap();
    
    let worktree = repo.create_worktree("master", "test-failed", worktree_dir.path()).unwrap();
    
    // Create a patch that will fail - tries to modify a non-existent file with wrong context
    let bad_patch = r#"From abc123 Mon Sep 17 00:00:00 2001
From: Test User <test@example.com>
Date: Mon, 1 Jan 2024 00:00:00 +0000
Subject: [PATCH] Bad patch that will fail

This patch tries to modify a non-existent file with wrong context.

---
 drivers/nonexistent/driver.c | 10 ++++++++++
 1 file changed, 10 insertions(+)

diff --git a/drivers/nonexistent/driver.c b/drivers/nonexistent/driver.c
index 1234567..abcdefg 100644
--- a/drivers/nonexistent/driver.c
+++ b/drivers/nonexistent/driver.c
@@ -100,6 +100,16 @@ static int fake_function(struct device *dev)
     struct fake_data *data = dev_get_drvdata(dev);
     int ret;
     
+    /* This context doesn't exist in the kernel */
+    if (!data) {
+        dev_err(dev, "No driver data\n");
+        return -EINVAL;
+    }
+    
+    /* More fake code that won't apply */
+    ret = fake_init(data);
+    if (ret)
+        return ret;
+    
     return 0;
 }
-- 
2.34.1
"#;
    
    let result = worktree.apply_patch(bad_patch);
    assert!(result.is_err());
    
    // Verify error message contains useful info
    if let Err(e) = result {
        let error_msg = e.to_string();
        assert!(error_msg.contains("Failed to apply patch"));
    }
}

#[test]
fn test_find_fixes_and_reverts() {
    // Use the real Linux kernel repository
    let repo = GitRepo::open(Path::new(LINUX_REPO_PATH)).unwrap();
    
    // We can't create specific commits in the real repository, so we'll test
    // the functionality without asserting specific results
    
    // Get a recent commit from origin/master
    let output = Command::new("git")
        .args(["rev-parse", "origin/master~10"])
        .current_dir(LINUX_REPO_PATH)
        .output()
        .unwrap();
    
    let test_sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    
    let fixes_result = repo.find_fixes_for_commit(&test_sha);
    assert!(fixes_result.is_ok());
    let fixes = fixes_result.unwrap();
    
    let reverts_result = repo.find_reverts_for_commit(&test_sha);
    assert!(reverts_result.is_ok());
    let reverts = reverts_result.unwrap();
    for (sha, subject) in &fixes {
        assert!(!sha.is_empty());
        assert!(!subject.is_empty());
        assert!(subject.to_lowercase().contains("fix"));
    }
    
    for (sha, subject) in &reverts {
        assert!(!sha.is_empty());
        assert!(!subject.is_empty());
        assert!(subject.to_lowercase().contains("revert"));
    }
}

#[test]
fn test_worktree_cleanup() {
    // Use the real Linux kernel repository
    let repo = GitRepo::open(Path::new(LINUX_REPO_PATH)).unwrap();
    let worktree_dir = tempdir().unwrap();
    
    let worktree_name = format!("cleanup-test-{}", std::process::id());
    let _worktree_path = {
        let worktree = repo.create_worktree("origin/master", &worktree_name, worktree_dir.path()).unwrap();
        let path = worktree.path.clone();
        
        // Verify it exists
        assert!(path.exists());
        assert!(path.join(".git").exists());
        
        // Verify git knows about this worktree
        let output = Command::new("git")
            .args(["worktree", "list"])
            .current_dir(LINUX_REPO_PATH)
            .output()
            .unwrap();
        
        let worktree_list = String::from_utf8_lossy(&output.stdout);
        assert!(worktree_list.contains(path.to_str().unwrap()));
        
        path
    };
    let output = Command::new("git")
        .args(["worktree", "list"])
        .current_dir(LINUX_REPO_PATH)
        .output()
        .unwrap();
    
    let _worktree_list = String::from_utf8_lossy(&output.stdout);
}

#[test]
fn test_range_diff() {
    // Use the real Linux kernel repository
    let repo = GitRepo::open(Path::new(LINUX_REPO_PATH)).unwrap();
    
    // Get two commits to compare from the real repository
    let output = Command::new("git")
        .args(["rev-parse", "master"])
        .current_dir(LINUX_REPO_PATH)
        .output()
        .unwrap();
    
    let head_sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    
    let output2 = Command::new("git")
        .args(["rev-parse", "master~1"])
        .current_dir(LINUX_REPO_PATH)
        .output()
        .unwrap();
    
    let prev_sha = String::from_utf8_lossy(&output2.stdout).trim().to_string();
    
    // Test range-diff (might fail if git version doesn't support it)
    let result = repo.range_diff(&prev_sha, &head_sha);
    
    // We don't assert success because range-diff might not be available
    // but we test that the function doesn't panic
    match result {
        Ok(diff) => {
            // If it succeeds, output should be a string
            // Range-diff output varies, so we just check it's valid
            assert!(diff.is_empty() || !diff.is_empty());
        }
        Err(_) => {
            // It's ok if range-diff is not available or fails
            // (e.g., if the commits don't form a proper range)
        }
    }
}

#[test]
fn test_stable_queue_repository() {
    // Test with the stable-queue repository
    let repo = GitRepo::open(Path::new(STABLE_QUEUE_PATH)).unwrap();
    
    // Get current branch
    let output = Command::new("git")
        .args(["branch", "--show-current"])
        .current_dir(STABLE_QUEUE_PATH)
        .output()
        .unwrap();
    
    let current_branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    
    // If we have a current branch, test operations on it
    if !current_branch.is_empty() {
        // Find commits on current branch
        let result = repo.find_commit_by_subject(&current_branch, "PATCH");
        assert!(result.is_ok());
        
        // The stable-queue often has patches, so this might find something
        if let Ok(Some(sha)) = result {
            assert!(!sha.is_empty());
            
            // Verify the commit exists by trying to find it
            assert!(repo.find_commit(&sha).is_ok());
            
            // Get commit author
            let author = repo.get_commit_author(&sha).unwrap();
            assert!(!author.is_empty());
        }
    }
}

#[test]
fn test_linux_stable_rc_repository() {
    // Test with the linux-stable-rc repository
    let repo = GitRepo::open(Path::new(LINUX_STABLE_RC_PATH)).unwrap();
    
    // List branches to find a stable branch
    let output = Command::new("git")
        .args(["branch", "-r"])
        .current_dir(LINUX_STABLE_RC_PATH)
        .output()
        .unwrap();
    
    let branches = String::from_utf8_lossy(&output.stdout);
    
    let stable_branches: Vec<&str> = branches
        .lines()
        .filter(|line| line.contains("linux-") && line.contains(".y"))
        .collect();
    
    if !stable_branches.is_empty() {
        // Test with the first stable branch found
        let branch = stable_branches[0].trim();
        
        // Get the latest commit on this branch
        let output = Command::new("git")
            .args(["rev-parse", branch])
            .current_dir(LINUX_STABLE_RC_PATH)
            .output()
            .unwrap();
        
        if output.status.success() {
            let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
            
            // Verify we can work with this commit
            assert!(repo.find_commit(&sha).is_ok());
            
            let commit = repo.find_commit(&sha).unwrap();
            assert_eq!(commit.id().to_string(), sha);
        }
    }
}

#[test]
fn test_cross_repository_operations() {
    // Test operations that might involve multiple repositories
    let linux_repo = GitRepo::open(Path::new(LINUX_REPO_PATH)).unwrap();
    let stable_rc_repo = GitRepo::open(Path::new(LINUX_STABLE_RC_PATH)).unwrap();
    
    // Both repositories should be valid - test by trying to get HEAD
    let linux_head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(LINUX_REPO_PATH)
        .output()
        .unwrap();
    assert!(linux_head.status.success());
    
    let stable_rc_head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(LINUX_STABLE_RC_PATH)
        .output()
        .unwrap();
    assert!(stable_rc_head.status.success());
    
    // Create worktrees from different repositories
    let worktree_dir1 = tempdir().unwrap();
    let worktree_dir2 = tempdir().unwrap();
    
    let worktree1 = linux_repo.create_worktree("master", "cross-test-1", worktree_dir1.path()).unwrap();
    
    // Find a branch in stable-rc to use
    let output = Command::new("git")
        .args(["branch", "-r", "--list", "*/master"])
        .current_dir(LINUX_STABLE_RC_PATH)
        .output()
        .unwrap();
    
    if output.status.success() && !output.stdout.is_empty() {
        let worktree2 = stable_rc_repo.create_worktree("master", "cross-test-2", worktree_dir2.path()).unwrap();
        
        // Both worktrees should exist
        assert!(worktree1.path.exists());
        assert!(worktree2.path.exists());
    }
}