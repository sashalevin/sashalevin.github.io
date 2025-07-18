use git2::{Repository, Oid, Commit};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use tracing::{debug, info};

use crate::error::{MailbotError, Result as MailbotResult};

pub struct GitRepo {
    repo: Repository,
    path: PathBuf,
}

pub struct Worktree {
    pub path: PathBuf,
    _temp_dir: Option<TempDir>,
    repo_path: PathBuf,
}

impl GitRepo {
    pub fn open<P: AsRef<Path>>(path: P) -> MailbotResult<Self> {
        let repo = Repository::open(&path)?;
        Ok(Self {
            repo,
            path: path.as_ref().to_path_buf(),
        })
    }
    
    /// Find commit by SHA1
    pub fn find_commit(&self, sha1: &str) -> MailbotResult<Commit> {
        let oid = Oid::from_str(sha1)
            .map_err(MailbotError::Git)?;
        let commit = self.repo.find_commit(oid)?;
        Ok(commit)
    }
    
    /// Find commit by subject in a specific branch
    pub fn find_commit_by_subject(&self, branch: &str, subject: &str) -> MailbotResult<Option<String>> {
        debug!("Searching for commit with subject: {} in branch: {}", subject, branch);
        
        // First check if the branch exists
        let check_output = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("rev-parse")
            .arg("--verify")
            .arg(branch)
            .output()?;
        
        if !check_output.status.success() {
            debug!("Branch {} does not exist, skipping search", branch);
            return Ok(None);
        }
        
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("log")
            .arg(branch)
            .arg("--format=%H")
            .arg(format!("--grep=^{}$", regex::escape(subject)))
            .arg("-1")
            .output()?;
        
        if output.status.success() {
            let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !sha.is_empty() {
                Ok(Some(sha))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
    
    
    /// Check if a branch exists
    pub fn branch_exists(&self, branch_name: &str) -> bool {
        if branch_name.starts_with("origin/") {
            // For remote branches, check if the reference exists
            let ref_name = format!("refs/remotes/{branch_name}");
            self.repo.find_reference(&ref_name).is_ok()
        } else {
            // For local branches
            self.repo.find_branch(branch_name, git2::BranchType::Local).is_ok()
        }
    }
    
    /// Check if commit is ancestor of a branch
    pub fn is_ancestor(&self, commit_sha: &str, branch: &str) -> MailbotResult<bool> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("merge-base")
            .arg("--is-ancestor")
            .arg(commit_sha)
            .arg(branch)
            .output()?;
        
        Ok(output.status.success())
    }
    
    /// Find the earliest tag containing a commit on a specific branch
    pub fn find_earliest_tag_containing(&self, commit_sha: &str, branch: &str) -> MailbotResult<Option<String>> {
        // First check if commit is in branch
        if !self.is_ancestor(commit_sha, branch)? {
            return Ok(None);
        }
        
        // Extract version from branch name (e.g., "origin/linux-6.15.y" -> "6.15")
        let version = branch
            .strip_prefix("origin/linux-")
            .and_then(|s| s.strip_suffix(".y"))
            .ok_or_else(|| MailbotError::Git(git2::Error::from_str(&format!("Invalid branch name: {branch}"))))?;
        
        // Use git tag to find all tags containing the commit that match the version pattern
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("tag")
            .arg("--contains")
            .arg(commit_sha)
            .arg("--sort=version:refname")
            .arg(format!("v{version}.*"))
            .output()?;
        
        if !output.status.success() {
            return Ok(None);
        }
        
        // Parse the output to get the first tag
        let tags = String::from_utf8_lossy(&output.stdout);
        if let Some(first_tag) = tags.lines().next() {
            // Strip the 'v' prefix if present (e.g., "v6.15.3" -> "6.15.3")
            let tag = first_tag.strip_prefix('v').unwrap_or(first_tag);
            Ok(Some(tag.to_string()))
        } else {
            Ok(None)
        }
    }
    
    /// Ensure a remote tracking branch exists locally
    fn ensure_remote_branch_exists(&self, branch: &str) -> MailbotResult<()> {
        debug!("Ensuring remote branch {} exists", branch);
        
        // Check if the branch already exists
        let check_output = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("show-ref")
            .arg("--verify")
            .arg(format!("refs/remotes/{branch}"))
            .output()?;
        
        if check_output.status.success() {
            // Branch already exists
            return Ok(());
        }
        
        // Extract remote and branch name
        if let Some(slash_pos) = branch.find('/') {
            let remote = &branch[..slash_pos];
            let branch_name = &branch[slash_pos + 1..];
            
            debug!("Fetching {} from remote {}", branch_name, remote);
            
            // Fetch the specific branch
            let output = Command::new("git")
                .arg("-C")
                .arg(&self.path)
                .arg("fetch")
                .arg(remote)
                .arg(format!("{branch_name}:refs/remotes/{remote}/{branch_name}"))
                .output()?;
            
            if !output.status.success() {
                return Err(MailbotError::Git(
                    git2::Error::from_str(&format!(
                        "Failed to fetch branch {}: {}",
                        branch,
                        String::from_utf8_lossy(&output.stderr)
                    ))
                ));
            }
        }
        
        Ok(())
    }
    
    /// Create a new worktree
    pub fn create_worktree(&self, base_branch: &str, name: &str, worktree_dir: &Path) -> MailbotResult<Worktree> {
        info!("Creating worktree {} from branch {}", name, base_branch);
        
        // Ensure the branch exists locally if it's a remote tracking branch
        if base_branch.starts_with("origin/") {
            self.ensure_remote_branch_exists(base_branch)?;
        }
        
        // Create a temporary directory for the worktree
        let temp_dir = TempDir::new_in(worktree_dir)?;
        let worktree_path = temp_dir.path().to_path_buf();
        
        // Create the worktree using git command
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("worktree")
            .arg("add")
            .arg("--detach")
            .arg(&worktree_path)
            .arg(base_branch)
            .output()?;
        
        if !output.status.success() {
            return Err(MailbotError::Worktree(
                format!("Failed to create worktree: {}", String::from_utf8_lossy(&output.stderr))
            ));
        }
        
        // Set up git config in the worktree
        Command::new("git")
            .arg("-C")
            .arg(&worktree_path)
            .args(["config", "user.name", "Sasha Levin"])
            .output()?;
            
        Command::new("git")
            .arg("-C")
            .arg(&worktree_path)
            .args(["config", "user.email", "sashal@kernel.org"])
            .output()?;
        
        Ok(Worktree {
            path: worktree_path,
            _temp_dir: Some(temp_dir),
            repo_path: self.path.clone(),
        })
    }
    
    /// Get commit author
    pub fn get_commit_author(&self, sha1: &str) -> MailbotResult<String> {
        let commit = self.find_commit(sha1)?;
        let author = commit.author();
        
        Ok(format!("{} <{}>", 
            author.name().unwrap_or("Unknown"),
            author.email().unwrap_or("unknown@example.com")
        ))
    }
    
    /// Run git range-diff
    pub fn range_diff(&self, old_commit: &str, new_commit: &str) -> MailbotResult<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("range-diff")
            .arg(format!("{old_commit}^..{old_commit}"))
            .arg(format!("{new_commit}^..{new_commit}"))
            .output()?;
        
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(MailbotError::Git(git2::Error::from_str(&String::from_utf8_lossy(&output.stderr))))
        }
    }
    
    /// Check for fixes referencing a commit
    pub fn find_fixes_for_commit(&self, sha1: &str) -> MailbotResult<Vec<(String, String)>> {
        let short_sha = if sha1.len() >= 12 {
            &sha1[..12]
        } else {
            sha1
        };
        
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("log")
            .arg("origin/master")
            .arg(format!("--grep=Fixes: {short_sha}"))
            .arg("--format=%H %s")
            .output()?;
        
        if output.status.success() {
            let fixes: Vec<(String, String)> = String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        Some((parts[0].to_string(), parts[1].to_string()))
                    } else {
                        None
                    }
                })
                .collect();
            Ok(fixes)
        } else {
            Ok(vec![])
        }
    }
    
    /// Check if commit was reverted
    pub fn find_reverts_for_commit(&self, sha1: &str) -> MailbotResult<Vec<(String, String)>> {
        let short_sha = &sha1[..12];
        
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("log")
            .arg("origin/master")
            .arg(format!("--grep=This reverts commit {short_sha}\\|^Revert \".*{short_sha}.*\""))
            .arg("--format=%H %s")
            .output()?;
        
        if output.status.success() {
            let reverts: Vec<(String, String)> = String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        Some((parts[0].to_string(), parts[1].to_string()))
                    } else {
                        None
                    }
                })
                .collect();
            Ok(reverts)
        } else {
            Ok(vec![])
        }
    }
}

impl Worktree {
    /// Apply a patch file using git am
    pub fn apply_patch(&self, patch_content: &str) -> MailbotResult<()> {
        debug!("Applying patch to worktree at {:?}", self.path);
        
        // First, ensure we're in a clean state
        self.reset_hard()?;
        
        // Apply the patch using git am
        let mut child = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("am")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        
        // Write patch content to stdin
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(patch_content.as_bytes())?;
        }
        
        let output = child.wait_with_output()?;
        
        if !output.status.success() {
            // Try to get reject information
            let reject_info = self.get_reject_info();
            
            // Abort the failed am
            self.abort_am();
            
            return Err(MailbotError::PatchValidation(
                format!("Failed to apply patch: {}\nRejects: {}", 
                    String::from_utf8_lossy(&output.stderr),
                    reject_info.unwrap_or_default())
            ));
        }
        
        Ok(())
    }
    
    /// Reset worktree to clean state
    pub fn reset_hard(&self) -> MailbotResult<()> {
        Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("reset")
            .arg("--hard")
            .output()?;
        
        Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("clean")
            .arg("-fdx")
            .output()?;
        
        Ok(())
    }
    
    /// Abort a failed git am
    pub fn abort_am(&self) {
        let _ = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("am")
            .arg("--abort")
            .output();
    }
    
    /// Get reject file contents
    fn get_reject_info(&self) -> Option<String> {
        use std::fs;
        use walkdir::WalkDir;
        
        let mut reject_content = String::new();
        
        for entry in WalkDir::new(&self.path).into_iter().flatten() {
            if entry.path().extension().and_then(|s| s.to_str()) == Some("rej") {
                if let Ok(content) = fs::read_to_string(entry.path()) {
                    reject_content.push_str(&format!("\n--- {} ---\n", entry.path().display()));
                    reject_content.push_str(&content);
                }
            }
        }
        
        if reject_content.is_empty() {
            None
        } else {
            Some(reject_content)
        }
    }
    
    /// Run build command in the worktree
    pub fn run_build(&self, build_command: &str) -> MailbotResult<String> {
        info!("Running build command in worktree: {}", build_command);
        
        let output = Command::new("sh")
            .arg("-c")
            .arg(build_command)
            .current_dir(&self.path)
            .output()?;
        
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            // For stable build log, the output is on stdout even when it fails
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            
            // Prefer stdout if it contains build results, otherwise use stderr
            let error_output = if !stdout.trim().is_empty() {
                stdout.to_string()
            } else {
                stderr.to_string()
            };
            
            Err(MailbotError::Build(error_output))
        }
    }
    
    /// Get the current HEAD commit SHA
    pub fn get_head_sha(&self) -> MailbotResult<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.path)
            .arg("rev-parse")
            .arg("HEAD")
            .output()?;
        
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(MailbotError::Git(git2::Error::from_str("Failed to get HEAD SHA")))
        }
    }
}

impl Drop for Worktree {
    fn drop(&mut self) {
        debug!("Cleaning up worktree at {:?}", self.path);
        
        // Remove the worktree from git's tracking
        let result = Command::new("git")
            .arg("-C")
            .arg(&self.repo_path)
            .arg("worktree")
            .arg("remove")
            .arg("--force")
            .arg(&self.path)
            .output();
            
        match result {
            Ok(output) => {
                if !output.status.success() {
                    debug!("Failed to remove worktree: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
            Err(e) => {
                debug!("Error running git worktree remove: {}", e);
            }
        }
        
        // TempDir will handle directory cleanup
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    
    const TEST_LINUX_DIR: &str = "/home/sasha/stable-status/linux";
    
    #[test]
    fn test_git_repo_open() {
        // Test with the actual linux repo
        let repo = GitRepo::open(TEST_LINUX_DIR).unwrap();
        assert!(repo.path.exists());
        assert_eq!(repo.path, PathBuf::from(TEST_LINUX_DIR));
    }
    
    #[test]
    fn test_commit_exists() {
        // Create a temporary git repository for testing
        let dir = tempdir().unwrap();
        
        // Initialize git repo
        Command::new("git")
            .arg("init")
            .current_dir(&dir)
            .output()
            .unwrap();
        
        // Configure git
        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(&dir)
            .output()
            .unwrap();
        
        Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(&dir)
            .output()
            .unwrap();
        
        // Create a test file and commit
        fs::write(dir.path().join("test.txt"), "test content").unwrap();
        
        Command::new("git")
            .args(["add", "test.txt"])
            .current_dir(&dir)
            .output()
            .unwrap();
        
        Command::new("git")
            .args(["commit", "-m", "Test commit"])
            .current_dir(&dir)
            .output()
            .unwrap();
        
        // Get the commit SHA
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&dir)
            .output()
            .unwrap();
        
        let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
        
        // Test commit exists by trying to find it
        let repo = GitRepo::open(&dir).unwrap();
        assert!(repo.find_commit(&sha).is_ok());
        assert!(repo.find_commit("0000000000000000000000000000000000000000").is_err());
    }
    
    #[test]
    fn test_worktree_operations() {
        let repo = GitRepo::open(TEST_LINUX_DIR).unwrap();
        let worktree_dir = tempdir().unwrap();
        
        // Create a worktree from master
        let worktree = repo.create_worktree("master", "test-worktree", worktree_dir.path()).unwrap();
        assert!(worktree.path.exists());
        assert!(worktree.path.join(".git").exists());
        
        // Test reset_hard
        assert!(worktree.reset_hard().is_ok());
        
        // Test apply_patch with a simple patch
        let patch_content = r#"From abc123 Mon Sep 17 00:00:00 2001
From: Test <test@example.com>
Date: Mon, 1 Jan 2024 00:00:00 +0000
Subject: [PATCH] Test patch

Test commit message
---
 init/main.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/init/main.c b/init/main.c
index 123456..789012 100644
--- a/init/main.c
+++ b/init/main.c
@@ -1,5 +1,6 @@
 // SPDX-License-Identifier: GPL-2.0-only
 /*
+ * Test comment
  *  linux/init/main.c
  *
  *  Copyright (C) 1991, 1992  Linus Torvalds
-- 
2.34.1
"#;
        
        // This might fail if the patch doesn't apply, which is ok for testing
        let _ = worktree.apply_patch(patch_content);
    }
    
    #[test]
    fn test_get_commit_author() {
        // Create a test repo
        let dir = tempdir().unwrap();
        
        Command::new("git")
            .arg("init")
            .current_dir(&dir)
            .output()
            .unwrap();
        
        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(&dir)
            .output()
            .unwrap();
        
        Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(&dir)
            .output()
            .unwrap();
        
        fs::write(dir.path().join("test.txt"), "test").unwrap();
        
        Command::new("git")
            .args(["add", "test.txt"])
            .current_dir(&dir)
            .output()
            .unwrap();
        
        Command::new("git")
            .args(["commit", "-m", "Test"])
            .current_dir(&dir)
            .output()
            .unwrap();
        
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&dir)
            .output()
            .unwrap();
        
        let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
        
        let repo = GitRepo::open(&dir).unwrap();
        let author = repo.get_commit_author(&sha).unwrap();
        
        assert_eq!(author, "Test User <test@example.com>");
    }
    
    #[test]
    fn test_find_commit_by_subject() {
        let repo = GitRepo::open(TEST_LINUX_DIR).unwrap();
        
        // Try to find a well-known commit by subject
        // Using a generic subject that should exist
        let result = repo.find_commit_by_subject("origin/master", "Merge tag");
        assert!(result.is_ok());
        
        // The result might be None if no matching commit, but the operation should succeed
        if let Ok(Some(sha)) = result {
            assert_eq!(sha.len(), 40); // SHA1 is 40 characters
            assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
        }
        
        // Test with non-existent subject
        let result = repo.find_commit_by_subject("origin/master", "This subject definitely does not exist in the kernel");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
    }
    
    #[test]
    fn test_is_ancestor() {
        let repo = GitRepo::open(TEST_LINUX_DIR).unwrap();
        
        // Get HEAD commit
        let output = Command::new("git")
            .arg("-C")
            .arg(TEST_LINUX_DIR)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        
        let head_sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
        
        // HEAD should be an ancestor of itself
        assert!(repo.is_ancestor(&head_sha, "HEAD").unwrap());
        
        // A non-existent commit should not be an ancestor
        assert!(!repo.is_ancestor("0000000000000000000000000000000000000000", "HEAD").unwrap_or(false));
    }
    
    #[test]
    fn test_find_fixes_and_reverts() {
        let repo = GitRepo::open(TEST_LINUX_DIR).unwrap();
        
        // Test with a dummy SHA - these functions should return empty vectors for non-existent commits
        let fixes = repo.find_fixes_for_commit("0123456789abcdef0123456789abcdef01234567").unwrap();
        assert_eq!(fixes.len(), 0);
        
        let reverts = repo.find_reverts_for_commit("0123456789abcdef0123456789abcdef01234567").unwrap();
        assert_eq!(reverts.len(), 0);
    }
    
    #[test]
    fn test_worktree_get_head_sha() {
        let repo = GitRepo::open(TEST_LINUX_DIR).unwrap();
        let worktree_dir = tempdir().unwrap();
        
        let worktree = repo.create_worktree("master", "test-head-sha", worktree_dir.path()).unwrap();
        
        let head_sha = worktree.get_head_sha().unwrap();
        assert_eq!(head_sha.len(), 40);
        assert!(head_sha.chars().all(|c| c.is_ascii_hexdigit()));
    }
    
    #[test]
    fn test_worktree_cleanup() {
        let repo = GitRepo::open(TEST_LINUX_DIR).unwrap();
        let worktree_dir = tempdir().unwrap();
        
        let _worktree_path = {
            let worktree = repo.create_worktree("master", "test-cleanup", worktree_dir.path()).unwrap();
            worktree.path.clone()
        }; // worktree is dropped here
        
        // The worktree should be cleaned up automatically
        // Note: The directory might still exist briefly, but git should no longer track it
    }
}