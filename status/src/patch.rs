use regex::Regex;
use std::sync::Arc;
use tracing::{debug, info, warn};
use lazy_static::lazy_static;

use crate::config::Config;
use crate::email::LeiEmail;
use crate::error::Result as MailbotResult;
use crate::git::GitRepo;
use crate::kernel::{KernelVersion, KernelVersionManager};
use crate::response::{ResponseBuilder, TestResult, PatchStatus};
use crate::series::SeriesManager;

lazy_static! {
    static ref SHA1_PATTERN: Regex = Regex::new(r"[0-9a-f]{40}").unwrap();
    static ref COMMIT_UPSTREAM_PATTERN: Regex = Regex::new(r"(?i)commit ([0-9a-f]{40}) upstream").unwrap();
    static ref UPSTREAM_COMMIT_PATTERN: Regex = Regex::new(r"(?i)\[\s*upstream\s+commit\s+([0-9a-f]{40})\s*\]").unwrap();
}

pub struct PatchProcessor {
    config: Arc<Config>,
    git_repo: GitRepo,
    kernel_manager: KernelVersionManager,
    series_manager: SeriesManager,
}

pub struct PatchInfo {
    pub email: LeiEmail,
    pub claimed_sha1: Option<String>,
    pub found_sha1: Option<String>,
    pub author_mismatch: Option<String>,
    pub series_info: Option<(u32, u32)>,
    pub target_versions: Vec<KernelVersion>,
}

impl PatchProcessor {
    pub fn new(config: Config) -> MailbotResult<Self> {
        let git_repo = GitRepo::open(&config.linux_dir)?;
        let kernel_manager = KernelVersionManager::load(&config.active_versions_file)?;
        let series_manager = SeriesManager::new(config.pending_dir.clone());
        
        Ok(Self {
            config: Arc::new(config),
            git_repo,
            kernel_manager,
            series_manager,
        })
    }
    
    /// Process a single email containing a patch
    pub async fn process_email(&self, email: LeiEmail) -> MailbotResult<()> {
        // Skip emails with empty subjects
        if email.subject.is_empty() {
            warn!("Skipping email with empty subject");
            return Ok(());
        }
        
        info!("Processing email: {}", email.subject);
        
        // Extract patch information
        let patch_info = self.extract_patch_info(email)?;
        
        // Skip if no SHA1 and no specific kernel versions (matching mailbot.sh behavior)
        if patch_info.found_sha1.is_none() && patch_info.claimed_sha1.is_none() && patch_info.target_versions.is_empty() {
            info!("No commit SHA1 found and no specific kernel versions in subject. Skipping patch.");
            return Ok(());
        }
        
        // If we have no specific versions but have a SHA1, use all active versions
        let mut patch_info = patch_info;
        if patch_info.target_versions.is_empty() && (patch_info.found_sha1.is_some() || patch_info.claimed_sha1.is_some()) {
            patch_info.target_versions = self.kernel_manager.default_versions();
        }
        
        // Handle series if applicable
        if let Some((current, total)) = patch_info.series_info {
            if current == 0 {
                info!("Skipping 0/{} patch", total);
                return Ok(());
            }
            
            // Store patch in series
            self.series_manager.store_patch(&patch_info.email, current, total)?;
            
            // Check if series is complete
            if self.series_manager.is_series_complete(&patch_info.email, total)? {
                info!("Series complete, processing all {} patches", total);
                return self.process_complete_series(&patch_info.email, total).await;
            } else {
                info!("Series incomplete, waiting for remaining patches");
                return Ok(());
            }
        }
        
        // Process single patch
        self.process_single_patch(patch_info).await
    }
    
    /// Extract patch information from email
    fn extract_patch_info(&self, email: LeiEmail) -> MailbotResult<PatchInfo> {
        // Extract SHA1 from email body
        let claimed_sha1 = self.extract_commit_sha1(&email.body);
        
        // Try to find the commit
        let found_sha1 = if let Some(ref sha) = claimed_sha1 {
            if self.git_repo.commit_exists(sha) {
                Some(sha.clone())
            } else {
                self.find_commit_by_subject(&email.clean_subject())?
            }
        } else {
            self.find_commit_by_subject(&email.clean_subject())?
        };
        
        // Check for author mismatch
        let author_mismatch = if let Some(ref sha) = found_sha1 {
            self.check_author_mismatch(&email, sha)?
        } else {
            None
        };
        
        // Extract series info
        let series_info = email.extract_series_info();
        
        // Extract target kernel versions
        let target_versions = self.kernel_manager.extract_versions_from_subject(&email.subject);
        
        Ok(PatchInfo {
            email,
            claimed_sha1,
            found_sha1,
            author_mismatch,
            series_info,
            target_versions,
        })
    }
    
    /// Process a single patch
    async fn process_single_patch(&self, patch_info: PatchInfo) -> MailbotResult<()> {
        let mut response_builder = ResponseBuilder::new(&patch_info.email, &self.config);
        
        // Add patch validation info
        response_builder.set_commit_info(
            patch_info.claimed_sha1.clone(),
            patch_info.found_sha1.clone(),
            patch_info.author_mismatch.clone(),
        );
        
        // Test patch on each target version
        let results = self.test_patch_on_versions(&patch_info).await?;
        for result in results {
            response_builder.add_test_result(result);
        }
        
        // Check for newer kernel status if we have a valid SHA1
        if let Some(ref sha) = patch_info.found_sha1 {
            let newer_results = self.check_newer_kernels(sha, &patch_info.target_versions)?;
            response_builder.set_newer_kernel_results(newer_results);
            
            // Check for fixes and reverts
            let fixes = self.git_repo.find_fixes_for_commit(sha)?;
            let reverts = self.git_repo.find_reverts_for_commit(sha)?;
            
            if !fixes.is_empty() {
                response_builder.set_fixes(fixes);
            }
            
            if !reverts.is_empty() {
                response_builder.set_reverts(reverts);
            }
            
            // Generate diff with upstream if possible
            if let Some(diff) = self.generate_upstream_diff(&patch_info, sha)? {
                response_builder.set_diff_output(diff);
            }
        }
        
        // Generate and save response
        let response = response_builder.build()?;
        response.save(&self.config.output_dir)?;
        
        // Send email if not in dry-run mode
        if !self.config.debug {
            response.send(&self.config.email)?;
        }
        
        Ok(())
    }
    
    /// Process a complete patch series
    async fn process_complete_series(&self, first_email: &LeiEmail, total: u32) -> MailbotResult<()> {
        info!("Processing complete series of {} patches", total);
        
        // Get all patches in the series
        let patches = self.series_manager.get_series_patches(first_email, total)?;
        
        // Test the series on each target version
        for patch in patches {
            self.process_single_patch(patch).await?;
        }
        
        // Clean up series directory
        self.series_manager.cleanup_series(first_email)?;
        
        Ok(())
    }
    
    /// Convert email body to proper git-format-patch format
    fn format_patch_content(email: &LeiEmail) -> String {
        let mut formatted = String::new();
        
        // Add proper git-format-patch header
        formatted.push_str(&format!("From {} Mon Sep 17 00:00:00 2001\n", "0000000000000000000000000000000000000000"));
        formatted.push_str(&format!("From: {}\n", email.from));
        formatted.push_str(&format!("Date: {}\n", email.date));
        formatted.push_str(&format!("Subject: {}\n", email.subject));
        formatted.push('\n');
        
        // Add the body
        formatted.push_str(&email.body);
        
        // Ensure it ends with signature line
        if !email.body.contains("\n-- \n") && !email.body.contains("\n---\n") {
            formatted.push_str("\n-- \n2.34.1\n");
        }
        
        formatted
    }
    
    /// Test patch on multiple kernel versions
    async fn test_patch_on_versions(&self, patch_info: &PatchInfo) -> MailbotResult<Vec<TestResult>> {
        let config = Arc::clone(&self.config);
        let patch_content = Self::format_patch_content(&patch_info.email);
        let mut results = Vec::new();
        
        // Test sequentially
        for version in &patch_info.target_versions {
            let result = self.test_patch_on_version(version, &patch_content, &config);
            results.push(result);
        }
        
        Ok(results)
    }
    
    /// Test patch on a single kernel version
    fn test_patch_on_version(
        &self, 
        version: &KernelVersion, 
        patch_content: &str,
        config: &Arc<Config>
    ) -> TestResult {
        let branch = version.stable_branch();
        debug!("Testing patch on branch: {}", branch);
        
        // Create worktree for testing
        let worktree_result = self.git_repo.create_worktree(&branch, 
            &format!("test-{}-{}", version, chrono::Utc::now().timestamp()),
            &config.worktree_dir
        );
        
        let mut result = TestResult {
            branch: branch.clone(),
            patch_status: PatchStatus::Failed,
            build_status: None,
            error: None,
        };
        
        let worktree = match worktree_result {
            Ok(wt) => wt,
            Err(e) => {
                result.error = Some(format!("Failed to create worktree: {e}"));
                return result;
            }
        };
        
        // Apply patch
        match worktree.apply_patch(patch_content) {
            Ok(_) => {
                result.patch_status = PatchStatus::Success;
                
                // Run build test if not skipped
                if !config.debug {
                    match worktree.run_build(&config.build_command) {
                        Ok(_) => {
                            result.build_status = Some(true);
                        }
                        Err(e) => {
                            result.build_status = Some(false);
                            result.error = Some(format!("Build failed: {e}"));
                        }
                    }
                }
            }
            Err(e) => {
                result.error = Some(format!("Patch failed to apply: {e}"));
            }
        }
        
        result
    }
    
    /// Extract commit SHA1 from email body
    fn extract_commit_sha1(&self, body: &str) -> Option<String> {
        // Try commit X upstream pattern
        if let Some(captures) = COMMIT_UPSTREAM_PATTERN.captures(body) {
            return Some(captures.get(1).unwrap().as_str().to_string());
        }
        
        // Try [Upstream commit X] pattern
        if let Some(captures) = UPSTREAM_COMMIT_PATTERN.captures(body) {
            return Some(captures.get(1).unwrap().as_str().to_string());
        }
        
        None
    }
    
    /// Find commit by subject
    fn find_commit_by_subject(&self, subject: &str) -> MailbotResult<Option<String>> {
        self.git_repo.find_commit_by_subject("origin/master", subject)
    }
    
    /// Check for author mismatch
    fn check_author_mismatch(&self, email: &LeiEmail, sha: &str) -> MailbotResult<Option<String>> {
        let patch_author = email.normalized_from();
        let commit_author = self.git_repo.get_commit_author(sha)?;
        
        if !self.authors_match(&patch_author, &commit_author) {
            Ok(Some(format!(
                "Backport author: {patch_author}\nCommit author: {commit_author}"
            )))
        } else {
            Ok(None)
        }
    }
    
    /// Check if two authors match (comparing email addresses)
    fn authors_match(&self, author1: &str, author2: &str) -> bool {
        // Extract email addresses
        let email1 = extract_email(author1);
        let email2 = extract_email(author2);
        
        match (email1, email2) {
            (Some(e1), Some(e2)) => e1 == e2,
            _ => author1 == author2,
        }
    }
    
    /// Check status in newer kernels
    fn check_newer_kernels(
        &self,
        sha: &str,
        target_versions: &[KernelVersion]
    ) -> MailbotResult<Vec<String>> {
        if target_versions.is_empty() {
            return Ok(vec![]);
        }
        
        let newest_target = target_versions.iter().max().unwrap();
        let newer_versions = self.kernel_manager.get_newer_versions(newest_target);
        
        let mut results = vec![];
        for version in newer_versions {
            let stable_branch = version.stable_branch();
            
            let status = if self.git_repo.is_ancestor(sha, &stable_branch).unwrap_or(false) {
                format!("{version}.y | Present (exact SHA1)")
            } else {
                // Try to find by subject
                if let Some(subject) = self.get_commit_subject(sha)? {
                    // Check stable branch first
                    if let Ok(Some(found_sha)) = self.git_repo.find_commit_by_subject(&stable_branch, &subject) {
                        format!("{}.y | Present (different SHA1: {})", version, &found_sha[..12])
                    } else {
                        // Check if patch exists in queue directory
                        if self.check_queue_for_patch(&subject, &version) {
                            format!("{version}.y | In queue")
                        } else {
                            format!("{version}.y | Not found")
                        }
                    }
                } else {
                    format!("{version}.y | Not found")
                }
            };
            results.push(status);
        }
        
        Ok(results)
    }
    
    /// Check if patch exists in stable-queue directory for a version
    fn check_queue_for_patch(&self, subject: &str, version: &KernelVersion) -> bool {
        let queue_dir = self.config.stable_queue_dir.parent()
            .map(|p| p.join(format!("queue-{}.{}", version.major, version.minor)));
            
        if let Some(queue_path) = queue_dir {
            if queue_path.exists() {
                // Simple check - look for files containing the subject
                if let Ok(entries) = std::fs::read_dir(&queue_path) {
                    for entry in entries.flatten() {
                        if let Ok(content) = std::fs::read_to_string(entry.path()) {
                            if content.contains(subject) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }
    
    /// Get commit subject
    fn get_commit_subject(&self, sha: &str) -> MailbotResult<Option<String>> {
        let commit = self.git_repo.find_commit(sha)?;
        Ok(commit.summary().map(|s| s.to_string()))
    }
    
    /// Generate diff with upstream commit
    fn generate_upstream_diff(&self, patch_info: &PatchInfo, sha: &str) -> MailbotResult<Option<String>> {
        if patch_info.target_versions.is_empty() {
            return Ok(None);
        }
        
        // Use the newest version for comparison
        let version = patch_info.target_versions.iter().max().unwrap();
        let branch = version.stable_branch();
        
        // Create a temporary worktree
        let worktree = self.git_repo.create_worktree(
            &branch,
            &format!("diff-{}-{}", version, chrono::Utc::now().timestamp()),
            &self.config.worktree_dir
        )?;
        
        // Apply the patch with proper formatting
        let patch_content = Self::format_patch_content(&patch_info.email);
        if worktree.apply_patch(&patch_content).is_ok() {
            let new_sha = worktree.get_head_sha()?;
            match self.git_repo.range_diff(sha, &new_sha) {
                Ok(diff) => Ok(Some(diff)),
                Err(_) => Ok(Some("Note: Could not generate diff with upstream commit".to_string())),
            }
        } else {
            Ok(Some("Note: Could not generate diff - patch failed to apply for comparison".to_string()))
        }
    }
}

fn extract_email(author: &str) -> Option<String> {
    if let Some(start) = author.find('<') {
        if let Some(end) = author.find('>') {
            return Some(author[start + 1..end].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    use std::path::PathBuf;
    
    #[test]
    fn test_extract_email() {
        assert_eq!(
            extract_email("John Doe <john@example.com>"),
            Some("john@example.com".to_string())
        );
        
        assert_eq!(extract_email("john@example.com"), None);
        assert_eq!(extract_email("Just a name"), None);
        assert_eq!(
            extract_email("<only@email.com>"),
            Some("only@email.com".to_string())
        );
    }
    
    #[test]
    fn test_extract_commit_sha1() {
        let test_dir = tempdir().unwrap();
        let config = create_test_config(&test_dir);
        let processor = PatchProcessor::new(config).unwrap();
        
        // Test "commit X upstream" pattern
        let body1 = "Some text\ncommit abcdef1234567890abcdef1234567890abcdef12 upstream\nMore text";
        assert_eq!(
            processor.extract_commit_sha1(body1),
            Some("abcdef1234567890abcdef1234567890abcdef12".to_string())
        );
        
        // Test "[ Upstream commit X ]" pattern
        let body2 = "Patch description\n[ Upstream commit fedcba0987654321fedcba0987654321fedcba09 ]\nMore";
        assert_eq!(
            processor.extract_commit_sha1(body2),
            Some("fedcba0987654321fedcba0987654321fedcba09".to_string())
        );
        
        // Test case insensitive
        let body3 = "COMMIT ABCDEF1234567890ABCDEF1234567890ABCDEF12 UPSTREAM";
        assert_eq!(
            processor.extract_commit_sha1(body3),
            Some("ABCDEF1234567890ABCDEF1234567890ABCDEF12".to_string())
        );
        
        // Test no SHA1
        let body4 = "Just a regular patch description without SHA";
        assert_eq!(processor.extract_commit_sha1(body4), None);
    }
    
    #[test]
    fn test_authors_match() {
        let test_dir = tempdir().unwrap();
        let config = create_test_config(&test_dir);
        let processor = PatchProcessor::new(config).unwrap();
        
        // Same email addresses should match
        assert!(processor.authors_match(
            "John Doe <john@example.com>",
            "John D. <john@example.com>"
        ));
        
        // Different emails should not match
        assert!(!processor.authors_match(
            "John Doe <john@example.com>",
            "Jane Doe <jane@example.com>"
        ));
        
        // Same full string should match
        assert!(processor.authors_match(
            "John Doe <john@example.com>",
            "John Doe <john@example.com>"
        ));
        
        // Handle UTF-8 names
        assert!(processor.authors_match(
            "José García <jose@example.com>",
            "Jose Garcia <jose@example.com>"
        ));
    }
    
    #[test]
    fn test_patch_info_extraction() {
        let test_dir = tempdir().unwrap();
        let config = create_test_config(&test_dir);
        let processor = PatchProcessor::new(config).unwrap();
        
        // Test single patch
        let email = LeiEmail {
            subject: "[PATCH 5.10] Fix bug".to_string(),
            from: "Dev <dev@example.com>".to_string(),
            message_id: "<test@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "Fix description\ncommit abcdef1234567890abcdef1234567890abcdef12 upstream".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        
        let patch_info = processor.extract_patch_info(email).unwrap();
        assert!(patch_info.claimed_sha1.is_some());
        assert_eq!(patch_info.series_info, None);
        assert!(!patch_info.target_versions.is_empty());
    }
    
    #[test]
    fn test_series_detection() {
        let test_dir = tempdir().unwrap();
        let config = create_test_config(&test_dir);
        let processor = PatchProcessor::new(config).unwrap();
        
        // Test series patch
        let email = LeiEmail {
            subject: "[PATCH v2 3/5] mm: Fix memory leak".to_string(),
            from: "Dev <dev@example.com>".to_string(),
            message_id: "<part3@example.com>".to_string(),
            in_reply_to: Some("<cover@example.com>".to_string()),
            date: "2024-01-01".to_string(),
            body: "Patch content".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        
        let patch_info = processor.extract_patch_info(email).unwrap();
        assert_eq!(patch_info.series_info, Some((3, 5)));
    }
    
    fn create_test_config(test_dir: &tempfile::TempDir) -> Config {
        let versions_file = test_dir.path().join("versions");
        fs::write(&versions_file, "5.10\n5.15\n6.1\n").unwrap();
        
        Config {
            linux_dir: PathBuf::from("/home/sasha/stable-status/linux"),
            stable_queue_dir: PathBuf::from("/home/sasha/stable-status/stable-queue"),
            active_versions_file: versions_file,
            pending_dir: test_dir.path().join("pending"),
            worktree_dir: test_dir.path().join("worktrees"),
            output_dir: test_dir.path().join("output"),
            ignored_authors: vec![],
            email: crate::config::EmailConfig {
                from: "Bot <bot@test.com>".to_string(),
                reply_to: None,
                smtp: None,
            },
            build_command: "true".to_string(),
            debug: true,
        }
    }
}