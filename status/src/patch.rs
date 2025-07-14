use regex::Regex;
use std::sync::Arc;
use std::fs;
use tracing::{debug, info, warn, error};
use lazy_static::lazy_static;

use crate::config::Config;
use crate::email::LeiEmail;
use crate::error::Result as MailbotResult;
use crate::git::GitRepo;
use crate::kernel::{KernelVersion, KernelVersionManager};
use crate::response::{ResponseBuilder, TestResult, PatchStatus};
use crate::series::SeriesManager;
use crate::tracking::{TrackingStore, PatchTracking, PatchState, ProcessingEvent, ProcessingEventType, MailingListActivity, MailingListMessage, MessageType, message_id_to_lore_url};
use chrono::Utc;

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
    tracking_store: Arc<std::sync::Mutex<TrackingStore>>,
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
        
        // Load or create tracking store
        let tracking_path = config.tracking_file.clone();
        
        // Ensure the parent directory exists
        if let Some(parent) = tracking_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        
        let tracking_store = TrackingStore::load_from_file(&tracking_path)
            .unwrap_or_else(|_| TrackingStore::new());
        
        Ok(Self {
            config: Arc::new(config),
            git_repo,
            kernel_manager,
            series_manager,
            tracking_store: Arc::new(std::sync::Mutex::new(tracking_store)),
        })
    }
    
    /// Process a single email containing a patch
    pub async fn process_email(&self, email: LeiEmail) -> MailbotResult<()> {
        // Skip emails with empty subjects
        if email.subject.is_empty() {
            warn!("Skipping email with empty subject");
            return Ok(());
        }
        
        // Check if we already have a response for this email
        if self.response_already_exists(&email.message_id) {
            info!("Response already exists for email: {}. Skipping.", email.subject);
            return Ok(());
        }
        
        info!("Processing email: {}", email.subject);
        
        // Extract patch information first
        let patch_info = self.extract_patch_info(email)?;
        
        // Check if there are specific kernel versions in the subject
        let has_specific_versions = !patch_info.target_versions.is_empty() && 
            patch_info.target_versions != self.kernel_manager.default_versions();
        
        // Skip if no SHA1 and no specific kernel versions (matching mailbot.sh behavior)
        // This matches mailbot.sh lines 1520-1524
        if patch_info.found_sha1.is_none() && patch_info.claimed_sha1.is_none() && !has_specific_versions {
            info!("No commit SHA1 found and no specific kernel versions in subject. Skipping patch.");
            return Ok(());
        }
        
        // Create or update tracking entry now that we know we'll process it
        {
            let mut store = self.tracking_store.lock().unwrap();
            
            if store.get_patch(&patch_info.email.message_id).is_none() {
                // New patch, create tracking entry
                let tracking = PatchTracking {
                    message_id: patch_info.email.message_id.clone(),
                    sha1: patch_info.found_sha1.clone().or(patch_info.claimed_sha1.clone()),
                    subject: patch_info.email.subject.clone(),
                    author: patch_info.email.from.clone(),
                    from_email: patch_info.email.from.clone(),
                    first_seen: Utc::now(),
                    last_updated: Utc::now(),
                    state: PatchState::OnMailingList,
                    processing_history: vec![ProcessingEvent {
                        timestamp: Utc::now(),
                        event_type: ProcessingEventType::Received,
                        details: "Patch received on mailing list".to_string(),
                    }],
                    mailbot_results: vec![],
                    mailing_list_activity: MailingListActivity {
                        replies: vec![],
                        reviews: vec![],
                        related_patches: vec![],
                        fixes_commit: None,
                        fixes_cve: None,
                    },
                    target_versions: patch_info.target_versions.iter()
                        .map(|v| v.to_string())
                        .collect(),
                    lore_url: Some(message_id_to_lore_url(&patch_info.email.message_id)),
                };
                store.add_or_update_patch(tracking);
            }
            
            // Update state to processing
            store.update_state(&patch_info.email.message_id, PatchState::Processing).ok();
            store.add_processing_event(&patch_info.email.message_id, ProcessingEvent {
                timestamp: Utc::now(),
                event_type: ProcessingEventType::ProcessingStarted,
                details: "Starting patch processing".to_string(),
            }).ok();
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
        
        // Processing has already started, no need to update state again
        
        // Process single patch
        let result = self.process_single_patch(patch_info).await;
        
        // Save tracking store after processing
        self.save_tracking_store();
        
        result
    }
    
    /// Extract patch information from email
    fn extract_patch_info(&self, email: LeiEmail) -> MailbotResult<PatchInfo> {
        // Extract SHA1 from email body
        let claimed_sha1 = self.extract_commit_sha1(&email.body);
        
        // Try to find the commit - this matches mailbot.sh logic (lines 1510-1518)
        let found_sha1 = if let Some(ref sha) = claimed_sha1 {
            // Validate the claimed SHA1
            if self.git_repo.is_ancestor(sha, "origin/master").unwrap_or(false) {
                Some(sha.clone())
            } else {
                // Claimed SHA doesn't validate, try to find by subject
                self.find_commit_by_subject(&email.clean_subject())?
            }
        } else {
            // No claimed SHA, try to find by subject
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
        
        // Create mailbot result for tracking
        let test_branches: Vec<String> = results.iter().map(|r| r.branch.clone()).collect();
        let test_passed = results.iter().all(|r| matches!(r.patch_status, PatchStatus::Success));
        let build_passed = results.iter().all(|r| !matches!(r.build_passed, Some(false)));
        let errors: Vec<String> = results.iter()
            .filter_map(|r| r.error.as_ref().map(|e| format!("{}: {}", r.branch, e)))
            .collect();
        
        // Store mailbot result in tracking
        {
            let mut store = self.tracking_store.lock().unwrap();
            let mailbot_result = crate::tracking::MailbotResult {
                timestamp: Utc::now(),
                test_branches,
                test_passed,
                build_passed,
                errors,
                response_sent: false, // Will be updated after sending
                response_message_id: None,
            };
            
            if let Some(patch) = store.get_patch_mut(&patch_info.email.message_id) {
                patch.mailbot_results.push(mailbot_result);
            }
        }
        
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
        
        // Update tracking with response info
        {
            let mut store = self.tracking_store.lock().unwrap();
            store.add_processing_event(&patch_info.email.message_id, ProcessingEvent {
                timestamp: Utc::now(),
                event_type: ProcessingEventType::ResponseGenerated,
                details: "Response generated".to_string(),
            }).ok();
            
            // Update mailbot result to show response was sent
            if let Some(patch) = store.get_patch_mut(&patch_info.email.message_id) {
                if let Some(last_result) = patch.mailbot_results.last_mut() {
                    last_result.response_sent = true;
                }
            }
            
            // Update state based on test results
            let all_passed = response_builder.all_tests_passed();
            if all_passed {
                store.update_state(&patch_info.email.message_id, PatchState::TestsPassed).ok();
                store.add_processing_event(&patch_info.email.message_id, ProcessingEvent {
                    timestamp: Utc::now(),
                    event_type: ProcessingEventType::TestCompleted,
                    details: "All tests passed successfully".to_string(),
                }).ok();
            } else {
                let error_msg = response_builder.get_test_errors().join("; ");
                store.update_state(&patch_info.email.message_id, PatchState::IssuesFound(error_msg.clone())).ok();
                store.add_processing_event(&patch_info.email.message_id, ProcessingEvent {
                    timestamp: Utc::now(),
                    event_type: ProcessingEventType::TestCompleted,
                    details: format!("Issues found: {}", error_msg),
                }).ok();
            }
        }
        
        // Send email if not in dry-run mode
        if !self.config.dry_run {
            response.send(&self.config.email)?;
        }
        
        Ok(())
    }
    
    /// Save tracking store to disk
    fn save_tracking_store(&self) {
        let tracking_path = &self.config.tracking_file;
        
        // Ensure the parent directory exists
        if let Some(parent) = tracking_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                warn!("Failed to create tracking directory: {}", e);
                return;
            }
        }
        
        let store = self.tracking_store.lock().unwrap();
        if let Err(e) = store.save_to_file(tracking_path) {
            warn!("Failed to save tracking store: {}", e);
        }
    }
    
    /// Process an email that might be a reply or comment to an existing patch
    pub async fn process_reply_or_comment(&self, email: LeiEmail) -> MailbotResult<bool> {
        // First check if this is a FAILED email
        let message_type = determine_message_type(&email);
        let is_failed_email = matches!(message_type, MessageType::FailedToApply);
        
        // For FAILED emails, try to find the patch by extracting the subject from the FAILED message
        if is_failed_email {
            // Extract the patch subject from the FAILED email
            let clean_subject = email.clean_subject();
            
            // Try to find a patch with this subject in our tracking store
            let mut store = self.tracking_store.lock().unwrap();
            
            // Find matching patch message ID
            let matching_message_id = store.patches.iter()
                .find(|(_, patch)| {
                    let patch_clean_subject = LeiEmail {
                        subject: patch.subject.clone(),
                        from: String::new(),
                        message_id: String::new(),
                        in_reply_to: None,
                        date: String::new(),
                        body: String::new(),
                        headers: None,
                        references: None,
                        cc: None,
                        to: None,
                    }.clean_subject();
                    
                    patch_clean_subject == clean_subject
                })
                .map(|(message_id, _)| message_id.clone());
            
            if let Some(target_message_id) = matching_message_id {
                // Found the patch this FAILED email refers to
                let ml_message = MailingListMessage {
                    message_id: email.message_id.clone(),
                    from: email.from.clone(),
                    subject: email.subject.clone(),
                    timestamp: Utc::now(),
                    message_type: MessageType::FailedToApply,
                    lore_url: Some(message_id_to_lore_url(&email.message_id)),
                };
                
                store.add_mailing_list_message(&target_message_id, ml_message)?;
                
                // Save the updated tracking store
                drop(store);
                self.save_tracking_store();
                
                return Ok(true);
            }
        }
        
        // Check if this email has In-Reply-To or References headers
        let parent_id = email.in_reply_to.as_ref().or(email.references.as_ref());
        
        if parent_id.is_none() && !is_failed_email {
            return Ok(false); // Not a reply and not a FAILED email
        }
        
        if let Some(parent_id) = parent_id {
            // Try to find the parent patch in our tracking store
            let mut store = self.tracking_store.lock().unwrap();
            
            // Check if the parent is a tracked patch
            if store.get_patch(parent_id).is_some() {
                // This is a direct reply to a tracked patch
                let ml_message = MailingListMessage {
                    message_id: email.message_id.clone(),
                    from: email.from.clone(),
                    subject: email.subject.clone(),
                    timestamp: Utc::now(),
                    message_type,
                    lore_url: Some(message_id_to_lore_url(&email.message_id)),
                };
                
                store.add_mailing_list_message(parent_id, ml_message)?;
                
                // Check if this is a comment from a maintainer indicating state change
                if (email.from.contains("Sasha Levin") || email.from.contains("Greg Kroah-Hartman")) 
                    && !matches!(store.get_patch(parent_id).unwrap().state, PatchState::Queued | PatchState::Released | PatchState::Merged(_)) {
                    // Update state to CommentsProvided
                    store.update_state(parent_id, PatchState::CommentsProvided)?;
                }
                
                // Save the updated tracking store
                drop(store);
                self.save_tracking_store();
                
                return Ok(true);
            }
        }
        
        // If not a direct reply, check if any tracked patch references this thread
        // This would require more complex threading analysis
        // For now, return false
        Ok(false)
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
            build_passed: None,
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
                
                // Run build test if patch applied successfully and builds are not skipped
                if !config.skip_build {
                    info!("Running build test for {}", branch);
                    match worktree.run_build(&config.build_command) {
                        Ok(_) => {
                            result.build_passed = Some(true);
                            info!("Build test passed for {}", branch);
                        }
                        Err(e) => {
                            result.build_passed = Some(false);
                            let build_error = format!("Build failed: {}", e);
                            error!("{}", build_error);
                            // Append build error to existing error or set it
                            result.error = Some(match result.error {
                                Some(existing) => format!("{}\n{}", existing, build_error),
                                None => build_error,
                            });
                        }
                    }
                } else {
                    debug!("Skipping build test (skip_build is true)");
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
        
        // Try cherry-picked from commit pattern
        let cherry_pick_pattern = Regex::new(r"(?i)cherry.?picked?\s+from\s+commit\s+([0-9a-f]{40})").unwrap();
        if let Some(captures) = cherry_pick_pattern.captures(body) {
            return Some(captures.get(1).unwrap().as_str().to_string());
        }
        
        // Try (cherry picked from commit X) pattern  
        let cherry_pick_paren_pattern = Regex::new(r"(?i)\(cherry.?picked?\s+from\s+commit\s+([0-9a-f]{40})\)").unwrap();
        if let Some(captures) = cherry_pick_paren_pattern.captures(body) {
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
    
    /// Check if a response file already exists for the given email message ID
    fn response_already_exists(&self, message_id: &str) -> bool {
        let output_dir = &self.config.output_dir;
        
        if !output_dir.exists() {
            return false;
        }
        
        // Read all response files in the output directory
        if let Ok(entries) = fs::read_dir(output_dir) {
            for entry in entries.flatten() {
                if let Ok(path) = entry.path().canonicalize() {
                    // Check if it's a response file
                    if path.extension().and_then(|s| s.to_str()) == Some("response") {
                        // Read the file to check the In-Reply-To header
                        if let Ok(content) = fs::read_to_string(&path) {
                            // Look for the In-Reply-To header that matches our message ID
                            for line in content.lines() {
                                if let Some(in_reply_to) = line.strip_prefix("In-Reply-To: ") {
                                    if in_reply_to.trim() == message_id {
                                        info!("Found existing response file for message ID {}: {:?}", message_id, path.file_name());
                                        return true;
                                    }
                                }
                                // Stop after headers (empty line)
                                if line.is_empty() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        false
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

/// Determine the type of message based on subject and content
fn determine_message_type(email: &LeiEmail) -> MessageType {
    let subject_lower = email.subject.to_lowercase();
    let body_lower = email.body.to_lowercase();
    
    // Check for FAILED: patch... emails from maintainers
    if email.subject.starts_with("FAILED: patch") && email.subject.contains("failed to apply") {
        MessageType::FailedToApply
    } else if subject_lower.contains("nack") || body_lower.contains("nacked-by:") {
        MessageType::Nack
    } else if subject_lower.contains("ack") || body_lower.contains("acked-by:") {
        MessageType::Ack
    } else if body_lower.contains("tested-by:") {
        MessageType::TestedBy
    } else if body_lower.contains("reviewed-by:") || subject_lower.contains("review") {
        MessageType::Review
    } else if subject_lower.starts_with("re:") {
        MessageType::Reply
    } else {
        MessageType::Other
    }
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
    
    #[test]
    fn test_determine_message_type() {
        // Test FAILED email detection
        let failed_email = LeiEmail {
            subject: "FAILED: patch \"drm/i915: Fix crash\" failed to apply to 6.6-stable tree".to_string(),
            from: "gregkh@kernel.org".to_string(),
            message_id: "<failed123@example.com>".to_string(),
            in_reply_to: Some("<patch123@example.com>".to_string()),
            date: "2024-01-01".to_string(),
            body: "The patch failed to apply cleanly.".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        assert!(matches!(determine_message_type(&failed_email), MessageType::FailedToApply));
        
        // Test regular reply
        let reply_email = LeiEmail {
            subject: "Re: [PATCH] Fix something".to_string(),
            from: "dev@example.com".to_string(),
            message_id: "<reply123@example.com>".to_string(),
            in_reply_to: Some("<patch456@example.com>".to_string()),
            date: "2024-01-01".to_string(),
            body: "Looks good to me.".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        assert!(matches!(determine_message_type(&reply_email), MessageType::Reply));
        
        // Test Ack email
        let ack_email = LeiEmail {
            subject: "Re: [PATCH] Fix something".to_string(),
            from: "maintainer@example.com".to_string(),
            message_id: "<ack123@example.com>".to_string(),
            in_reply_to: Some("<patch789@example.com>".to_string()),
            date: "2024-01-01".to_string(),
            body: "Acked-by: Maintainer <maintainer@example.com>".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        assert!(matches!(determine_message_type(&ack_email), MessageType::Ack));
    }
    
    #[test]
    fn test_response_already_exists() {
        let test_dir = tempdir().unwrap();
        let config = create_test_config(&test_dir);
        let processor = PatchProcessor::new(config).unwrap();
        
        // Create output directory
        let output_dir = test_dir.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();
        
        let message_id = "<test123@example.com>";
        
        // Initially, no response should exist
        assert!(!processor.response_already_exists(message_id));
        
        // Create a response file
        let response_content = format!(
            "From: Bot <bot@test.com>\n\
             To: stable@vger.kernel.org\n\
             Subject: Re: Test patch\n\
             Message-ID: <response123@test.com>\n\
             In-Reply-To: {}\n\
             Date: 2024-01-01\n\
             \n\
             Test response body",
            message_id
        );
        
        let response_file = output_dir.join("20240101120000-abcd1234.response");
        fs::write(&response_file, response_content).unwrap();
        
        // Now the response should exist
        assert!(processor.response_already_exists(message_id));
        
        // Test with a different message ID
        assert!(!processor.response_already_exists("<different@example.com>"));
    }
    
    
    #[tokio::test]
    async fn test_process_failed_email_without_in_reply_to() {
        let test_dir = tempdir().unwrap();
        let config = create_test_config(&test_dir);
        let processor = PatchProcessor::new(config).unwrap();
        
        // First, add a patch to the tracking store
        {
            let mut store = processor.tracking_store.lock().unwrap();
            let tracking = PatchTracking {
                message_id: "<original-patch@example.com>".to_string(),
                sha1: Some("abcdef1234567890abcdef1234567890abcdef12".to_string()),
                subject: "[PATCH] drm/i915: Fix crash".to_string(),
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
        }
        
        // Create a FAILED email without In-Reply-To header
        let failed_email = LeiEmail {
            subject: "FAILED: patch \"drm/i915: Fix crash\" failed to apply to 6.6-stable tree".to_string(),
            from: "Greg KH <gregkh@kernel.org>".to_string(),
            message_id: "<failed-no-reply@example.com>".to_string(),
            in_reply_to: None,  // No In-Reply-To header
            date: "2024-01-02".to_string(),
            body: "The patch failed to apply cleanly to the 6.6 stable tree.".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        
        // Process the FAILED email
        let result = processor.process_reply_or_comment(failed_email).await.unwrap();
        assert!(result, "FAILED email should be processed successfully");
        
        // Check that the patch state was updated
        {
            let store = processor.tracking_store.lock().unwrap();
            let patch = store.get_patch("<original-patch@example.com>").unwrap();
            assert!(matches!(patch.state, PatchState::Failed(_)));
            assert_eq!(patch.mailing_list_activity.replies.len(), 1);
            assert!(matches!(patch.mailing_list_activity.replies[0].message_type, MessageType::FailedToApply));
        }
    }
    
    #[tokio::test]
    async fn test_process_email_skips_if_response_exists() {
        let test_dir = tempdir().unwrap();
        let config = create_test_config(&test_dir);
        let processor = PatchProcessor::new(config).unwrap();
        
        // Create output directory
        let output_dir = test_dir.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();
        
        // Create a test email
        let email = LeiEmail {
            subject: "[PATCH] Fix memory leak".to_string(),
            from: "Test <test@example.com>".to_string(),
            message_id: "<patch123@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "commit abcdef1234567890abcdef1234567890abcdef12 upstream\n\nPatch content".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        
        // Create a response file for this email
        let response_content = format!(
            "From: Bot <bot@test.com>\n\
             To: stable@vger.kernel.org\n\
             Subject: Re: [PATCH] Fix memory leak\n\
             Message-ID: <response456@test.com>\n\
             In-Reply-To: {}\n\
             Date: 2024-01-01\n\
             \n\
             Response already sent",
            email.message_id
        );
        
        let response_file = output_dir.join("20240101130000-efgh5678.response");
        fs::write(&response_file, response_content).unwrap();
        
        // Process the email - it should skip processing
        let result = processor.process_email(email).await;
        assert!(result.is_ok());
        
        // Verify no new response files were created
        let response_files: Vec<_> = fs::read_dir(&output_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry.path().extension()
                    .and_then(|s| s.to_str()) == Some("response")
            })
            .collect();
        
        // Should still have only one response file
        assert_eq!(response_files.len(), 1);
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
            tracking_file: test_dir.path().join("tracking.json"),
            ignored_authors: vec![],
            email: crate::config::EmailConfig {
                from: "Bot <bot@test.com>".to_string(),
                reply_to: None,
                smtp: None,
            },
            build_command: "true".to_string(),
            debug: true,
            dry_run: false,
            skip_build: true,
        }
    }
}