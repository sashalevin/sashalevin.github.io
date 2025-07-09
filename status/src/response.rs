use chrono::Utc;
use std::fs;
use std::path::Path;

use crate::config::{Config, EmailConfig};
use crate::email::LeiEmail;
use crate::error::{MailbotError, Result as MailbotResult};

#[derive(Debug, Clone)]
pub enum PatchStatus {
    Success,
    Failed,
}

#[derive(Debug, Clone)]
pub struct TestResult {
    pub branch: String,
    pub patch_status: PatchStatus,
    pub build_status: Option<bool>,
    pub error: Option<String>,
}

pub struct ResponseBuilder {
    email: LeiEmail,
    config: Config,
    claimed_sha1: Option<String>,
    found_sha1: Option<String>,
    author_mismatch: Option<String>,
    test_results: Vec<TestResult>,
    newer_kernel_results: Vec<String>,
    fixes: Vec<(String, String)>,
    reverts: Vec<(String, String)>,
    diff_output: Option<String>,
}

pub struct EmailResponse {
    pub message_id: String,
    pub subject: String,
    pub body: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub from: String,
    pub in_reply_to: String,
}

impl ResponseBuilder {
    pub fn new(email: &LeiEmail, config: &Config) -> Self {
        Self {
            email: email.clone(),
            config: config.clone(),
            claimed_sha1: None,
            found_sha1: None,
            author_mismatch: None,
            test_results: vec![],
            newer_kernel_results: vec![],
            fixes: vec![],
            reverts: vec![],
            diff_output: None,
        }
    }
    
    pub fn set_commit_info(
        &mut self,
        claimed_sha1: Option<String>,
        found_sha1: Option<String>,
        author_mismatch: Option<String>,
    ) {
        self.claimed_sha1 = claimed_sha1;
        self.found_sha1 = found_sha1;
        self.author_mismatch = author_mismatch;
    }
    
    pub fn add_test_result(&mut self, result: TestResult) {
        self.test_results.push(result);
    }
    
    pub fn set_newer_kernel_results(&mut self, results: Vec<String>) {
        self.newer_kernel_results = results;
    }
    
    pub fn set_fixes(&mut self, fixes: Vec<(String, String)>) {
        self.fixes = fixes;
    }
    
    pub fn set_reverts(&mut self, reverts: Vec<(String, String)>) {
        self.reverts = reverts;
    }
    
    pub fn set_diff_output(&mut self, diff: String) {
        self.diff_output = Some(diff);
    }
    
    pub fn build(&self) -> MailbotResult<EmailResponse> {
        let has_issues = self.has_issues();
        let (to, cc) = self.determine_recipients(has_issues)?;
        
        let body = self.generate_body(has_issues)?;
        let subject = self.generate_subject();
        
        Ok(EmailResponse {
            message_id: self.generate_message_id(),
            subject,
            body,
            to,
            cc,
            from: self.config.email.from.clone(),
            in_reply_to: self.email.message_id.clone(),
        })
    }
    
    fn has_issues(&self) -> bool {
        // Check for build failures
        let has_build_failures = self.test_results.iter()
            .any(|r| matches!(r.patch_status, PatchStatus::Failed) || 
                     r.build_status == Some(false));
        
        // Check for missing or incorrect commit
        let has_commit_issues = self.found_sha1.is_none() ||
            (self.claimed_sha1.is_some() && self.claimed_sha1 != self.found_sha1);
        
        // Check for fixes or reverts
        let has_fixes = !self.fixes.is_empty();
        let has_reverts = !self.reverts.is_empty();
        
        has_build_failures || has_commit_issues || has_fixes || has_reverts
    }
    
    fn determine_recipients(&self, has_issues: bool) -> MailbotResult<(Vec<String>, Vec<String>)> {
        if has_issues {
            // Send to author and CC stable
            let author_email = self.email.extract_email_address()
                .ok_or_else(|| MailbotError::EmailParse("Cannot extract author email".to_string()))?;
            
            Ok((vec![author_email], vec!["stable@vger.kernel.org".to_string()]))
        } else {
            // Send only to stable
            Ok((vec!["stable@vger.kernel.org".to_string()], vec![]))
        }
    }
    
    fn generate_subject(&self) -> String {
        let orig_subject = &self.email.subject;
        
        // Add Re: if not already present
        if orig_subject.starts_with("Re:") {
            orig_subject.clone()
        } else {
            format!("Re: {orig_subject}")
        }
    }
    
    fn generate_body(&self, has_issues: bool) -> MailbotResult<String> {
        let mut body = String::new();
        
        // Header
        body.push_str("[ Sasha's backport helper bot ]\n\n");
        body.push_str("Hi,\n\n");
        
        // Summary section
        if has_issues {
            body.push_str("Summary of potential issues:\n");
            
            if let Some((current, total)) = self.email.extract_series_info() {
                if current > 1 {
                    body.push_str(&format!("ℹ️ This is part {current}/{total} of a series\n"));
                }
            }
            
            if self.test_results.iter().any(|r| matches!(r.patch_status, PatchStatus::Failed) || 
                                     r.build_status == Some(false)) {
                body.push_str("❌ Build failures detected\n");
            }
            
            if self.found_sha1.is_none() {
                body.push_str("⚠️ Could not find matching upstream commit\n");
            } else if self.claimed_sha1.is_some() && self.claimed_sha1 != self.found_sha1 {
                body.push_str("⚠️ Provided upstream commit SHA1 does not match found commit\n");
            } else if self.claimed_sha1.is_none() && self.found_sha1.is_some() {
                body.push_str("⚠️ Found matching upstream commit but patch is missing proper reference to it\n");
            }
            
            if !self.fixes.is_empty() {
                body.push_str("⚠️ Found follow-up fixes in mainline\n");
            }
            
            if !self.reverts.is_empty() {
                body.push_str("❌ Commit was reverted in mainline\n");
            }
            
            body.push('\n');
        } else {
            body.push_str("✅ All tests passed successfully. No issues detected.\n");
            body.push_str("No action required from the submitter.\n\n");
        }
        
        // SHA1 verification section
        if let Some(ref claimed) = self.claimed_sha1 {
            if Some(claimed) == self.found_sha1.as_ref() {
                body.push_str(&format!("The upstream commit SHA1 provided is correct: {claimed}\n"));
                if let Some(ref mismatch) = self.author_mismatch {
                    body.push_str("\nWARNING: Author mismatch between patch and upstream commit:\n");
                    body.push_str(mismatch);
                    body.push('\n');
                }
            } else {
                body.push_str(&format!("The claimed upstream commit SHA1 ({claimed}) was not found.\n"));
                if let Some(ref found) = self.found_sha1 {
                    body.push_str(&format!("However, I found a matching commit: {found}\n"));
                    if let Some(ref mismatch) = self.author_mismatch {
                        body.push_str("\nWARNING: Author mismatch between patch and found commit:\n");
                        body.push_str(mismatch);
                        body.push('\n');
                    }
                }
            }
        } else if let Some(ref found) = self.found_sha1 {
            body.push_str(&format!("Found matching upstream commit: {found}\n"));
            if let Some(ref mismatch) = self.author_mismatch {
                body.push_str("\nWARNING: Author mismatch between patch and found commit:\n");
                body.push_str(mismatch);
                body.push('\n');
            }
        } else {
            body.push_str("No upstream commit was identified. Using temporary commit for testing.\n");
        }
        body.push('\n');
        
        // Newer kernel status
        if !self.newer_kernel_results.is_empty() {
            body.push_str("Status in newer kernel trees:\n");
            for result in &self.newer_kernel_results {
                body.push_str(result);
                body.push('\n');
            }
            body.push('\n');
        }
        
        // Fixes and reverts
        if !self.fixes.is_empty() {
            body.push_str("Found fixes commits:\n");
            for (sha, subject) in &self.fixes {
                body.push_str(&format!("{} {}\n", &sha[..12], subject));
            }
            body.push('\n');
        }
        
        if !self.reverts.is_empty() {
            body.push_str("Found revert commits:\n");
            for (sha, subject) in &self.reverts {
                body.push_str(&format!("{} {}\n", &sha[..12], subject));
            }
            body.push('\n');
        }
        
        // Diff output
        if let Some(ref diff) = self.diff_output {
            if diff.contains("Could not generate") {
                body.push_str("Note: Could not generate a diff with upstream commit:\n");
            } else {
                body.push_str("Note: The patch differs from the upstream commit:\n");
            }
            body.push_str("---\n");
            body.push_str(diff);
            body.push_str("\n---\n\n");
        }
        
        // Results table
        if let Some((current, _)) = self.email.extract_series_info() {
            if current > 1 && has_issues {
                body.push_str("NOTE: These results are for this patch alone. Full series testing will be\n");
                body.push_str("performed when all parts are received.\n\n");
            }
        }
        
        body.push_str("Results of testing on various branches:\n\n");
        body.push_str("| Branch                    | Patch Apply | Build Test |\n");
        body.push_str("|---------------------------|-------------|------------|\n");
        
        for result in &self.test_results {
            let patch_status = match result.patch_status {
                PatchStatus::Success => "Success",
                PatchStatus::Failed => "Failed",
            };
            
            let build_status = match result.build_status {
                Some(true) => "Success",
                Some(false) => "Failed",
                None => "N/A",
            };
            
            body.push_str(&format!("| {:<25} | {:<11} | {:<10} |\n", 
                result.branch, patch_status, build_status));
        }
        
        // Build errors
        let build_errors: Vec<&TestResult> = self.test_results.iter()
            .filter(|r| r.error.is_some())
            .collect();
        
        if !build_errors.is_empty() {
            body.push_str("\nBuild Errors:\n");
            for result in build_errors {
                if let Some(ref error) = result.error {
                    body.push_str(error);
                    body.push('\n');
                }
            }
        }
        
        Ok(body)
    }
    
    fn generate_message_id(&self) -> String {
        use sha1::{Sha1, Digest};
        
        let timestamp = Utc::now().timestamp();
        let mut hasher = Sha1::new();
        hasher.update(timestamp.to_string().as_bytes());
        hasher.update(&self.email.message_id);
        
        let hash = format!("{:x}", hasher.finalize());
        format!("<{}-{}@stable.kernel.org>", timestamp, &hash[..8])
    }
}

impl EmailResponse {
    pub fn save<P: AsRef<Path>>(&self, output_dir: P) -> MailbotResult<()> {
        let filename = self.generate_filename();
        let file_path = output_dir.as_ref().join(&filename);
        
        // Create directory if it doesn't exist
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)?;
        }
        
        // Generate email content
        let content = self.to_email_format()?;
        fs::write(&file_path, content)?;
        
        Ok(())
    }
    
    pub fn send(&self, _email_config: &EmailConfig) -> MailbotResult<()> {
        // For now, we'll save to file instead of sending
        // In production, this would use lettre to send via SMTP
        Ok(())
    }
    
    fn generate_filename(&self) -> String {
        use sha1::{Sha1, Digest};
        
        let mut hasher = Sha1::new();
        hasher.update(&self.message_id);
        hasher.update(&self.subject);
        
        let hash = format!("{:x}", hasher.finalize());
        let timestamp = Utc::now().format("%Y%m%d%H%M%S");
        
        format!("{}-{}.response", timestamp, &hash[..8])
    }
    
    fn to_email_format(&self) -> MailbotResult<String> {
        let mut email = String::new();
        
        // Headers
        email.push_str(&format!("From: {}\n", self.from));
        email.push_str(&format!("To: {}\n", self.to.join(", ")));
        if !self.cc.is_empty() {
            email.push_str(&format!("Cc: {}\n", self.cc.join(", ")));
        }
        email.push_str(&format!("Subject: {}\n", self.subject));
        email.push_str(&format!("Message-ID: {}\n", self.message_id));
        email.push_str(&format!("In-Reply-To: {}\n", self.in_reply_to));
        email.push_str(&format!("Date: {}\n", Utc::now().to_rfc2822()));
        email.push('\n');
        
        // Body
        email.push_str(&self.body);
        
        Ok(email)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_response_builder() {
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
        
        // Set commit info so it's not treated as an issue
        builder.set_commit_info(
            Some("abcdef1234567890abcdef1234567890abcdef12".to_string()),
            Some("abcdef1234567890abcdef1234567890abcdef12".to_string()),
            None,
        );
        
        builder.add_test_result(TestResult {
            branch: "stable/linux-6.1.y".to_string(),
            patch_status: PatchStatus::Success,
            build_status: Some(true),
            error: None,
        });
        
        let response = builder.build().unwrap();
        assert_eq!(response.subject, "Re: [PATCH] Test patch");
        assert!(response.body.contains("✅ All tests passed successfully"));
    }
    
    #[test]
    fn test_response_with_failures() {
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
        
        // Add a failed test result
        builder.add_test_result(TestResult {
            branch: "stable/linux-6.1.y".to_string(),
            patch_status: PatchStatus::Failed,
            build_status: None,
            error: Some("Patch failed to apply".to_string()),
        });
        
        let response = builder.build().unwrap();
        assert!(response.body.contains("❌ Build failures detected"));
        assert!(response.body.contains("Patch failed to apply"));
        
        // Check recipients - should send to author when there are issues
        assert_eq!(response.to, vec!["test@example.com"]);
        assert_eq!(response.cc, vec!["stable@vger.kernel.org"]);
    }
    
    #[test]
    fn test_response_with_missing_commit() {
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
        
        // No commit info set - should be treated as missing
        builder.add_test_result(TestResult {
            branch: "stable/linux-6.1.y".to_string(),
            patch_status: PatchStatus::Success,
            build_status: Some(true),
            error: None,
        });
        
        let response = builder.build().unwrap();
        assert!(response.body.contains("⚠️ Could not find matching upstream commit"));
    }
    
    #[test]
    fn test_response_with_fixes_and_reverts() {
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
        
        builder.set_commit_info(
            Some("abc123".to_string()),
            Some("abc123".to_string()),
            None,
        );
        
        builder.set_fixes(vec![(
            "def456789012".to_string(),
            "Fix memory leak in original patch".to_string(),
        )]);
        
        builder.set_reverts(vec![(
            "fed987654321".to_string(),
            "Revert \"Original patch\"".to_string(),
        )]);
        
        let response = builder.build().unwrap();
        assert!(response.body.contains("⚠️ Found follow-up fixes in mainline"));
        assert!(response.body.contains("❌ Commit was reverted in mainline"));
        assert!(response.body.contains("def456789012 Fix memory leak"));
        assert!(response.body.contains("fed987654321 Revert"));
    }
    
    #[test]
    fn test_response_series_patch() {
        let email = LeiEmail {
            subject: "[PATCH 2/5] Test patch".to_string(),
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
        
        // Missing commit for a series patch
        builder.add_test_result(TestResult {
            branch: "stable/linux-6.1.y".to_string(),
            patch_status: PatchStatus::Success,
            build_status: Some(true),
            error: None,
        });
        
        let response = builder.build().unwrap();
        assert!(response.body.contains("ℹ️ This is part 2/5 of a series"));
    }
    
    #[test]
    fn test_email_response_filename() {
        let response = EmailResponse {
            message_id: "<test123@example.com>".to_string(),
            subject: "Re: Test".to_string(),
            body: "Test".to_string(),
            to: vec!["test@example.com".to_string()],
            cc: vec![],
            from: "bot@example.com".to_string(),
            in_reply_to: "<orig@example.com>".to_string(),
        };
        
        let filename = response.generate_filename();
        assert!(filename.ends_with(".response"));
        assert!(filename.contains("-")); // Contains timestamp separator
    }
}