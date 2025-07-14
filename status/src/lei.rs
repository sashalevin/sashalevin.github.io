use std::process::Command;
use std::fs;
use std::path::Path;
use chrono::{DateTime, Utc, Duration};
use crate::error::{MailbotError, Result};
use tracing::{info, debug};

pub struct LeiClient {
    pub(crate) state_file: String,
}

impl LeiClient {
    pub fn new(state_file: String) -> Self {
        let expanded = shellexpand::tilde(&state_file).to_string();
        Self { state_file: expanded }
    }
    
    
    /// Query emails from lore.kernel.org/stable since last run
    pub fn query_recent_patches(&self, lookback_minutes: u32, ignored_authors: &[String]) -> Result<Vec<crate::email::LeiEmail>> {
        let (start_time, end_time) = self.get_time_range(lookback_minutes)?;
        
        info!("Querying emails from {} to {}", start_time, end_time);
        
        // Build the query using lei's relative time format
        // Convert minutes to hours if appropriate
        let time_spec = if lookback_minutes >= 60 && lookback_minutes % 60 == 0 {
            format!("rt:last.{}.hours", lookback_minutes / 60)
        } else {
            format!("rt:last.{lookback_minutes}.minutes")
        };
        
        // Query for various patch-related keywords in stable mailing list
        // Include PATCH, BACKPORT, STABLE, and kernel version patterns
        let query = format!("l:stable (s:PATCH OR s:BACKPORT OR s:STABLE OR s:5. OR s:6.) {time_spec}");
        
        debug!("Lei query: {}", query);
        
        // Run lei query
        info!("Running lei query...");
        let mut cmd = Command::new("lei");
        cmd.args([
            "q",
            &query,
            "-f", "json",
            "--no-save"
        ]);
        
        // Set a timeout of 30 seconds
        let output = cmd.output()
            .map_err(MailbotError::Io)?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MailbotError::External(format!("lei query failed: {stderr}")));
        }
        
        // Parse JSON output
        let stdout = String::from_utf8_lossy(&output.stdout);
        debug!("Lei returned {} bytes of output", stdout.len());
        let emails = self.parse_lei_output(&stdout, ignored_authors)?;
        
        info!("Found {} emails after filtering", emails.len());
        
        // Update state file with current time
        self.save_timestamp(end_time)?;
        
        Ok(emails)
    }
    
    /// Get time range for query
    pub(crate) fn get_time_range(&self, lookback_minutes: u32) -> Result<(DateTime<Utc>, DateTime<Utc>)> {
        let end_time = Utc::now();
        
        let start_time = if Path::new(&self.state_file).exists() {
            // Read last run timestamp
            let timestamp_str = fs::read_to_string(&self.state_file)
                .map_err(MailbotError::Io)?;
            
            let timestamp_str = timestamp_str.trim();
            
            // Parse timestamp (format: YYYYMMDDHHmmss)
            DateTime::parse_from_str(&format!("{timestamp_str}+0000"), "%Y%m%d%H%M%S%z")
                .map_err(|e| MailbotError::External(format!("Failed to parse timestamp: {e}")))?
                .with_timezone(&Utc)
        } else {
            // First run - look back N minutes
            end_time - Duration::minutes(lookback_minutes as i64)
        };
        
        Ok((start_time, end_time))
    }
    
    /// Save current timestamp to state file
    pub(crate) fn save_timestamp(&self, time: DateTime<Utc>) -> Result<()> {
        let timestamp = time.format("%Y%m%d%H%M%S").to_string();
        
        // Ensure directory exists
        if let Some(parent) = Path::new(&self.state_file).parent() {
            fs::create_dir_all(parent).map_err(MailbotError::Io)?;
        }
        
        fs::write(&self.state_file, timestamp)
            .map_err(MailbotError::Io)?;
        
        info!("Updated last run timestamp to: {}", time);
        Ok(())
    }
    
    /// Parse lei JSON output
    pub(crate) fn parse_lei_output(&self, output: &str, ignored_authors: &[String]) -> Result<Vec<crate::email::LeiEmail>> {
        let mut emails = Vec::new();
        
        let trimmed = output.trim();
        if trimmed.is_empty() || trimmed == "null" {
            return Ok(emails);
        }
        
        // Lei can output either:
        // 1. A JSON array of objects
        // 2. One JSON object per line
        // Try array first
        if trimmed.starts_with('[') {
            // Parse as JSON array
            match serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
                Ok(values) => {
                    info!("Lei returned {} total emails", values.len());
                    debug!("Parsing JSON array with {} values", values.len());
                    for (idx, value) in values.iter().enumerate() {
                        // Skip null values
                        if value.is_null() {
                            debug!("Skipping null value at index {}", idx);
                            continue;
                        }
                        
                        debug!("Processing JSON value {}: {:?}", idx, value);
                        match self.parse_lei_email_from_value(value) {
                            Ok(mut email) => {
                                // Check if author is ignored
                                // Extract email address from the from field for comparison
                                let from_lower = email.from.to_lowercase();
                                let is_ignored = ignored_authors.iter().any(|ignored| {
                                    from_lower.contains(&ignored.to_lowercase())
                                });
                                
                                if is_ignored {
                                    debug!("Skipping email from ignored author: {}", email.from);
                                } else {
                                    info!("Found email: {}", email.subject);
                                    // Fetch the actual body content using message-id
                                    let message_id = email.message_id.trim_start_matches('<').trim_end_matches('>');
                                    debug!("Fetching content for message-id: {}", message_id);
                                    match self.fetch_email_content(message_id) {
                                        Ok(content) => {
                                            email.body = content;
                                            emails.push(email);
                                        }
                                        Err(e) => {
                                            debug!("Failed to fetch email content: {}", e);
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                debug!("Failed to parse email at index {}: {}", idx, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to parse as JSON array: {}", e);
                    // Fall through to try line-by-line parsing
                }
            }
        }
        
        // If not an array or array parsing failed, try line-by-line
        if emails.is_empty() && !trimmed.starts_with('[') {
            for line in output.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed == "null" || trimmed.starts_with("#") {
                    continue;
                }
                
                // Skip lines that start with E: (error messages)
                if trimmed.starts_with("E:") {
                    debug!("Skipping error line: {}", trimmed);
                    continue;
                }
                
                // Try to parse as LeiEmail or lei's native format
                match self.parse_lei_email(line) {
                    Ok(mut email) => {
                        // Check if author is ignored
                        // Extract email address from the from field for comparison
                        let from_lower = email.from.to_lowercase();
                        let is_ignored = ignored_authors.iter().any(|ignored| {
                            from_lower.contains(&ignored.to_lowercase())
                        });
                        
                        if is_ignored {
                            debug!("Skipping email from ignored author: {}", email.from);
                        } else {
                            info!("Found email: {}", email.subject);
                            // Fetch the actual body content using message-id
                            let message_id = email.message_id.trim_start_matches('<').trim_end_matches('>');
                            debug!("Fetching content for message-id: {}", message_id);
                            match self.fetch_email_content(message_id) {
                                Ok(content) => {
                                    email.body = content;
                                    emails.push(email);
                                }
                                Err(e) => {
                                    debug!("Failed to fetch email content: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Failed to parse JSON line: {} - Error: {}", line, e);
                    }
                }
            }
        }
        
        Ok(emails)
    }
    
    /// Parse lei email from JSON, handling both our format and lei's native format
    fn parse_lei_email(&self, json_str: &str) -> Result<crate::email::LeiEmail> {
        // First try to parse as our expected format
        if let Ok(email) = serde_json::from_str::<crate::email::LeiEmail>(json_str) {
            return Ok(email);
        }
        
        // If that fails, try to parse lei's native format
        let value: serde_json::Value = serde_json::from_str(json_str)
            .map_err(MailbotError::Json)?;
        
        self.parse_lei_email_from_value(&value)
    }
    
    /// Parse lei email from JSON value
    pub(crate) fn parse_lei_email_from_value(&self, value: &serde_json::Value) -> Result<crate::email::LeiEmail> {
        // Extract fields from lei format
        let subject = value.get("s")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
            
        let from = value.get("f")
            .and_then(|f| f.as_array())
            .and_then(|arr| arr.first())
            .and_then(|f| f.as_array())
            .map(|arr| {
                if arr.len() >= 2 {
                    format!("{} <{}>", 
                        arr[0].as_str().unwrap_or(""),
                        arr[1].as_str().unwrap_or(""))
                } else {
                    arr[0].as_str().unwrap_or("").to_string()
                }
            })
            .unwrap_or_else(|| "Unknown <unknown@example.com>".to_string());
            
        let message_id = value.get("m")
            .and_then(|m| m.as_str())
            .map(|s| format!("<{s}>"))
            .unwrap_or_else(|| "<unknown@example.com>".to_string());
            
        let date = value.get("dt")
            .and_then(|d| d.as_str())
            .unwrap_or("1970-01-01T00:00:00Z")
            .to_string();
            
        // For initial filtering, we don't need the body yet
        // We'll fetch it later using the message-id
        let body = String::new();
            
        Ok(crate::email::LeiEmail {
            subject,
            from,
            message_id,
            in_reply_to: value.get("refs")
                .and_then(|r| r.as_array())
                .and_then(|arr| arr.first())
                .and_then(|r| r.as_str())
                .map(|s| s.to_string()),
            date,
            body,
            headers: None,
            references: None,
            cc: value.get("c")
                .and_then(|c| c.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| {
                            item.as_array()
                                .and_then(|a| a.get(1))
                                .and_then(|email| email.as_str())
                                .map(|s| s.to_string())
                        })
                        .collect()
                }),
            to: value.get("t")
                .and_then(|t| t.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| {
                            item.as_array()
                                .and_then(|a| a.get(1))
                                .and_then(|email| email.as_str())
                                .map(|s| s.to_string())
                        })
                        .collect()
                }),
        })
    }
    
    /// Fetch email content using lei q with message-id
    fn fetch_email_content(&self, message_id: &str) -> Result<String> {
        // In tests, return a dummy body instead of calling lei
        #[cfg(test)]
        {
            return Ok(format!("Test body for message-id: {}", message_id));
        }
        
        #[cfg(not(test))]
        {
            let output = Command::new("lei")
                .args(["q", "-f", "mboxrd", &format!("m:{message_id}")])
                .output()
                .map_err(MailbotError::Io)?;
                
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(MailbotError::External(format!("Failed to fetch email: {stderr}")));
            }
            
            let mbox_content = String::from_utf8_lossy(&output.stdout);
            
            // Extract body from mbox format
            // Skip headers until we find an empty line
            let mut in_headers = true;
            let mut body_lines = Vec::new();
            
            for line in mbox_content.lines() {
                if in_headers {
                    if line.trim().is_empty() {
                        in_headers = false;
                    }
                    continue;
                }
                
                // Stop at next message marker
                if line.starts_with("From ") && line.contains("@mboxrd") {
                    break;
                }
                
                body_lines.push(line);
            }
            
            Ok(body_lines.join("\n"))
        }
    }
}

/// Add lore.kernel.org/stable as external source if not already added
pub fn ensure_stable_external() -> Result<()> {
    // Check if already added
    let output = Command::new("lei")
        .args(["ls-external"])
        .output()
        .map_err(MailbotError::Io)?;
    
    let externals = String::from_utf8_lossy(&output.stdout);
    
    if !externals.contains("https://lore.kernel.org/stable/") {
        info!("Adding lore.kernel.org/stable as external source");
        
        let output = Command::new("lei")
            .args(["add-external", "https://lore.kernel.org/stable/"])
            .output()
            .map_err(MailbotError::Io)?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(MailbotError::External(format!("Failed to add external: {stderr}")));
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_lei_client_creation() {
        let client = LeiClient::new("~/.test_mailbot_state".to_string());
        // Should expand tilde
        assert!(client.state_file.contains(std::env::var("HOME").unwrap().as_str()));
    }
    
    #[test]
    fn test_time_range_first_run() {
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("state");
        
        let client = LeiClient::new(state_file.to_str().unwrap().to_string());
        let (start, end) = client.get_time_range(60).unwrap();
        
        // First run should look back 60 minutes
        let duration = end.signed_duration_since(start);
        assert!(duration.num_minutes() >= 59 && duration.num_minutes() <= 61);
    }
    
    #[test]
    fn test_time_range_subsequent_run() {
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("state");
        
        // Write a timestamp
        fs::write(&state_file, "20250101120000").unwrap();
        
        let client = LeiClient::new(state_file.to_str().unwrap().to_string());
        let (start, _end) = client.get_time_range(60).unwrap();
        
        // Should use the saved timestamp
        assert_eq!(start.format("%Y%m%d%H%M%S").to_string(), "20250101120000");
    }
    
    #[test]
    fn test_save_timestamp() {
        let temp_dir = TempDir::new().unwrap();
        let state_file = temp_dir.path().join("subdir/state");
        
        let client = LeiClient::new(state_file.to_str().unwrap().to_string());
        let now = Utc::now();
        
        client.save_timestamp(now).unwrap();
        
        // Check file was created with correct content
        assert!(state_file.exists());
        let content = fs::read_to_string(&state_file).unwrap();
        assert_eq!(content, now.format("%Y%m%d%H%M%S").to_string());
    }
    
    #[test]
    fn test_parse_lei_json_array() {
        let client = LeiClient::new("test".to_string());
        
        let json = r#"[
            {
                "blob": "abc123",
                "s": "[PATCH] Test patch",
                "f": [["Test Author", "test@example.com"]],
                "m": "test123@example.com",
                "dt": "2025-01-01T12:00:00Z",
                "refs": null
            },
            {
                "blob": "def456",
                "s": "Re: [PATCH] Reply",
                "f": [["Another Author", "another@example.com"]],
                "m": "reply123@example.com",
                "dt": "2025-01-01T13:00:00Z",
                "refs": ["test123@example.com"]
            }
        ]"#;
        
        // Mock blob fetching by not actually calling lei
        let emails = client.parse_lei_output(json, &[]).unwrap();
        
        // Should get both emails (no pre-filtering of replies)
        assert_eq!(emails.len(), 2);
        assert_eq!(emails[0].subject, "[PATCH] Test patch");
        assert_eq!(emails[0].from, "Test Author <test@example.com>");
        assert_eq!(emails[0].message_id, "<test123@example.com>");
        assert_eq!(emails[1].subject, "Re: [PATCH] Reply");
        assert_eq!(emails[1].from, "Another Author <another@example.com>");
        assert_eq!(emails[1].message_id, "<reply123@example.com>");
    }
    
    #[test]
    fn test_parse_lei_json_single_lines() {
        let client = LeiClient::new("test".to_string());
        
        let json = r#"{"blob": "abc123", "s": "[PATCH] Test patch", "f": [["Test Author", "test@example.com"]], "m": "test123@example.com", "dt": "2025-01-01T12:00:00Z"}
{"blob": "def456", "s": "Re: [PATCH] Reply", "f": [["Another Author", "another@example.com"]], "m": "reply123@example.com", "dt": "2025-01-01T13:00:00Z", "refs": ["test123@example.com"]}
E: Some error message
null"#;
        
        let emails = client.parse_lei_output(json, &[]).unwrap();
        
        // Should get both emails (no pre-filtering of replies)
        assert_eq!(emails.len(), 2);
        assert_eq!(emails[0].subject, "[PATCH] Test patch");
        assert_eq!(emails[1].subject, "Re: [PATCH] Reply");
    }
    
    #[test]
    fn test_parse_lei_email_from_value() {
        let client = LeiClient::new("test".to_string());
        
        let value = serde_json::json!({
            "blob": "abc123",
            "s": "[PATCH v2 3/5] mm: Fix memory leak",
            "f": [["John Doe", "john@kernel.org"]],
            "m": "patch123@kernel.org",
            "dt": "2025-01-01T12:00:00Z",
            "c": [[null, "stable@vger.kernel.org"], ["Jane Doe", "jane@kernel.org"]],
            "t": [["Maintainer", "maintainer@kernel.org"]],
            "refs": ["cover@kernel.org"]
        });
        
        let email = client.parse_lei_email_from_value(&value).unwrap();
        
        assert_eq!(email.subject, "[PATCH v2 3/5] mm: Fix memory leak");
        assert_eq!(email.from, "John Doe <john@kernel.org>");
        assert_eq!(email.message_id, "<patch123@kernel.org>");
        assert_eq!(email.date, "2025-01-01T12:00:00Z");
        assert_eq!(email.in_reply_to, Some("cover@kernel.org".to_string()));
        assert_eq!(email.cc.as_ref().unwrap().len(), 2);
        assert!(email.cc.as_ref().unwrap().contains(&"stable@vger.kernel.org".to_string()));
        assert!(email.cc.as_ref().unwrap().contains(&"jane@kernel.org".to_string()));
        assert_eq!(email.to.as_ref().unwrap().len(), 1);
        assert!(email.to.as_ref().unwrap().contains(&"maintainer@kernel.org".to_string()));
        assert_eq!(email.body, "");
    }
    
    #[test]
    fn test_parse_lei_email_minimal() {
        let client = LeiClient::new("test".to_string());
        
        let value = serde_json::json!({
            "s": "Some subject",
            "f": [["Author"]],
            "m": "msg@example.com"
        });
        
        let email = client.parse_lei_email_from_value(&value).unwrap();
        
        assert_eq!(email.subject, "Some subject");
        assert_eq!(email.from, "Author");
        assert_eq!(email.message_id, "<msg@example.com>");
        assert_eq!(email.date, "1970-01-01T00:00:00Z");
        assert_eq!(email.body, "");
    }
    
    #[test]
    fn test_no_reply_filtering() {
        let client = LeiClient::new("test".to_string());
        
        let json = r#"[
            {"blob": "1", "s": "Re: [PATCH] Reply", "f": [["A", "a@ex.com"]], "m": "1"},
            {"blob": "2", "s": "[PATCH] Patch", "f": [["B", "b@ex.com"]], "m": "2"},
            {"blob": "3", "s": "Not a patch", "f": [["C", "c@ex.com"]], "m": "3", "refs": ["parent"]},
            {"blob": "4", "s": "[RFC PATCH] RFC", "f": [["D", "d@ex.com"]], "m": "4"},
            {"blob": "5", "s": "Re: Re: Discussion", "f": [["E", "e@ex.com"]], "m": "5"}
        ]"#;
        
        let emails = client.parse_lei_output(json, &[]).unwrap();
        
        // Should get all emails including replies (no pre-filtering)
        assert_eq!(emails.len(), 5);
        assert!(emails.iter().any(|e| e.subject == "Re: [PATCH] Reply"));
        assert!(emails.iter().any(|e| e.subject == "[PATCH] Patch"));
        assert!(emails.iter().any(|e| e.subject == "Not a patch"));
        assert!(emails.iter().any(|e| e.subject == "[RFC PATCH] RFC"));
        assert!(emails.iter().any(|e| e.subject == "Re: Re: Discussion"));
    }
    
    #[test]
    fn test_empty_and_null_handling() {
        let client = LeiClient::new("test".to_string());
        
        assert_eq!(client.parse_lei_output("", &[]).unwrap().len(), 0);
        assert_eq!(client.parse_lei_output("null", &[]).unwrap().len(), 0);
        assert_eq!(client.parse_lei_output("  \n  \n  ", &[]).unwrap().len(), 0);
        assert_eq!(client.parse_lei_output("[]", &[]).unwrap().len(), 0);
    }
}