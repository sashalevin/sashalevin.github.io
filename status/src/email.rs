use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use lazy_static::lazy_static;

use crate::config::Config;
use crate::error::{MailbotError, Result as MailbotResult};

lazy_static! {
    static ref PATCH_PATTERN: Regex = Regex::new(r"\[PATCH[^\]]*\]").unwrap();
    static ref SERIES_PATTERN: Regex = Regex::new(r"\[PATCH[^\]]*\s+(\d+)/(\d+)\]").unwrap();
    static ref DIFF_PATTERN: Regex = Regex::new(r"(?m)^diff --git").unwrap();
    static ref INDEX_PATTERN: Regex = Regex::new(r"(?m)^index [0-9a-f]").unwrap();
    static ref UTF8_PATTERN: Regex = Regex::new(r"=\?UTF-8\?[BQ]\?[^?]+\?=").unwrap();
}

/// Lei JSON email structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeiEmail {
    pub subject: String,
    pub from: String,
    #[serde(rename = "message-id")]
    pub message_id: String,
    #[serde(rename = "in-reply-to")]
    pub in_reply_to: Option<String>,
    pub date: String,
    pub body: String,
    pub headers: Option<serde_json::Value>,
    
    // Additional fields that lei might include
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Vec<String>>,
}

impl LeiEmail {
    /// Load email from lei JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> MailbotResult<Self> {
        let contents = fs::read_to_string(path)?;
        let email: LeiEmail = serde_json::from_str(&contents)
            .map_err(|e| MailbotError::EmailParse(format!("Failed to parse lei JSON: {e}")))?;
        Ok(email)
    }
    
    /// Load email from maildir file
    pub fn from_maildir<P: AsRef<Path>>(path: P) -> MailbotResult<Self> {
        let content = fs::read_to_string(path)?;
        Self::parse_rfc822(&content)
    }
    
    /// Parse RFC822 email format
    fn parse_rfc822(content: &str) -> MailbotResult<Self> {
        let mut headers = Vec::new();
        let mut body = String::new();
        let mut in_body = false;
        
        for line in content.lines() {
            if !in_body && line.is_empty() {
                in_body = true;
                continue;
            }
            
            if in_body {
                body.push_str(line);
                body.push('\n');
            } else {
                headers.push(line.to_string());
            }
        }
        
        // Parse headers
        let mut subject = String::new();
        let mut from = String::new();
        let mut message_id = String::new();
        let mut in_reply_to = None;
        let mut date = String::new();
        let mut references = None;
        let mut cc = None;
        let mut to = None;
        
        let mut current_header = String::new();
        for line in headers.iter() {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation of previous header
                current_header.push(' ');
                current_header.push_str(line.trim());
            } else {
                // Process previous header if any
                if !current_header.is_empty() {
                    Self::process_header(&current_header, &mut subject, &mut from, &mut message_id,
                                       &mut in_reply_to, &mut date, &mut references, &mut cc, &mut to);
                }
                current_header = line.to_string();
            }
        }
        // Process last header
        if !current_header.is_empty() {
            Self::process_header(&current_header, &mut subject, &mut from, &mut message_id,
                               &mut in_reply_to, &mut date, &mut references, &mut cc, &mut to);
        }
        
        Ok(LeiEmail {
            subject,
            from,
            message_id,
            in_reply_to,
            date,
            body: body.trim().to_string(),
            headers: Some(serde_json::json!(headers)),
            references,
            cc,
            to,
        })
    }
    
    #[allow(clippy::too_many_arguments)]
    fn process_header(header: &str, subject: &mut String, from: &mut String, message_id: &mut String,
                     in_reply_to: &mut Option<String>, date: &mut String, references: &mut Option<String>,
                     cc: &mut Option<Vec<String>>, to: &mut Option<Vec<String>>) {
        if let Some(pos) = header.find(':') {
            let (name, value) = header.split_at(pos);
            let name = name.trim().to_lowercase();
            let value = value[1..].trim(); // Skip the colon
            
            match name.as_str() {
                "subject" => *subject = Self::decode_mime_header(value),
                "from" => *from = Self::decode_mime_header(value),
                "message-id" => *message_id = value.to_string(),
                "in-reply-to" => *in_reply_to = Some(value.to_string()),
                "date" => *date = value.to_string(),
                "references" => {
                    *references = Some(value.to_string());
                }
                "cc" => {
                    *cc = Some(value.split(',')
                        .map(|s| s.trim().to_string())
                        .collect());
                }
                "to" => {
                    *to = Some(value.split(',')
                        .map(|s| s.trim().to_string())
                        .collect());
                }
                _ => {}
            }
        }
    }
    
    /// Check if we should ignore this email based on sender
    pub fn should_ignore(&self, config: &Config) -> bool {
        for ignored in &config.ignored_authors {
            if self.from.contains(ignored) {
                return true;
            }
        }
        false
    }
    
    /// Check if this email contains a git patch
    pub fn is_git_patch(&self) -> bool {
        // Check for [PATCH] in subject
        if !PATCH_PATTERN.is_match(&self.subject) {
            return false;
        }
        
        // Check for patch content in body
        let has_separator = self.body.contains("\n---\n");
        let has_diff = DIFF_PATTERN.is_match(&self.body);
        let has_index = INDEX_PATTERN.is_match(&self.body);
        
        has_separator && (has_diff || has_index)
    }
    
    /// Extract series information from subject if present
    pub fn extract_series_info(&self) -> Option<(u32, u32)> {
        if let Some(captures) = SERIES_PATTERN.captures(&self.subject) {
            let current = captures.get(1)?.as_str().parse::<u32>().ok()?;
            let total = captures.get(2)?.as_str().parse::<u32>().ok()?;
            Some((current, total))
        } else {
            None
        }
    }
    
    /// Decode UTF-8 MIME encoded text
    pub fn decode_mime_header(text: &str) -> String {
        let mut result = text.to_string();
        
        while let Some(mat) = UTF8_PATTERN.find(&result) {
            let encoded = mat.as_str();
            let decoded = decode_mime_part(encoded).unwrap_or_else(|| encoded.to_string());
            result.replace_range(mat.range(), &decoded);
        }
        
        result
    }
    
    /// Get clean subject (remove [PATCH] tags, etc)
    pub fn clean_subject(&self) -> String {
        let mut subject = self.subject.clone();
        
        // Special handling for FAILED patch subjects
        if let Some(start) = subject.find("FAILED:") {
            if let Some(quote_start) = subject[start..].find('"') {
                if let Some(quote_end) = subject[start + quote_start + 1..].find('"') {
                    return subject[start + quote_start + 1..start + quote_start + 1 + quote_end].to_string();
                }
            }
        }
        
        // Remove [PATCH] tags and similar
        subject = PATCH_PATTERN.replace_all(&subject, "").to_string();
        
        // Remove Re: prefix
        if subject.starts_with("Re:") {
            subject = subject[3..].trim().to_string();
        }
        
        subject.trim().to_string()
    }
    
    /// Get normalized author/from string
    pub fn normalized_from(&self) -> String {
        let from = Self::decode_mime_header(&self.from);
        
        // Remove extra quotes and normalize whitespace
        from.trim_matches('"')
            .replace("  ", " ")
            .trim()
            .to_string()
    }
    
    /// Extract email address from From field
    pub fn extract_email_address(&self) -> Option<String> {
        let from = &self.from;
        
        // Look for email in angle brackets
        if let Some(start) = from.find('<') {
            if let Some(end) = from.find('>') {
                return Some(from[start + 1..end].to_string());
            }
        }
        
        // If no angle brackets, assume the whole thing is an email
        if from.contains('@') {
            Some(from.trim().to_string())
        } else {
            None
        }
    }
}

fn decode_mime_part(encoded: &str) -> Option<String> {
    // Parse =?UTF-8?B?...?= or =?UTF-8?Q?...?=
    let parts: Vec<&str> = encoded.trim_matches('=').trim_matches('?').split('?').collect();
    
    if parts.len() != 3 {
        return None;
    }
    
    let charset = parts[0];
    let encoding = parts[1];
    let encoded_text = parts[2];
    
    if charset != "UTF-8" {
        return None;
    }
    
    match encoding {
        "B" | "b" => {
            // Base64 encoding
            use base64::{Engine as _, engine::general_purpose};
            general_purpose::STANDARD.decode(encoded_text)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        }
        "Q" | "q" => {
            // Quoted-printable encoding
            decode_quoted_printable(encoded_text)
        }
        _ => None,
    }
}

fn decode_quoted_printable(text: &str) -> Option<String> {
    let mut result = String::new();
    let mut chars = text.chars().peekable();
    
    while let Some(ch) = chars.next() {
        if ch == '=' {
            if let (Some(h1), Some(h2)) = (chars.next(), chars.next()) {
                if let Ok(byte) = u8::from_str_radix(&format!("{h1}{h2}"), 16) {
                    result.push(byte as char);
                } else {
                    // Invalid hex sequence
                    result.push('=');
                    result.push(h1);
                    result.push(h2);
                }
            } else {
                result.push('=');
            }
        } else if ch == '_' {
            result.push(' ');
        } else {
            result.push(ch);
        }
    }
    
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_decode_mime_header() {
        let encoded = "=?UTF-8?B?VGVzdCBTdWJqZWN0?=";
        let decoded = LeiEmail::decode_mime_header(encoded);
        assert_eq!(decoded, "Test Subject");
        
        let encoded = "=?UTF-8?Q?Test_Subject?=";
        let decoded = LeiEmail::decode_mime_header(encoded);
        assert_eq!(decoded, "Test Subject");
    }
    
    #[test]
    fn test_series_info_extraction() {
        let email = LeiEmail {
            subject: "[PATCH 02/10] Some patch".to_string(),
            from: "test@example.com".to_string(),
            message_id: "<123@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        
        assert_eq!(email.extract_series_info(), Some((2, 10)));
    }
    
    #[test]
    fn test_is_git_patch() {
        let email = LeiEmail {
            subject: "[PATCH] Fix something".to_string(),
            from: "test@example.com".to_string(),
            message_id: "<123@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "Some description\n---\ndiff --git a/file.c b/file.c\nindex 123..456".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        
        assert!(email.is_git_patch());
    }
    
    #[test]
    fn test_is_not_git_patch() {
        // No [PATCH] in subject
        let email = LeiEmail {
            subject: "Fix something".to_string(),
            from: "test@example.com".to_string(),
            message_id: "<123@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "Some description\n---\ndiff --git a/file.c b/file.c".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        assert!(!email.is_git_patch());
        
        // No patch content
        let email2 = LeiEmail {
            subject: "[PATCH] Fix something".to_string(),
            from: "test@example.com".to_string(),
            message_id: "<123@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "Just some text without patch content".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        assert!(!email2.is_git_patch());
    }
    
    #[test]
    fn test_clean_subject() {
        let email = LeiEmail {
            subject: "[PATCH v2 3/5] net: Fix buffer overflow".to_string(),
            from: "test@example.com".to_string(),
            message_id: "<123@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        assert_eq!(email.clean_subject(), "net: Fix buffer overflow");
        
        // Test FAILED patch subject
        let email2 = LeiEmail {
            subject: "FAILED: patch \"drm/i915: Fix crash\" failed to apply".to_string(),
            from: "test@example.com".to_string(),
            message_id: "<123@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        assert_eq!(email2.clean_subject(), "drm/i915: Fix crash");
    }
    
    #[test]
    fn test_extract_email_address() {
        let email = LeiEmail {
            subject: "".to_string(),
            from: "John Doe <john@example.com>".to_string(),
            message_id: "<123@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        assert_eq!(email.extract_email_address(), Some("john@example.com".to_string()));
        
        let email2 = LeiEmail {
            subject: "".to_string(),
            from: "plain@email.com".to_string(),
            message_id: "<123@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        assert_eq!(email2.extract_email_address(), Some("plain@email.com".to_string()));
    }
    
    #[test]
    fn test_should_ignore() {
        let config = crate::config::Config::default();
        
        let email = LeiEmail {
            subject: "[PATCH] Fix".to_string(),
            from: "Greg Kroah-Hartman <gregkh@kernel.org>".to_string(),
            message_id: "<123@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        assert!(email.should_ignore(&config));
        
        let email2 = LeiEmail {
            subject: "[PATCH] Fix".to_string(),
            from: "Random Developer <dev@example.com>".to_string(),
            message_id: "<123@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        assert!(!email2.should_ignore(&config));
    }
    
    #[test]
    fn test_parse_rfc822() {
        let rfc822_content = r#"From: John Doe <john@example.com>
Subject: [PATCH] Fix memory leak
Message-ID: <123456@example.com>
Date: Mon, 1 Jan 2024 10:00:00 +0000
In-Reply-To: <789@example.com>
References: <456@example.com> <789@example.com>
To: linux-stable@vger.kernel.org
Cc: maintainer@example.com, reviewer@example.com

This patch fixes a memory leak in the driver.

Signed-off-by: John Doe <john@example.com>
---
 drivers/example/driver.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/drivers/example/driver.c b/drivers/example/driver.c
index 1234567..abcdefg 100644
--- a/drivers/example/driver.c
+++ b/drivers/example/driver.c
@@ -100,6 +100,7 @@ static int example_probe(struct platform_device *pdev)
 	if (!data)
 		return -ENOMEM;
 
+	kfree(data);
 	return 0;
 }
"#;
        
        let email = LeiEmail::parse_rfc822(rfc822_content).unwrap();
        
        assert_eq!(email.subject, "[PATCH] Fix memory leak");
        assert_eq!(email.from, "John Doe <john@example.com>");
        assert_eq!(email.message_id, "<123456@example.com>");
        assert_eq!(email.in_reply_to, Some("<789@example.com>".to_string()));
        assert_eq!(email.date, "Mon, 1 Jan 2024 10:00:00 +0000");
        assert!(email.body.contains("This patch fixes a memory leak"));
        assert!(email.body.contains("diff --git"));
        
        // Check references parsing
        assert!(email.references.is_some());
        let refs = email.references.unwrap();
        assert_eq!(refs, "<456@example.com> <789@example.com>");
        
        // Check to/cc parsing
        assert!(email.to.is_some());
        assert_eq!(email.to.unwrap()[0], "linux-stable@vger.kernel.org");
        
        assert!(email.cc.is_some());
        let cc = email.cc.unwrap();
        assert_eq!(cc.len(), 2);
        assert_eq!(cc[0], "maintainer@example.com");
        assert_eq!(cc[1], "reviewer@example.com");
    }
    
    #[test]
    fn test_parse_rfc822_multiline_headers() {
        let rfc822_content = r#"From: Very Long Name That Continues
 On Next Line <long@example.com>
Subject: [PATCH] This is a very long subject that
 continues on the next line
Message-ID: <123@example.com>
Date: Mon, 1 Jan 2024 10:00:00 +0000

Test body
"#;
        
        let email = LeiEmail::parse_rfc822(rfc822_content).unwrap();
        
        assert_eq!(email.from, "Very Long Name That Continues On Next Line <long@example.com>");
        assert_eq!(email.subject, "[PATCH] This is a very long subject that continues on the next line");
    }
}