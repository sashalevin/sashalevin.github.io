use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

use crate::email::LeiEmail;
use crate::error::{MailbotError, Result as MailbotResult};

pub struct SeriesManager {
    pending_dir: PathBuf,
}

#[derive(Debug)]
pub struct SeriesInfo {
    pub series_id: String,
    pub series_dir: PathBuf,
    #[allow(dead_code)]
    pub total_parts: u32,
}

impl SeriesManager {
    pub fn new(pending_dir: PathBuf) -> Self {
        Self { pending_dir }
    }
    
    /// Store a patch in a series directory
    pub fn store_patch(&self, email: &LeiEmail, part: u32, total: u32) -> MailbotResult<()> {
        let series_info = self.get_series_info(email)?;
        
        // Create series directory if it doesn't exist
        fs::create_dir_all(&series_info.series_dir)?;
        
        // Save patch with part number
        let patch_path = series_info.series_dir.join(format!("{part}.json"));
        let json_content = serde_json::to_string_pretty(email)?;
        fs::write(&patch_path, json_content)?;
        
        // Create symlink for backward compatibility
        let symlink_path = series_info.series_dir.join(format!("{part}.mbox"));
        if symlink_path.exists() {
            fs::remove_file(&symlink_path)?;
        }
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let _ = symlink(&patch_path, &symlink_path);
        }
        
        // Store series metadata
        let metadata_path = series_info.series_dir.join("metadata.json");
        let metadata = SeriesMetadata {
            total_parts: total,
            series_id: series_info.series_id.clone(),
            first_message_id: email.message_id.clone(),
        };
        let metadata_json = serde_json::to_string_pretty(&metadata)?;
        fs::write(metadata_path, metadata_json)?;
        
        info!("Stored patch {}/{} for series {}", part, total, series_info.series_id);
        Ok(())
    }
    
    /// Check if a series is complete
    pub fn is_series_complete(&self, email: &LeiEmail, total: u32) -> MailbotResult<bool> {
        let series_info = self.get_series_info(email)?;
        
        if !series_info.series_dir.exists() {
            return Ok(false);
        }
        
        // Check if all parts exist
        for i in 1..=total {
            let patch_path = series_info.series_dir.join(format!("{i}.json"));
            if !patch_path.exists() {
                debug!("Missing part {} of series {}", i, series_info.series_id);
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Get all patches in a series
    pub fn get_series_patches(&self, email: &LeiEmail, total: u32) -> MailbotResult<Vec<LeiEmail>> {
        let series_info = self.get_series_info(email)?;
        let mut patches = Vec::new();
        
        for i in 1..=total {
            let patch_path = series_info.series_dir.join(format!("{i}.json"));
            let content = fs::read_to_string(&patch_path)?;
            let patch_email: LeiEmail = serde_json::from_str(&content)?;
            
            patches.push(patch_email);
        }
        
        Ok(patches)
    }
    
    /// Get the first patch in a series
    pub fn get_first_patch(&self, email: &LeiEmail) -> MailbotResult<LeiEmail> {
        let series_info = self.get_series_info(email)?;
        let patch_path = series_info.series_dir.join("1.json");
        let content = fs::read_to_string(&patch_path)?;
        let patch_email: LeiEmail = serde_json::from_str(&content)?;
        Ok(patch_email)
    }
    
    /// Clean up a completed series
    pub fn cleanup_series(&self, email: &LeiEmail) -> MailbotResult<()> {
        let series_info = self.get_series_info(email)?;
        
        if series_info.series_dir.exists() {
            fs::remove_dir_all(&series_info.series_dir)?;
            info!("Cleaned up series directory: {:?}", series_info.series_dir);
        }
        
        Ok(())
    }
    
    /// Get series information from email
    fn get_series_info(&self, email: &LeiEmail) -> MailbotResult<SeriesInfo> {
        // Determine series ID from message ID and in-reply-to
        let series_id = if let Some(ref reply_to) = email.in_reply_to {
            // Use the first message's ID
            self.clean_message_id(reply_to)
        } else {
            // This is the first message
            self.clean_message_id(&email.message_id)
        };
        
        let series_dir = self.pending_dir.join(&series_id);
        
        // Try to get total parts from existing metadata
        let total_parts = if let Ok(metadata) = self.load_metadata(&series_dir) {
            metadata.total_parts
        } else if let Some((_, total)) = email.extract_series_info() {
            total
        } else {
            return Err(MailbotError::Series("Cannot determine total parts for series".to_string()));
        };
        
        Ok(SeriesInfo {
            series_id,
            series_dir,
            total_parts,
        })
    }
    
    /// Clean message ID for use as directory name
    fn clean_message_id(&self, message_id: &str) -> String {
        message_id
            .trim_matches('<')
            .trim_matches('>')
            .chars()
            .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect()
    }
    
    /// Load series metadata
    fn load_metadata(&self, series_dir: &Path) -> MailbotResult<SeriesMetadata> {
        let metadata_path = series_dir.join("metadata.json");
        if metadata_path.exists() {
            let content = fs::read_to_string(metadata_path)?;
            let metadata: SeriesMetadata = serde_json::from_str(&content)?;
            Ok(metadata)
        } else {
            Err(MailbotError::Series("Metadata file not found".to_string()))
        }
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SeriesMetadata {
    total_parts: u32,
    series_id: String,
    first_message_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_clean_message_id() {
        let manager = SeriesManager::new(PathBuf::from("/tmp"));
        
        assert_eq!(
            manager.clean_message_id("<123@example.com>"),
            "123_example_com"
        );
        
        assert_eq!(
            manager.clean_message_id("<test-patch@kernel.org>"),
            "test-patch_kernel_org"
        );
    }
    
    #[test]
    fn test_series_storage() {
        let dir = tempdir().unwrap();
        let manager = SeriesManager::new(dir.path().to_path_buf());
        
        let email = LeiEmail {
            subject: "[PATCH 1/3] Test patch".to_string(),
            from: "test@example.com".to_string(),
            message_id: "<123@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "Test patch content".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        
        // Store first patch
        manager.store_patch(&email, 1, 3).unwrap();
        
        // Check series is not complete
        assert!(!manager.is_series_complete(&email, 3).unwrap());
        
        // Store remaining patches
        manager.store_patch(&email, 2, 3).unwrap();
        manager.store_patch(&email, 3, 3).unwrap();
        
        // Check series is complete
        assert!(manager.is_series_complete(&email, 3).unwrap());
        
        // Clean up
        manager.cleanup_series(&email).unwrap();
    }
    
    #[test]
    fn test_series_with_reply_to() {
        let dir = tempdir().unwrap();
        let manager = SeriesManager::new(dir.path().to_path_buf());
        
        // First email in series
        let _first_email = LeiEmail {
            subject: "[PATCH 0/3] Cover letter".to_string(),
            from: "test@example.com".to_string(),
            message_id: "<first@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "Cover letter".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        
        // Reply to first email
        let second_email = LeiEmail {
            subject: "[PATCH 1/3] First patch".to_string(),
            from: "test@example.com".to_string(),
            message_id: "<second@example.com>".to_string(),
            in_reply_to: Some("<first@example.com>".to_string()),
            date: "2024-01-01".to_string(),
            body: "First patch".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        
        // Store second email - should use first email's ID as series ID
        manager.store_patch(&second_email, 1, 3).unwrap();
        
        // Verify series directory was created with first email's ID
        let series_info = manager.get_series_info(&second_email).unwrap();
        assert!(series_info.series_id.contains("first_example_com"));
    }
    
    #[test]
    fn test_series_incomplete() {
        let dir = tempdir().unwrap();
        let manager = SeriesManager::new(dir.path().to_path_buf());
        
        let email = LeiEmail {
            subject: "[PATCH 1/5] Test".to_string(),
            from: "test@example.com".to_string(),
            message_id: "<test@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "Test".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        
        // Store only first patch
        manager.store_patch(&email, 1, 5).unwrap();
        
        // Check completeness for different totals
        assert!(!manager.is_series_complete(&email, 5).unwrap());
        assert!(manager.is_series_complete(&email, 1).unwrap()); // Only 1 patch expected
        
        // Store more patches
        manager.store_patch(&email, 2, 5).unwrap();
        manager.store_patch(&email, 3, 5).unwrap();
        assert!(!manager.is_series_complete(&email, 5).unwrap());
        
        // Complete the series
        manager.store_patch(&email, 4, 5).unwrap();
        manager.store_patch(&email, 5, 5).unwrap();
        assert!(manager.is_series_complete(&email, 5).unwrap());
    }
    
    #[test]
    fn test_get_series_patches() {
        let dir = tempdir().unwrap();
        let manager = SeriesManager::new(dir.path().to_path_buf());
        
        // Create a series
        for i in 1..=3 {
            let email = LeiEmail {
                subject: format!("[PATCH {i}/3] Part {i}"),
                from: "test@example.com".to_string(),
                message_id: format!("<part{i}@example.com>"),
                in_reply_to: if i == 1 { None } else { Some("<part1@example.com>".to_string()) },
                date: "2024-01-01".to_string(),
                body: format!("Content of part {i}"),
                headers: None,
                references: None,
                cc: None,
                to: None,
            };
            manager.store_patch(&email, i as u32, 3).unwrap();
        }
        
        // Get all patches
        let first_email = LeiEmail {
            subject: "[PATCH 1/3] Part 1".to_string(),
            from: "test@example.com".to_string(),
            message_id: "<part1@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "Content of part 1".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        
        let patches = manager.get_series_patches(&first_email, 3).unwrap();
        assert_eq!(patches.len(), 3);
        
        // Verify patches are in order
        for (i, patch) in patches.iter().enumerate() {
            assert!(patch.subject.contains(&format!("Part {}", i + 1)));
        }
    }
    
    #[test]
    fn test_series_metadata() {
        let dir = tempdir().unwrap();
        let manager = SeriesManager::new(dir.path().to_path_buf());
        
        let email = LeiEmail {
            subject: "[PATCH 1/2] Test".to_string(),
            from: "test@example.com".to_string(),
            message_id: "<metadata@example.com>".to_string(),
            in_reply_to: None,
            date: "2024-01-01".to_string(),
            body: "Test".to_string(),
            headers: None,
            references: None,
            cc: None,
            to: None,
        };
        
        manager.store_patch(&email, 1, 2).unwrap();
        
        // Load metadata
        let series_info = manager.get_series_info(&email).unwrap();
        let metadata = manager.load_metadata(&series_info.series_dir).unwrap();
        
        assert_eq!(metadata.total_parts, 2);
        assert_eq!(metadata.first_message_id, "<metadata@example.com>");
    }
}