use regex::Regex;
use std::cmp::Ordering;
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};

use crate::error::{MailbotError, Result as MailbotResult};

lazy_static! {
    static ref VERSION_PATTERN: Regex = Regex::new(r"(\d+)\.(\d+)(?:\.(\d+))?").unwrap();
    static ref VERSION_RANGE_PATTERN: Regex = Regex::new(
        r"(^|[^0-9.])(v)?(\d+\.\d+)(\.y)?-(v)?(\d+\.\d+)(\.y)?([^0-9.]|$)"
    ).unwrap();
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: Option<u32>,
}

impl KernelVersion {
    /// Parse a kernel version string
    pub fn parse(version: &str) -> MailbotResult<Self> {
        if let Some(captures) = VERSION_PATTERN.captures(version) {
            let major = captures.get(1).unwrap().as_str().parse::<u32>()
                .map_err(|_| MailbotError::InvalidKernelVersion(version.to_string()))?;
            let minor = captures.get(2).unwrap().as_str().parse::<u32>()
                .map_err(|_| MailbotError::InvalidKernelVersion(version.to_string()))?;
            let patch = captures.get(3).and_then(|m| m.as_str().parse::<u32>().ok());
            
            Ok(Self { major, minor, patch })
        } else {
            Err(MailbotError::InvalidKernelVersion(version.to_string()))
        }
    }
    
    
    /// Get stable branch name
    pub fn stable_branch(&self) -> String {
        format!("origin/linux-{}.{}.y", self.major, self.minor)
    }
    
}

impl PartialOrd for KernelVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for KernelVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => match (&self.patch, &other.patch) {
                    (Some(a), Some(b)) => a.cmp(b),
                    (Some(_), None) => Ordering::Greater,
                    (None, Some(_)) => Ordering::Less,
                    (None, None) => Ordering::Equal,
                },
                other => other,
            },
            other => other,
        }
    }
}

impl fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(patch) = self.patch {
            write!(f, "{}.{}.{}", self.major, self.minor, patch)
        } else {
            write!(f, "{}.{}", self.major, self.minor)
        }
    }
}

impl FromStr for KernelVersion {
    type Err = MailbotError;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

pub struct KernelVersionManager {
    active_versions: Vec<KernelVersion>,
}

impl KernelVersionManager {
    /// Load active kernel versions from file
    pub fn load<P: AsRef<Path>>(path: P) -> MailbotResult<Self> {
        let contents = fs::read_to_string(path)?;
        let versions: Vec<KernelVersion> = contents
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| KernelVersion::parse(line.trim()))
            .collect::<Result<Vec<_>, _>>()?;
        
        Ok(Self {
            active_versions: versions,
        })
    }
    
    /// Extract kernel versions from email subject
    pub fn extract_versions_from_subject(&self, subject: &str) -> Vec<KernelVersion> {
        let mut found_versions = Vec::new();
        
        // First check for version ranges
        if let Some(captures) = VERSION_RANGE_PATTERN.captures(subject) {
            if let (Ok(v1), Ok(v2)) = (
                KernelVersion::parse(captures.get(3).unwrap().as_str()),
                KernelVersion::parse(captures.get(6).unwrap().as_str())
            ) {
                let (start, end) = if v1 <= v2 { (v1, v2) } else { (v2, v1) };
                
                // Find all versions in the range
                for version in &self.active_versions {
                    if *version >= start && *version <= end {
                        found_versions.push(version.clone());
                    }
                }
            }
        }
        
        // If no range found, check for individual versions
        if found_versions.is_empty() {
            for version in &self.active_versions {
                let patterns = vec![
                    format!(r"(^|[^0-9.]){}(\.y)?([^0-9.]|$)", regex::escape(&version.to_string())),
                    format!(r"(^|[\s\[]|)v{}(\.y)?([^0-9.]|$)", regex::escape(&version.to_string())),
                ];
                
                for pattern in patterns {
                    if let Ok(re) = Regex::new(&pattern) {
                        if re.is_match(subject) {
                            found_versions.push(version.clone());
                            break;
                        }
                    }
                }
            }
        }
        
        // Remove duplicates and sort
        found_versions.sort();
        found_versions.dedup();
        found_versions
    }
    
    /// Get versions newer than the given version
    pub fn get_newer_versions(&self, version: &KernelVersion) -> Vec<KernelVersion> {
        self.active_versions
            .iter()
            .filter(|v| *v > version)
            .cloned()
            .collect()
    }
    
    /// Get default versions (all active) if none specified
    pub fn default_versions(&self) -> Vec<KernelVersion> {
        self.active_versions.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_kernel_version_parse() {
        let v1 = KernelVersion::parse("5.10").unwrap();
        assert_eq!(v1.major, 5);
        assert_eq!(v1.minor, 10);
        assert_eq!(v1.patch, None);
        
        let v2 = KernelVersion::parse("6.1.52").unwrap();
        assert_eq!(v2.major, 6);
        assert_eq!(v2.minor, 1);
        assert_eq!(v2.patch, Some(52));
    }
    
    #[test]
    fn test_kernel_version_ordering() {
        let v1 = KernelVersion::parse("5.10").unwrap();
        let v2 = KernelVersion::parse("5.15").unwrap();
        let v3 = KernelVersion::parse("6.1").unwrap();
        let v4 = KernelVersion::parse("5.10.1").unwrap();
        
        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v4);
    }
    
    #[test]
    fn test_extract_versions_from_subject() {
        use tempfile::NamedTempFile;
        use std::io::Write;
        
        // Create a temporary file with test versions
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "5.10\n5.15\n6.1\n6.6").unwrap();
        
        let manager = KernelVersionManager::load(file.path()).unwrap();
        
        // Test single version
        let versions = manager.extract_versions_from_subject("[PATCH 5.15] Fix something");
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].to_string(), "5.15");
        
        // Test version range
        let versions = manager.extract_versions_from_subject("[PATCH 5.10-6.1] Fix something");
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].to_string(), "5.10");
        assert_eq!(versions[1].to_string(), "5.15");
        assert_eq!(versions[2].to_string(), "6.1");
    }
    
    #[test]
    fn test_version_with_v_prefix() {
        use tempfile::NamedTempFile;
        use std::io::Write;
        
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "5.10\n5.15\n6.1").unwrap();
        
        let manager = KernelVersionManager::load(file.path()).unwrap();
        
        // Test with v prefix
        let versions = manager.extract_versions_from_subject("[PATCH v5.15] Fix");
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].to_string(), "5.15");
        
        // Test with .y suffix
        let versions = manager.extract_versions_from_subject("[PATCH 5.10.y] Fix");
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].to_string(), "5.10");
        
        // Test range with v prefix and .y suffix
        let versions = manager.extract_versions_from_subject("[PATCH v5.10.y-v6.1.y] Fix");
        assert_eq!(versions.len(), 3);
    }
    
    #[test]
    fn test_get_newer_versions() {
        use tempfile::NamedTempFile;
        use std::io::Write;
        
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "5.10\n5.15\n6.1\n6.6").unwrap();
        
        let manager = KernelVersionManager::load(file.path()).unwrap();
        let v5_15 = KernelVersion::parse("5.15").unwrap();
        
        let newer = manager.get_newer_versions(&v5_15);
        assert_eq!(newer.len(), 2);
        assert_eq!(newer[0].to_string(), "6.1");
        assert_eq!(newer[1].to_string(), "6.6");
    }
    
    #[test]
    fn test_stable_branch_name() {
        let version = KernelVersion::parse("5.10").unwrap();
        assert_eq!(version.stable_branch(), "origin/linux-5.10.y");
    }
    
    #[test]
    fn test_invalid_version_parsing() {
        assert!(KernelVersion::parse("invalid").is_err());
        assert!(KernelVersion::parse("5").is_err());
        assert!(KernelVersion::parse("5.").is_err());
        assert!(KernelVersion::parse("").is_err());
    }
    
    #[test]
    fn test_version_range_edge_cases() {
        use tempfile::NamedTempFile;
        use std::io::Write;
        
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "5.10\n5.15\n6.1\n6.6").unwrap();
        
        let manager = KernelVersionManager::load(file.path()).unwrap();
        
        // Test reverse range (should still work)
        let versions = manager.extract_versions_from_subject("[PATCH 6.1-5.10] Fix");
        assert_eq!(versions.len(), 3);
        
        // Test no matching versions
        let versions = manager.extract_versions_from_subject("[PATCH] Fix without version");
        assert_eq!(versions.len(), 0);
        
        // Test non-existent version
        let versions = manager.extract_versions_from_subject("[PATCH 7.0] Fix");
        assert_eq!(versions.len(), 0);
    }
}