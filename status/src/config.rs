use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the Linux kernel git repository
    pub linux_dir: PathBuf,
    
    /// Path to the stable-queue directory
    pub stable_queue_dir: PathBuf,
    
    /// Path to active kernel versions file
    pub active_versions_file: PathBuf,
    
    /// Path to pending series directory
    pub pending_dir: PathBuf,
    
    /// Path to worktree directory
    pub worktree_dir: PathBuf,
    
    /// Path to output directory for responses
    pub output_dir: PathBuf,
    
    /// Path to tracking JSON file
    pub tracking_file: PathBuf,
    
    /// Authors to ignore (email addresses)
    pub ignored_authors: Vec<String>,
    
    /// Email configuration
    pub email: EmailConfig,
    
    /// Build command template
    pub build_command: String,
    
    /// Enable debug mode
    pub debug: bool,
    
    /// Skip sending emails (dry run mode)
    pub dry_run: bool,
    
    /// Skip build tests
    pub skip_build: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// From address for responses
    pub from: String,
    
    /// Reply-to address
    pub reply_to: Option<String>,
    
    /// SMTP server configuration (if not using sendmail)
    pub smtp: Option<SmtpConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::load_with_validation(path, true)
    }
    
    #[cfg(test)]
    pub fn load_without_validation<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::load_with_validation(path, false)
    }
    
    fn load_with_validation<P: AsRef<Path>>(path: P, validate: bool) -> Result<Self> {
        let expanded_path = expand_tilde(path.as_ref());
        
        // Try to load from file
        let config = if expanded_path.exists() {
            let contents = fs::read_to_string(&expanded_path)?;
            let mut config: Config = serde_json::from_str(&contents)?;
            
            // Expand tildes in all paths
            config.linux_dir = expand_tilde(&config.linux_dir);
            config.stable_queue_dir = expand_tilde(&config.stable_queue_dir);
            config.active_versions_file = expand_tilde(&config.active_versions_file);
            config.pending_dir = expand_tilde(&config.pending_dir);
            config.worktree_dir = expand_tilde(&config.worktree_dir);
            config.output_dir = expand_tilde(&config.output_dir);
            config.tracking_file = expand_tilde(&config.tracking_file);
            
            config
        } else {
            // Return default config if file doesn't exist
            Self::default()
        };
        
        // Validate the configuration if requested
        if validate {
            config.validate()?;
        }
        Ok(config)
    }
    
    /// Validate that all required paths exist and are correct
    pub fn validate(&self) -> Result<()> {
        // Check linux directory exists and has .git
        if !self.linux_dir.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Linux directory not found: {:?}", self.linux_dir)
            ).into());
        }
        if !self.linux_dir.join(".git").exists() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Linux directory is not a git repository: {:?}", self.linux_dir)
            ).into());
        }
        
        // Check stable-queue directory exists
        if !self.stable_queue_dir.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Stable queue directory not found: {:?}", self.stable_queue_dir)
            ).into());
        }
        
        // Check active versions file exists
        if !self.active_versions_file.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Active versions file not found: {:?}", self.active_versions_file)
            ).into());
        }
        
        // Create directories that should exist but might not yet
        if !self.pending_dir.exists() {
            fs::create_dir_all(&self.pending_dir)?;
        }
        if !self.worktree_dir.exists() {
            fs::create_dir_all(&self.worktree_dir)?;
        }
        if !self.output_dir.exists() {
            fs::create_dir_all(&self.output_dir)?;
        }
        
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            linux_dir: PathBuf::from("../linux"),
            stable_queue_dir: PathBuf::from("../stable-queue/scripts"),
            active_versions_file: PathBuf::from("../stable-queue/active_kernel_versions"),
            pending_dir: PathBuf::from("./pending/series"),
            worktree_dir: PathBuf::from("./worktrees"),
            output_dir: PathBuf::from("./output"),
            tracking_file: PathBuf::from("./status/patch_tracking.json"),
            ignored_authors: vec![
                "Sasha Levin".to_string(),
                "Linux Kernel Distribution System".to_string(),
                "Greg Kroah-Hartman".to_string(),
            ],
            email: EmailConfig {
                from: "Sasha Levin <sashal@kernel.org>".to_string(),
                reply_to: None,
                smtp: None,
            },
            build_command: "stable build log".to_string(),
            debug: false,
            dry_run: false,
            skip_build: false,
        }
    }
}

fn expand_tilde<P: AsRef<Path>>(path: P) -> PathBuf {
    let path = path.as_ref();
    if let Some(path_str) = path.to_str() {
        if path_str.starts_with("~") {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(path_str.replacen("~", &home, 1));
            }
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    /// Create a test config that doesn't validate paths
    #[allow(dead_code)]
    fn test_config(dir: &Path) -> Config {
        Config {
            linux_dir: dir.join("linux"),
            stable_queue_dir: dir.join("stable-queue/scripts"),
            active_versions_file: dir.join("stable-queue/active_kernel_versions"),
            pending_dir: dir.join("pending/series"),
            worktree_dir: dir.join("worktrees"),
            output_dir: dir.join("output"),
            tracking_file: dir.join("status/patch_tracking.json"),
            ignored_authors: vec![
                "Test Author".to_string(),
            ],
            email: EmailConfig {
                from: "Test <test@example.com>".to_string(),
                reply_to: None,
                smtp: None,
            },
            build_command: "echo test".to_string(),
            debug: true,
            dry_run: false,
            skip_build: false,
        }
    }
    
    #[test]
    fn test_config_load() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        
        // Test loading default config when file doesn't exist
        let config = Config::load_without_validation(&config_path).unwrap();
        assert_eq!(config.linux_dir, PathBuf::from("../linux"));
        
        // Test loading config from file
        let json = r#"
        {
            "linux_dir": "/custom/linux",
            "stable_queue_dir": "/custom/stable-queue",
            "active_versions_file": "/custom/versions",
            "pending_dir": "/custom/pending",
            "worktree_dir": "/custom/worktrees",
            "output_dir": "/custom/output",
            "tracking_file": "/custom/patch_tracking.json",
            "ignored_authors": ["Test Author"],
            "email": {
                "from": "test@example.com",
                "reply_to": null,
                "smtp": null
            },
            "build_command": "make test",
            "debug": true,
            "dry_run": true,
            "skip_build": false
        }
        "#;
        fs::write(&config_path, json).unwrap();
        
        let loaded = Config::load_without_validation(&config_path).unwrap();
        assert_eq!(loaded.linux_dir, PathBuf::from("/custom/linux"));
        assert!(loaded.debug);
    }
    
    #[test]
    fn test_expand_tilde() {
        unsafe { std::env::set_var("HOME", "/home/test"); }
        assert_eq!(expand_tilde("~/foo"), PathBuf::from("/home/test/foo"));
        assert_eq!(expand_tilde("/absolute/path"), PathBuf::from("/absolute/path"));
    }
}