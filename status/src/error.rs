use thiserror::Error;

#[derive(Error, Debug)]
pub enum MailbotError {
    #[error("Git error: {0}")]
    Git(#[from] git2::Error),
    
    #[error("Email parsing error: {0}")]
    EmailParse(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Series error: {0}")]
    Series(String),
    
    #[error("Patch validation error: {0}")]
    PatchValidation(String),
    
    #[error("Build error: {0}")]
    Build(String),
    
    
    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Invalid kernel version: {0}")]
    InvalidKernelVersion(String),
    
    #[error("Worktree error: {0}")]
    Worktree(String),
    
    #[error("External command error: {0}")]
    External(String),
    
    #[error("Tracking error: {0}")]
    TrackingError(String),
    
    #[error("File read error: {0}: {1}")]
    FileReadError(std::path::PathBuf, std::io::Error),
    
    #[error("File write error: {0}: {1}")]
    FileWriteError(std::path::PathBuf, std::io::Error),
    
    #[error("JSON parse error: {0}")]
    JsonParseError(serde_json::Error),
    
    #[error("JSON serialize error: {0}")]
    JsonSerializeError(serde_json::Error),
}

pub type Result<T> = std::result::Result<T, MailbotError>;