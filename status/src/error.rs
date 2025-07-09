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
}

pub type Result<T> = std::result::Result<T, MailbotError>;