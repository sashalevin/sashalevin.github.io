use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use chrono::{DateTime, Utc};
use crate::error::{MailbotError as Error, Result};
use tracing::debug;

/// Generate a lore.kernel.org URL from a message ID
pub fn message_id_to_lore_url(message_id: &str) -> String {
    // Remove angle brackets if present
    let clean_id = message_id.trim_start_matches('<').trim_end_matches('>');
    format!("https://lore.kernel.org/stable/{clean_id}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchTracking {
    pub message_id: String,
    pub sha1: Option<String>,
    pub subject: String,
    pub author: String,
    pub from_email: String,
    pub first_seen: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub state: PatchState,
    pub processing_history: Vec<ProcessingEvent>,
    pub mailbot_results: Vec<MailbotResult>,
    pub mailing_list_activity: MailingListActivity,
    pub target_versions: Vec<String>,
    pub lore_url: Option<String>,  // Link to the original patch on lore.kernel.org
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PatchState {
    OnMailingList,           // Initial state when seen on ML
    Processing,              // Currently being processed by mailbot
    IssuesFound(String),     // Mailbot found issues with the patch
    TestsPassed,             // Mailbot tests passed successfully  
    CommentsProvided,        // Feedback/comments have been provided
    Queued,                  // Patch landed in stable-queue.git
    Released,                // Released in a stable kernel version
    Merged(Vec<String>),     // Merged to branches
    Rejected(String),        // Rejected with reason
    Superseded(String),      // Superseded by another patch (message_id)
    Failed(String),          // Processing failed
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: ProcessingEventType,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProcessingEventType {
    Received,
    QueuedForProcessing,
    ProcessingStarted,
    TestCompleted,
    ResponseGenerated,
    Released,
    StateChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailbotResult {
    pub timestamp: DateTime<Utc>,
    pub test_branches: Vec<String>,
    pub test_passed: bool,
    pub build_passed: bool,
    pub errors: Vec<String>,
    pub response_sent: bool,
    pub response_message_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailingListActivity {
    pub replies: Vec<MailingListMessage>,
    pub reviews: Vec<MailingListMessage>,
    pub related_patches: Vec<String>, // message_ids of related patches
    pub fixes_commit: Option<String>,
    pub fixes_cve: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailingListMessage {
    pub message_id: String,
    pub from: String,
    pub subject: String,
    pub timestamp: DateTime<Utc>,
    pub message_type: MessageType,
    pub lore_url: Option<String>,  // Link to this message on lore.kernel.org
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Reply,
    Review,
    Ack,
    Nack,
    TestedBy,
    FailedToApply,  // For FAILED: patch... emails from maintainers
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingStore {
    pub patches: HashMap<String, PatchTracking>,
    pub sha1_index: HashMap<String, Vec<String>>, // sha1 -> [message_ids]
    pub last_updated: DateTime<Utc>,
}

impl TrackingStore {
    pub fn new() -> Self {
        Self {
            patches: HashMap::new(),
            sha1_index: HashMap::new(),
            last_updated: Utc::now(),
        }
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        
        let contents = fs::read_to_string(path)
            .map_err(|e| Error::FileReadError(path.to_path_buf(), e))?;
        
        serde_json::from_str(&contents)
            .map_err(Error::JsonParseError)
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let mut store = self.clone();
        store.last_updated = Utc::now();
        
        let json = serde_json::to_string_pretty(&store)
            .map_err(Error::JsonSerializeError)?;
        
        // Write to temp file first for atomicity
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, json)
            .map_err(|e| Error::FileWriteError(temp_path.clone(), e))?;
        
        fs::rename(&temp_path, path)
            .map_err(|e| Error::FileWriteError(path.to_path_buf(), e))?;
        
        Ok(())
    }

    pub fn add_or_update_patch(&mut self, tracking: PatchTracking) {
        // Update SHA1 index
        if let Some(sha1) = &tracking.sha1 {
            let entries = self.sha1_index.entry(sha1.clone()).or_default();
            if !entries.contains(&tracking.message_id) {
                entries.push(tracking.message_id.clone());
            }
        }
        
        self.patches.insert(tracking.message_id.clone(), tracking);
    }

    pub fn remove_patch(&mut self, message_id: &str) -> Result<()> {
        // Remove from patches map
        if let Some(patch) = self.patches.remove(message_id) {
            // Update sha1_index
            if let Some(sha1) = &patch.sha1 {
                if let Some(ids) = self.sha1_index.get_mut(sha1) {
                    ids.retain(|id| id != message_id);
                    if ids.is_empty() {
                        self.sha1_index.remove(sha1);
                    }
                }
            }
            self.last_updated = Utc::now();
            Ok(())
        } else {
            Err(Error::TrackingError(format!("Patch {message_id} not found")))
        }
    }

    pub fn get_patch(&self, message_id: &str) -> Option<&PatchTracking> {
        self.patches.get(message_id)
    }

    pub fn get_patch_mut(&mut self, message_id: &str) -> Option<&mut PatchTracking> {
        self.patches.get_mut(message_id)
    }

    pub fn find_by_sha1(&self, sha1: &str) -> Vec<&PatchTracking> {
        self.sha1_index.get(sha1)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.patches.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn update_state(&mut self, message_id: &str, new_state: PatchState) -> Result<()> {
        let patch = self.get_patch_mut(message_id)
            .ok_or_else(|| Error::TrackingError(format!("Patch {message_id} not found")))?;
        
        if patch.state != new_state {
            patch.state = new_state.clone();
            patch.last_updated = Utc::now();
            patch.processing_history.push(ProcessingEvent {
                timestamp: Utc::now(),
                event_type: ProcessingEventType::StateChanged,
                details: format!("State changed to: {new_state:?}"),
            });
        }
        
        Ok(())
    }

    pub fn add_processing_event(&mut self, message_id: &str, event: ProcessingEvent) -> Result<()> {
        let patch = self.get_patch_mut(message_id)
            .ok_or_else(|| Error::TrackingError(format!("Patch {message_id} not found")))?;
        
        patch.processing_history.push(event);
        patch.last_updated = Utc::now();
        
        Ok(())
    }

    #[allow(dead_code)]
    pub fn add_mailbot_result(&mut self, message_id: &str, result: MailbotResult) -> Result<()> {
        let patch = self.get_patch_mut(message_id)
            .ok_or_else(|| Error::TrackingError(format!("Patch {message_id} not found")))?;
        
        patch.mailbot_results.push(result);
        patch.last_updated = Utc::now();
        
        Ok(())
    }

    pub fn add_mailing_list_message(&mut self, message_id: &str, ml_message: MailingListMessage) -> Result<()> {
        let patch = self.get_patch_mut(message_id)
            .ok_or_else(|| Error::TrackingError(format!("Patch {message_id} not found")))?;
        
        match ml_message.message_type {
            MessageType::Reply | MessageType::Other => {
                patch.mailing_list_activity.replies.push(ml_message);
            }
            MessageType::Review | MessageType::Ack | MessageType::Nack | MessageType::TestedBy => {
                patch.mailing_list_activity.reviews.push(ml_message);
            }
            MessageType::FailedToApply => {
                // Add to replies and update patch state to Failed
                patch.mailing_list_activity.replies.push(ml_message);
                patch.state = PatchState::Failed("Failed to apply to stable tree".to_string());
            }
        }
        
        patch.last_updated = Utc::now();
        
        Ok(())
    }

    pub fn get_patches_by_state(&self, state: &PatchState) -> Vec<&PatchTracking> {
        self.patches.values()
            .filter(|p| std::mem::discriminant(&p.state) == std::mem::discriminant(state))
            .collect()
    }

    pub fn get_active_patches(&self) -> Vec<&PatchTracking> {
        self.patches.values()
            .filter(|p| matches!(p.state, 
                PatchState::OnMailingList | 
                PatchState::Processing | 
                PatchState::TestsPassed |
                PatchState::CommentsProvided |
                PatchState::Queued | 
                PatchState::Released
            ))
            .collect()
    }
}

impl Default for TrackingStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize)]
pub struct TrackingDashboardData {
    pub generated_at: String,
    pub total_patches_tracked: usize,
    pub patches_by_state: HashMap<String, usize>,
    pub recent_activity: Vec<PatchActivity>,
    pub mailbot_summary: MailbotSummary,
    pub active_patches: Vec<PatchSummary>,
    pub completed_patches: Vec<PatchSummary>,
    pub failed_patches: Vec<PatchSummary>,
}

#[derive(Debug, Serialize)]
pub struct PatchActivity {
    pub message_id: String,
    pub subject: String,
    pub author: String,
    pub state: String,
    pub last_event: String,
    pub last_updated: DateTime<Utc>,
    pub lore_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MailbotSummary {
    pub total_tests_run: usize,
    pub tests_passed: usize,
    pub tests_failed: usize,
    pub average_branches_tested: f64,
}

#[derive(Debug, Serialize)]
pub struct PatchSummary {
    pub message_id: String,
    pub sha1: Option<String>,
    pub subject: String,
    pub author: String,
    pub from_email: String,
    pub state: String,
    pub first_seen: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub test_results: Vec<TestSummary>,
    pub review_count: usize,
    pub reply_count: usize,
    pub lore_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TestSummary {
    pub branches: Vec<String>,
    pub passed: bool,
    pub timestamp: DateTime<Utc>,
}

/// Update tracking status based on queue and release status
pub fn update_tracking_status(store: &mut TrackingStore, stable_queue_dir: &Path, git_repo: &crate::git::GitRepo) -> Result<()> {
    use std::collections::HashMap;
    
    // Get all active patches (not yet released or rejected)
    let active_patches: Vec<_> = store.patches.values()
        .filter(|p| matches!(p.state, 
            PatchState::OnMailingList | 
            PatchState::Processing | 
            PatchState::TestsPassed |
            PatchState::CommentsProvided |
            PatchState::IssuesFound(_)
        ))
        .cloned()
        .collect();
    
    // Cache for SHA1 release checks to avoid redundant git operations
    let mut release_cache: HashMap<String, Option<Vec<String>>> = HashMap::new();
    
    for patch in active_patches {
        if let Some(sha1) = &patch.sha1 {
            // Check if patch is in stable queue
            if let Some(queued_versions) = is_patch_in_queue(sha1, &patch.subject, &patch.target_versions, stable_queue_dir)? {
                store.update_state(&patch.message_id, PatchState::Queued)?;
                store.add_processing_event(&patch.message_id, ProcessingEvent {
                    timestamp: Utc::now(),
                    event_type: ProcessingEventType::StateChanged,
                    details: format!("Patch found in stable queue for: {}", queued_versions.join(", ")),
                })?;
            }
            // Check if patch has been released (with caching)
            else {
                let cache_key = format!("{}-{}", sha1, patch.target_versions.join(","));
                let branches = if let Some(cached) = release_cache.get(&cache_key) {
                    cached.clone()
                } else {
                    let result = is_patch_released(sha1, &patch.target_versions, git_repo)?;
                    release_cache.insert(cache_key, result.clone());
                    result
                };
                
                if let Some(branches) = branches {
                    if !branches.is_empty() {
                        store.update_state(&patch.message_id, PatchState::Released)?;
                        store.add_processing_event(&patch.message_id, ProcessingEvent {
                            timestamp: Utc::now(),
                            event_type: ProcessingEventType::Released,
                            details: format!("Patch released in: {}", branches.join(", ")),
                        })?;
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// Check if a patch is in the stable queue for target versions
fn is_patch_in_queue(sha1: &str, subject: &str, target_versions: &[String], stable_queue_dir: &Path) -> Result<Option<Vec<String>>> {
    use std::fs;
    
    let mut queued_versions = Vec::new();
    // stable_queue_dir already points to stable-queue directory
    let queue_parent = stable_queue_dir;
    
    // Only check queue directories that match target versions
    for version in target_versions {
        let queue_dir = queue_parent.join(format!("queue-{}", version));
        debug!("Checking queue directory: {:?} for version {}", queue_dir, version);
        
        if queue_dir.exists() && queue_dir.is_dir() {
            // Search for the SHA1 or subject in patch files
            if let Ok(patch_entries) = fs::read_dir(&queue_dir) {
                for patch_entry in patch_entries.flatten() {
                    if let Ok(content) = fs::read_to_string(patch_entry.path()) {
                        if content.contains(sha1) || content.contains(subject) {
                            debug!("Found patch {} in queue for version {}", subject, version);
                            queued_versions.push(version.clone());
                            break; // Found in this version, move to next
                        }
                    }
                }
            }
        } else {
            debug!("Queue directory does not exist: {:?}", queue_dir);
        }
    }
    
    if queued_versions.is_empty() {
        Ok(None)
    } else {
        Ok(Some(queued_versions))
    }
}

/// Check if a patch has been released in stable branches
fn is_patch_released(sha1: &str, target_versions: &[String], git_repo: &crate::git::GitRepo) -> Result<Option<Vec<String>>> {
    let mut released_tags = Vec::new();
    
    // Only check branches that match the patch's target versions
    for version in target_versions {
        let branch = format!("origin/linux-{version}.y");
        // Skip if branch doesn't exist
        if !git_repo.branch_exists(&branch) {
            continue;
        }
        
        // Find the earliest tag containing this commit on this branch
        if let Ok(Some(tag)) = git_repo.find_earliest_tag_containing(sha1, &branch) {
            // Only include tags that match the target version
            // e.g., for a 5.4 patch, only include tags like v5.4.123
            if tag.starts_with(&format!("v{version}.")) {
                released_tags.push(tag);
            }
        }
    }
    
    if released_tags.is_empty() {
        Ok(None)
    } else {
        Ok(Some(released_tags))
    }
}

pub fn generate_tracking_dashboard(store: &TrackingStore, output_path: &Path) -> Result<()> {
    use chrono::Local;
    use std::fs;
    
    // Calculate statistics
    let mut patches_by_state: HashMap<String, usize> = HashMap::new();
    let mut recent_activity: Vec<PatchActivity> = Vec::new();
    let mut active_patches: Vec<PatchSummary> = Vec::new();
    let mut completed_patches: Vec<PatchSummary> = Vec::new();
    let mut failed_patches: Vec<PatchSummary> = Vec::new();
    
    let mut total_tests = 0;
    let mut tests_passed = 0;
    let mut tests_failed = 0;
    let mut total_branches = 0;
    
    for patch in store.patches.values() {
        // Count by state
        let state_name = match &patch.state {
            PatchState::OnMailingList => "On Mailing List",
            PatchState::Processing => "Processing",
            PatchState::IssuesFound(_) => "Issues Found",
            PatchState::TestsPassed => "Tests Passed",
            PatchState::CommentsProvided => "Comments Provided",
            PatchState::Queued => "Queued",
            PatchState::Released => "Released",
            PatchState::Merged(_) => "Merged",
            PatchState::Rejected(_) => "Rejected",
            PatchState::Superseded(_) => "Superseded",
            PatchState::Failed(_) => "Failed",
        };
        *patches_by_state.entry(state_name.to_string()).or_insert(0) += 1;
        
        // Collect mailbot statistics
        for result in &patch.mailbot_results {
            total_tests += 1;
            if result.test_passed {
                tests_passed += 1;
            } else {
                tests_failed += 1;
            }
            total_branches += result.test_branches.len();
        }
        
        
        // Create patch summary
        let test_summaries: Vec<TestSummary> = patch.mailbot_results.iter()
            .map(|r| TestSummary {
                branches: r.test_branches.clone(),
                passed: r.test_passed,
                timestamp: r.timestamp,
            })
            .collect();
        
        let summary = PatchSummary {
            message_id: patch.message_id.clone(),
            sha1: patch.sha1.clone(),
            subject: patch.subject.clone(),
            author: patch.author.clone(),
            from_email: patch.from_email.clone(),
            state: state_name.to_string(),
            first_seen: patch.first_seen,
            last_updated: patch.last_updated,
            test_results: test_summaries,
            review_count: patch.mailing_list_activity.reviews.len(),
            reply_count: patch.mailing_list_activity.replies.len(),
            lore_url: patch.lore_url.clone(),
        };
        
        // Categorize patches
        match &patch.state {
            PatchState::OnMailingList | PatchState::Processing | PatchState::TestsPassed | PatchState::CommentsProvided | PatchState::Queued => {
                active_patches.push(summary);
            }
            PatchState::Released | PatchState::Merged(_) => {
                completed_patches.push(summary);
            }
            PatchState::Failed(_) | PatchState::Rejected(_) | PatchState::IssuesFound(_) => {
                failed_patches.push(summary);
            }
            _ => {}
        }
        
        // Add to recent activity
        if let Some(last_event) = patch.processing_history.last() {
            recent_activity.push(PatchActivity {
                message_id: patch.message_id.clone(),
                subject: patch.subject.clone(),
                author: patch.author.clone(),
                state: state_name.to_string(),
                last_event: last_event.details.clone(),
                last_updated: patch.last_updated,
                lore_url: patch.lore_url.clone(),
            });
        }
    }
    
    // Sort recent activity by date
    recent_activity.sort_by(|a, b| b.last_updated.cmp(&a.last_updated));
    recent_activity.truncate(50); // Keep only 50 most recent
    
    // Sort patch lists
    active_patches.sort_by(|a, b| b.last_updated.cmp(&a.last_updated));
    completed_patches.sort_by(|a, b| b.last_updated.cmp(&a.last_updated));
    failed_patches.sort_by(|a, b| b.last_updated.cmp(&a.last_updated));
    
    let avg_branches = if total_tests > 0 {
        total_branches as f64 / total_tests as f64
    } else {
        0.0
    };
    
    let dashboard_data = TrackingDashboardData {
        generated_at: Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string(),
        total_patches_tracked: store.patches.len(),
        patches_by_state,
        recent_activity,
        mailbot_summary: MailbotSummary {
            total_tests_run: total_tests,
            tests_passed,
            tests_failed,
            average_branches_tested: avg_branches,
        },
        active_patches,
        completed_patches,
        failed_patches,
    };
    
    // Generate HTML
    let html = render_tracking_dashboard_html(&dashboard_data)?;
    
    // Write to file
    fs::write(output_path, html)
        .map_err(|e| Error::FileWriteError(output_path.to_path_buf(), e))?;
    
    Ok(())
}

fn render_tracking_dashboard_html(data: &TrackingDashboardData) -> Result<String> {
    // Pre-compute formatted values to avoid format! within format!
    let avg_branches = format!("{:.1}", data.mailbot_summary.average_branches_tested);
    let failed_section = if !data.failed_patches.is_empty() {
        format!(r#"<h2>Failed/Rejected Patches</h2>
        <div class="section">
            {}
        </div>"#, render_patches_table(&data.failed_patches, false))
    } else {
        String::new()
    };
    
    let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Stable Patch Tracking</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 10px;
            background-color: #f5f5f5;
            color: #333;
            font-size: 15px;
        }}
        .container {{
            max-width: 1600px;
            margin: 0 auto;
        }}
        h1 {{
            color: #2c3e50;
            font-size: 1.8em;
            margin: 10px 0;
        }}
        h2 {{
            color: #2c3e50;
            font-size: 1.4em;
            margin-top: 20px;
            margin-bottom: 10px;
            border-bottom: 2px solid #3498db;
            padding-bottom: 5px;
        }}
        .header {{
            background-color: white;
            padding: 12px 18px;
            border-radius: 4px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            margin-bottom: 12px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-bottom: 15px;
        }}
        .stat-card {{
            background-color: white;
            padding: 12px;
            border-radius: 4px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-value {{
            font-size: 1.8em;
            font-weight: bold;
            color: #3498db;
        }}
        .stat-label {{
            color: #7f8c8d;
            margin-top: 2px;
            font-size: 0.9em;
        }}
        .section {{
            background-color: white;
            padding: 15px;
            border-radius: 4px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            margin-bottom: 15px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.95em;
        }}
        th {{
            background-color: #f8f9fa;
            padding: 6px 8px;
            text-align: left;
            font-weight: 600;
            color: #2c3e50;
            border-bottom: 1px solid #dee2e6;
        }}
        td {{
            padding: 5px 8px;
            border-bottom: 1px solid #eee;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .subject {{
            font-weight: 500;
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .author {{
            color: #7f8c8d;
            font-size: 0.92em;
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .sha1 {{
            font-family: monospace;
            font-size: 0.92em;
            color: #e74c3c;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .state {{
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            display: inline-block;
        }}
        .state-queued {{
            background-color: #f39c12;
            color: white;
        }}
        .state-processing {{
            background-color: #3498db;
            color: white;
        }}
        .state-released {{
            background-color: #27ae60;
            color: white;
        }}
        .state-merged {{
            background-color: #2ecc71;
            color: white;
        }}
        .state-failed {{
            background-color: #e74c3c;
            color: white;
        }}
        .state-rejected {{
            background-color: #c0392b;
            color: white;
        }}
        .state-on-mailing-list {{
            background-color: #95a5a6;
            color: white;
        }}
        .state-tests-passed {{
            background-color: #27ae60;
            color: white;
        }}
        .state-comments {{
            background-color: #e67e22;
            color: white;
        }}
        .nav {{
            background-color: #2c3e50;
            padding: 10px 0;
            margin-bottom: 10px;
        }}
        .nav-links {{
            max-width: 1600px;
            margin: 0 auto;
            padding: 0 10px;
        }}
        .nav-links a {{
            color: white;
            text-decoration: none;
            padding: 8px 16px;
            margin-right: 10px;
            border-radius: 4px;
            display: inline-block;
        }}
        .nav-links a:hover {{
            background-color: #34495e;
        }}
        .nav-links a.active {{
            background-color: #3498db;
        }}
        .subject a {{
            color: #3498db;
            text-decoration: none;
        }}
        .subject a:hover {{
            text-decoration: underline;
        }}
        .test-result {{
            font-size: 0.85em;
        }}
        .test-passed {{
            color: #27ae60;
        }}
        .test-failed {{
            color: #e74c3c;
        }}
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-links">
            <a href="queue-status.html">Queue Status</a>
            <a href="possible-issues.html">Possible Issues</a>
            <a href="patch-tracking.html" class="active">Patch Tracking</a>
        </div>
    </nav>
    <div class="container">
        <div class="header">
            <h1>Linux Stable Patch Tracking</h1>
            <p class="timestamp">Generated at: {generated_at}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{total_patches}</div>
                <div class="stat-label">Total Patches Tracked</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{active_patches}</div>
                <div class="stat-label">Active Patches</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{test_pass_rate}%</div>
                <div class="stat-label">Test Pass Rate</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{avg_branches}</div>
                <div class="stat-label">Avg Branches Tested</div>
            </div>
        </div>
        
        <h2>Patch State Distribution</h2>
        <div class="section">
            <div style="display: flex; flex-wrap: wrap; gap: 10px;">
                {state_distribution}
            </div>
        </div>
        
        <h2>Active Patches</h2>
        <div class="section">
            {active_patches_table}
        </div>
        
        {failed_section}
        
        <h2>Recent Activity</h2>
        <div class="section">
            {recent_activity_table}
        </div>
        
        <h2>Completed Patches</h2>
        <div class="section">
            {completed_patches_table}
        </div>
    </div>
</body>
</html>"#,
        generated_at = data.generated_at,
        total_patches = data.total_patches_tracked,
        active_patches = data.active_patches.len(),
        test_pass_rate = if data.mailbot_summary.total_tests_run > 0 {
            (data.mailbot_summary.tests_passed * 100) / data.mailbot_summary.total_tests_run
        } else { 0 },
        avg_branches = avg_branches,
        state_distribution = render_state_distribution(&data.patches_by_state),
        active_patches_table = render_patches_table(&data.active_patches, true),
        recent_activity_table = render_recent_activity_table(&data.recent_activity),
        completed_patches_table = render_patches_table(&data.completed_patches, false),
        failed_section = failed_section
    );
    
    Ok(html)
}

fn render_state_distribution(states: &HashMap<String, usize>) -> String {
    let mut html = String::new();
    let total: usize = states.values().sum();
    
    for (state, count) in states {
        let percentage = if total > 0 {
            (*count as f64 / total as f64 * 100.0) as u32
        } else {
            0
        };
        
        let state_class = match state.as_str() {
            "Processing" => "state-processing",
            "Issues Found" => "state-failed",
            "Tests Passed" => "state-tests-passed",
            "Comments Provided" => "state-comments",
            "Queued" => "state-queued",
            "Released" => "state-released",
            "Merged" => "state-merged",
            "Failed" => "state-failed",
            "Rejected" => "state-rejected",
            "On Mailing List" => "state-on-mailing-list",
            _ => "",
        };
        
        html.push_str(&format!(
            r#"<div class="stat-card" style="min-width: 150px;">
                <div class="state {state_class}">{state}</div>
                <div class="stat-value" style="font-size: 1.2em; margin-top: 5px;">{count}</div>
                <div class="stat-label" style="font-size: 0.8em;">{percentage}%</div>
            </div>"#
        ));
    }
    
    html
}

fn render_patches_table(patches: &[PatchSummary], show_state: bool) -> String {
    if patches.is_empty() {
        return "<p style='text-align: center; color: #7f8c8d;'>No patches in this category</p>".to_string();
    }
    
    let mut html = String::from(r#"<table>
        <thead>
            <tr>
                <th>Subject</th>
                <th>Author</th>
                <th>SHA1</th>"#);
    
    if show_state {
        html.push_str("<th>State</th>");
    }
    
    html.push_str(r#"
                <th>Test Results</th>
                <th>Reviews/Replies</th>
            </tr>
        </thead>
        <tbody>"#);
    
    for patch in patches {
        let sha1_display = patch.sha1.as_ref()
            .map(|s| &s[..8])
            .unwrap_or("-");
        
        let test_results = if patch.test_results.is_empty() {
            "-".to_string()
        } else {
            let passed = patch.test_results.iter().filter(|t| t.passed).count();
            let total = patch.test_results.len();
            let class = if passed == total { "test-passed" } else { "test-failed" };
            format!(r#"<span class="{class}">{passed}/{total} passed</span>"#)
        };
        
        let reviews_replies = format!("{}/{}", patch.review_count, patch.reply_count);
        
        let state_class = match patch.state.as_str() {
            "Processing" => "state-processing",
            "Issues Found" => "state-failed",
            "Tests Passed" => "state-tests-passed",
            "Comments Provided" => "state-comments",
            "Queued" => "state-queued",
            "Released" => "state-released",
            "Merged" => "state-merged",
            "Failed" => "state-failed",
            "Rejected" => "state-rejected",
            "On Mailing List" => "state-on-mailing-list",
            _ => "",
        };
        
        let subject_html = if let Some(ref url) = patch.lore_url {
            format!(r#"<a href="{}" target="_blank">{}</a>"#, 
                    html_escape(url), 
                    html_escape(&patch.subject))
        } else {
            html_escape(&patch.subject)
        };
        
        html.push_str(&format!(r#"
            <tr>
                <td class="subject" title="{}">{}</td>
                <td class="author" title="{}">{}</td>
                <td class="sha1">{}</td>"#,
            html_escape(&patch.subject),
            subject_html,
            html_escape(&patch.from_email),
            html_escape(&patch.author),
            sha1_display
        ));
        
        if show_state {
            html.push_str(&format!(
                r#"<td><span class="state {}">{}</span></td>"#,
                state_class, patch.state
            ));
        }
        
        html.push_str(&format!(r#"
                <td class="test-result">{test_results}</td>
                <td>{reviews_replies}</td>
            </tr>"#
        ));
    }
    
    html.push_str("</tbody></table>");
    html
}

fn render_recent_activity_table(activities: &[PatchActivity]) -> String {
    if activities.is_empty() {
        return "<p style='text-align: center; color: #7f8c8d;'>No recent activity</p>".to_string();
    }
    
    let mut html = String::from(r#"<table>
        <thead>
            <tr>
                <th>Time</th>
                <th>Subject</th>
                <th>Author</th>
                <th>State</th>
                <th>Event</th>
            </tr>
        </thead>
        <tbody>"#);
    
    for activity in activities {
        let time_ago = format_time_ago(activity.last_updated);
        
        let state_class = match activity.state.as_str() {
            "Processing" => "state-processing",
            "Issues Found" => "state-failed",
            "Tests Passed" => "state-tests-passed",
            "Comments Provided" => "state-comments",
            "Queued" => "state-queued",
            "Released" => "state-released",
            "Merged" => "state-merged",
            "Failed" => "state-failed",
            "Rejected" => "state-rejected",
            "On Mailing List" => "state-on-mailing-list",
            _ => "",
        };
        
        let subject_html = if let Some(ref url) = activity.lore_url {
            format!(r#"<a href="{}" target="_blank">{}</a>"#, 
                    html_escape(url), 
                    html_escape(&activity.subject))
        } else {
            html_escape(&activity.subject)
        };
        
        html.push_str(&format!(r#"
            <tr>
                <td class="timestamp">{}</td>
                <td class="subject" title="{}">{}</td>
                <td class="author">{}</td>
                <td><span class="state {}">{}</span></td>
                <td>{}</td>
            </tr>"#,
            time_ago,
            html_escape(&activity.subject),
            subject_html,
            html_escape(&activity.author),
            state_class,
            activity.state,
            html_escape(&activity.last_event)
        ));
    }
    
    html.push_str("</tbody></table>");
    html
}

fn format_time_ago(time: DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(time);
    
    if duration.num_seconds() < 60 {
        "just now".to_string()
    } else if duration.num_minutes() < 60 {
        format!("{} min ago", duration.num_minutes())
    } else if duration.num_hours() < 24 {
        format!("{} hours ago", duration.num_hours())
    } else if duration.num_days() < 7 {
        format!("{} days ago", duration.num_days())
    } else {
        time.format("%Y-%m-%d").to_string()
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_id_to_lore_url() {
        // Test with angle brackets
        assert_eq!(
            message_id_to_lore_url("<test@example.com>"),
            "https://lore.kernel.org/stable/test@example.com"
        );
        
        // Test without angle brackets
        assert_eq!(
            message_id_to_lore_url("test@example.com"),
            "https://lore.kernel.org/stable/test@example.com"
        );
        
        // Test with complex message ID
        assert_eq!(
            message_id_to_lore_url("<20240112.123456.patch@kernel.org>"),
            "https://lore.kernel.org/stable/20240112.123456.patch@kernel.org"
        );
    }
}