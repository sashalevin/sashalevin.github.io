mod cli;
mod config;
mod email;
mod git;
mod kernel;
mod lei;
mod patch;
mod response;
mod series;
mod dashboard;
mod tracking;
mod utils;
mod error;

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn, error, debug};
use std::path::PathBuf;

use crate::cli::{Args, Commands};
use crate::config::Config;
use crate::email::LeiEmail;
use crate::patch::PatchProcessor;
use crate::dashboard::DashboardGenerator;
use crate::tracking::{TrackingStore, generate_tracking_dashboard, update_tracking_status, PatchState};
use crate::git::GitRepo;
use chrono::{DateTime, Utc};
use std::fs;

/// Read timestamp from file
fn read_timestamp(path: &PathBuf) -> Result<Option<DateTime<Utc>>> {
    if !path.exists() {
        return Ok(None);
    }
    
    let content = fs::read_to_string(path)?;
    let timestamp = content.trim().parse::<DateTime<Utc>>()?;
    Ok(Some(timestamp))
}

/// Write timestamp to file
fn write_timestamp(path: &PathBuf, timestamp: DateTime<Utc>) -> Result<()> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    
    fs::write(path, timestamp.to_rfc3339())?;
    Ok(())
}

/// Parse time range string (e.g., "60", "24h", "7d") into minutes
fn parse_time_range(time_range: &str) -> Result<u32> {
    let time_range = time_range.trim();
    
    if let Ok(minutes) = time_range.parse::<u32>() {
        return Ok(minutes);
    }
    
    if time_range.is_empty() {
        return Ok(60); // Default to 60 minutes
    }
    
    let (num_str, unit) = time_range.split_at(time_range.len() - 1);
    let num: u32 = num_str.parse()
        .map_err(|_| anyhow::anyhow!("Invalid time range format: {}", time_range))?;
    
    match unit {
        "m" => Ok(num),
        "h" => Ok(num * 60),
        "d" => Ok(num * 60 * 24),
        _ => anyhow::bail!("Invalid time unit: {}. Use 'm' for minutes, 'h' for hours, or 'd' for days", unit)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter("mailbot=debug")
        .init();

    // Parse command line arguments
    let args = Args::parse();
    
    // Load configuration
    let config = Config::load(&args.config)?;
    
    // Process based on command
    match args.command {
        Commands::Process { 
            input,
            input_type,
            time_range,
            state_file,
            skip_build,
            output_dir,
        } => {
            // Set skip_build flag
            let mut config = config;
            config.skip_build = skip_build;
            config.output_dir = PathBuf::from(&output_dir);
            
            // Auto-detect input type if not specified
            let input_type = input_type.unwrap_or_else(|| {
                if input == "lei" {
                    "lei".to_string()
                } else if input.ends_with(".mbox") {
                    "mbox".to_string()
                } else if std::path::Path::new(&input).is_dir() {
                    "maildir".to_string()
                } else {
                    "lei-json".to_string()
                }
            });
            
            // Process based on input type
            match input_type.as_str() {
                "lei-json" => process_lei_json(&input, &config).await?,
                "mbox" => process_mbox(&input, &config).await?,
                "lei" | "lei-query" => {
                    let minutes = if let Some(range) = time_range {
                        Some(parse_time_range(&range)?)
                    } else {
                        None
                    };
                    process_lei_query(&input, minutes, &state_file, &config).await?
                },
                "maildir" => process_maildir(&input, &config).await?,
                _ => anyhow::bail!("Unsupported input type: {}", input_type),
            }
        },
        Commands::Dashboard { 
            dashboard_type,
            output_dir,
        } => {
            generate_dashboards(&dashboard_type, &output_dir, &config)?;
        }
        Commands::Query {
            query_type,
            value,
            format,
        } => {
            query_tracking_data(&query_type, value.as_deref(), &format, &config)?;
        }
        Commands::ProcessEmail { path } => {
            
            // Process single email
            process_single_email(&path, &config).await?;
        }
    }
    
    Ok(())
}

async fn process_lei_json(input: &str, config: &Config) -> Result<()> {
    info!("Processing lei JSON input from: {}", input);
    
    // Parse lei JSON email
    let email = LeiEmail::from_file(input)?;
    
    // Process based on email type
    let processor = PatchProcessor::new(config.clone())?;
    
    if email.is_git_patch() {
        // Check if we should ignore patches from this author
        if email.should_ignore(config) {
            info!("Ignoring patch from: {}", email.from);
            return Ok(());
        }
        // Process as a patch
        processor.process_email(email).await?;
    } else {
        // Try to process as a reply/comment (including FAILED emails)
        let processed = processor.process_reply_or_comment(email).await?;
        if !processed {
            info!("Email is not a patch or a reply to a tracked patch, skipping");
        }
    }
    
    Ok(())
}

async fn process_mbox(_input: &str, _config: &Config) -> Result<()> {
    anyhow::bail!("Mbox input not yet implemented")
}

async fn process_maildir(_input: &str, _config: &Config) -> Result<()> {
    anyhow::bail!("Maildir input not yet implemented")
}

async fn process_lei_query(
    _input: &str,
    lookback_minutes: Option<u32>,
    _state_file: &str,
    config: &Config
) -> Result<()> {
    use crate::lei::{LeiClient, ensure_stable_external};
    
    // Capture the start time of this processing run
    let processing_start_time = Utc::now();
    
    info!("Ensuring lore.kernel.org/stable is configured");
    ensure_stable_external()?;
    
    // Determine lookback time
    let actual_lookback_minutes = if let Some(minutes) = lookback_minutes {
        // Explicit time range provided
        info!("Using explicit time range: {} minutes", minutes);
        minutes
    } else {
        // Check timestamp file
        let timestamp_path = &config.timestamp_file;
        if let Some(last_timestamp) = read_timestamp(timestamp_path)? {
            let now = Utc::now();
            let duration = now.signed_duration_since(last_timestamp);
            let minutes = duration.num_minutes() as u32;
            // Add a small buffer to ensure no emails are missed
            let buffered_minutes = minutes + 5;
            info!("Using time since last run: {} minutes (from {})", buffered_minutes, last_timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
            buffered_minutes
        } else {
            // First run, default to 60 minutes
            info!("No previous timestamp found, using default: 60 minutes");
            60
        }
    };
    
    info!("Querying recent patches from lore.kernel.org/stable");
    let client = LeiClient::new();
    let emails = client.query_recent_patches(actual_lookback_minutes, &config.ignored_authors)?;
    
    if emails.is_empty() {
        info!("No new emails found");
        return Ok(());
    }
    
    info!("Processing {} emails", emails.len());
    
    let processor = PatchProcessor::new(config.clone())?;
    
    // Initialize statistics
    let mut processed = 0;
    let mut errors = 0;
    let mut ignored = 0;
    let mut non_patches = 0;
    let mut replies = 0;
    
    // Process each email
    for email in emails {
        // Check if this is a git patch
        if email.is_git_patch() {
            // Check if we should ignore patches from this author
            if email.should_ignore(config) {
                ignored += 1;
                continue;
            }
            match processor.process_email(email).await {
                Ok(_) => processed += 1,
                Err(e) => {
                    error!("Failed to process email: {}", e);
                    errors += 1;
                }
            }
        } else {
            // Check if this is a FAILED email or other reply/comment
            match processor.process_reply_or_comment(email).await {
                Ok(true) => replies += 1,
                Ok(false) => non_patches += 1,
                Err(e) => {
                    debug!("Failed to process as reply: {}", e);
                    non_patches += 1;
                }
            }
        }
    }
    
    // Print summary
    info!("Processing complete:");
    info!("  Processed: {}", processed);
    info!("  Replies/Comments: {}", replies);
    info!("  Ignored: {}", ignored);
    info!("  Non-patches: {}", non_patches);
    if errors > 0 {
        warn!("  Errors: {}", errors);
    }
    
    // Update timestamp file with the start time of this processing run
    write_timestamp(&config.timestamp_file, processing_start_time)?;
    info!("Updated timestamp file: {} with start time: {}", 
          config.timestamp_file.display(), 
          processing_start_time.format("%Y-%m-%d %H:%M:%S UTC"));
    
    Ok(())
}

fn query_tracking_data(query_type: &str, value: Option<&str>, format: &str, config: &Config) -> Result<()> {
    let tracking_path = &config.tracking_file;
    let store = TrackingStore::load_from_file(tracking_path)
        .unwrap_or_else(|_| TrackingStore::new());
    
    match query_type {
        "message-id" => {
            let message_id = value.ok_or_else(|| anyhow::anyhow!("Message ID required for this query"))?;
            if let Some(patch) = store.get_patch(message_id) {
                if format == "json" {
                    println!("{}", serde_json::to_string_pretty(patch)?);
                } else {
                    println!("Patch: {}", patch.subject);
                    println!("Author: {}", patch.author);
                    println!("State: {:?}", patch.state);
                    println!("SHA1: {}", patch.sha1.as_ref().unwrap_or(&"None".to_string()));
                    println!("First seen: {}", patch.first_seen.format("%Y-%m-%d %H:%M:%S"));
                    println!("Last updated: {}", patch.last_updated.format("%Y-%m-%d %H:%M:%S"));
                    println!("Test results: {}", patch.mailbot_results.len());
                    println!("Reviews: {}", patch.mailing_list_activity.reviews.len());
                    println!("Replies: {}", patch.mailing_list_activity.replies.len());
                }
            } else {
                println!("Patch with message ID '{message_id}' not found");
            }
        }
        "sha1" => {
            let sha1 = value.ok_or_else(|| anyhow::anyhow!("SHA1 required for this query"))?;
            let patches = store.find_by_sha1(sha1);
            if patches.is_empty() {
                println!("No patches found with SHA1 '{sha1}'");
            } else if format == "json" {
                println!("{}", serde_json::to_string_pretty(&patches)?);
            } else {
                println!("Found {} patches with SHA1 {}:", patches.len(), sha1);
                for patch in patches {
                    println!("\n- {}", patch.subject);
                    println!("  Message ID: {}", patch.message_id);
                    println!("  State: {:?}", patch.state);
                    println!("  Author: {}", patch.author);
                }
            }
        }
        "state" => {
            let state_str = value.ok_or_else(|| anyhow::anyhow!("State required for this query"))?;
            let state = match state_str.to_lowercase().as_str() {
                "onmailinglist" | "on-mailing-list" => PatchState::OnMailingList,
                "processing" => PatchState::Processing,
                "issuesfound" | "issues-found" => PatchState::IssuesFound(String::new()),
                "testspassed" | "tests-passed" => PatchState::TestsPassed,
                "commentsprovided" | "comments-provided" => PatchState::CommentsProvided,
                "queued" => PatchState::Queued,
                "released" => PatchState::Released,
                "merged" => PatchState::Merged(vec![]),
                "rejected" => PatchState::Rejected(String::new()),
                "superseded" => PatchState::Superseded(String::new()),
                "failed" => PatchState::Failed(String::new()),
                _ => anyhow::bail!("Unknown state: {}", state_str),
            };
            let patches = store.get_patches_by_state(&state);
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&patches)?);
            } else {
                println!("Found {} patches in state '{}':", patches.len(), state_str);
                for patch in patches {
                    println!("\n- {}", patch.subject);
                    println!("  Message ID: {}", patch.message_id);
                    println!("  Author: {}", patch.author);
                    println!("  Last updated: {}", patch.last_updated.format("%Y-%m-%d %H:%M:%S"));
                }
            }
        }
        "active" => {
            let patches = store.get_active_patches();
            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&patches)?);
            } else {
                println!("Found {} active patches:", patches.len());
                for patch in patches {
                    println!("\n- {}", patch.subject);
                    println!("  Message ID: {}", patch.message_id);
                    println!("  State: {:?}", patch.state);
                    println!("  Author: {}", patch.author);
                    println!("  Last updated: {}", patch.last_updated.format("%Y-%m-%d %H:%M:%S"));
                }
            }
        }
        _ => anyhow::bail!("Unknown query type: {}", query_type),
    }
    
    Ok(())
}

fn generate_dashboards(dashboard_type: &str, output_dir: &str, config: &Config) -> Result<()> {
    info!("Generating {} dashboard(s) in {}", dashboard_type, output_dir);
    
    let generator = DashboardGenerator::new(
        config.stable_queue_dir.clone(),
        PathBuf::from(output_dir),
        Some(config.linux_dir.clone()),
    );
    
    match dashboard_type {
        "all" => {
            generator.generate_all()?;
            // Also generate patch tracking dashboard
            let tracking_path = &config.tracking_file;
            let mut store = TrackingStore::load_from_file(tracking_path)
                .unwrap_or_else(|_| TrackingStore::new());
            
            // Update tracking status based on queue/release status
            let git_repo = GitRepo::open(&config.linux_dir)?;
            update_tracking_status(&mut store, &config.stable_queue_dir, &git_repo)?;
            store.save_to_file(tracking_path)?;
            
            let output_path = PathBuf::from(output_dir).join("patch-tracking.html");
            generate_tracking_dashboard(&store, &output_path)?;
        },
        "queue-status" => generator.generate_queue_status_dashboard()?,
        "possible-issues" => generator.generate_possible_issues_dashboard()?,
        "patch-tracking" => {
            let tracking_path = &config.tracking_file;
            let mut store = TrackingStore::load_from_file(tracking_path)
                .unwrap_or_else(|_| TrackingStore::new());
            
            // Update tracking status based on queue/release status
            let git_repo = GitRepo::open(&config.linux_dir)?;
            update_tracking_status(&mut store, &config.stable_queue_dir, &git_repo)?;
            store.save_to_file(tracking_path)?;
            
            let output_path = PathBuf::from(output_dir).join("patch-tracking.html");
            generate_tracking_dashboard(&store, &output_path)?;
        },
        _ => anyhow::bail!("Unknown dashboard type: {}", dashboard_type),
    }
    
    Ok(())
}

async fn process_single_email(path: &str, config: &Config) -> Result<()> {
    info!("Processing single email from: {}", path);
    
    // Parse lei JSON email
    let email = LeiEmail::from_file(path)?;
    
    // Process based on email type
    let processor = PatchProcessor::new(config.clone())?;
    
    if email.is_git_patch() {
        // Check if we should ignore patches from this author
        if email.should_ignore(config) {
            info!("Ignoring patch from: {}", email.from);
            return Ok(());
        }
        // Process as a patch
        match processor.process_email(email).await {
            Ok(_) => info!("Email processed successfully"),
            Err(e) => error!("Failed to process email: {}", e),
        }
    } else {
        // Try to process as a reply/comment (including FAILED emails)
        match processor.process_reply_or_comment(email).await {
            Ok(true) => info!("Email processed as reply/comment"),
            Ok(false) => info!("Email is not a patch or a reply to a tracked patch, skipping"),
            Err(e) => error!("Failed to process email as reply: {}", e),
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_parse_time_range() {
        // Test plain minutes
        assert_eq!(parse_time_range("60").unwrap(), 60);
        assert_eq!(parse_time_range("120").unwrap(), 120);
        
        // Test with units
        assert_eq!(parse_time_range("5m").unwrap(), 5);
        assert_eq!(parse_time_range("2h").unwrap(), 120);
        assert_eq!(parse_time_range("1d").unwrap(), 1440);
        assert_eq!(parse_time_range("7d").unwrap(), 10080);
        
        // Test edge cases
        assert_eq!(parse_time_range("").unwrap(), 60); // default
        assert_eq!(parse_time_range(" 24h ").unwrap(), 1440); // with spaces
        
        // Test errors
        assert!(parse_time_range("abc").is_err());
        assert!(parse_time_range("12x").is_err());
        assert!(parse_time_range("h").is_err());
    }
}