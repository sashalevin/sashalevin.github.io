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
mod utils;
mod error;

use anyhow::Result;
use clap::Parser;
use tracing::{info, warn, error};
use std::path::PathBuf;

use crate::cli::{Args, Commands};
use crate::config::Config;
use crate::email::LeiEmail;
use crate::patch::PatchProcessor;
use crate::dashboard::DashboardGenerator;

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
            dry_run,
            skip_build,
            output_dir,
        } => {
            // Override debug flag with skip_build or dry_run
            let mut config = config;
            if skip_build || dry_run {
                config.debug = true;
            }
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
                    let minutes = parse_time_range(&time_range)?;
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
    }
    
    Ok(())
}

async fn process_lei_json(input: &str, config: &Config) -> Result<()> {
    info!("Processing lei JSON input from: {}", input);
    
    // Parse lei JSON email
    let email = LeiEmail::from_file(input)?;
    
    // Check if we should ignore this email
    if email.should_ignore(config) {
        info!("Ignoring email from: {}", email.from);
        return Ok(());
    }
    
    // Check if this is a git patch
    if !email.is_git_patch() {
        info!("Email is not a git patch, skipping");
        return Ok(());
    }
    
    // Process the patch
    let processor = PatchProcessor::new(config.clone())?;
    processor.process_email(email).await?;
    
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
    lookback_minutes: u32,
    state_file: &str,
    config: &Config
) -> Result<()> {
    use crate::lei::{LeiClient, ensure_stable_external};
    
    info!("Ensuring lore.kernel.org/stable is configured");
    ensure_stable_external()?;
    
    info!("Querying recent patches from lore.kernel.org/stable");
    let client = LeiClient::new(state_file.to_string());
    let emails = client.query_recent_patches(lookback_minutes, &config.ignored_authors)?;
    
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
    
    // Process each email
    for email in emails {
        // Check if we should ignore this email
        if email.should_ignore(config) {
            ignored += 1;
            continue;
        }
        
        // Check if this is a git patch
        if !email.is_git_patch() {
            non_patches += 1;
            continue;
        }
        
        match processor.process_email(email).await {
            Ok(_) => processed += 1,
            Err(e) => {
                error!("Failed to process email: {}", e);
                errors += 1;
            }
        }
    }
    
    // Print summary
    info!("Processing complete:");
    info!("  Processed: {}", processed);
    info!("  Ignored: {}", ignored);
    info!("  Non-patches: {}", non_patches);
    if errors > 0 {
        warn!("  Errors: {}", errors);
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
        "all" => generator.generate_all()?,
        "queue-status" => generator.generate_queue_status_dashboard()?,
        "possible-issues" => generator.generate_possible_issues_dashboard()?,
        _ => anyhow::bail!("Unknown dashboard type: {}", dashboard_type),
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