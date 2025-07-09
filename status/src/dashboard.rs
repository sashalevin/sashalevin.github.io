use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use chrono::Local;
use serde::Serialize;
use tracing::{debug, info};
use rayon::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};

use crate::error::{MailbotError, Result as MailbotResult};
use crate::kernel::KernelVersion;

#[derive(Debug, Serialize)]
pub struct QueuePatch {
    pub filename: String,
    pub subject: String,
    pub author: String,
    pub date: Option<String>,
    pub upstream_commit: Option<String>,
    pub lines_added: usize,
    pub lines_removed: usize,
}

#[derive(Debug, Serialize)]
pub struct QueueStatus {
    pub version: KernelVersion,
    pub patches: Vec<QueuePatch>,
    pub total_patches: usize,
    pub queue_path: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct DashboardData {
    pub generated_at: String,
    pub queues: Vec<QueueStatus>,
    pub total_patches_all_queues: usize,
    pub active_versions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct IssuesPatch {
    pub filename: String,
    pub subject: String,
    pub author: String,
    pub queue_version: KernelVersion,
    pub upstream_commit: Option<String>,
    pub missing_from_versions: Vec<KernelVersion>,
}

#[derive(Debug, Serialize)]
pub struct IssuesData {
    pub generated_at: String,
    pub patches_without_sha: Vec<IssuesPatch>,
    pub patches_missing_from_newer: Vec<IssuesPatch>,
    pub total_issues: usize,
}

pub struct DashboardGenerator {
    stable_queue_dir: PathBuf,
    output_dir: PathBuf,
    linux_dir: Option<PathBuf>,
}

impl DashboardGenerator {
    pub fn new(stable_queue_dir: PathBuf, output_dir: PathBuf, linux_dir: Option<PathBuf>) -> Self {
        Self {
            stable_queue_dir,
            output_dir,
            linux_dir,
        }
    }
    
    /// Generate all dashboards
    pub fn generate_all(&self) -> MailbotResult<()> {
        info!("Generating HTML dashboards");
        
        // Create output directory if it doesn't exist
        fs::create_dir_all(&self.output_dir)?;
        
        // Generate both dashboards in parallel
        let (queue_result, issues_result) = rayon::join(
            || self.generate_queue_status_dashboard(),
            || self.generate_possible_issues_dashboard()
        );
        
        // Check for errors
        queue_result?;
        issues_result?;
        
        Ok(())
    }
    
    /// Generate the queue status dashboard
    pub fn generate_queue_status_dashboard(&self) -> MailbotResult<()> {
        info!("Generating queue status dashboard");
        
        // Read active kernel versions
        let active_versions = self.read_active_versions()?;
        
        // Create progress bar
        let progress = ProgressBar::new(active_versions.len() as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} queues ({msg})")
                .unwrap()
                .progress_chars("#>-")
        );
        
        // Scan all queue directories in parallel
        let queues: Vec<_> = active_versions
            .par_iter()
            .map(|version| {
                progress.set_message(format!("Processing {}", version));
                let result = self.scan_queue_for_version(version).ok();
                progress.inc(1);
                result
            })
            .filter_map(|x| x)
            .collect();
        
        progress.finish_with_message("All queues processed");
        
        let total_patches: usize = queues.iter().map(|q| q.total_patches).sum();
        
        // Sort queues by version (newest first)
        let mut queues = queues;
        queues.sort_by(|a, b| b.version.cmp(&a.version));
        
        // Create dashboard data
        let dashboard_data = DashboardData {
            generated_at: Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string(),
            queues,
            total_patches_all_queues: total_patches,
            active_versions: active_versions.iter().map(|v| v.to_string()).collect(),
        };
        
        // Generate HTML
        let html = self.render_queue_status_html(&dashboard_data)?;
        
        // Write to file
        let output_path = self.output_dir.join("queue-status.html");
        fs::write(&output_path, html)?;
        
        info!("Queue status dashboard written to: {}", output_path.display());
        
        Ok(())
    }
    
    /// Read active kernel versions from the stable-queue directory
    fn read_active_versions(&self) -> MailbotResult<Vec<KernelVersion>> {
        let versions_file = self.stable_queue_dir.join("active_kernel_versions");
        
        if !versions_file.exists() {
            return Err(MailbotError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Active versions file not found: {versions_file:?}")
            )));
        }
        
        let content = fs::read_to_string(&versions_file)?;
        let mut versions = Vec::new();
        
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() {
                if let Ok(version) = line.parse::<KernelVersion>() {
                    versions.push(version);
                }
            }
        }
        
        Ok(versions)
    }
    
    /// Scan queue directory for a specific kernel version
    fn scan_queue_for_version(&self, version: &KernelVersion) -> MailbotResult<QueueStatus> {
        let queue_dir = self.stable_queue_dir.join(format!("queue-{}.{}", version.major, version.minor));
        
        if !queue_dir.exists() {
            debug!("Queue directory not found: {:?}", queue_dir);
            return Ok(QueueStatus {
                version: version.clone(),
                patches: Vec::new(),
                total_patches: 0,
                queue_path: queue_dir,
            });
        }
        
        // Collect all patch file paths
        let patch_files: Vec<_> = fs::read_dir(&queue_dir)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("patch")
            })
            .collect();
        
        // Parse all patch files in parallel
        let mut patches: Vec<_> = patch_files
            .par_iter()
            .filter_map(|path| self.parse_patch_file(path).ok())
            .collect();
        
        // Sort patches by filename
        patches.sort_by(|a, b| a.filename.cmp(&b.filename));
        
        Ok(QueueStatus {
            version: version.clone(),
            total_patches: patches.len(),
            patches,
            queue_path: queue_dir,
        })
    }
    
    /// Parse a patch file to extract information
    fn parse_patch_file(&self, path: &Path) -> MailbotResult<QueuePatch> {
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
            
        let content = fs::read_to_string(path)?;
        let lines: Vec<&str> = content.lines().collect();
        
        let mut subject = String::new();
        let mut author = String::new();
        let mut date = None;
        let mut upstream_commit = None;
        let mut found_header_end = false;
        let mut lines_added = 0;
        let mut lines_removed = 0;
        let mut in_diff = false;
        
        // Parse headers and find first SHA after headers, then count diff lines
        let mut seen_blank = false;
        for line in &lines {
            if !found_header_end {
                if line.starts_with("Subject: ") {
                    subject = line.strip_prefix("Subject: ").unwrap_or("").to_string();
                    // Remove [PATCH ...] prefix if present
                    if let Some(idx) = subject.find(']') {
                        if subject.starts_with('[') {
                            subject = subject[idx + 1..].trim().to_string();
                        }
                    }
                } else if line.starts_with("Date: ") {
                    date = Some(line.strip_prefix("Date: ").unwrap_or("").to_string());
                } else if line.trim().is_empty() {
                    seen_blank = true;
                } else if seen_blank && line.starts_with("From: ") {
                    // This is the actual author line after the blank line
                    author = line.strip_prefix("From: ").unwrap_or("").to_string();
                    found_header_end = true;
                }
            } else if upstream_commit.is_none() {
                // Look for first 40-char hex string after headers
                if let Some(sha) = extract_sha_from_line(line) {
                    upstream_commit = Some(sha);
                }
            }
            
            // Count diff lines
            if line.starts_with("diff --git") || line.starts_with("--- ") || line.starts_with("+++ ") {
                in_diff = true;
            } else if in_diff {
                if line.starts_with('+') && !line.starts_with("+++") {
                    lines_added += 1;
                } else if line.starts_with('-') && !line.starts_with("---") {
                    lines_removed += 1;
                }
            }
        }
        
        // If we still don't have an author, try to look it up from git
        if author.is_empty() || author == "Unknown <unknown@unknown>" {
            if let (Some(sha), Some(linux_dir)) = (&upstream_commit, &self.linux_dir) {
                // Use git show to get author information
                let output = Command::new("git")
                    .arg("-C")
                    .arg(linux_dir)
                    .arg("show")
                    .arg("--no-patch")
                    .arg("--format=%an <%ae>")
                    .arg(sha)
                    .output();
                
                if let Ok(output) = output {
                    if output.status.success() {
                        if let Ok(git_author) = String::from_utf8(output.stdout) {
                            let git_author = git_author.trim();
                            if !git_author.is_empty() {
                                author = git_author.to_string();
                            }
                        }
                    }
                }
            }
        }
        
        // If we still don't have an author, default to unknown
        if author.is_empty() {
            author = "Unknown <unknown@unknown>".to_string();
        }
        
        Ok(QueuePatch {
            filename,
            subject,
            author,
            date,
            upstream_commit,
            lines_added,
            lines_removed,
        })
    }
    
    /// Render the queue status dashboard as HTML
    fn render_queue_status_html(&self, data: &DashboardData) -> MailbotResult<String> {
        let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Stable Queue Status</title>
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
        .header {{
            background-color: white;
            padding: 12px 18px;
            border-radius: 4px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            margin-bottom: 12px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
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
        .queue-section {{
            background-color: white;
            padding: 12px;
            border-radius: 4px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            margin-bottom: 10px;
        }}
        .queue-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
            padding-bottom: 8px;
            border-bottom: 1px solid #ecf0f1;
        }}
        .queue-version {{
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .patch-count {{
            background-color: #3498db;
            color: white;
            padding: 4px 12px;
            border-radius: 14px;
            font-weight: bold;
            font-size: 0.95em;
        }}
        .patch-list {{
            overflow-x: auto;
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
            font-size: 0.95em;
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
            max-width: 600px;
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
        .author a {{
            color: #7f8c8d;
            text-decoration: none;
        }}
        .author a:hover {{
            color: #3498db;
            text-decoration: underline;
        }}
        .commit-sha {{
            font-family: monospace;
            font-size: 0.92em;
        }}
        .commit-sha a {{
            color: #e74c3c;
            text-decoration: none;
        }}
        .commit-sha a:hover {{
            text-decoration: underline;
        }}
        .filename {{
            font-family: monospace;
            font-size: 0.88em;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .filename a {{
            color: #3498db;
            text-decoration: none;
        }}
        .filename a:hover {{
            text-decoration: underline;
        }}
        .empty-queue {{
            text-align: center;
            color: #7f8c8d;
            padding: 20px;
            font-style: italic;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .collapsible {{
            cursor: pointer;
            user-select: none;
        }}
        .collapsed {{
            display: none;
        }}
        .changes {{
            font-family: monospace;
            font-size: 0.9em;
            white-space: nowrap;
        }}
        .additions {{
            color: #27ae60;
        }}
        .deletions {{
            color: #e74c3c;
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
        .issue-indicator {{
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #e74c3c;
            margin-left: 5px;
            vertical-align: middle;
        }}
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-links">
            <a href="queue-status.html" class="active">Queue Status</a>
            <a href="possible-issues.html">Possible Issues</a>
        </div>
    </nav>
    <div class="container">
        <div class="header">
            <h1>Linux Stable Queue Status</h1>
            <p class="timestamp">Generated at: {}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Total Patches</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Active Queues</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{}</div>
                <div class="stat-label">Active Versions</div>
            </div>
        </div>
        
        {}
    </div>
    
    <script>
        function toggleQueue(version) {{
            // Get all queue sections
            const allQueues = document.querySelectorAll('[id^="queue-"]');
            const allHeaders = document.querySelectorAll('[id^="header-"]');
            
            // Close all queues
            allQueues.forEach(queue => {{
                queue.classList.add('collapsed');
            }});
            
            // Update all headers to show closed arrow
            allHeaders.forEach(header => {{
                const text = header.textContent.trim();
                header.textContent = '▶' + text.substring(1);
            }});
            
            // Open the clicked queue
            const table = document.getElementById('queue-' + version);
            const header = document.getElementById('header-' + version);
            
            table.classList.remove('collapsed');
            const headerText = header.textContent.trim();
            header.textContent = '▼' + headerText.substring(1);
        }}
    </script>
</body>
</html>"#,
            data.generated_at,
            data.total_patches_all_queues,
            data.queues.iter().filter(|q| q.total_patches > 0).count(),
            data.active_versions.len(),
            self.render_queues_html(&data.queues)
        );
        
        Ok(html)
    }
    
    /// Render the queue sections
    fn render_queues_html(&self, queues: &[QueueStatus]) -> String {
        let mut html = String::new();
        
        for (index, queue) in queues.iter().enumerate() {
            let version_str = queue.version.to_string();
            let is_first = index == 0;
            let arrow = if is_first { "▼" } else { "▶" };
            let collapsed_class = if is_first { "" } else { " collapsed" };
            
            html.push_str(&format!(r#"
        <div class="queue-section">
            <div class="queue-header">
                <div class="queue-version collapsible" id="header-{}" onclick="toggleQueue('{}')">
                    {} Linux {}
                </div>
                <div class="patch-count">{} patches</div>
            </div>
            "#, 
                version_str.replace('.', "-"),
                version_str.replace('.', "-"),
                arrow,
                version_str,
                queue.total_patches
            ));
            
            if queue.patches.is_empty() {
                html.push_str(&format!(r#"<div class="empty-queue{}" id="queue-{}">No patches in queue</div>"#, 
                    collapsed_class,
                    version_str.replace('.', "-")
                ));
            } else {
                html.push_str(&format!(r#"
            <div class="patch-list{}" id="queue-{}">
                <table>
                    <thead>
                        <tr>
                            <th>Subject</th>
                            <th>Author</th>
                            <th>Upstream Commit</th>
                            <th>Changes</th>
                            <th>Filename</th>
                        </tr>
                    </thead>
                    <tbody>
                "#, collapsed_class, version_str.replace('.', "-")));
                
                for patch in &queue.patches {
                    let commit_cell = if let Some(sha) = &patch.upstream_commit {
                        format!(
                            r#"<a href="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id={}" target="_blank">{}</a>"#,
                            sha,
                            &sha[..8]
                        )
                    } else {
                        "-".to_string()
                    };
                    
                    let changes = format!(
                        r#"<span class="additions">+{}</span> <span class="deletions">-{}</span>"#,
                        patch.lines_added,
                        patch.lines_removed
                    );
                    
                    html.push_str(&format!(r#"
                        <tr>
                            <td class="subject" title="{}">{}</td>
                            <td class="author">{}</td>
                            <td class="commit-sha">{}</td>
                            <td class="changes">{}</td>
                            <td class="filename"><a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/stable-queue.git/tree/queue-{}/{}" title="{}" target="_blank">{}</a></td>
                        </tr>
                    "#,
                        html_escape(&patch.subject),
                        html_escape(&patch.subject),
                        format_author_link(&patch.author, &patch.subject),
                        commit_cell,
                        changes,
                        version_str,
                        patch.filename,
                        html_escape(&patch.filename),
                        html_escape(&patch.filename)
                    ));
                }
                
                html.push_str(r#"
                    </tbody>
                </table>
            </div>
                "#);
            }
            
            html.push_str("</div>\n");
        }
        
        html
    }
    
    /// Generate the possible issues dashboard
    pub fn generate_possible_issues_dashboard(&self) -> MailbotResult<()> {
        info!("Generating possible issues dashboard");
        
        // Read active kernel versions
        let active_versions = self.read_active_versions()?;
        
        // Create progress bar for processing versions
        let progress = ProgressBar::new(active_versions.len() as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} versions ({msg})")
                .unwrap()
                .progress_chars("#>-")
        );
        
        // Process all versions in parallel
        let issues_per_version: Vec<_> = active_versions
            .par_iter()
            .map(|version| {
                progress.set_message(format!("Analyzing {}", version));
                let queue_dir = self.stable_queue_dir.join(format!("queue-{}.{}", version.major, version.minor));
                
                if !queue_dir.exists() {
                    return Ok((Vec::new(), Vec::new()));
                }
                
                // Collect all patch file paths
                let patch_files: Vec<_> = fs::read_dir(&queue_dir)?
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| {
                        path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("patch")
                    })
                    .collect();
                
                // Process patches in parallel
                let version_issues: Vec<_> = patch_files
                    .par_iter()
                    .filter_map(|path| {
                        if let Ok(patch_info) = self.parse_patch_file(path) {
                            // Check if patch has upstream SHA
                            if patch_info.upstream_commit.is_none() {
                                Some((Some(IssuesPatch {
                                    filename: patch_info.filename,
                                    subject: patch_info.subject,
                                    author: patch_info.author,
                                    queue_version: version.clone(),
                                    upstream_commit: None,
                                    missing_from_versions: Vec::new(),
                                }), None))
                            } else if let Some(ref sha) = patch_info.upstream_commit {
                                // Only check if patch is missing if it has Fixes: or cc: stable tags
                                if self.patch_needs_stable_backport(path) {
                                    // Check if this patch is missing from newer versions
                                    if let Ok(missing_from) = self.check_missing_from_newer_versions(
                                        sha,
                                        &patch_info.subject,
                                        version,
                                        &active_versions
                                    ) {
                                        if !missing_from.is_empty() {
                                            Some((None, Some(IssuesPatch {
                                                filename: patch_info.filename,
                                                subject: patch_info.subject,
                                                author: patch_info.author,
                                                queue_version: version.clone(),
                                                upstream_commit: patch_info.upstream_commit,
                                                missing_from_versions: missing_from,
                                            })))
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect();
                
                let mut without_sha = Vec::new();
                let mut missing_from_newer = Vec::new();
                
                for (without, missing) in version_issues {
                    if let Some(patch) = without {
                        without_sha.push(patch);
                    }
                    if let Some(patch) = missing {
                        missing_from_newer.push(patch);
                    }
                }
                
                let result = Ok::<_, MailbotError>((without_sha, missing_from_newer));
                progress.inc(1);
                result
            })
            .collect::<Result<Vec<_>, _>>()?;
        
        progress.finish_with_message("Analysis complete");
        
        // Flatten results
        let mut patches_without_sha = Vec::new();
        let mut patches_missing_from_newer = Vec::new();
        
        for (without, missing) in issues_per_version {
            patches_without_sha.extend(without);
            patches_missing_from_newer.extend(missing);
        }
        
        // Sort by queue version
        patches_without_sha.sort_by(|a, b| a.queue_version.cmp(&b.queue_version));
        patches_missing_from_newer.sort_by(|a, b| a.queue_version.cmp(&b.queue_version));
        
        // Create issues data
        let issues_data = IssuesData {
            generated_at: Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string(),
            total_issues: patches_without_sha.len() + patches_missing_from_newer.len(),
            patches_without_sha,
            patches_missing_from_newer,
        };
        
        // Generate HTML
        let html = self.render_issues_html(&issues_data)?;
        
        // Write to file
        let output_path = self.output_dir.join("possible-issues.html");
        fs::write(&output_path, html)?;
        
        info!("Possible issues dashboard written to: {}", output_path.display());
        
        Ok(())
    }
    
    /// Check if a patch is missing from newer kernel versions
    fn check_missing_from_newer_versions(
        &self,
        upstream_sha: &str,
        subject: &str,
        current_version: &KernelVersion,
        all_versions: &[KernelVersion]
    ) -> MailbotResult<Vec<KernelVersion>> {
        // Get all versions newer than current
        let newer_versions: Vec<&KernelVersion> = all_versions
            .iter()
            .filter(|v| *v > current_version)
            .collect();
            
        // For debugging/progress, we can show what we're checking
        if !newer_versions.is_empty() {
            debug!("Checking {} against {} newer versions", subject, newer_versions.len());
        }
            
        // Check each newer version in parallel
        let missing_from: Vec<KernelVersion> = newer_versions
            .par_iter()
            .filter_map(|&newer_version| {
                let queue_dir = self.stable_queue_dir.join(
                    format!("queue-{}.{}", newer_version.major, newer_version.minor)
                );
                
                let mut found = false;
                
                // Check if patch exists in this queue
                if queue_dir.exists() {
                    // Read patch files in parallel to search for the patch
                    let patch_files: Vec<_> = fs::read_dir(&queue_dir).ok()?
                        .filter_map(Result::ok)
                        .map(|entry| entry.path())
                        .filter(|path| {
                            path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("patch")
                        })
                        .collect();
                    
                    found = patch_files
                        .par_iter()
                        .any(|path| {
                            if let Ok(content) = fs::read_to_string(path) {
                                content.contains(upstream_sha) || content.contains(subject)
                            } else {
                                false
                            }
                        });
                }
                
                // If not found in queue, check if it's in releases first (faster)
                if !found {
                    // Use git grep to search for the SHA in the stable-queue repo
                    let output = Command::new("git")
                        .arg("-C")
                        .arg(&self.stable_queue_dir)
                        .arg("grep")
                        .arg("-l")  // Only show filenames
                        .arg(upstream_sha)
                        .arg("--")
                        .arg(format!("releases/{}.{}*", newer_version.major, newer_version.minor))
                        .output();
                    
                    if let Ok(output) = output {
                        if output.status.success() && !output.stdout.is_empty() {
                            found = true;
                        }
                    }
                }
                
                // If still not found, check if it's already upstream in the kernel
                if !found {
                    if let Some(ref linux_dir) = self.linux_dir {
                        // Check if the commit exists in the Linux repository
                        let output = Command::new("git")
                            .arg("-C")
                            .arg(linux_dir)
                            .arg("cat-file")
                            .arg("-e")
                            .arg(upstream_sha)
                            .output();
                        
                        if let Ok(output) = output {
                            if output.status.success() {
                                // Commit exists, now check if it's in the stable branch
                                let branch_name = format!("origin/linux-{}.{}.y", newer_version.major, newer_version.minor);
                                let merge_base_output = Command::new("git")
                                    .arg("-C")
                                    .arg(linux_dir)
                                    .arg("merge-base")
                                    .arg("--is-ancestor")
                                    .arg(upstream_sha)
                                    .arg(&branch_name)
                                    .output();
                                
                                if let Ok(merge_base_output) = merge_base_output {
                                    if merge_base_output.status.success() {
                                        found = true;
                                    }
                                }
                            }
                        }
                    }
                }
                
                if !found {
                    Some(newer_version.clone())
                } else {
                    None
                }
            })
            .collect();
        
        Ok(missing_from)
    }
    
    /// Check if a patch needs stable backport by looking for Fixes: or cc: stable tags
    fn patch_needs_stable_backport(&self, patch_path: &Path) -> bool {
        if let Ok(content) = fs::read_to_string(patch_path) {
            // Check for Fixes: tag
            if content.lines().any(|line| line.trim_start().starts_with("Fixes:")) {
                return true;
            }
            
            // Check for cc: stable tag (case insensitive)
            let lower_content = content.to_lowercase();
            if lower_content.contains("cc:") && lower_content.contains("stable") {
                // More precise check for "cc: stable" patterns
                for line in content.lines() {
                    let line_lower = line.to_lowercase();
                    if (line_lower.contains("cc:") || line_lower.contains("cc :")) && 
                       (line_lower.contains("stable@") || 
                        line_lower.contains("<stable@") ||
                        line_lower.contains("stable <") ||
                        line_lower.contains("stable kernel")) {
                        return true;
                    }
                }
            }
            
            false
        } else {
            false
        }
    }
    
    /// Render the issues dashboard as HTML
    fn render_issues_html(&self, data: &IssuesData) -> MailbotResult<String> {
        let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Linux Stable Queue - Possible Issues</title>
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
        h1, h2 {{
            color: #2c3e50;
        }}
        h1 {{
            font-size: 1.8em;
            margin: 10px 0;
        }}
        h2 {{
            font-size: 1.4em;
            margin-top: 30px;
            margin-bottom: 15px;
            padding-bottom: 5px;
            border-bottom: 2px solid #3498db;
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
            margin-bottom: 20px;
        }}
        .stat-card {{
            background-color: white;
            padding: 15px;
            border-radius: 4px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
        }}
        .stat-label {{
            color: #7f8c8d;
            margin-top: 5px;
            font-size: 0.9em;
        }}
        .issue-section {{
            background-color: white;
            padding: 15px;
            border-radius: 4px;
            box-shadow: 0 1px 2px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.95em;
        }}
        th {{
            background-color: #f8f9fa;
            padding: 8px 10px;
            text-align: left;
            font-weight: 600;
            color: #2c3e50;
            border-bottom: 2px solid #dee2e6;
        }}
        td {{
            padding: 6px 10px;
            border-bottom: 1px solid #eee;
        }}
        tr:hover {{
            background-color: #f8f9fa;
        }}
        .subject {{
            font-weight: 500;
        }}
        .author {{
            color: #7f8c8d;
            font-size: 0.92em;
        }}
        .author a {{
            color: #7f8c8d;
            text-decoration: none;
        }}
        .author a:hover {{
            color: #3498db;
            text-decoration: underline;
        }}
        .queue-version {{
            font-weight: 600;
            color: #3498db;
        }}
        .missing-versions {{
            color: #e74c3c;
            font-size: 0.9em;
        }}
        .filename {{
            font-family: monospace;
            font-size: 0.88em;
        }}
        .filename a {{
            color: #3498db;
            text-decoration: none;
        }}
        .filename a:hover {{
            text-decoration: underline;
        }}
        .queue-version a {{
            color: #3498db;
            text-decoration: none;
        }}
        .queue-version a:hover {{
            text-decoration: underline;
        }}
        .warning {{
            background-color: #e74c3c;
            color: white;
        }}
        .info {{
            background-color: #f39c12;
            color: white;
        }}
        .timestamp {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .no-issues {{
            text-align: center;
            color: #27ae60;
            padding: 40px;
            font-size: 1.2em;
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
    </style>
</head>
<body>
    <nav class="nav">
        <div class="nav-links">
            <a href="queue-status.html">Queue Status</a>
            <a href="possible-issues.html" class="active">Possible Issues</a>
        </div>
    </nav>
    <div class="container">
        <div class="header">
            <h1>Linux Stable Queue - Possible Issues</h1>
            <p class="timestamp">Generated at: {}</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value {}">{}</div>
                <div class="stat-label">Total Issues</div>
            </div>
            <div class="stat-card">
                <div class="stat-value {}">{}</div>
                <div class="stat-label">Patches Without SHA</div>
            </div>
            <div class="stat-card">
                <div class="stat-value {}">{}</div>
                <div class="stat-label">Patches Missing From Newer</div>
            </div>
        </div>
        
        {}
    </div>
</body>
</html>"#,
            data.generated_at,
            if data.total_issues > 0 { "warning" } else { "info" },
            data.total_issues,
            if data.patches_without_sha.is_empty() { "info" } else { "warning" },
            data.patches_without_sha.len(),
            if data.patches_missing_from_newer.is_empty() { "info" } else { "warning" },
            data.patches_missing_from_newer.len(),
            self.render_issues_sections(data)
        );
        
        Ok(html)
    }
    
    /// Render the issues sections
    fn render_issues_sections(&self, data: &IssuesData) -> String {
        let mut html = String::new();
        
        if data.total_issues == 0 {
            html.push_str(r#"<div class="issue-section"><div class="no-issues">✓ No issues detected! All patches have upstream SHAs and are properly queued.</div></div>"#);
            return html;
        }
        
        // Patches without SHA section
        if !data.patches_without_sha.is_empty() {
            html.push_str(r#"
        <h2>Patches Without Upstream SHA</h2>
        <div class="issue-section">
            <table>
                <thead>
                    <tr>
                        <th>Queue</th>
                        <th>Subject</th>
                        <th>Author</th>
                        <th>Filename</th>
                    </tr>
                </thead>
                <tbody>
            "#);
            
            for patch in &data.patches_without_sha {
                html.push_str(&format!(r#"
                    <tr>
                        <td class="queue-version"><a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/stable-queue.git/tree/queue-{}">{}</a></td>
                        <td class="subject" title="{}">{}</td>
                        <td class="author">{}</td>
                        <td class="filename"><a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/stable-queue.git/tree/queue-{}/{}" title="{}">{}</a></td>
                    </tr>
                "#,
                    patch.queue_version,
                    patch.queue_version,
                    html_escape(&patch.subject),
                    html_escape(&patch.subject),
                    format_author_link(&patch.author, &patch.subject),
                    patch.queue_version,
                    patch.filename,
                    html_escape(&patch.filename),
                    html_escape(&patch.filename)
                ));
            }
            
            html.push_str(r#"
                </tbody>
            </table>
        </div>
            "#);
        }
        
        // Patches missing from newer versions section
        if !data.patches_missing_from_newer.is_empty() {
            html.push_str(r#"
        <h2>Patches Missing From Newer Kernel Versions</h2>
        <div class="issue-section">
            <table>
                <thead>
                    <tr>
                        <th>Queue</th>
                        <th>Subject</th>
                        <th>Author</th>
                        <th>Missing From</th>
                        <th>Filename</th>
                    </tr>
                </thead>
                <tbody>
            "#);
            
            for patch in &data.patches_missing_from_newer {
                let missing_versions = patch.missing_from_versions
                    .iter()
                    .map(|v| v.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                
                html.push_str(&format!(r#"
                    <tr>
                        <td class="queue-version"><a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/stable-queue.git/tree/queue-{}">{}</a></td>
                        <td class="subject" title="{}">{}</td>
                        <td class="author">{}</td>
                        <td class="missing-versions">{}</td>
                        <td class="filename"><a href="https://git.kernel.org/pub/scm/linux/kernel/git/stable/stable-queue.git/tree/queue-{}/{}" title="{}">{}</a></td>
                    </tr>
                "#,
                    patch.queue_version,
                    patch.queue_version,
                    html_escape(&patch.subject),
                    html_escape(&patch.subject),
                    format_author_link(&patch.author, &patch.subject),
                    missing_versions,
                    patch.queue_version,
                    patch.filename,
                    html_escape(&patch.filename),
                    html_escape(&patch.filename)
                ));
            }
            
            html.push_str(r#"
                </tbody>
            </table>
        </div>
            "#);
        }
        
        html
    }
}

/// Extract SHA1 from a line containing commit information
fn extract_sha_from_line(line: &str) -> Option<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    for word in words {
        if word.len() == 40 && word.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(word.to_string());
        }
    }
    None
}

/// HTML escape a string
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Format author with mailto link
fn format_author_link(author: &str, subject: &str) -> String {
    // Extract email from "Name <email>" format
    if let (Some(start), Some(end)) = (author.find('<'), author.find('>')) {
        if start < end {
            let email = &author[start + 1..end];
            let name = author[..start].trim();
            // URL encode the subject
            let subject_with_re = format!("Re: {subject}");
            let encoded_subject = urlencoding::encode(&subject_with_re);
            return format!(
                r#"<a href="mailto:{}?subject={}" title="{}">{}</a>"#,
                email,
                encoded_subject,
                html_escape(author),
                html_escape(name)
            );
        }
    }
    // If no email found, just return escaped author
    html_escape(author)
}