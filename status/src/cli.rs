use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "mailbot")]
#[command(author = "Sasha Levin <sashal@kernel.org>")]
#[command(version = "0.1.0")]
#[command(about = "Linux kernel stable patch validation bot", long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub command: Commands,
    
    /// Configuration file path
    #[arg(short, long, default_value = "~/.config/mailbot/config.json", global = true)]
    pub config: String,
    
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Process patches from email
    Process {
        /// Input file path (lei JSON or mbox file), or "lei" to fetch from lore
        #[arg(short, long)]
        input: String,
        
        /// Input type: "lei-json", "mbox", "lei", or "maildir" (auto-detected if not specified)
        #[arg(short = 't', long)]
        input_type: Option<String>,
        
        /// Time range for lei queries (e.g., "60" for minutes, "24h" for hours, "7d" for days)
        #[arg(long, default_value = "60")]
        time_range: String,
        
        /// State file to track last run timestamp
        #[arg(long, default_value = "~/.mailbot_last_run")]
        state_file: String,
        
        /// Enable dry run mode (don't send emails)
        #[arg(short, long)]
        dry_run: bool,
        
        /// Skip build tests
        #[arg(long)]
        skip_build: bool,
        
        /// Output directory for responses
        #[arg(short, long, default_value = "./output")]
        output_dir: String,
    },
    
    /// Generate HTML dashboards
    Dashboard {
        /// Type of dashboard to generate (all, queue-status, possible-issues)
        #[arg(short = 't', long, default_value = "all")]
        dashboard_type: String,
        
        /// Output directory for HTML files
        #[arg(short, long, default_value = "./dashboard")]
        output_dir: String,
    },
}