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
    
    /// Enable debug output
    #[arg(long, global = true)]
    pub debug: bool,
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
        /// If not specified, uses timestamp from previous run
        #[arg(long)]
        time_range: Option<String>,
        
        /// State file to track last run timestamp
        #[arg(long, default_value = "~/.mailbot_last_run")]
        state_file: String,
        
        /// Skip build tests
        #[arg(long)]
        skip_build: bool,
        
        /// Output directory for responses
        #[arg(short, long, default_value = "./output")]
        output_dir: String,
    },
    
    /// Generate HTML dashboards
    Dashboard {
        /// Type of dashboard to generate (all, queue-status, possible-issues, patch-tracking)
        #[arg(short = 't', long, default_value = "all")]
        dashboard_type: String,
        
        /// Output directory for HTML files
        #[arg(short, long, default_value = "./dashboard")]
        output_dir: String,
    },
    
    /// Query patch tracking information
    Query {
        /// Query type: "message-id", "sha1", "state", or "active"
        #[arg(short = 't', long)]
        query_type: String,
        
        /// Query value (not needed for "active" query)
        #[arg(long)]
        value: Option<String>,
        
        /// Output format: "json" or "summary"
        #[arg(short = 'f', long, default_value = "summary")]
        format: String,
    },
    
    /// Process a single email (for testing)
    ProcessEmail {
        /// Path to email file (lei JSON format)
        path: String,
    },
}