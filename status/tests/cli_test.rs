use clap::Parser;
use mailbot::cli::{Args, Commands};

#[test]
fn test_cli_process_subcommand() {
    let args = Args::parse_from(["mailbot", "process", "-i", "test.json"]);
    assert_eq!(args.config, "~/.config/mailbot/config.json");
    assert!(!args.verbose);
    
    match args.command {
        Commands::Process { input, input_type, skip_build, output_dir, .. } => {
            assert_eq!(input, "test.json");
            assert_eq!(input_type, None); // Auto-detected
            assert!(!skip_build);
            assert_eq!(output_dir, "./output");
        }
        _ => panic!("Wrong command parsed"),
    }
}

#[test]
fn test_cli_process_with_all_args() {
    let args = Args::parse_from([
        "mailbot",
        "-c", "/custom/config.json",
        "--verbose",
        "process",
        "-i", "patch.mbox",
        "-t", "mbox",
        "--skip-build",
        "-o", "/custom/output",
    ]);
    
    assert_eq!(args.config, "/custom/config.json");
    assert!(args.verbose);
    
    match args.command {
        Commands::Process { input, input_type, skip_build, output_dir, .. } => {
            assert_eq!(input, "patch.mbox");
            assert_eq!(input_type, Some("mbox".to_string()));
            assert!(skip_build);
            assert_eq!(output_dir, "/custom/output");
        }
        _ => panic!("Wrong command parsed"),
    }
}

#[test]
fn test_cli_dashboard_subcommand() {
    let args = Args::parse_from([
        "mailbot",
        "dashboard",
        "-t", "queue-status",
        "-o", "/tmp/dashboard",
    ]);
    
    match args.command {
        Commands::Dashboard { dashboard_type, output_dir } => {
            assert_eq!(dashboard_type, "queue-status");
            assert_eq!(output_dir, "/tmp/dashboard");
        }
        _ => panic!("Wrong command parsed"),
    }
}

#[test]
fn test_cli_missing_subcommand() {
    let result = Args::try_parse_from(["mailbot"]);
    assert!(result.is_err());
    
    if let Err(err) = result {
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand);
    }
}

#[test]
fn test_cli_help() {
    let result = Args::try_parse_from(["mailbot", "--help"]);
    assert!(result.is_err());
    
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
}

#[test]
fn test_cli_version() {
    let result = Args::try_parse_from(["mailbot", "--version"]);
    assert!(result.is_err());
    
    let err = result.unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
}