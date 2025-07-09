# Mailbot

A Rust implementation of the Linux kernel stable patch validation bot.

## Overview

Mailbot processes git patches submitted via email (using lei JSON format) and:
- Validates patches against upstream commits
- Tests patches on multiple stable kernel branches
- Checks for fixes and reverts
- Generates email responses with test results

## Usage

```bash
mailbot --input /path/to/lei.json
```

## Configuration

Default configuration is loaded from `~/.config/mailbot/config.json`. Key settings:
- `linux_dir`: Path to Linux kernel git repository
- `stable_queue_dir`: Path to stable-queue directory
- `active_versions_file`: Path to file listing active kernel versions
- `build_command`: Command to run for build testing

## Features

- Lei JSON email parsing
- Git worktree management for isolated testing
- Patch series support
- Parallel testing on multiple kernel versions (disabled by default)
- Comprehensive error handling and reporting

## Testing

```bash
cargo test
cargo clippy
```