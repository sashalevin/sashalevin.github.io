#!/bin/bash
set -e

echo "=== Updating Linux Kernel Stable Status Dashboards ==="
echo

# Navigate to repository root
cd "$(dirname "$0")"

echo "1. Updating git submodules..."
git submodule update --init --recursive

# Update each submodule to latest master/origin
echo "2. Updating submodules to latest master..."
git -C linux fetch origin && git -C linux checkout origin/master
git -C linux-stable-rc fetch origin && git -C linux-stable-rc checkout origin/master 
git -C stable-queue fetch origin && git -C stable-queue checkout origin/master

# Update all remote branches for comprehensive checking
echo "3. Updating all remote branches..."
git -C linux remote update
git -C linux-stable-rc remote update
git -C stable-queue remote update

# Build the dashboard generator
echo "4. Building mailbot..."
cd status
cargo build --release
cd ..

# Generate dashboards
echo "5. Generating dashboards..."
cd status
time ./target/release/mailbot dashboard -t all -o ./dashboard -c ./dashboard-config.json
cd ..

echo
echo "✓ Dashboards updated successfully!"
echo "  - Queue Status: status/dashboard/queue-status.html"
echo "  - Possible Issues: status/dashboard/possible-issues.html"
echo "  - Index: index.html"
