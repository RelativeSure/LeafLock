#!/bin/bash
# Wrapper script for golangci-lint to run from backend directory
# This solves MegaLinter's subdirectory limitation for Go projects

# Check if golangci-lint is installed
if ! command -v golangci-lint &> /dev/null; then
    echo "⚠️  golangci-lint not installed, skipping Go linting" >&2
    exit 0
fi

# Change to backend directory (relative to the script location or /tmp/lint)
if [ -d "/tmp/lint/backend" ]; then
    cd /tmp/lint/backend || exit 1
elif [ -d "backend" ]; then
    cd backend || exit 1
else
    echo "Error: backend directory not found"
    exit 1
fi

exec golangci-lint "$@"
