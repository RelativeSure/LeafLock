#!/bin/bash

# LeafLock PostgreSQL Restore Script from S3
# This script downloads and restores encrypted database backups from S3

set -euo pipefail

# Configuration from environment variables
POSTGRES_HOST="${POSTGRES_HOST:-postgres}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-notes}"
POSTGRES_USER="${POSTGRES_USER:-postgres}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-}"

BACKUP_S3_BUCKET="${BACKUP_S3_BUCKET:-}"
BACKUP_S3_ENDPOINT="${BACKUP_S3_ENDPOINT:-https://s3.amazonaws.com}"
BACKUP_S3_ACCESS_KEY="${BACKUP_S3_ACCESS_KEY:-}"
BACKUP_S3_SECRET_KEY="${BACKUP_S3_SECRET_KEY:-}"
BACKUP_S3_REGION="${BACKUP_S3_REGION:-us-east-1}"
BACKUP_ENCRYPTION_KEY="${BACKUP_ENCRYPTION_KEY:-}"

# Restore directory
RESTORE_DIR="/tmp/restore"
mkdir -p "$RESTORE_DIR"

# Show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -f, --file S3_KEY     Restore from specific S3 key"
    echo "  -l, --list           List available backups"
    echo "  -h, --help           Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --list"
    echo "  $0 --file backups/2025/01/21/leaflock_backup_20250121_020000.sql.gz.enc"
    echo ""
    echo "Environment variables required:"
    echo "  POSTGRES_PASSWORD, BACKUP_S3_BUCKET, BACKUP_S3_ACCESS_KEY,"
    echo "  BACKUP_S3_SECRET_KEY, BACKUP_ENCRYPTION_KEY"
}

# Parse command line arguments
BACKUP_FILE=""
LIST_BACKUPS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--file)
            BACKUP_FILE="$2"
            shift 2
            ;;
        -l|--list)
            LIST_BACKUPS=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Check if required environment variables are set
if [[ -z "$POSTGRES_PASSWORD" ]]; then
    echo "Error: POSTGRES_PASSWORD is required"
    exit 1
fi

if [[ -z "$BACKUP_S3_BUCKET" ]]; then
    echo "Error: BACKUP_S3_BUCKET is required"
    exit 1
fi

if [[ -z "$BACKUP_S3_ACCESS_KEY" || -z "$BACKUP_S3_SECRET_KEY" ]]; then
    echo "Error: BACKUP_S3_ACCESS_KEY and BACKUP_S3_SECRET_KEY are required"
    exit 1
fi

if [[ -z "$BACKUP_ENCRYPTION_KEY" ]]; then
    echo "Error: BACKUP_ENCRYPTION_KEY is required"
    exit 1
fi

# Configure AWS CLI for S3 access
export AWS_ACCESS_KEY_ID="$BACKUP_S3_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$BACKUP_S3_SECRET_KEY"
export AWS_DEFAULT_REGION="$BACKUP_S3_REGION"

# List available backups
if [[ "$LIST_BACKUPS" == "true" ]]; then
    echo "Available backups in s3://${BACKUP_S3_BUCKET}/backups/:"
    echo ""
    aws s3 ls "s3://${BACKUP_S3_BUCKET}/backups/" --recursive --endpoint-url "$BACKUP_S3_ENDPOINT" \
        --human-readable --summarize | grep "\.sql\.gz\.enc$" | \
        awk '{print $1 " " $2 " " $3 " " $4}' | \
        sort -r | head -20
    echo ""
    echo "Use --file option with the S3 key (4th column) to restore a specific backup"
    exit 0
fi

# If no backup file specified, try to find the latest one
if [[ -z "$BACKUP_FILE" ]]; then
    echo "Finding latest backup..."
    LATEST_BACKUP=$(aws s3 ls "s3://${BACKUP_S3_BUCKET}/backups/" --recursive --endpoint-url "$BACKUP_S3_ENDPOINT" | \
        grep "\.sql\.gz\.enc$" | sort -k1,1 -k2,2 | tail -n1 | awk '{print $4}')

    if [[ -z "$LATEST_BACKUP" ]]; then
        echo "Error: No backups found in s3://${BACKUP_S3_BUCKET}/backups/"
        echo "Use --list to see available backups"
        exit 1
    fi

    BACKUP_FILE="$LATEST_BACKUP"
    echo "Using latest backup: $BACKUP_FILE"
fi

# Function to cleanup restore files
cleanup_restore() {
    local restore_files=("$@")
    for file in "${restore_files[@]}"; do
        if [[ -f "$file" ]]; then
            rm -f "$file"
            echo "Cleaned up temporary file: $file"
        fi
    done
}

# Trap to ensure cleanup on exit
RESTORE_FILE="${RESTORE_DIR}/$(basename "$BACKUP_FILE")"
DECRYPTED_FILE="${RESTORE_FILE%.enc}"
UNCOMPRESSED_FILE="${DECRYPTED_FILE%.gz}"

trap 'cleanup_restore "$RESTORE_FILE" "$DECRYPTED_FILE" "$UNCOMPRESSED_FILE"' EXIT

echo "Starting LeafLock restore at $(date)"
echo "Database: ${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"
echo "Backup: s3://${BACKUP_S3_BUCKET}/${BACKUP_FILE}"

# Download backup from S3
echo "Downloading backup from S3..."
if ! aws s3 cp "s3://${BACKUP_S3_BUCKET}/${BACKUP_FILE}" "$RESTORE_FILE" \
    --endpoint-url "$BACKUP_S3_ENDPOINT"; then
    echo "Error: Failed to download backup from S3"
    exit 1
fi

echo "Backup downloaded: $(stat -c%s "$RESTORE_FILE") bytes"

# Decrypt the backup
echo "Decrypting backup..."
if ! openssl enc -aes-256-cbc -d -in "$RESTORE_FILE" -out "$DECRYPTED_FILE" -pass pass:"$BACKUP_ENCRYPTION_KEY"; then
    echo "Error: Failed to decrypt backup"
    echo "Please check BACKUP_ENCRYPTION_KEY"
    exit 1
fi

echo "Backup decrypted: $(stat -c%s "$DECRYPTED_FILE") bytes"

# Decompress the backup
echo "Decompressing backup..."
if ! gunzip -c "$DECRYPTED_FILE" > "$UNCOMPRESSED_FILE"; then
    echo "Error: Failed to decompress backup"
    exit 1
fi

echo "Backup decompressed: $(stat -c%s "$UNCOMPRESSED_FILE") bytes"

# Check database connection
echo "Testing database connection..."
export PGPASSWORD="$POSTGRES_PASSWORD"
if ! psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d postgres -c "SELECT 1;" > /dev/null; then
    echo "Error: Cannot connect to database"
    exit 1
fi

echo "Database connection successful"

# Confirm before proceeding
echo ""
echo "WARNING: This will completely replace the current database!"
echo "Database: ${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"
echo "Backup: $BACKUP_FILE"
echo ""
read -p "Are you sure you want to continue? (yes/no): " -r
if [[ ! $REPLY =~ ^[Yy]([Ee][Ss])?$ ]]; then
    echo "Restore cancelled"
    exit 0
fi

# Restore the database
echo "Restoring database..."
if ! psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d postgres \
    --set ON_ERROR_STOP=on --quiet < "$UNCOMPRESSED_FILE"; then
    echo "Error: Database restore failed"
    echo "Please check the backup file and database connection"
    exit 1
fi

echo "Database restored successfully"

# Verify the restore
echo "Verifying restore..."
TABLE_COUNT=$(psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -t -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';" | tr -d ' ')

if [[ "$TABLE_COUNT" -gt 0 ]]; then
    echo "Restore verification successful: $TABLE_COUNT tables found"
else
    echo "Warning: No tables found after restore"
fi

echo "Restore completed at $(date)"
echo ""
echo "Next steps:"
echo "1. Restart the LeafLock backend service"
echo "2. Verify application functionality"
echo "3. Check logs for any errors"