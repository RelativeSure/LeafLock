#!/bin/bash

# LeafLock PostgreSQL Backup Script with S3 Upload
# This script creates encrypted database backups and uploads them to S3

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
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

# Backup directory
BACKUP_DIR="/tmp/backups"
mkdir -p "$BACKUP_DIR"

# Generate timestamp for backup filename
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILENAME="leaflock_backup_${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DIR}/${BACKUP_FILENAME}"

echo "Starting LeafLock backup at $(date)"
echo "Database: ${POSTGRES_HOST}:${POSTGRES_PORT}/${POSTGRES_DB}"

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

# Function to send metrics to backend (if available)
send_metric() {
    local status="$1"
    local duration="$2"
    local size="${3:-0}"

    # Try to send metrics to the backend API
    if curl -s -f "http://backend:8080/api/v1/health" > /dev/null 2>&1; then
        curl -s -X POST "http://backend:8080/metrics/backup" \
            -H "Content-Type: application/json" \
            -d "{\"status\":\"$status\",\"duration\":$duration,\"size\":$size}" \
            > /dev/null 2>&1 || true
    fi
}

# Function to cleanup backup files
cleanup_backup() {
    local backup_file="$1"
    if [[ -f "$backup_file" ]]; then
        rm -f "$backup_file"
        echo "Cleaned up temporary backup file: $backup_file"
    fi
}

# Trap to ensure cleanup on exit
trap 'cleanup_backup "${BACKUP_PATH}.sql.gz.enc"' EXIT

START_TIME=$(date +%s)

# Create PostgreSQL dump
echo "Creating database dump..."
export PGPASSWORD="$POSTGRES_PASSWORD"

if ! pg_dump -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    --verbose --clean --if-exists --create --no-password | gzip > "${BACKUP_PATH}.sql.gz"; then
    echo "Error: Database dump failed"
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    send_metric "failure" "$DURATION" 0
    exit 1
fi

# Get size of compressed dump
DUMP_SIZE=$(stat -c%s "${BACKUP_PATH}.sql.gz")
echo "Database dump created: ${DUMP_SIZE} bytes (compressed)"

# Encrypt the backup
echo "Encrypting backup..."
if ! openssl enc -aes-256-cbc -salt -in "${BACKUP_PATH}.sql.gz" -out "${BACKUP_PATH}.sql.gz.enc" -pass pass:"$BACKUP_ENCRYPTION_KEY"; then
    echo "Error: Backup encryption failed"
    rm -f "${BACKUP_PATH}.sql.gz"
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    send_metric "failure" "$DURATION" 0
    exit 1
fi

# Remove unencrypted backup
rm -f "${BACKUP_PATH}.sql.gz"

# Get size of encrypted backup
ENCRYPTED_SIZE=$(stat -c%s "${BACKUP_PATH}.sql.gz.enc")
echo "Backup encrypted: ${ENCRYPTED_SIZE} bytes"

# Configure AWS CLI for S3 upload
export AWS_ACCESS_KEY_ID="$BACKUP_S3_ACCESS_KEY"
export AWS_SECRET_ACCESS_KEY="$BACKUP_S3_SECRET_KEY"
export AWS_DEFAULT_REGION="$BACKUP_S3_REGION"

# Upload to S3
echo "Uploading backup to S3..."
S3_KEY="backups/$(date +%Y)/$(date +%m)/$(date +%d)/${BACKUP_FILENAME}.sql.gz.enc"

if ! aws s3 cp "${BACKUP_PATH}.sql.gz.enc" "s3://${BACKUP_S3_BUCKET}/${S3_KEY}" \
    --endpoint-url "$BACKUP_S3_ENDPOINT" \
    --storage-class STANDARD_IA; then
    echo "Error: S3 upload failed"
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    send_metric "failure" "$DURATION" 0
    exit 1
fi

echo "Backup uploaded to S3: s3://${BACKUP_S3_BUCKET}/${S3_KEY}"

# Cleanup old backups (optional)
if command -v aws >/dev/null 2>&1 && [[ "$BACKUP_RETENTION_DAYS" -gt 0 ]]; then
    echo "Cleaning up backups older than $BACKUP_RETENTION_DAYS days..."
    CUTOFF_DATE=$(date -d "$BACKUP_RETENTION_DAYS days ago" +%Y-%m-%d)

    # List and delete old backups
    aws s3 ls "s3://${BACKUP_S3_BUCKET}/backups/" --recursive --endpoint-url "$BACKUP_S3_ENDPOINT" | \
    while read -r line; do
        # Extract date from S3 listing (YYYY-MM-DD)
        backup_date=$(echo "$line" | awk '{print $1}')
        if [[ "$backup_date" < "$CUTOFF_DATE" ]]; then
            backup_key=$(echo "$line" | awk '{print $4}')
            echo "Deleting old backup: $backup_key"
            aws s3 rm "s3://${BACKUP_S3_BUCKET}/${backup_key}" --endpoint-url "$BACKUP_S3_ENDPOINT" || true
        fi
    done
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo "Backup completed successfully in ${DURATION} seconds"
echo "Backup size: ${ENCRYPTED_SIZE} bytes"
echo "S3 location: s3://${BACKUP_S3_BUCKET}/${S3_KEY}"

# Send success metrics
send_metric "success" "$DURATION" "$ENCRYPTED_SIZE"

echo "Backup completed at $(date)"