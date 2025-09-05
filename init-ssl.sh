#!/bin/bash
# SSL Certificate Generation for PostgreSQL
# This script generates self-signed SSL certificates for PostgreSQL

echo "🔐 Initializing SSL certificates for PostgreSQL..."

# Check if certificates already exist
if [ -f /var/lib/postgresql/server.crt ] && [ -f /var/lib/postgresql/server.key ]; then
    echo "✅ SSL certificates already exist, skipping generation"
    exit 0
fi

echo "📜 Generating SSL certificates..."

# Generate self-signed SSL certificate and private key
openssl req -new -x509 -days 365 -nodes -text \
    -out /var/lib/postgresql/server.crt \
    -keyout /var/lib/postgresql/server.key \
    -subj "/C=US/ST=State/L=City/O=SecureNotes/OU=Database/CN=postgres"

# Set proper ownership and permissions for PostgreSQL
if id "postgres" &>/dev/null; then
    chown postgres:postgres /var/lib/postgresql/server.crt /var/lib/postgresql/server.key
else
    # Fallback for containers where postgres user might not exist yet
    chown 999:999 /var/lib/postgresql/server.crt /var/lib/postgresql/server.key
fi

# Set secure permissions
chmod 600 /var/lib/postgresql/server.key
chmod 644 /var/lib/postgresql/server.crt

echo "✅ SSL certificates generated successfully"
echo "   - Certificate: /var/lib/postgresql/server.crt"
echo "   - Private Key: /var/lib/postgresql/server.key"
echo "🔒 PostgreSQL SSL is now configured"