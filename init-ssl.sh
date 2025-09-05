#!/bin/bash
# SSL Certificate Generation for PostgreSQL
# This script generates self-signed SSL certificates for PostgreSQL with improved security

set -e  # Exit on any error

echo "🔐 Initializing SSL certificates for PostgreSQL..."

# Configuration
CERT_DIR="/var/lib/postgresql"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"
DOMAIN="${SSL_DOMAIN:-postgres}"
POSTGRES_UID=999
POSTGRES_GID=999

# Check if certificates already exist and are valid
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    # Verify certificate validity (not expired)
    if openssl x509 -checkend 86400 -noout -in "$CERT_FILE" >/dev/null 2>&1; then
        echo "✅ Valid SSL certificates already exist, skipping generation"
        echo "   Certificate expires: $(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)"
        exit 0
    else
        echo "⚠️  Existing SSL certificate is expired or invalid, regenerating..."
        rm -f "$CERT_FILE" "$KEY_FILE"
    fi
fi

echo "📜 Generating SSL certificates for domain: $DOMAIN"

# Create temporary directory for certificate generation
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Generate stronger private key (2048-bit RSA minimum for PostgreSQL)
echo "🔑 Generating private key..."
openssl genpkey -algorithm RSA -out "$TEMP_DIR/server.key" -pkcs8 -aes256 -pass pass:temp
openssl rsa -in "$TEMP_DIR/server.key" -out "$TEMP_DIR/server.key" -passin pass:temp

# Create certificate configuration with Subject Alternative Names
cat > "$TEMP_DIR/cert.conf" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=State
L=City
O=SecureNotes
OU=Database
CN=$DOMAIN

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = localhost
DNS.3 = postgres
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

# Generate certificate signing request
echo "📝 Generating certificate signing request..."
openssl req -new -key "$TEMP_DIR/server.key" -out "$TEMP_DIR/server.csr" -config "$TEMP_DIR/cert.conf"

# Generate self-signed certificate (valid for 365 days)
echo "📜 Generating self-signed certificate..."
openssl x509 -req -days 365 -in "$TEMP_DIR/server.csr" \
    -signkey "$TEMP_DIR/server.key" -out "$TEMP_DIR/server.crt" \
    -extensions v3_req -extfile "$TEMP_DIR/cert.conf"

# Copy certificates to PostgreSQL directory
cp "$TEMP_DIR/server.crt" "$CERT_FILE"
cp "$TEMP_DIR/server.key" "$KEY_FILE"

# Set proper ownership and permissions for PostgreSQL
echo "🔒 Setting secure permissions..."

# Check if postgres user exists, otherwise use UID/GID
if id "postgres" &>/dev/null; then
    chown postgres:postgres "$CERT_FILE" "$KEY_FILE"
    echo "   Using postgres user/group"
else
    # Use numeric UID/GID for containers
    chown $POSTGRES_UID:$POSTGRES_GID "$CERT_FILE" "$KEY_FILE"
    echo "   Using UID/GID $POSTGRES_UID:$POSTGRES_GID"
fi

# Set secure permissions (PostgreSQL requires specific permissions)
chmod 600 "$KEY_FILE"    # Private key readable only by owner
chmod 644 "$CERT_FILE"   # Certificate can be world-readable

# Verify certificate
echo "🔍 Verifying generated certificate..."
if openssl x509 -noout -text -in "$CERT_FILE" | grep -q "Subject Alternative Name"; then
    echo "✅ Certificate includes Subject Alternative Names"
else
    echo "⚠️  Warning: Certificate may not include all required SANs"
fi

# Display certificate information
echo "✅ SSL certificates generated successfully:"
echo "   - Certificate: $CERT_FILE"
echo "   - Private Key: $KEY_FILE (secure permissions: $(stat -c '%a' "$KEY_FILE"))"
echo "   - Subject: $(openssl x509 -subject -noout -in "$CERT_FILE" | cut -d' ' -f2-)"
echo "   - Valid until: $(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)"
echo "   - SHA256 fingerprint: $(openssl x509 -fingerprint -sha256 -noout -in "$CERT_FILE" | cut -d= -f2)"

echo "🔒 PostgreSQL SSL is now configured and ready for secure connections"