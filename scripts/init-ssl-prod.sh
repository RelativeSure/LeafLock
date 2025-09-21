#!/bin/bash
# Production SSL Certificate Setup for PostgreSQL
# This script copies pre-existing certificates or generates production-ready ones

set -e  # Exit on any error

echo "🔐 Setting up SSL certificates for PostgreSQL (Production Mode)..."

# Configuration
CERT_DIR="/var/lib/postgresql"
SSL_CERT_DIR="/var/lib/postgresql/ssl-certs"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"
DOMAIN="${SSL_DOMAIN:-leaflock.app}"
POSTGRES_UID=999
POSTGRES_GID=999

# Check if external certificates are provided
if [ -d "$SSL_CERT_DIR" ] && [ -f "$SSL_CERT_DIR/server.crt" ] && [ -f "$SSL_CERT_DIR/server.key" ]; then
    echo "📋 Using provided SSL certificates from $SSL_CERT_DIR"
    
    # Validate certificates before copying
    if openssl x509 -checkend 86400 -noout -in "$SSL_CERT_DIR/server.crt" >/dev/null 2>&1; then
        echo "✅ Provided certificate is valid"
        cp "$SSL_CERT_DIR/server.crt" "$CERT_FILE"
        cp "$SSL_CERT_DIR/server.key" "$KEY_FILE"
        
        # Set proper ownership and permissions
        chown $POSTGRES_UID:$POSTGRES_GID "$CERT_FILE" "$KEY_FILE"
        chmod 644 "$CERT_FILE"
        chmod 600 "$KEY_FILE"
        
        echo "✅ Production SSL certificates installed from external source"
        echo "   - Subject: $(openssl x509 -subject -noout -in "$CERT_FILE" | cut -d' ' -f2-)"
        echo "   - Valid until: $(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)"
        exit 0
    else
        echo "❌ Provided certificate is invalid or expired"
        exit 1
    fi
fi

# Check if certificates already exist and are valid
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    if openssl x509 -checkend 86400 -noout -in "$CERT_FILE" >/dev/null 2>&1; then
        echo "✅ Valid SSL certificates already exist"
        echo "   Certificate expires: $(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)"
        exit 0
    else
        echo "⚠️  Existing SSL certificate is expired or invalid, regenerating..."
        rm -f "$CERT_FILE" "$KEY_FILE"
    fi
fi

echo "📜 Generating production SSL certificates for domain: $DOMAIN"
echo "⚠️  NOTICE: Using self-signed certificates. For production, use CA-signed certificates."

# Create temporary directory for certificate generation
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# Generate strong private key
echo "🔑 Generating RSA private key (2048-bit)..."
openssl genpkey -algorithm RSA -out "$TEMP_DIR/server.key" -pkcs8 -aes256 -pass pass:temp
openssl rsa -in "$TEMP_DIR/server.key" -out "$TEMP_DIR/server.key" -passin pass:temp

# Create certificate configuration for production
cat > "$TEMP_DIR/cert.conf" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=${SSL_COUNTRY:-US}
ST=${SSL_STATE:-State}
L=${SSL_CITY:-City}
O=${SSL_ORG:-LeafLock}
OU=${SSL_OU:-Production Database}
CN=$DOMAIN

[v3_req]
basicConstraints = CA:FALSE
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
DNS.2 = postgres
DNS.3 = db
IP.1 = 127.0.0.1
EOF

# Add additional SANs if provided
if [ -n "$SSL_ADDITIONAL_DOMAINS" ]; then
    IFS=',' read -ra DOMAINS <<< "$SSL_ADDITIONAL_DOMAINS"
    for i in "${!DOMAINS[@]}"; do
        echo "DNS.$((i+4)) = ${DOMAINS[i]}" >> "$TEMP_DIR/cert.conf"
    done
fi

# Generate certificate signing request
echo "📝 Generating certificate signing request..."
openssl req -new -key "$TEMP_DIR/server.key" -out "$TEMP_DIR/server.csr" -config "$TEMP_DIR/cert.conf"

# Generate self-signed certificate valid for 1 year
echo "📜 Generating self-signed certificate (valid for 365 days)..."
openssl x509 -req -days 365 -in "$TEMP_DIR/server.csr" \
    -signkey "$TEMP_DIR/server.key" -out "$TEMP_DIR/server.crt" \
    -extensions v3_req -extfile "$TEMP_DIR/cert.conf" \
    -sha256

# Copy certificates to PostgreSQL directory
cp "$TEMP_DIR/server.crt" "$CERT_FILE"
cp "$TEMP_DIR/server.key" "$KEY_FILE"

# Set proper ownership and permissions
echo "🔒 Setting secure permissions..."
chown $POSTGRES_UID:$POSTGRES_GID "$CERT_FILE" "$KEY_FILE"
chmod 644 "$CERT_FILE"   # Certificate can be world-readable
chmod 600 "$KEY_FILE"    # Private key readable only by owner

# Verify certificate
echo "🔍 Verifying generated certificate..."
if openssl x509 -noout -text -in "$CERT_FILE" | grep -q "Subject Alternative Name"; then
    echo "✅ Certificate includes Subject Alternative Names"
else
    echo "⚠️  Warning: Certificate may not include all required SANs"
fi

# Display certificate information
echo "✅ Production SSL certificates generated successfully:"
echo "   - Certificate: $CERT_FILE"
echo "   - Private Key: $KEY_FILE (permissions: $(stat -c '%a' "$KEY_FILE"))"
echo "   - Subject: $(openssl x509 -subject -noout -in "$CERT_FILE" | cut -d' ' -f2-)"
echo "   - Valid until: $(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)"
echo "   - SHA256 fingerprint: $(openssl x509 -fingerprint -sha256 -noout -in "$CERT_FILE" | cut -d= -f2)"

# Generate certificate info for documentation
cat > "$CERT_DIR/cert-info.txt" <<EOF
SSL Certificate Information
Generated: $(date)
Domain: $DOMAIN
Subject: $(openssl x509 -subject -noout -in "$CERT_FILE" | cut -d' ' -f2-)
Valid until: $(openssl x509 -enddate -noout -in "$CERT_FILE" | cut -d= -f2)
SHA256 Fingerprint: $(openssl x509 -fingerprint -sha256 -noout -in "$CERT_FILE" | cut -d= -f2)

Note: This is a self-signed certificate for development/testing.
For production, replace with CA-signed certificates.
EOF

echo "📄 Certificate information saved to $CERT_DIR/cert-info.txt"
echo "🔒 PostgreSQL SSL is now configured for production use"

# Security recommendations
echo ""
echo "🛡️  SECURITY RECOMMENDATIONS:"
echo "   1. Replace self-signed certificates with CA-signed certificates for production"
echo "   2. Regularly monitor certificate expiration dates"
echo "   3. Use proper certificate rotation procedures"
echo "   4. Ensure private keys are properly secured and never shared"
echo "   5. Configure firewall rules to restrict database access"
