#!/bin/bash
# Test Railway API token validity
# Usage: ./scripts/test-railway-token.sh <your-railway-token>

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <railway-token>"
  echo ""
  echo "Get your Railway token from: https://railway.app/account/tokens"
  exit 1
fi

TOKEN="$1"

echo "🔍 Testing Railway API authentication..."
echo ""

# Test 1: Query current user (me)
echo "Test 1: Authenticating and fetching user info..."
QUERY='{"query":"query { me { id name email } }"}'

RESPONSE=$(curl -s -X POST https://backboard.railway.app/graphql/v2 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$QUERY")

echo "Response:"
echo "$RESPONSE" | jq '.'
echo ""

# Check for errors
if echo "$RESPONSE" | jq -e '.errors' > /dev/null 2>&1; then
  echo "❌ Authentication FAILED"
  echo "Error details:"
  echo "$RESPONSE" | jq '.errors'
  echo ""
  echo "Possible causes:"
  echo "1. Token is invalid or malformed"
  echo "2. Token has expired"
  echo "3. Token has been revoked"
  echo "4. Wrong token type (need Account Token from railway.app/account/tokens)"
  exit 1
fi

# Check if we got user data
if echo "$RESPONSE" | jq -e '.data.me' > /dev/null 2>&1; then
  echo "✅ Authentication SUCCESSFUL"
  echo "User: $(echo "$RESPONSE" | jq -r '.data.me.name // .data.me.email')"
  echo "User ID: $(echo "$RESPONSE" | jq -r '.data.me.id')"
else
  echo "❌ Authentication returned unexpected response"
  exit 1
fi

echo ""
echo "Test 2: Listing accessible projects..."
QUERY='{"query":"query { me { projects { edges { node { id name } } } } }"}'

RESPONSE=$(curl -s -X POST https://backboard.railway.app/graphql/v2 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$QUERY")

echo "Response:"
echo "$RESPONSE" | jq '.'
echo ""

if echo "$RESPONSE" | jq -e '.errors' > /dev/null 2>&1; then
  echo "❌ Failed to list projects"
  echo "$RESPONSE" | jq '.errors'
  exit 1
fi

# List projects
PROJECT_COUNT=$(echo "$RESPONSE" | jq '.data.me.projects.edges | length')
echo "✅ Found $PROJECT_COUNT project(s):"
echo "$RESPONSE" | jq -r '.data.me.projects.edges[].node | "  - \(.name) (ID: \(.id))"'

echo ""
echo "🎉 Token is valid and has access to $PROJECT_COUNT project(s)"
echo ""
echo "To use in GitHub Actions:"
echo "1. Copy one of the Project IDs above"
echo "2. Go to GitHub repo → Settings → Secrets and variables → Actions"
echo "3. Set RAILWAY_TOKEN_ACCOUNT to your token"
echo "4. Set RAILWAY_PROJECT_ID to the project ID you want to deploy"
