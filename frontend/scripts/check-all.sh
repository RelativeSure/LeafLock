#!/bin/bash

# Script to run all checks with proper error handling and timeout management
set -e

echo "🚀 Starting check-all sequence..."
echo "=================================="

# Track total time
START_TIME=$(date +%s)

echo ""
echo "1️⃣  Checking for prohibited .jsx files..."
sh scripts/check-no-jsx.sh
echo "✅ No .jsx files found"

echo ""
echo "2️⃣  Checking shadcn/ui compliance..."
sh scripts/check-shadcn-compliance.sh
echo "✅ shadcn/ui compliance verified"

echo ""
echo "3️⃣  Checking documentation policy..."
sh scripts/check-frontend-docs.sh
echo "✅ Documentation policy compliance verified"

echo ""
echo "4️⃣  Running TypeScript type check..."
pnpm run type-check
echo "✅ Type check passed"

echo ""
echo "5️⃣  Running ESLint..."
pnpm run lint
echo "✅ Linting passed"

echo ""
echo "6️⃣  Running Prettier format check..."
pnpm run format:check
echo "✅ Format check passed"

echo ""
echo "7️⃣  Running tests..."
echo "   Note: Tests take ~90-160 seconds to complete. Please be patient..."
pnpm run test
echo "✅ All tests passed"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "=================================="
echo "✅ All checks completed successfully!"
echo "⏱️  Total duration: ${DURATION} seconds"
echo "=================================="
