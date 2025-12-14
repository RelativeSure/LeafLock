#!/bin/bash

# Script to run all checks with proper error handling and timeout management
set -e

echo "🚀 Starting check-all sequence..."
echo "=================================="

# Track total time
START_TIME=$(date +%s)

echo ""
echo "1️⃣  Running TypeScript type check..."
pnpm run type-check
echo "✅ Type check passed"

echo ""
echo "2️⃣  Running ESLint..."
pnpm run lint
echo "✅ Linting passed"

echo ""
echo "3️⃣  Running Prettier format check..."
pnpm run format:check
echo "✅ Format check passed"

echo ""
echo "4️⃣  Running tests..."
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
