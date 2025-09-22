#!/bin/bash

echo "🚀 Testing ElysiaJS Documentation Setup"
echo "======================================"

# Check if bun is available
if command -v bun &> /dev/null; then
    echo "✅ Bun is available"
    RUNTIME="bun"
elif command -v node &> /dev/null; then
    echo "✅ Node.js is available (fallback)"
    RUNTIME="npm"
else
    echo "❌ Neither Bun nor Node.js found"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
if [ "$RUNTIME" = "bun" ]; then
    bun install
else
    npm install
fi

# Type check
echo "🔍 Running type check..."
if [ "$RUNTIME" = "bun" ]; then
    bun run typecheck
else
    npm run typecheck
fi

# Test build
echo "🏗️ Testing build..."
if [ "$RUNTIME" = "bun" ]; then
    bun run build
else
    npm run build
fi

echo ""
echo "✅ Setup test completed successfully!"
echo ""
echo "To start the development server:"
if [ "$RUNTIME" = "bun" ]; then
    echo "  bun run dev"
else
    echo "  npm run dev"
fi
echo ""
echo "Then visit:"
echo "  📚 Documentation: http://localhost:3000/docs"
echo "  🔧 API Docs: http://localhost:3000/api-docs"
echo "  💚 Health Check: http://localhost:3000/api/health"