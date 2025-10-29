#!/bin/bash
set -e

URL="https://frontend-leaflock-pr-363.up.railway.app/"
ITERATION=0
MAX_ITERATIONS=20

echo "🔁 Starting automated test-and-fix loop for React error #185"
echo "Testing URL: $URL"
echo ""

while [ $ITERATION -lt $MAX_ITERATIONS ]; do
  ITERATION=$((ITERATION + 1))
  echo "=== Iteration $ITERATION ==="
  
  echo "⏳ Waiting 120s for deployment..."
  sleep 120
  
  echo "🔍 Testing deployment..."
  BUNDLE=$(curl -s "$URL" 2>&1 | grep -oE "index-[A-Za-z0-9]+\.js" | head -1 || echo "")
  
  if [ -z "$BUNDLE" ]; then
    echo "⚠️  No bundle found, waiting 60s more..."
    sleep 60
    BUNDLE=$(curl -s "$URL" 2>&1 | grep -oE "index-[A-Za-z0-9]+\.js" | head -1 || echo "")
  fi
  
  if [ -n "$BUNDLE" ]; then
    echo "✅ Bundle deployed: $BUNDLE"
    echo "✅ Test completed. Manual verification needed for React error #185."
    echo "   Please check: $URL in browser console for error #185"
    break
  else
    echo "❌ Still waiting for deployment..."
  fi
  
  echo ""
done

echo "🏁 Loop completed after $ITERATION iterations"

