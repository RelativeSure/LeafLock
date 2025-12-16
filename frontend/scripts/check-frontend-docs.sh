#!/bin/bash
# Check for prohibited .md files in frontend/src directory
# This enforces the documentation policy: no standalone docs in source

set -e

echo "🔍 Scanning frontend/src for prohibited documentation files..."

# Find .md files in src directory (excluding node_modules, dist, git, etc)
PROHIBITED_DOCS=$(find src -name "*.md" -type f 2>/dev/null | grep -v node_modules | grep -v dist | grep -v ".git" || true)

VIOLATIONS=0

if [ -n "$PROHIBITED_DOCS" ]; then
  echo "❌ PROHIBITED DOCUMENTATION FILES FOUND IN frontend/src/:"
  echo ""
  echo "$PROHIBITED_DOCS" | while read -r file; do
    echo "   - $file"
    VIOLATIONS=$((VIOLATIONS + 1))
  done
  echo ""
  echo "📋 DOCUMENTATION POLICY (from AGENTS.md):"
  echo "   ❌ NEVER create standalone .md files in /frontend/src"
  echo "   ❌ DO NOT create COMPONENT_README.md, API.md, or feature-specific docs"
  echo "   ✅ ONLY update: CLAUDE.md (automation), README.md (project overview)"
  echo "   ✅ ONLY update: docs/src/content/docs/ (AstroJS documentation)"
  echo ""
  echo "💡 ACTION REQUIRED:"
  echo "   1. Delete all .md files from frontend/src/"
  echo "   2. If documentation is needed, add it to docs/src/content/docs/"
  echo "   3. Or update CLAUDE.md if it's automation-related"
  echo ""
  exit 1
else
  echo "✅ No prohibited documentation files in frontend/src/"
fi

# Check common component directories
check_dir() {
  local dir="$1"
  if [ -d "src/$dir" ]; then
    local DOCS_IN_DIR
    DOCS_IN_DIR=$(find "src/$dir" -name "*.md" -type f 2>/dev/null || true)
    if [ -n "$DOCS_IN_DIR" ]; then
      if [ "$VIOLATIONS" -eq 0 ]; then
        echo ""
        echo "❌ DOCUMENTATION FILES FOUND IN COMPONENT DIRECTORIES:"
        echo ""
      fi
      echo "   In src/$dir/:"
      echo "$DOCS_IN_DIR" | while read -r file; do
        rel_path=$(echo "$file" | sed "s|src/$dir/||")
        echo "     - $rel_path"
        VIOLATIONS=$((VIOLATIONS + 1))
      done
    fi
  fi
}

# Check component directories
check_dir "components"
check_dir "stores" 
check_dir "lib"
check_dir "utils"
check_dir "hooks"

# Final verdict
if [ "$VIOLATIONS" -gt 0 ]; then
  echo ""
  echo "=========================================="
  echo "❌ DOCUMENTATION COMPLIANCE FAILED"
  echo "=========================================="
  echo "Found $VIOLATIONS prohibited documentation file(s)"
  echo ""
  echo "💡 Remember: Documentation belongs in docs/src/content/docs/"
  echo "   NEVER in source code directories."
  echo ""
  exit 1
else
  echo "✅ All documentation complies with policy"
  exit 0
fi
