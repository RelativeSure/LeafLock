#!/bin/sh
# Check for prohibited custom UI components that should use shadcn/ui instead
# This script enforces the UI architecture mandate: shadcn/ui ONLY

set -e

echo "🔍 Scanning for prohibited custom UI component patterns..."

VIOLATIONS=0

# Helper function to check a pattern
check_pattern_simple() {
  pattern="$1"
  message="$2"
  skip_components_ui="$3" # Set to "true" to skip checking components/ui
  
  # Use grep to find matches, excluding test files and stories
  matches=$(find src -name "*.tsx" -o -name "*.ts" | \
    grep -v node_modules | grep -v dist | grep -v ".git" | \
    grep -v "\.test\." | grep -v "\.stories\." | \
    {
      if [ "$skip_components_ui" = "true" ]; then
        grep -v "src/components/ui/"
      else
        cat
      fi
    } | \
    xargs grep -n -E "$pattern" 2>/dev/null || true)
  
  if [ -n "$matches" ]; then
    echo "❌ VIOLATION: $message"
    echo "$matches" | while read -r match; do
      if [ -n "$match" ]; then
        file=$(echo "$match" | cut -d: -f1)
        line=$(echo "$match" | cut -d: -f2)
        
        # Skip if this is a shadcn component implementation file
        case "$file" in
          */components/ui/input.tsx|*/components/ui/textarea.tsx|*/components/ui/button.tsx|*/components/ui/sidebar.tsx)
            continue
            ;;
        esac
        
        echo "   File: $file:$line"
        VIOLATIONS=$((VIOLATIONS + 1))
      fi
    done
    echo ""
  fi
}

# Basic form controls that should use shadcn (excluding components/ui implementations)
check_pattern_simple '<button[^>]*className' 'Use <Button> from @/components/ui/button instead of raw <button>' "true"
check_pattern_simple '<input[^>]*className' 'Use <Input> from @/components/ui/input instead of raw <input>' "true"
check_pattern_simple '<select[^>]*className' 'Use <Select> from @/components/ui/select instead of raw <select>' "true"
check_pattern_simple '<textarea[^>]*className' 'Use <Textarea> from @/components/ui/textarea instead of raw <textarea>' "true"

# Custom component wrappers (pointless abstractions) - but not in components/ui
# These patterns target simple wrapper functions that just pass props through
check_pattern_simple 'export.*function.*[Bb]utton.*\(.*props.*\).*return.*<Button.*\.\.\.props' 'Do not create custom Button wrappers - use shadcn <Button> directly' "true"
check_pattern_simple 'export.*function.*[Ii]nput.*\(.*props.*\).*return.*<Input.*\.\.\.props' 'Do not create custom Input wrappers - use shadcn <Input> directly' "true"
check_pattern_simple 'export.*function.*[Cc]ard.*\(.*props.*\).*return.*<[Cc]ard.*\.\.\.props' 'Do not create custom Card wrappers - use shadcn <Card> directly' "true"

# Layout components that shadcn provides
check_pattern_simple 'export.*function.*[Tt]able.*\(' 'Use shadcn <Table> from @/components/ui/table instead' "true"
check_pattern_simple 'export.*function.*[Bb]adge.*\(' 'Use shadcn <Badge> from @/components/ui/badge instead' "true"

# Check for pointless Dialog wrappers (components that just forward props without adding logic)
# This is more complex - we look for Dialog components with minimal implementation
if [ -d "src/components" ]; then
  echo "🔍 Checking for pointless Dialog wrappers..."
  
  # Find potential dialog wrapper files (but exclude test files and components/ui)
  dialog_files=$(find src/components -name "*.tsx" ! -name "*.test.tsx" ! -path "*/ui/*" | \
    xargs grep -l 'export.*function.*[Dd]ialog' 2>/dev/null || true)
  
  for file in $dialog_files; do
    # Check if this file imports from @/components/ui/dialog
    imports_shadcn_dialog=$(grep -c "from '@/components/ui/dialog'" "$file" 2>/dev/null || echo "0")
    
    if [ "$imports_shadcn_dialog" -gt 0 ]; then
      # This is likely a legitimate business component using shadcn Dialog
      continue
    fi
    
    # If it doesn't import shadcn dialog, it might be a wrapper - check for simple patterns
    simple_wrapper=$(grep -E 'return.*<Dialog.*\.\.\.props' "$file" 2>/dev/null || true)
    
    if [ -n "$simple_wrapper" ]; then
      echo "❌ VIOLATION: Pointless Dialog wrapper detected (doesn't add business logic)"
      echo "   File: $file"
      echo ""
      VIOLATIONS=$((VIOLATIONS + 1))
    fi
  done
fi

# Check for raw HTML in components/ui that aren't standard implementations
echo "🔍 Checking components/ui for non-shadcn patterns..."
UI_ELEMENTS=$(find src/components/ui -name "*.tsx" ! -name "*.test.tsx" ! -name "input.tsx" ! -name "textarea.tsx" ! -name "button.tsx" ! -name "sidebar.tsx" | \
  xargs grep -n -E '<button|<input|<select|<textarea' 2>/dev/null || true)

if [ -n "$UI_ELEMENTS" ]; then
  echo "❌ VIOLATION: Unexpected raw HTML elements found in components/ui/:"
  echo "$UI_ELEMENTS"
  echo ""
  VIOLATIONS=$((VIOLATIONS + 1))
fi

# Final verdict
if [ "$VIOLATIONS" -gt 0 ]; then
  echo ""
  echo "=========================================="
  echo "❌ SHADCN/UI COMPLIANCE FAILED"
  echo "=========================================="
  echo "Found $VIOLATIONS violation(s)"
  echo ""
  echo "💡 Fixes:"
  echo "1. Remove custom UI components and use shadcn components directly"
  echo "2. Check shadcn docs: https://ui.shadcn.com/docs"
  echo "3. Install missing components: cd frontend && pnpm dlx shadcn@latest add <component>"
  echo "4. Never wrap shadcn components unless adding significant business logic"
  echo ""
  exit 1
else
  echo "✅ All UI components comply with shadcn/ui mandate"
  exit 0
fi
