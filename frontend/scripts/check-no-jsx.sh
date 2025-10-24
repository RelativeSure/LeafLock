#!/bin/sh
# Check for .jsx files - all files should be .tsx for TypeScript consistency

jsx_files=$(find src -name "*.jsx" -type f 2>/dev/null)

if [ -n "$jsx_files" ]; then
  echo "Error: Found .jsx files. All React files must use .tsx extension:"
  echo "$jsx_files"
  echo ""
  echo "Please rename these files to .tsx:"
  echo "$jsx_files" | while read -r file; do
    echo "  mv $file ${file%.jsx}.tsx"
  done
  exit 1
fi

echo "No .jsx files found - all React files use .tsx"
exit 0
