#!/bin/bash
set -e

echo "Fixing remaining TypeScript test errors..."

# Fix Note/Folder/Tag/Template mock data types

# 1. Fix Folder objects - add color and parentId
echo "Fixing Folder mock data..."
find src/__tests__ -name "*.test.tsx" -exec sed -i '/id:.*name:.*Folder/,/}/ {
  /color:/! s/}/, color: "#000000", parentId: null }/
}' {} \;

# 2. Fix Tag objects - remove createdAt
echo "Fixing Tag mock data..."
find src/__tests__ -name "*.test.tsx" -exec sed -i 's/, createdAt: [^}]*//g' {} \; -exec sed -i 's/createdAt: [^,}]*,//g' {} \;

# 3. Fix Template objects - add tags, isPublic, usageCount
echo "Fixing Template mock data..."
# This is complex, will need manual fixes

# 4. Fix templateStore error property
echo "Fixing template store error refs..."
sed -i 's/error: null,/\/\/ error removed/g' src/__tests__/integration/template-flow.test.tsx

# 5. Fix NoteVersion - add createdBy
echo "Note: NoteVersion createdBy needs manual fix"

# 6. Fix enableMFA calls with arguments in auth tests
echo "Fixing enableMFA argument count..."
find src/stores/__tests__ -name "authStore*.test.ts" -exec sed -i "s/enableMFA('[^']*')/enableMFA()/g" {} \;

echo "Done!"
