#!/bin/bash
set -e

echo "Fixing component test errors..."

# Fix forgot-password-form - add onToggleMode prop
sed -i 's/<ForgotPasswordForm \/>/<ForgotPasswordForm onToggleMode={() => {}} \/>/g' src/components/auth/__tests__/forgot-password-form.test.tsx

# Fix ProtectedRoute - add user prop and remove requireAdmin
sed -i 's/<ProtectedRoute>/<ProtectedRoute user={{ id: "1", email: "test@example.com", name: "Test", role: "user", isAdmin: false, mfaEnabled: false, createdAt: "2024-01-01" }}>/g' src/components/common/__tests__/ProtectedRoute.test.tsx
sed -i 's/requireAdmin={true}//g' src/components/common/__tests__/ProtectedRoute.test.tsx

# Fix pages-render - add user prop
sed -i 's/<ProtectedRoute>/<ProtectedRoute user={{ id: "1", email: "test@example.com", name: "Test", role: "user", isAdmin: false, mfaEnabled: false, createdAt: "2024-01-01" }}>/g' src/components/__tests__/pages-render.test.tsx

# Fix NoteStats - add content prop
sed -i 's/<NoteStats \/>/<NoteStats content="" \/>/g' src/components/dashboard/__tests__/note-stats.test.tsx

# Fix shareNote calls - remove third argument
sed -i "s/shareNote([^,]*,[^,]*, '[^']*')/shareNote(\1, \2)/g" src/services/api/__tests__/secureApi.test.ts

# Fix beginMFASetup - add qrCode property
sed -i '/secret:.*JBSWY3DPEHPK3PXP/{ N; /}/! s/}/}, qrCode: "data:image\/png;base64,test" }/; }' src/stores/__tests__/authStore.test.ts

echo "Done with batch fixes!"
