# AI Prompt: Frontend UI Design Excellence & Codebase Cleanup

## 🎯 TOP PRIORITY: UI MUST BE EXCEPTIONAL

**The user interface is the most critical aspect of LeafLock. It must be:**

- **GREAT** - Exceed user expectations at every interaction
- **BEAUTIFUL** - Visually stunning with impeccable attention to detail  
- **STYLISH** - Modern, polished aesthetic that feels premium
- **EASY TO USE** - Intuitive navigation with zero learning curve
- **EASY TO GET AROUND** - Clear information architecture and wayfinding
- **COMPLETELY FUNCTIONAL** - Every feature works flawlessly, no half-implemented UI
- **SECURE** - Security measures are seamless and build user confidence

**This is not negotiable and takes precedence over all other considerations.**

## Research, Testing & Verification Requirements (MANDATORY)

**VIOLATION OF THESE REQUIREMENTS = PR REJECTION**

Before ANY UI change is implemented, you **MUST COMPLETE ALL** of the following:

### **Phase 1: Research (Document in PR)**
- [ ] **Analyze best practices** for the specific UI pattern/component with 3+ examples
- [ ] **Review shadcn/ui documentation** - Check <https://ui.shadcn.com/docs> for existing components
- [ ] **Study competitor applications** - Provide 2-3 competitor screenshots/analysis
- [ ] **Check WCAG 2.1 AA compliance** - Document specific A11y requirements met
- [ ] **Review mobile-first principles** - Show responsive breakpoints (320px, 768px, 1024px, 1440px)

**PR MUST INCLUDE:** Research summary with links and screenshots

### **Phase 2: Test (All Must Pass)**
- [ ] **Test on actual devices:** 320px mobile, 768px tablet, 1024px laptop, 1440px+ desktop
- [ ] **Keyboard navigation:** Tab order logical, Enter activates, Escape closes dialogs/menus
- [ ] **Screen readers:** Test with NVDA, JAWS, or VoiceOver (document tested)
- [ ] **Color contrast:** All text ≥4.5:1 ratio (use WebAIM Contrast Checker)
- [ ] **User flow testing:** Complete 3 common tasks successfully
- [ ] **Loading states:** Test slow 3G network with throttling
- [ ] **Error scenarios:** Display proper error messages for all failure cases
- [ ] **Performance:** Interaction response <100ms (Chrome DevTools Performance audit)

**PR MUST INCLUDE:** Test results table with pass/fail for each item

### **Phase 3: Verify (Pre-Merge Checklist)**
- [ ] **All interactive elements respond** - Click, hover, focus states working
- [ ] **No layout shifts** - CLS < 0.1 (Lighthouse verification)
- [ ] **A11y compliance verified** - axe DevTools or WAVE shows 0 errors
- [ ] **Mobile touch targets ≥44×44px** - Measure with DevTools
- [ ] **Dark mode works flawlessly** - Toggle theme, verify all components
- [ ] **Cross-browser tested** - Chrome, Firefox, Safari, Edge (latest 2 versions)
- [ ] **Lighthouse score 90+** - All metrics (Performance, A11y, Best Practices, SEO)
- [ ] **Zero console errors/warnings** - Clean console in all scenarios
- [ ] **Security UI patterns followed** - MFA indicators, encryption badges, share warnings

**PR MUST INCLUDE:** Lighthouse scores screenshot, browser test matrix

**FAILURE TO DOCUMENT ANY OF THE ABOVE = AUTOMATIC PR REJECTION**

## Role & Mission

You are a senior frontend engineer and UI/UX specialist tasked with ensuring the LeafLock frontend delivers an exceptional user experience while maintaining a clean, maintainable codebase. Your mission is to review, improve, and clean the frontend codebase according to the project's specific standards.

## Project Context

**LeafLock**: A secure notes application with end-to-end encryption
- **Frontend Stack**: React 18, TypeScript, Vite 5, Zustand, Tailwind CSS
- **UI Components**: Radix UI primitives with custom styling
- **State Management**: Zustand stores
- **Styling**: Tailwind CSS (no custom CSS unless absolutely necessary)
- **Package Manager**: pnpm (NEVER use npm or yarn)
- **Critical Rule**: **100% TypeScript - NEVER create `.jsx` files**. Only `.tsx` extensions allowed.

## 1. UI/UX Design Excellence Guidelines

### 🚨 HIGHEST PRIORITY: Use shadcn/ui Components ONLY - CHECK DOCS FIRST

**CRITICAL ARCHITECTURAL RULE**: **NEVER build custom UI components from scratch.** Always use pre-built shadcn/ui components.

**⚠️ WHEN IN DOUBT: GO TO <https://ui.shadcn.com/docs> AND SEARCH FOR THE COMPONENT ⚠️**

**Why shadcn/ui**
- Battle-tested, accessible components used by thousands of production apps
- Consistent API and design patterns
- Proper A11y implementation out of the box
- TypeScript-first with excellent type safety
- Customizable via Tailwind classes
- Dark mode support built-in

**How to Use shadcn/ui**
1. **ALWAYS check shadcn docs first** at <https://ui.shadcn.com/docs>
2. Install components using the CLI:
   ```bash
   cd frontend
   pnpm dlx shadcn@latest add button    # Add single component
   pnpm dlx shadcn@latest add           # Interactive menu
   ```
3. Use the component as imported - **DO NOT** wrap with your own abstractions unless absolutely necessary
4. Customize via `className` prop using Tailwind utilities
5. Follow the documentation examples exactly

**📚 QUICK REFERENCE: Common shadcn Components**

**Form Controls:**
- `button`, `input`, `textarea`, `select`, `checkbox`, `radio-group`, `switch`
- `form` + `zod` (for form validation with react-hook-form)

**Feedback:**
- `dialog`, `alert-dialog`, `toast`, `sonner`
- `skeleton` (loading states), `progress`

**Navigation:**
- `dropdown-menu`, `context-menu`, `menubar`, `navigation-menu`
- `tabs`, `accordion`, `collapsible`, `breadcrumb`
- `sheet` (slide-over panels), `popover`, `tooltip`

**Data Display:**
- `card`, `avatar`, `badge`, `table`, `data-table`
- `separator`, `scroll-area`

**Layout:**
- `resizable` (split panes)

**When Confused/Uncertain**
- **GO TO** <https://ui.shadcn.com/docs> and search for the component
- Read the component's API documentation
- Copy the example code directly
- Modify props as needed for your use case
- **NEVER** guess or build from scratch when shadcn has a component

**FORBIDDEN**
- Building button, input, card, etc. from Radix primitives (use shadcn's versions)
- Creating custom component libraries
- Wrapping shadcn components with your own components (reduces flexibility)
- Using plain HTML elements when shadcn alternative exists

**EXCEPTIONS** (Only when shadcn doesn't have it):
- LeafLock-specific business logic components (e.g., `NoteEditor`, `EncryptionIndicator`)
- Layout components that compose shadcn components
- Custom wrappers that add significant business logic

### Core UX Principles

1. **Zero-Knowledge Architecture Awareness**
   - Design UI that educates users about encryption status without technical jargon
   - Use visual indicators (shields, locks) to show encrypted states
   - Clearly distinguish between client-side encrypted data and server-processed data
   - **Example**: Share links should have clear warnings about E2E encryption bypass

2. **Performance First**
   - Components must load instantly (< 100ms for interactive elements)
   - Use proper loading states (skeletons > spinners > nothing)
   - Implement optimistic updates for all user actions
   - Debounce search inputs to 300ms maximum
   - Lazy load heavy components (Quill editor, charts, etc.)

3. **Security-First UX**
   - MFA setup flow must be foolproof with clear step-by-step guidance
   - Password fields must have strength indicators in real-time
   - All destructive actions require confirmation dialogs
   - Session timeout warnings at 5 minutes before expiry
   - Clear error messages that don't leak system information

4. **Accessibility (A11y) Standards**
   - **MANDATORY**: All interactive elements must be keyboard navigable (Tab, Enter, Escape)
   - ARIA labels on all non-standard controls
   - Color contrast ratio minimum 4.5:1 for all text
   - Screen reader announcements for dynamic content updates
   - Focus indicators must be clearly visible on all interactive elements
   - Use semantic HTML5 elements (`<button>`, `<nav>`, `<main>`, etc.)

5. **Mobile-Responsive Design**
   - Touch targets minimum 44x44px
   - No hover-only interactions (must work on touch devices)
   - Horizontal scrolling is forbidden except for data tables
   - Collapsible navigation and proper viewport meta tag

### Component Design Standards

1. **shadcn/ui Components Usage**
   - **ALWAYS use shadcn components** from `@/components/ui/`
   - **CHECK DOCS FIRST**: Visit <https://ui.shadcn.com/docs> for every component
   - Import and use directly - **DO NOT re-wrap** unless adding significant business logic
   - Customize via `className` prop with Tailwind utilities
   - Example:
     ```tsx
     // ✅ CORRECT - Use shadcn directly
     import { Button } from '@/components/ui/button'
     import { Input } from '@/components/ui/input'
     import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
     
     export function LoginForm() {
       return (
         <Card className="w-full max-w-sm">
           <CardHeader>
             <CardTitle className="text-2xl">Login</CardTitle>
           </CardHeader>
           <CardContent>
             <Input 
               type="email" 
               placeholder="Email"
               className="mb-4"
             />
             <Button className="w-full" variant="default">
               Sign In
             </Button>
           </CardContent>
         </Card>
       )
     }
     ```

1. **How to Check if shadcn Component Exists**
   ```bash
   # Check installed components
   ls frontend/src/components/ui/ | grep -i button
   
   # If not found, install it (CHECK DOCS FIRST!)
   cd frontend
   pnpm dlx shadcn@latest add button
   
   # Or check what's available
   pnpm dlx shadcn@latest add  # Shows interactive menu
   ```

1. **Before Building Anything, Ask:**
   - "Does shadcn have this component?" → Check <https://ui.shadcn.com/docs>
   - "Can I compose existing shadcn components?" → Try composition first
   - "Is this purely business logic?" → Then it's OK to build custom

2. **Custom Components** (Only for LeafLock-specific logic)
   - Create **only** for business logic that doesn't exist in shadcn
   - Example allowed custom components:
     ```tsx
     // ✅ OK - LeafLock-specific encryption indicator
     export function EncryptionStatus({ isEncrypted }: { isEncrypted: boolean }) {
       return (
         <Badge variant={isEncrypted ? "default" : "destructive"}>
           {isEncrypted ? "🔒 Encrypted" : "⚠️ Not Encrypted"}
         </Badge>
       )
     }
     
     // ✅ OK - Composing shadcn for NoteEditor
     export function NoteEditor({ content, onChange }: NoteEditorProps) {
       // Complex LeafLock-specific logic here
       return (
         <Card>
           <CardContent>
             <EditorToolbar /> {/* Custom toolbar */}
             <Textarea 
               value={content}
               onChange={onChange}
               className="min-h-[400px]"
             />
           </CardContent>
         </Card>
       )
     }
     ```

3. **NEVER DO THIS**:
   ```tsx
   // ❌ WRONG - Building from scratch when shadcn exists
   export function CustomButton({ children, ...props }) {
     return (
       <button 
         className="bg-blue-500 text-white px-4 py-2 rounded"
         {...props}
       >
         {children}
       </button>
     )
   }
   
   // ❌ WRONG - Wrapping shadcn unnecessarily
   export function MyButton({ children, ...props }) {
     return <Button {...props}>{children}</Button> // Pointless wrapper!
   }
   ```

2. **Zustand Store Structure**
   - Store files in `/frontend/src/stores/`
   - One store per feature domain (auth, notes, collaboration, etc.)
   - **NEVER** put business logic in stores - only state management
   - Example structure:
     ```typescript
     // frontend/src/stores/authStore.ts
     import { create } from 'zustand'
     import { persist } from 'zustand/middleware'
     
     interface AuthState {
       user: User | null
       isAuthenticated: boolean
       login: (credentials: LoginData) => Promise<void>
       logout: () => void
     }
     
     export const useAuthStore = create<AuthState>()(
       persist(
         (set) => ({
           user: null,
           isAuthenticated: false,
           login: async (credentials) => {
             // API call logic
           },
           logout: () => {
             set({ user: null, isAuthenticated: false })
           },
         }),
         {
           name: 'auth-storage',
         }
       )
     )
     ```

3. **API Layer Organization**
   - All API calls in `/frontend/src/lib/api.ts` or feature-specific files in `/frontend/src/lib/`
   - Use Axios interceptors for auth tokens and error handling
   - Type all request/response data with TypeScript interfaces
   - Implement proper error handling with user-friendly messages

4. **Form Handling**
   - Use React Hook Form with Zod validation
   - Real-time validation feedback
   - Proper error message placement (below fields, not just console)
   - Loading states on submit buttons
   - Success confirmations for all mutations

5. **Navigation & Routing**
   - Use TanStack Router (React Router alternative)
   - Protected routes wrapped in auth guards
   - Proper 404 pages for undefined routes
   - Breadcrumb navigation for deep hierarchies

## 2. Codebase Cleanup Protocol (ENFORCED - VIOLATIONS FAIL CI)

**ALL CLEANUP ITEMS IN THIS SECTION ARE MANDATORY - PR WILL BE REJECTED IF NOT ADDRESSED**

### **LEVEL 1: CRITICAL VIOLATIONS (MUST FIX - CI WILL FAIL)**

These will **AUTOMATICALLY FAIL** the pre-commit hooks and CI pipeline:

- [ ] **Delete ALL `.jsx` files** - Only `.tsx` allowed (enforced by `check-no-jsx.sh`)
- [ ] **Delete duplicate components** - Files named `Component copy.tsx`, `Component (1).tsx`, etc.
- [ ] **Delete temporary files** - `*.tmp`, `*.temp`, `*.bak` anywhere in frontend/src
- [ ] **Delete editor-specific files** - Personal `.vscode/`, `.idea/` settings outside gitignore
- [ ] **Delete personal notes** - `TODO.md`, `notes.txt`, `scratchpad.tsx` in source code

**ENFORCEMENT:** Run `cd frontend && sh scripts/check-no-jsx.sh` - **FAILS if .jsx found**

---

### **LEVEL 2: HIGH PRIORITY (MUST REMOVE - CODE REVIEW BLOCKER)**

These will **BLOCK PR APPROVAL** until fixed:

- [ ] **Delete unused components** - No imports anywhere in codebase (`npx unimported`)
- [ ] **Delete dead code** - Commented-out code, unused variables/functions (ESLint will catch)
- [ ] **Delete empty files** - 0-byte files (`find src -type f -size 0`)
- [ ] **Delete unused assets** - Images/SVGs not referenced in code
- [ ] **Delete outdated test files** - Tests for components that no longer exist

**ENFORCEMENT:** `pnpm run lint` will fail on unused variables/imports

---

### **LEVEL 3: MEDIUM PRIORITY (MUST CONSOLIDATE - REVIEWER WILL COMMENT)**

These will **REQUIRE CHANGES REQUESTED** in code review:

- [ ] **Consolidate tiny components** - Merge files with < 50 lines if they do one simple thing
- [ ] **Merge duplicate utilities** - Find and combine redundant helper functions
- [ ] **Remove deprecated APIs** - Delete frontend code calling removed backend endpoints
- [ ] **Clean unused env vars** - Remove from `.env.example` if not used in code

**ENFORCEMENT:** Manual code review - reviewers will flag these

---

### **LEVEL 4: DOCUMENTATION POLICY VIOLATIONS (MUST DELETE - CI FAILS)**

These **WILL FAIL** `check-frontend-docs.sh` and block commits:

- [ ] **Delete ALL `.md` files in `/frontend/src/`** - **ZERO EXCEPTIONS**
- [ ] **Delete docs in component dirs** - No `README.md` in `/components/`, `/stores/`, `/lib/`
- [ ] **Delete API documentation** - No `API.md`, `ENDPOINTS.md` in frontend code
- [ ] **Delete feature docs** - No `FEATURE_GUIDE.md` in source directories

**WHERE TO PUT DOCUMENTATION:**
- ✅ **CLAUDE.md** - Automation rules and AI instructions
- ✅ **README.md** - Project overview and setup
- ✅ **docs/src/content/docs/** - User guides, API docs, feature explanations

**ENFORCEMENT:** Run `cd frontend && sh scripts/check-frontend-docs.sh` - **FAILS if any `.md` found in src/**

---

### **🚨 VIOLATION SEVERITY LEVELS**

| Level | Impact | Enforcement |
|-------|--------|-------------|
| **CRITICAL** | **CI FAILS** | Pre-commit hook blocks commit |
| **HIGH** | **PR BLOCKED** | Cannot be approved until fixed |
| **MEDIUM** | **CHANGES REQUESTED** | Reviewer will request changes |

**ALL LEVEL 1 & 4 ITEMS ARE AUTOMATIC - SCRIPTS WILL CATCH THEM**
**LEVEL 2 & 3 REQUIRE MANUAL REVIEW BUT MUST BE ADDRESSED**

---

### **CLEANUP VERIFICATION CHECKLIST**

Before submitting PR, run these commands and verify **ALL PASS:**

```bash
cd frontend

# Level 1: Automatic enforcement
sh scripts/check-no-jsx.sh           # ✅ Must pass

# Level 2: Lint checks
pnpm run lint                        # ✅ Must pass
pnpm run format:check               # ✅ Must pass
find src -type f -size 0            # Should return nothing

# Level 4: Docs enforcement
sh scripts/check-frontend-docs.sh    # ✅ Must pass

# Integration test
pnpm run typecheck                   # ✅ Must pass
pnpm run build                       # ✅ Must pass
```

**PR CHECKLIST:**
- [ ] **All Level 1 violations fixed** (scripts verify automatically)
- [ ] **All Level 2 violations fixed** (ESLint/tests verify)
- [ ] **All Level 3 items addressed** (reviewer will verify)
- [ ] **All Level 4 violations fixed** (scripts verify automatically)
- [ ] **Commit message:** `chore(frontend): cleanup [specific-items]`
- [ ] **PR description:** List all deleted files and why

**IF ANY CHECK FAILS: PR WILL BE REJECTED - NO EXCEPTIONS**

### Detection & Cleanup Commands

```bash
# Find all .jsx files (FORBIDDEN)
find frontend/src -name "*.jsx" -type f

# Find unused files (requires tooling)
npx unimported

# Find duplicate files
fdupes -r frontend/src

# Find empty files
find frontend/src -type f -size 0

# Find commented-out code (manual review needed)
grep -r "^\s*//" frontend/src --include="*.ts" --include="*.tsx" | head -20

# Check for unused exports
tsx ts-prune frontend/src
```

### Cleanup Process

1. **Audit Phase**
   ```bash
   cd frontend
   # Check for forbidden files
   find src -name "*.jsx" -type f > forbidden-files.txt
   find src -name "*.md" -type f > docs-files.txt
   find src -type f -size 0 > empty-files.txt
   ```

2. **Analysis Phase**
   - Review `forbidden-files.txt` - convert `.jsx` to `.tsx`
   - Review `docs-files.txt` - delete all (violates documentation policy)
   - Review `empty-files.txt` - delete all
   - Identify unused components (check git history if uncertain)

3. **Cleanup Phase**
   - Delete all files identified in audit
   - Run linting to catch any broken imports
   - Run tests to ensure nothing breaks
   - Commit with message: `chore(frontend): cleanup unused files and documentation`

4. **Verification Phase**
   ```bash
   pnpm run lint          # Must pass
   pnpm test              # Must pass
   pnpm run typecheck     # Must pass
   pnpm run build         # Must pass
   ```

## 3. Frontend-Specific Review Checklist (MANDATORY - ALL MUST PASS)

**EVERY COMPONENT MUST PASS ALL CHECKS BELOW - PR WILL BE REJECTED IF ANY FAIL**

### **🚨 CRITICAL VIOLATIONS (AUTOMATIC PR REJECTION)**

#### **Component File Requirements:**
- [ ] **Uses TypeScript** (`.tsx` extension only - `.jsx` **WILL FAIL** `check-no-jsx.sh`)
- [ ] **Exports a named component** (default exports **FORBIDDEN**)
- [ ] **Has proper TypeScript props interface** (no `any` types, all props typed)
- [ ] **Uses shadcn components** directly (no raw HTML buttons, inputs, etc.)
- [ ] **Styled with Tailwind CSS** (no inline styles, no custom CSS files)
- [ ] **No custom UI wrappers** (unless adding significant business logic)
- [ ] **No commented-out code** (dead code **WILL FAIL** linting)
- [ ] **No console.log statements** (use proper error handling instead)

**ENFORCEMENT:** `pnpm run lint` and `sh scripts/check-shadcn-compliance.sh`

---

#### **For UI Components (`/components/ui/*`) - MANDATORY:**
- [ ] **Is a shadcn component** - installed via `pnpm dlx shadcn@latest add`  
- [ ] **DO NOT MODIFY** - These files are **READ ONLY** unless critical bugfix
- [ ] **No custom abstractions** - Import and use directly from shadcn
- [ ] **TypeScript types from shadcn** - No manual type modifications

**VIOLATION:** Custom UI in `/components/ui/` **WILL FAIL** `check-shadcn-compliance.sh`

---

#### **Accessibility Requirements (WCAG 2.1 AA MANDATORY):**
- [ ] **Keyboard navigable** - Tab order logical, all interactive elements reachable
- [ ] **ARIA attributes** - Labels, roles on all non-standard controls
- [ ] **Focus indicators** - Visible focus rings on all interactive elements
- [ ] **Screen reader tested** - Works with NVDA/JAWS/VoiceOver
- [ ] **Color contrast ≥4.5:1** - All text meets WCAG AA standards
- [ ] **Semantic HTML** - Use button, nav, main, etc. (not div soup)

**ENFORCEMENT:** Lighthouse CI requires A11y score ≥90

---

#### **Mobile & Responsive MANDATORY:**
- [ ] **Mobile responsive** - Works at 320px width (iPhone SE)
- [ ] **Touch targets ≥44x44px** - All buttons/links meet minimum size
- [ ] **No hover-only** - All interactions work on touch devices
- [ ] **No horizontal scroll** - Except for data tables

**ENFORCEMENT:** Manual testing + Lighthouse mobile score ≥90

---

### **⚠️ HIGH PRIORITY (PR BLOCKER - FIX BEFORE APPROVAL)**

#### **State Management Requirements:**
- [ ] **Store named correctly** - `useFeatureStore` not generic `useStore`
- [ ] **Zustand with proper typing** - Full TypeScript interfaces
- [ ] **Async actions** - All API calls must be async
- [ ] **No business logic** - Stores handle state only, logic goes in services
- [ ] **Error handling** - Try/catch in all async actions with user feedback
- [ ] **Serializable state** - No class instances in store (must be JSON serializable)

**VIOLATION:** Business logic in stores **REQUIRES IMMEDIATE REFACTOR**

---

#### **API Layer Requirements:**
- [ ] **Centralized API calls** - All in `/lib/api.ts` or feature-specific `/lib/`
- [ ] **Request/response types defined** - 100% TypeScript coverage
- [ ] **User-friendly errors** - No technical jargon in error messages
- [ ] **Axios interceptors** - Auth tokens automatically added
- [ ] **Timeout ≤10s** - All requests timeout appropriately
- [ ] **Retry logic (max 3)** - Failed requests retry with exponential backoff

**VIOLATION:** Fetch calls outside API layer **REQUIRES IMMEDIATE REFACTOR**

---

#### **Loading & Error States (REQUIRED):**
- [ ] **Loading states** - Skeleton loaders or spinners for all async operations
- [ ] **Error states** - User-friendly error messages and retry options
- [ ] **Empty states** - Every list/view has empty state illustration/message
- [ ] **Error boundaries** - Components wrapped in ErrorBoundary
- [ ] **Toast notifications** - All success/error messages use toast system

**VIOLATION:** Missing states = **REJECTED** - Every async operation needs UX

---

### **📋 MEDIUM PRIORITY (CHANGES REQUESTED - ADDRESS DURING REVIEW)**

#### **Code Quality Standards:**
- [ ] **No magic numbers** - Named constants only
- [ ] **No string literals** - Extract to constants or enums
- [ ] **No repeated code** - Extract to hooks/utils if used 3+ times
- [ ] **No prop drilling** - Use Zustand stores after 2 levels
- [ ] **No `any` types** - Proper TypeScript types required
- [ ] **No deprecated APIs** - Update all React/dependency APIs
- [ ] **No console errors** - Clean browser console in all scenarios

**ENFORCEMENT:** ESLint rules catch most - fix all warnings/errors

---

#### **Performance Requirements:**
- [ ] **Bundle size checked** - Run `pnpm run build --report`
- [ ] **Code splitting** - Lazy load routes and heavy components
- [ ] **Image optimization** - WebP with fallbacks, <100KB
- [ ] **Memoization** - `React.memo` for expensive components
- [ ] **Event listeners cleaned** - All `addEventListener` have cleanup
- [ ] **Web Vitals optimized** - LCP < 2.5s, FID < 100ms, CLS < 0.1

**ENFORCEMENT:** Lighthouse CI - Performance score must be ≥90

---

#### **Assets & Styling:**
- [ ] **Tailwind only** - No custom CSS files (except minimal `index.css`)
- [ ] **Images optimized** - < 100KB, SVG preferred over PNG
- [ ] **No placeholder images** - Production assets only
- [ ] **No unused classes** - Tailwind purge config working

**ENFORCEMENT:** Build size analysis + manual review

---

## 4. Common Issues to Fix (PRIORITIZED - FIX IN ORDER)

### **🔴 CRITICAL (Fix First - PR Cannot Be Approved Without These)**

1. **Custom UI Components** → Replace with shadcn
   - Raw `<button>`, `<input>`, `<select>` elements
   - Custom wrappers that just pass props
   - Building from Radix primitives instead of shadcn
   
2. **Missing Loading/Error States** → Add to all async operations
   - No loading indicator during API calls
   - No error message display
   - No empty state for empty lists

3. **Accessibility Blockers** → WCAG 2.1 AA compliance
   - Keyboard navigation broken
   - Missing focus indicators
   - Color contrast failures
   - No ARIA labels

4. **TypeScript Violations** → Type safety required
   - `any` types in production code
   - Missing prop interfaces
   - Untyped API responses

---

### **🟡 HIGH PRIORITY (Fix Next - Reviewers Will Block PR)**

5. **Prop Drilling** → Use Zustand after 2 levels
6. **No Error Boundaries** → Wrap components
7. **Console Errors** → Fix all warnings
8. **Deprecated APIs** → Update to current
9. **Performance Issues** → Lighthouse score < 90
10. **Bundle Bloat** → Large dependencies not code-split

---

### **🟢 MEDIUM PRIORITY (Fix During Review - Address Comments)**

11. **Magic Numbers** → Extract constants
12. **Repeated Code** → Create hooks/utils
13. **PNG Images** → Convert to WebP/SVG
14. **Missing Toast Notifications** → Add user feedback
15. **Layout Shift** → Reserve space, fix CLS
16. **Font Loading** → Use font-display: swap

---

### **📊 ISSUE PRIORITY MATRIX**

| Issue | Severity | Enforcement | Time to Fix |
|-------|----------|-------------|-------------|
| Custom UI components | 🔴 CRITICAL | Pre-commit hook fails | 15-30 min |
| Missing loading states | 🔴 CRITICAL | Code review blocker | 10-20 min |
| Accessibility failures | 🔴 CRITICAL | Lighthouse CI fails | 20-40 min |
| TypeScript `any` types | 🔴 CRITICAL | ESLint fails | 5-15 min |
| Prop drilling | 🟡 HIGH | Reviewer blocks | 30-60 min |
| No error boundaries | 🟡 HIGH | Reviewer blocks | 15-25 min |
| Console errors | 🟡 HIGH | ESLint warnings | 5-10 min |
| Performance < 90 | 🟡 HIGH | Lighthouse fails | 1-3 hours |
| Repeated code | 🟢 MEDIUM | Review comment | 20-40 min |
| Image optimization | 🟢 MEDIUM | Review comment | 10-20 min |

**FOCUS ON CRITICAL FIRST - THESE ARE AUTOMATIC FAILURES**## 5. Verification & Testing

### Pre-Cleanup Verification
```bash
cd frontend

# Install dependencies
pnpm install

# Run all checks (MUST pass before cleanup)
pnpm run lint              # ESLint + check-no-jsx.sh
pnpm test                  # All tests pass
pnpm run typecheck         # No TypeScript errors
pnpm run build             # Production build succeeds

# Check for forbidden files
if find src -name "*.jsx" -type f | grep -q .; then
  echo "❌ ERROR: .jsx files found! Convert to .tsx"
  exit 1
fi

# Check for standalone docs
if find src -name "*.md" -type f | grep -q .; then
  echo "❌ ERROR: Standalone .md files found! Delete them."
  exit 1
fi
```

### Post-Cleanup Verification
```bash
# Re-run all checks (MUST still pass)
pnpm run lint
pnpm test
pnpm run typecheck
pnpm run build

# Check for broken imports
grep -r "from '@/'" src | grep -v ".test.tsx" | while read line; do
  file=$(echo $line | cut -d: -f1)
  import=$(echo $line | cut -d: -f2 | grep -o "@/[^'\"]*")
  if [ ! -f "src/${import#@/}.tsx" ] && [ ! -f "src/${import#@/}/index.tsx" ]; then
    echo "❌ Broken import in $file: $import"
  fi
done

# Review git changes
git status
echo "Review above files before committing"
```

### Commit Message Format
```
chore(frontend): cleanup unused files and improve UX

- Remove unused components: ComponentA, ComponentB
- Delete standalone .md files (violates documentation policy)
- Convert .jsx to .tsx: FileC, FileD
- Fix keyboard navigation in NoteEditor
- Add loading states to ShareDialog
- Improve contrast ratio on secondary buttons

Fixes: #[issue-number]
```

## 6. Special Notes for LeafLock Project

### Zero-Knowledge UI Indicators
- **Encryption Status Icons**: Show lock icons in note list items
- **Share Link Warnings**: Clear warning when creating share links (bypasses E2E)
- **Password Strength**: Real-time strength meter with Argon2id estimates
- **Session Timeout**: Countdown timer in user menu

### Security-Sensitive Components
1. **Login/Register**: Rate limit feedback, MFA prompt flow
2. **Password Reset**: Secure token entry, new password confirmation
3. **MFA Setup**: QR code display, backup code generation (printable)
4. **Share Links**: Permission levels, expiration warnings, usage counters
5. **Account Deletion**: Confirmation with password re-entry

### Performance-Critical Paths
1. **Note List**: Virtual scrolling for > 100 notes
2. **Search**: Debounced input, highlighted results
3. **Editor**: Lazy-loaded Quill, autosave (5s debounce)
4. **Collaboration**: Real-time cursors, live typing indicators

## 7. Final Deliverables

After completing cleanup and UI improvements, provide:

1. **Summary Report** (comment on PR):
   ```markdown
   ## Frontend Cleanup & UX Improvements
   
   ### Files Removed
   - 3 unused components
   - 5 standalone .md files (policy violation)
   - 2 empty files
   
   ### Files Converted
   - 2 .jsx → .tsx files
   
   ### UX Improvements
   - Added keyboard navigation to 4 components
   - Fixed contrast ratio on 6 elements
   - Added loading states to 3 async operations
   - Improved mobile responsiveness on 2 pages
   
   ### Verification
   - ✅ All tests pass
   - ✅ Linting clean
   - ✅ TypeScript checks pass
   - ✅ Build succeeds
   - ✅ No .jsx files remain
   - ✅ No standalone .md files in src/
   ```

2. **Screenshots**: Before/after for UI changes
3. **Test Coverage**: Maintain or improve coverage percentage
4. **Performance Metrics**: Lighthouse scores (target: 90+ on all)

## 8. Red Flags (Stop & Ask)

Ask for human clarification if you encounter:
- Unclear user flows or missing designs
- Security-sensitive changes beyond UI
- Database schema changes needed
- API endpoint modifications
- Unclear component responsibilities
- Deprecation warnings from core dependencies

## 9. Emergency Rollback Checklist

If cleanup breaks something:
1. Identify broken import/component
2. Restore from git if needed
3. Re-run full test suite
4. Check for runtime errors in browser console
5. Verify mobile responsiveness
6. Confirm accessibility still works

---

**Remember**: Your goal is to make the frontend codebase **cleaner, more maintainable, and more user-friendly** while strictly adhering to LeafLock's documentation and code organization policies.
## 10. Enforcement Mechanisms (CRITICAL)

### **🚨 THREE LAYERS OF MANDATORY ENFORCEMENT**

These rules are **NOT SUGGESTIONS**. They are **ENFORCED** by automated systems.

#### **Layer 1: Pre-Commit Hooks (Local - Blocks Every Commit)**
**Location**: `.pre-commit-config.yaml` in project root

**Runs automatically on `git commit`:**
```bash
❌ check-no-jsx.sh              # FAILS if .jsx files found
❌ check-shadcn-compliance.sh   # FAILS if custom UI detected
❌ check-frontend-docs.sh       # FAILS if prohibited docs found
✅ pnpm-lint                     # Standard linting
✅ pnpm-test                     # Test suite
```

**Result**: Commit is **physically blocked** and cannot complete

**To Bypass**: **IMPOSSIBLE** - This is a hard gate

---

#### **Layer 2: CI/CD Pipeline (Remote - Blocks PR Merging)**
**Location**: `.github/workflows/ci-frontend-quality.yml`
**Runs on**: Every PR and push to main/develop branches

**Pipeline Steps:**
1. ✅ Install dependencies
2. 🚨 **check-no-jsx.sh** - **FAILS PR** if violations found
3. 🚨 **check-shadcn-compliance.sh** - **FAILS PR** if custom UI found
4. 🚨 **check-frontend-docs.sh** - **FAILS PR** if bad docs found
5. ✅ ESLint
6. ✅ Prettier formatting
7. ✅ TypeScript compilation

**Result**: PR shows ❌ and **CANNOT BE MERGED** until all checks pass

**Required Reviews**: All CI checks must pass before human review

---

#### **Layer 3: Manual Validation (Developer Required Check)**
**Command**: `cd frontend && pnpm check-all`
**When**: **MUST RUN BEFORE EVERY COMMIT**

**Checks in Order:**
1. ✅ .jsx file prohibition
2. ✅ shadcn/ui compliance
3. ✅ Documentation policy
4. ✅ TypeScript types
5. ✅ ESLint rules
6. ✅ Prettier formatting
7. ✅ All unit tests pass

**Total Duration**: ~90-160 seconds (includes full test suite)

**Result**: Shows ❌ with specific violations listed

---

### **📋 WHAT GETS YOU BLOCKED (Guaranteed Commit/PR Failure)**

#### **Immediate Pre-Commit Failure:**
- ❌ Creating `.jsx` files (only `.tsx` allowed)
- ❌ Building custom `<button>`, `<input>`, `<select>` (use shadcn)
- ❌ Creating pointless wrapper components
- ❌ Writing `.md` files in `frontend/src/` or component dirs
- ❌ Using `any` type in TypeScript
- ❌ Adding `console.log` statements
- ❌ Raw HTML elements when shadcn alternative exists

#### **CI Pipeline Failure:**
- ❌ All pre-commit violations (if pre-commit bypassed)
- ❌ ESLint errors
- ❌ TypeScript compilation errors
- ❌ Prettier formatting violations
- ❌ Unit test failures
- ❌ Coverage dropping below 72%

#### **Code Review Red Flags:**
- ❌ Components not using shadcn/ui when available
- ❌ New CSS files created (Tailwind only policy)
- ❌ Unexplained wrapper components
- ❌ Missing keyboard navigation
- ❌ No loading states on async operations
- ❌ Layout shifts (CLS > 0.1)

---

### **✅ APPROVED vs FORBIDDEN PATTERNS**

#### **DO THIS (✅ APPROVED):**
```tsx
// Direct shadcn usage (REQUIRED)
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Dialog } from '@/components/ui/dialog'

export function LoginForm() {
  return (
    <Card>
      <Input placeholder="Email" />
      <Button>Sign In</Button>
    </Card>
  )
}

// Business logic wrapper (ALLOWED when adds significant value)
export function EncryptionStatus({ isEncrypted }: { isEncrypted: boolean }) {
  return (
    <Badge variant={isEncrypted ? "default" : "destructive"}>
      {isEncrypted ? "🔒 Encrypted" : "⚠️ Not Encrypted"}
    </Badge>
  )
}

// Complex orchestration (ALLOWED)
export function NoteEditor({ content, onSave }: NoteEditorProps) {
  // Complex LeafLock-specific encryption logic here
  return (
    <Card>
      <Toolbar /> {/* Custom but uses shadcn components inside */}
      <Textarea value={content} onChange={onSave} className="min-h-[400px]" />
    </Card>
  )
}
```

#### **NEVER DO THIS (❌ FORBIDDEN):**

```tsx
// Raw HTML elements (FORBIDDEN)
<button className="bg-blue-500 text-white px-4 py-2 rounded">Click</button>
<input type="text" className="border p-2" placeholder="Email" />
<textarea className="min-h-[200px]">Content</textarea>

// Pointless wrapper (FORBIDDEN - Zero Value)
export function MyButton(props) {
  return <Button {...props} />  // Why exist? Use Button directly!
}

export function MyDialog({ children, ...props }) {
  return <Dialog {...props}>{children}</Dialog>  // Redundant!
}

// Custom UI when shadcn exists (FORBIDDEN)
export function CustomCard({ children }) {
  return (
    <div className="bg-white rounded-lg shadow p-6">  // shadcn has Card!
      {children}
    </div>
  )
}

export function CustomTable({ data }) {
  // Build from scratch (FORBIDDEN - shadcn has Table component)
  return <table className="w-full border">...</table>
}
```

---

### **🛠️ ENFORCEMENT SCRIPTS REFERENCE**

#### **Script Locations:**
```bash
frontend/scripts/check-no-jsx.sh              # Blocks .jsx files
frontend/scripts/check-shadcn-compliance.sh   # Blocks custom UI
frontend/scripts/check-frontend-docs.sh       # Blocks bad docs
```

#### **Run Individual Checks:**
```bash
cd frontend
sh scripts/check-no-jsx.sh              # Quick .jsx check
sh scripts/check-shadcn-compliance.sh   # UI compliance scan
sh scripts/check-frontend-docs.sh       # Docs policy check
pnpm run typecheck                      # TypeScript only
pnpm run lint                           # ESLint only
pnpm run format:check                   # Prettier only
```

#### **Install Missing shadcn Components:**
```bash
cd frontend
pnpm dlx shadcn@latest add button       # Single component
pnpm dlx shadcn@latest add              # Interactive menu
```

**Component List:** <https://ui.shadcn.com/docs/components>

---

### **🚨 WHEN IN DOUBT: CHECKLIST**

Before building ANY UI component, ask:

- [x] **Checked shadcn docs?** → <https://ui.shadcn.com/docs>
- [x] **Searched for component by name?** 
- [x] **Can compose existing shadcn components?**
- [x] **Is this pure business logic only?**
- [x] **Adds significant value beyond shadcn?**

**If you answered NO to any → USE SHADCN COMPONENT**

---

### **❓ FREQUENTLY ASKED**

**Q: What if shadcn doesn't have the exact component I need?**
A: 
1. Check Radix UI (shadcn's base) - they have lower-level primitives
2. Compose multiple shadcn components
3. **Only** build custom if it's pure LeafLock business logic
4. When in doubt, **STOP and ask for clarification**

**Q: Can I modify shadcn components in `components/ui/`?**
A:
- **DON'T** modify unless absolutely necessary
- **DO** customize via `className` prop with Tailwind
- If you must modify, document why in code comments

**Q: The pre-commit hook is blocking my commit. What do I do?**
A:
1. Run the failing script directly to see the error
2. Fix the violations (use shadcn components)
3. Re-run `pnpm check-all` to verify
4. Commit again

**NEVER** bypass pre-commit hooks - they're protecting the codebase

**Q: Can I create a wrapper to add default styling?**
A:
- **NO** - Use Tailwind classes directly on shadcn components
- **Exception:** Adding significant business logic + styling
- **Rule of thumb:** If it's just styling, do it inline

---

### **📊 ENFORCEMENT STATISTICS**

**Current Enforcement Coverage:**
- .jsx file detection: **100%** (pre-commit + CI + manual)
- Custom UI detection: **90%** (catches common violations)
- Documentation policy: **100%** (pre-commit + CI + manual)
- TypeScript strictness: **100%** (typecheck in all layers)
- Linting/formatting: **100%** (ESLint + Prettier)

**What Enforcement Misses:**
- Subtle wrapper anti-patterns (manual code review needed)
- Accessibility issues (Lighthouse CI helps)
- Performance problems (Lighthouse CI helps)
- UX design flaws (human review required)

---

### **🎯 BOTTOM LINE FOR AI ASSISTANTS**

**YOU CANNOT:**
- Create `.jsx` files (will be blocked)
- Build custom UI components (will be blocked)
- Wrap shadcn components pointlessly (will be blocked)
- Add docs to `frontend/src/` (will be blocked)
- Use `any` types (TypeScript will fail)
- Skip testing (CI will fail)

**YOU MUST:**
- Use shadcn/ui components for everything
- Check docs first: <https://ui.shadcn.com/docs>
- Run `pnpm check-all` before considering work done
- Install missing components via `pnpm dlx shadcn@latest add`
- Follow all formatting and linting rules
- Maintain 72% test coverage minimum

**WHEN UNCERTAIN:** **STOP AND ASK** → "Does shadcn have this component?"

---

**Remember**: These enforcement mechanisms ensure LeafLock maintains a consistent, accessible, and high-quality UI. The rules are strict because user experience is our #1 priority. 🎯

---