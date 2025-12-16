# Repository Guidelines

## Project Structure & Module Organization
- Go backend in `backend/`; handlers in `handlers/`, domain logic in `services/`, helpers in `utils/`, realtime in `websocket/`, tests `_test.go` beside code.
- React/TypeScript frontend in `frontend/src`; UI in `components/`, stores in `stores/`, API helpers in `lib/`. pnpm is the supported package manager.
- Deployment tooling spans `docker-compose.yml`, `helm/`, and `leaflock-kube.yaml`. Docs live in `docs/`; automation in repo `scripts/` and service `scripts/`.

## Build, Test, and Development Commands
- `make up` — build and start the full stack via Docker Compose (`make down` stops it).
- `cd backend && make dev-setup` — install Go tooling and launch local Postgres/Redis for integration tests.
- `cd backend && make test` — format, vet, and execute the Go unit suite; `make test-coverage-check` enforces the 72% coverage floor.
- `cd frontend && pnpm install` (first run) then `pnpm dev` for Vite dev server.
- `cd frontend && pnpm check-all` — type-check, lint, format-check, and run Vitest.
- After each run, confirm `pnpm lint` (ESLint), pnpm check-all and `pre-commit run --all-files` both pass.

## Coding Style & Naming Conventions
- Run `make fmt` or `gofmt` before committing Go changes; exported identifiers use CamelCase, private helpers stay lowercase, and interfaces follow `SomethingService`.
- Author React components in `.tsx` only (convert any legacy `.jsx` before editing); `scripts/check-no-jsx.sh` enforces this. Frontend styling follows Prettier (2-space indent, single quotes, no semicolons) and Tailwind.
- **UI Components**: **ALWAYS use shadcn/ui components** from `frontend/src/components/ui/`. Install new components via `pnpm dlx shadcn@latest add <component>`. **NEVER** build from scratch when shadcn component exists. Check <https://ui.shadcn.com/docs> for usage examples.

## 🚨 CRITICAL UI ENFORCEMENT RULES (VIOLATIONS WILL BREAK CI)

### **ARCHITECTURAL MANDATE: shadcn/ui ONLY - NO EXCEPTIONS**

**VIOLATION = IMMEDIATE PRE-COMMIT FAILURE. THESE ARE NOT SUGGESTIONS.**

- **NEVER build UI components from scratch** - Use pre-built shadcn/ui components exclusively
- **CHECK DOCS FIRST** → Always visit <https://ui.shadcn.com/docs> before implementing any UI element
- **Install via CLI only**: `pnpm dlx shadcn@latest add <component>` - Never copy-paste from other projects
- **DO NOT wrap shadcn components** with custom abstractions (reduces flexibility, breaks consistency)
- **NEVER use plain HTML elements** (`<button>`, `<input>`, `<select>`, etc.) when shadcn alternative exists
- **NEVER build from Radix primitives directly** - Use shadcn's implementations

### **ABSOLUTELY FORBIDDEN**
```tsx
// ❌ NEVER DO THIS - Building from scratch
export function CustomButton({ children, ...props }) {
  return <button className="bg-blue-500 px-4 py-2" {...props}>{children}</button>
}

// ❌ NEVER DO THIS - Pointless wrapper
export function MyButton(props) { return <Button {...props} /> }

// ❌ NEVER DO THIS - Using DOM elements instead of shadcn
<input type="text" className="border p-2" />  // Use <Input /> from shadcn
```

### **MANDATORY PATTERN**
```tsx
// ✅ ALWAYS DO THIS - Import and use directly
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent } from '@/components/ui/card'

// ✅ CUSTOM COMPONENTS ALLOWED ONLY FOR BUSINESS LOGIC
export function EncryptionStatus({ isEncrypted }: { isEncrypted: boolean }) {
  return (
    <Badge variant={isEncrypted ? "default" : "destructive"}>
      {isEncrypted ? "🔒 Encrypted" : "⚠️ Not Encrypted"}
    </Badge>
  )
}
```

### **PRE-COMMIT ENFORCEMENT**
The following checks **WILL FAIL** your commit if violated:
- `scripts/check-no-jsx.sh` - Finds forbidden `.jsx` files
- `scripts/check-shadcn-compliance.sh` - Scans for custom UI component violations
- `scripts/check-frontend-docs.sh` - Finds forbidden `.md` files in `/frontend/src`*

### **TYPE-SCRIPT STRICTNESS**
- **ONLY `.tsx` files allowed** in frontend (scripts/check-no-jsx.sh enforces)
- **NEVER use `any` type** - Always define proper TypeScript interfaces
- **NEVER use `console.log`** - Use proper error handling and user feedback
- All components must have proper TypeScript props interfaces

### **DOCUMENTATION POLICY ENFORCEMENT**
- **NEVER create standalone `.md` files** in any directories or in root. NOWHERE.
- **DO NOT** create `COMPONENT_README.md`, `API.md`, or feature-specific docs
- **ONLY** update: `CLAUDE.md` (automation), `README.md` (project overview), `docs/src/content/docs/` (AstroJS docs)
- **DELETE** any existing standalone docs that violate this policy

### **UI/UX STANDARDS (AUTOMATED CHECKS)**
All UI changes must pass these verifications (checked via CI):
- ✅ Keyboard navigation works (Tab, Enter, Escape)
- ✅ ARIA labels on all non-standard controls
- ✅ Color contrast ratio 4.5:1 minimum for all text
- ✅ Mobile touch targets ≥44x44px
- ✅ Dark mode compatibility
- ✅ Lighthouse score 90+ on all metrics
- ✅ No layout shifts (CLS < 0.1)
- ✅ Works on Chrome, Firefox, Safari, Edge

### **TESTING REQUIREMENTS**
- Run `cd frontend && pnpm check-all` before EVERY commit
- All tests must pass: `pnpm test`
- TypeScript must compile: `pnpm run typecheck`
- Linting must be clean: `pnpm run lint`
- Build must succeed: `pnpm run build`
- Coverage must not decrease (current minimum: 72%)

### **COMMON CUSTOM COMPONENTS (ALLOWED)**
Only these patterns may be custom-built:
1. **LeafLock-specific business logic**: `NoteEditor`, `EncryptionIndicator`, `ShareLinkManager`
2. **Layout composition**: Combining shadcn components for page layouts
3. **Feature-specific containers**: Components that orchestrate multiple shadcn components with complex LeafLock logic

**When uncertain: STOP and ask** → "Does shadcn have this component?" Check docs first!

## Testing Guidelines
- Backend unit tests live beside code (`*_test.go`); flag integration suites with `Integration` in the test name and start dependencies via `make test-db-up`. Run `make test-ci` before submitting PRs.
- Keep coverage artifacts (`coverage.out`, `coverage.html`) in `backend/` and review them when touching auth, crypto, or storage flows.
- Frontend uses Vitest (`pnpm test`, `pnpm test:coverage`); name specs `<feature>.test.tsx` and keep snapshots stable.

## Commit & Pull Request Guidelines
- Favor Conventional Commit prefixes (`feat:`, `fix:`, `chore(deps):`) and scopes that mirror directories, e.g., `feat(frontend): add passkey modal`.
- Squash noisy work-in-progress commits; each PR should focus on one change, link issues, list manual checks, and attach screenshots for UI updates.
- Highlight configuration changes (env vars, secrets, helm values) in the PR body and reference `SECURITY.md` for disclosure or hardening tasks.

## Additional References
- Check `CLAUDE.md` for automation rules, documentation policy, and environment expectations.

---

# 📋 ENFORCEMENT MECHANISMS SUMMARY

## **Three Layers of Enforcement**

### **1. Pre-Commit Hooks (Local)**
**Location**: `.pre-commit-config.yaml`  
**Commands Run Automatically on Every Commit:**

```bash
# Layer 1: File type enforcement
cd frontend && scripts/check-no-jsx.sh          # ❌ FAILS on .jsx files
cd frontend && scripts/check-frontend-docs.sh   # ❌ FAILS on prohibited .md files

# Layer 2: UI architecture enforcement  
cd frontend && scripts/check-shadcn-compliance.sh  # ❌ FAILS on custom UI violations

# Layer 3: Code quality
pnpm run lint                                    # ❌ FAILS on ESLint errors
pnpm run format:check                           # ❌ FAILS on formatting issues
```

**To Bypass:** Not possible - these block commits entirely

### **2. CI/CD Pipeline (Remote)**
**Location**: `.github/workflows/ci-frontend-quality.yml`  
**Runs on:** Every PR and push to main/develop

**Enforcement Steps:**
1. ✅ Install dependencies
2. 🚨 **check-no-jsx.sh** - Blocks PR if .jsx found
3. 🚨 **check-shadcn-compliance.sh** - Blocks PR if custom UI detected
4. 🚨 **check-frontend-docs.sh** - Blocks PR if prohibited docs found
5. ✅ ESLint
6. ✅ Prettier formatting
7. ✅ TypeScript compilation

**Result:** PR cannot be merged until all checks pass

### **3. Manual Validation (Developer Responsibility)**
**Command**: `cd frontend && pnpm check-all`  
**When to Run**: Before EVERY commit

**What it Checks:**
1. ✅ .jsx file prohibition
2. ✅ shadcn/ui compliance
3. ✅ Documentation policy
4. ✅ TypeScript types
5. ✅ ESLint rules
6. ✅ Prettier formatting
7. ✅ All unit tests pass

---

## **🚨 What Gets You BLOCKED**

### **Immediate Pre-Commit Failure:**
- Creating `.jsx` files (must be `.tsx` only)
- Building custom `<button>`, `<input>`, `<select>` instead of using shadcn
- Creating pointless wrapper components: `export function MyButton(props) { return <Button {...props} /> }`
- Writing standalone `.md` files in `frontend/src/` or component directories
- Using `any` type in TypeScript
- Adding `console.log` statements

### **CI Pipeline Failure:**
- All of the above (if pre-commit is bypassed)
- ESLint errors
- TypeScript compilation errors
- Prettier formatting violations

### **Code Review Red Flags:**
- Components that don't use shadcn/ui when available
- New CSS files (Tailwind only)
- Unexplained wrapper components
- Missing keyboard navigation
- No loading states on async operations

---

## **✅ Approved Patterns**

### **DO THIS:**
```tsx
// ✅ Direct shadcn usage
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'

export function LoginForm() {
  return (
    <Card>
      <Button>Sign In</Button>
    </Card>
  )
}

// ✅ Business logic wrapper (allowed)
export function EncryptionStatus({ isEncrypted }: { isEncrypted: boolean }) {
  return (
    <Badge variant={isEncrypted ? "default" : "destructive"}>
      {isEncrypted ? "🔒 Encrypted" : "⚠️ Not Encrypted"}
    </Badge>
  )
}
```

### **NEVER DO THIS:**
```tsx
// ❌ Custom button (FORBIDDEN)
export function CustomButton({ children, ...props }) {
  return <button className="bg-blue-500 px-4 py-2" {...props}>{children}</button>
}

// ❌ Pointless wrapper (FORBIDDEN)
export function MyButton(props) {
  return <Button {...props} />  // Why wrap? Use Button directly!
}

// ❌ Raw HTML (FORBIDDEN)
<input type="text" className="border p-2" />  // Use <Input /> from shadcn
```

---

## **🛠️ Available Commands**

### **Install Missing shadcn Components:**
```bash
cd frontend
pnpm dlx shadcn@latest add button input card dialog  # Install specific
pnpm dlx shadcn@latest add                           # Interactive menu
```

### **Run All Checks:**
```bash
cd frontend
pnpm check-all        # Full validation (recommended before commits)
pnpm check-all:quick  # Fast validation (skip heavy tests)
```

### **Individual Checks:**
```bash
sh scripts/check-no-jsx.sh           # Check for .jsx files
sh scripts/check-shadcn-compliance.sh # Check UI compliance
sh scripts/check-frontend-docs.sh    # Check docs policy
pnpm run typecheck                   # TypeScript only
pnpm run lint                        # ESLint only
pnpm run format:check               # Formatting only
```

---

## **📚 Quick Reference: When to Use Which shadcn Component**

**Need a button?** → `pnpm dlx shadcn@latest add button`  
**Need a form input?** → `pnpm dlx shadcn@latest add input`  
**Need a card?** → `pnpm dlx shadcn@latest add card`  
**Need a dialog/modal?** → `pnpm dlx shadcn@latest add dialog`  
**Need a dropdown?** → `pnpm dlx shadcn@latest add dropdown-menu`  
**Need a table?** → `pnpm dlx shadcn@latest add table`  

**Full list:** <https://ui.shadcn.com/docs/components>

---

## **❓ What If shadcn Doesn't Have What I Need?**

1. **Check again:** Go to <https://ui.shadcn.com/docs> and search thoroughly
2. **Check Radix:** Many shadcn components are based on Radix - the pattern might exist
3. **Ask:** Stop and ask if you're truly building something unique
4. **Build ONLY if:** It's pure LeafLock business logic (e.g., EncryptionIndicator, NoteEditor)

**Bottom line:** 99% of UI needs are covered by shadcn. When in doubt, **check the docs first**.

---

**Remember:** These enforcement mechanisms exist to ensure LeafLock maintains a consistent, accessible, and high-quality UI. The rules are strict because user experience is our #1 priority. 🎯
