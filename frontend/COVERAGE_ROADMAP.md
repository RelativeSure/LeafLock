# Frontend Code Coverage Roadmap

## Current Status

**Current Coverage: ~17.5%**
**Target Coverage: 50%**
**Gap to Close: 32.5%**

## Progress Summary

### Tests Added in This Session

#### Component Tests

1. **UI Components**
   - ✅ `button.test.tsx` - Button component (100% coverage)
   - ✅ `switch.test.tsx` - Switch component (100% coverage)
   - ✅ `input.test.tsx` - Input component (100% coverage)
   - ✅ `card.test.tsx` - Card components (100% coverage)
   - ✅ `badge.test.tsx` - Badge component (100% coverage)
   - ✅ `alert.test.tsx` - Alert components (partial - some failures)
   - ✅ `avatar.test.tsx` - Avatar components (partial - some failures)
   - ✅ `separator.test.tsx` - Separator component (partial)
   - ✅ `skeleton.test.tsx` - Skeleton component (100% coverage)
   - ✅ `label.test.tsx` - Label component (100% coverage)
   - ✅ `theme-toggle.test.tsx` - Theme toggle (existing)

2. **Business Logic Tests**
   - ✅ Enhanced `authStore.test.ts` (100% coverage)
   - ✅ Enhanced `settingsStore.test.ts` (100% coverage)
   - ✅ Enhanced `templatesStore.test.ts` (98.49% coverage)
   - ✅ Partial `notesStore.test.ts` (36.52% coverage - needs expansion)
   - ✅ Initial `apiClient` and service tests added (needs expansion)

3. **Utility Tests**
   - ✅ `utils.test.ts` (100% coverage)
   - ✅ `config.test.ts` (92.38% coverage)
   - ✅ `navigation.test.ts` (100% coverage)
   - ✅ `gravatar-utils.test.ts` (100% coverage)
   - ✅ `permission-utils.test.ts` (100% coverage)
   - ✅ `activity-logger.test.ts` (100% coverage)
   - ⚠️ `encryption-utils.test.ts` (6.88% coverage - complex, needs work)

4. **Form Tests**
   - ✅ `login-form.test.tsx` (comprehensive)
   - ✅ `register-form.test.tsx` (comprehensive)
   - ⚠️ `forgot-password-form.test.tsx` (partial - some skipped tests)

5. **Hook Tests**
   - ✅ `useConfig.test.ts` (100% coverage)
   - ✅ `use-toast.test.ts` (100% coverage)
   - ✅ `use-decrypted-notes.test.ts` (92.85% coverage)

## Files Needing Immediate Attention

### High Priority (0-20% Coverage)

These files would give the biggest coverage boost:

1. **`encryption-utils.ts`** (6.88% coverage)
   - 295 lines, critical business logic
   - Complex encryption/decryption functions
   - **Impact**: ~3-4% total coverage increase if fully tested

2. **`notesStore.ts`** (36.52% coverage)
   - 646 lines, core state management
   - Many untested actions and selectors
   - **Impact**: ~5-6% total coverage increase if fully tested

3. **`apiClient.ts` & service layer** (newly split)
   - Shared HTTP client plus domain services (`authService`, `contentService`, `socialService`, `organizationService`)
   - Many endpoints still lack targeted tests
   - **Impact**: ~6-7% total coverage increase if fully tested

4. **`encryption-context.tsx`** (52% coverage)
   - Provider component for encryption
   - **Impact**: ~1-2% total coverage increase

### Medium Priority (Untested UI Components)

These components have 0% coverage:

1. **Dashboard Components** (0% coverage)
   - `note-editor.tsx` (~300+ lines)
   - `sidebar.tsx` (~200+ lines)
   - `notes-list.tsx`
   - **Impact**: ~8-10% total coverage increase

2. **Settings Components** (0% coverage)
   - `settings-page.tsx` (~180 lines)
   - Various settings sub-components
   - **Impact**: ~2-3% total coverage increase

3. **Management Components** (0% coverage)
   - `folders-tags-page.tsx` (~180 lines)
   - **Impact**: ~1-2% total coverage increase

4. **Admin Components** (0% coverage)
   - `admin-page.tsx`
   - **Impact**: ~1-2% total coverage increase

5. **UI Components** (many at 0%)
   - `alert-dialog.tsx`
   - `dialog.tsx`
   - `dropdown-menu.tsx` (38.41% - partially tested)
   - `select.tsx`
   - `popover.tsx`
   - `tooltip.tsx`
   - `tabs.tsx`
   - `table.tsx`
   - Many others
   - **Impact**: ~5-8% total coverage increase

## Roadmap to 50% Coverage

### Phase 1: Fix Existing Test Issues (Week 1)

**Target: Get to 20% with passing tests**

- [ ] Fix `encryption-utils.test.ts` mock issues
- [ ] Fix `forgot-password-form.test.tsx` timing issues
- [ ] Remove or fix failing UI component tests (alert, avatar)
- [ ] Ensure all existing tests pass

### Phase 2: Core Business Logic (Week 2-3)

**Target: Get to 35%**

- [ ] Complete `encryption-utils.ts` testing (high complexity)
  - Test all encryption/decryption paths
  - Test key derivation
  - Test error handling
- [ ] Expand `notesStore.ts` testing
  - Test all CRUD operations
  - Test filtering and sorting
  - Test trash operations
  - Test sharing operations
- [ ] Expand `apiClient` and service testing
  - Test all API endpoints
  - Test error handling
  - Test authentication flows
  - Test request/response transformations

### Phase 3: Major UI Components (Week 4)

**Target: Get to 45%**

- [ ] Test `note-editor.tsx`
  - Test note creation
  - Test note editing
  - Test TipTap editor integration
  - Test autosave
- [ ] Test `sidebar.tsx`
  - Test navigation
  - Test folder tree
  - Test search
- [ ] Test `notes-list.tsx`
  - Test note rendering
  - Test filtering
  - Test selection

### Phase 4: Settings & Admin (Week 5)

**Target: Get to 50%+**

- [ ] Test `settings-page.tsx`
  - Test all settings sections
  - Test form validation
  - Test settings persistence
- [ ] Test management components
  - Test folder CRUD
  - Test tag CRUD
- [ ] Test admin components
  - Test user management
  - Test system settings

### Phase 5: Remaining UI Components (Ongoing)

**Target: Maintain 50%+, push toward 60-70%**

- [ ] Test all remaining UI primitives
- [ ] Add integration tests
- [ ] Add E2E tests with Playwright

## Quick Wins for Immediate Coverage Boost

To quickly boost coverage from 17.5% to 30%+:

1. **Complete `notesStore.ts` tests** - Would add ~5-6%
2. **Complete `apiClient` + service tests** - Would add ~6-7%
3. **Add basic tests for `note-editor.tsx`** - Would add ~3-4%
4. **Add basic tests for `sidebar.tsx`** - Would add ~2-3%

**Total potential gain: 16-20% → Gets us to 33-37% coverage**

## Testing Strategy

### Unit Tests

- Focus on isolated component and function testing
- Mock external dependencies
- Test edge cases and error handling

### Integration Tests

- Test component interactions
- Test state management flow
- Test API integration

### E2E Tests (Playwright)

- User workflows
- Critical paths
- Cross-browser testing

## Commands

```bash
# Run all tests
pnpm run test

# Run tests with coverage
pnpm run test:coverage

# Run tests in watch mode
pnpm run test:watch

# Run tests with UI
pnpm run test:ui

# Run E2E tests
pnpm run test:playwright
```

## Notes

- Current threshold set to 50% in `vite.config.ts`
- Coverage reports generated in `./coverage` directory
- Some tests are currently skipped due to timing issues (`.skip`)
- Encryption tests have mock initialization issues that need fixing
- Focus on business logic tests first for maximum coverage impact

## Test File Naming Convention

- Unit tests: `[component-name].test.tsx` or `[file-name].test.ts`
- Place in `__tests__` folder adjacent to source files
- Integration tests: `[feature].integration.test.tsx`
- E2E tests: `tests/e2e/[feature].spec.ts`

## Coverage Configuration

Located in `vite.config.ts`:

```typescript
coverage: {
  provider: 'v8',
  reporter: ['text', 'html', 'json-summary', 'lcov'],
  reportsDirectory: './coverage',
  thresholds: {
    statements: 50,
    branches: 50,
    functions: 50,
    lines: 50,
  },
  all: true,
}
```

## Next Steps

1. ✅ Documentation created (this file)
2. ⬜ Fix failing tests in Phase 1
3. ⬜ Implement Phase 2 tests for core business logic
4. ⬜ Continue with Phases 3-5
5. ⬜ Regularly run coverage reports to track progress
6. ⬜ Update this document as coverage improves

---

**Last Updated**: [Current Date]
**Current Coverage**: 17.5%
**Target Coverage**: 50%
**Status**: In Progress - Phase 1
