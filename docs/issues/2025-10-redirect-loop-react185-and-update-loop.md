Title: Login redirect loop and React 185/update-depth errors on dashboard

Status
- Current: Site stable with Sidebar only; NoteEditor disabled temporarily.
- Scope: Frontend (Vite + React/TanStack Router + Zustand stores).

Environment
- PR preview: `https://frontend-leaflock-pr-363.up.railway.app/login`
- Frontend build: Vite, minification disabled globally (prod-equivalent) to avoid ref/name mangling.
- React StrictMode: disabled (removed double-invoke during mount/effects).

Observed Failures
1) Initial symptom: Redirect loop around /login and /. Root causes found:
   - Dashboard redirecting to /login while auth store user persisted but token missing.
   - 401 redirect handler triggering navigations on auth routes.

2) After fixing redirects, post-login crash with “Minified React error #185” → later surfaced as
   “Maximum update depth exceeded” (in dev build) during dashboard mount.

What we changed (chronological, highlights)
- Router/auth hardening
  - Added `safeRedirectToLogin()` and `isOnAuthRoute()` utility with debounce and auth-route guard.
  - Dashboard redirect now checks auth routes before navigating.
  - On login page, ensured auth store is initialized and clears stale in-memory user when token is missing.

- API 401 handling
  - Centralized in `ApiClient`: clear storage, skip redirect on auth routes, and debounce redirects.

- Minification and build mode
  - Disabled minification globally; later tried dev-like build to surface full stacks.
  - StrictMode removed to avoid double-mount/effect churn during debugging.

- Component isolation to track React 185/update-depth loop
  - Removed dropdown/header extras; later removed ThemeToggle.
  - Temporarily removed global error boundary/Toaster.
  - Simplified dashboard content → then re-enabled incrementally.
  - Result: Update loop persisted even with header extras removed; narrowed to dashboard/notes/editor path.

- Stable baseline achieved
  - Dashboard restored with Sidebar only → stable.
  - Re-enabling NoteEditor reintroduced “Maximum update depth exceeded”.
  - We rolled back NoteEditor again to keep PR usable.

Editor-specific mitigations attempted
- NoteEditor
  - Decrypt effect now conditionally sets state only when values actually change.
  - Autosave debounced; added last-saved plaintext snapshot (title/content/tags) to skip no-op saves.
  - Despite improvements, update-depth error still triggers when editor is enabled in PR env; disabled again for stability.

Hypothesis (current)
- A render cycle between NoteEditor state updates and store updates (notesStore.updateNote/selectNote) can create a loop under certain conditions (e.g., initial data load + initializeDefaultNote + editor onUpdate). Minification previously masked/changed behavior; with minify off, we still can hit a loop.
- Potential secondary contributors: TanStack Router route render mapping (stack shows setRef/map); however, isolating down to editor path strongly implicates editor/save/decrypt chain.

What’s working now
- Login → Dashboard (with Sidebar only) is stable.
- Notes bootstrap runs once (guarded ref), no redirect loop.

Next steps (implementation plan)
1) Add a one-time editor boot gate in Dashboard to mount NoteEditor only after notes bootstrap completes (and only once), then test.
2) In NoteEditor:
   - Make onUpdate a pure compare-and-save: skip save when HTML unchanged vs editor doc and vs last saved snapshot.
   - Ensure setState in decrypt/useEffect never runs redundantly: compare before set.
   - Confirm no code path calls selectNote during autosave.
3) In notesStore:
   - Verify `initializeDefaultNote` does not immediately trigger another write that causes editor onUpdate → save → updateNote → notes change → editor effect loop.
   - Consider deferring `initializeDefaultNote` with microtask or guarding with lastSelected ref to prevent rapid reselection.
4) Re-enable NoteEditor behind a feature flag (env var), then soak test in PR.

Request for help / review
- If someone can reproduce locally with prod-like build and share a precise stack when NoteEditor is enabled, please attach logs.
- Pay special attention to any places where we:
  - Save immediately after decrypt (shouldn’t happen)
  - Change selection while autosave debounce is pending
  - Mutate tags/content arrays/strings leading to identity changes each render

References (key diffs already merged)
- `frontend/src/lib/navigation.ts`: safe redirect helpers
- `frontend/src/services/api/apiClient.ts`: 401 handling with debounce and auth-route guard
- `frontend/src/stores/authStore.ts`: clear stale user when no token; guarded initialize
- `frontend/src/router.tsx`: guarded dashboard init; notes bootstrap once; staged dashboard enablement
- `frontend/src/components/dashboard/note-editor.tsx`: decrypt conditional sets; last-saved snapshot for autosave

PR preview to validate
- `https://frontend-leaflock-pr-363.up.railway.app/login`

Current mitigation in PR
- Full app usable post-login with Sidebar; `NoteEditor` temporarily disabled until loop is fixed.

Reproduction steps (current)
1) Open PR preview, login with a valid user.
2) Navigate to `/`.
3) When `NoteEditor` is enabled, the app crashes with “Maximum update depth exceeded”. With `NoteEditor` disabled, the dashboard stays stable.

Representative stacks (captured)
- React 185 / minified path (prod-like):
  - getRootForUpdatedFiber → enqueueConcurrentHookUpdate → dispatchSetState → setRef → Array.map
- Dev path (unminified message):
  - “Maximum update depth exceeded … a component repeatedly calls setState … during update.”

Config matrix we tried
- Minification: OFF globally (prod-equivalent) → still reproducible with editor on.
- StrictMode: OFF → reduces double-invoke but loop persists when editor is on.
- Error boundary + Toaster: removed → same loop.
- Header dropdown/theme toggle: removed → not a factor.
- Router Suspense/lazy vs direct imports: tried both; not root cause.

Components toggled (results)
- Sidebar only: OK (stable)
- Sidebar + Notes bootstrap only: OK (stable)
- Sidebar + NoteEditor: FAIL (update depth loop)

Commits in this investigation (selection)
- Harden redirects/401: cd14b68, 0638d7f
- Disable minification globally: 92a5e9b
- StrictMode removal: 351d71c
- Dashboard staged rollouts: 35f7370, 610c5e5, 4b77799, e2e3862
- Notes bootstrap guard: 001651f
- NoteEditor loop mitigations: 70dd766

Suspect loop edges (to inspect)
- NoteEditor onUpdate → notesStore.updateNote → store.set() → selectedNote changes → decrypt effect → state set → onUpdate again.
- initializeDefaultNote timing relative to editor mount.

Concrete follow-ups (checklist)
- [ ] Mount editor only after `loadData` + `initializeDefaultNote` resolve, and only once per route mount.
- [ ] Ensure `updateNote` does not re-emit a value identical to the current `selectedNote` reference (deep-equal check prior to `set`).
- [ ] In `selectNote`, avoid writing localStorage on identical selection; skip set when id/refs match.
- [ ] In `NoteEditor`, compare editor.getHTML() with incoming content before calling `setContent`/`setDisplayContent` (added, verify).
- [ ] Debounce editor onChange and cancel pending save when selection changes.
- [ ] Add telemetry console markers around save/decrypt/select flows to pinpoint the loop edge.

Owner/coordination
- Frontend: continue with guarded editor mount and store-level no-op guards.
- If needed, add a feature flag to enable editor per-session to A/B test the next fix in PR.
