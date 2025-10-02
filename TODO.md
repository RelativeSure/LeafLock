# LeafLock TODO

## 🐛 Critical Bug: Async Initialization Crashes

**Status**: NEEDS FIX
**Priority**: HIGH

### Problem Description
When `LAZY_INIT_ADMIN=true` and `ASYNC_TEMPLATE_SEED=true` are set in Coolify, the backend crashes during deployment. The async goroutines introduced in commit `3b4bfa50b52af94d7e8742fd86178e025c446146` have unhandled panics that crash the entire backend process.

### Current Workaround
Using synchronous mode with extended health check timeouts:
- `LAZY_INIT_ADMIN=true` (async mode - desired but crashes)
- `ASYNC_TEMPLATE_SEED=true` (async mode - desired but crashes)
- Health check timeouts increased to 60s start_period to accommodate slower initialization

### Root Cause Analysis
- Async goroutines for admin user creation, template seeding, and other initialization tasks have unhandled panics
- Goroutines crash without proper error handling/recovery
- When goroutines panic, the entire backend process terminates

### Failed Attempt
Tried adding panic recovery with `defer recover()` but got Go compile errors:
```plaintext
./main.go:6878:13: use of package recover not in selector
```

### Next Steps to Fix
1. **Debug the actual panic sources**:
   - Add detailed logging to identify what's causing panics in async functions
   - Check database connection issues during async initialization
   - Look for race conditions in shared resources

2. **Implement proper panic recovery**:
   - Fix the Go syntax error in panic recovery implementation
   - Ensure `readyState.markXXXReady()` is always called
   - Add proper error context and stack traces

3. **Test async mode thoroughly**:
   - Test in local Docker environment first
   - Verify all async initialization completes without crashes
   - Ensure health checks work correctly with async mode

4. **Alternative approaches**:
   - Consider sequential async initialization (one goroutine at a time)
   - Add proper synchronization between dependent initialization tasks
   - Implement timeout handling for async operations

### Files Involved
- `backend/main.go` - Main async initialization logic (lines ~6874-6950)
- `docker-compose.coolify.yml` - Health check configuration
- Admin service functions and template seeding functions

### Expected Outcome
- Async mode works without crashes (`LAZY_INIT_ADMIN=true`, `ASYNC_TEMPLATE_SEED=true`)
- Fast startup times (15-30 seconds instead of 60+ seconds)
- Reliable deployments in Coolify
- Health checks pass consistently

---

*Created: 2025-09-25*
*Last Updated: 2025-09-25*