## Problem

The `unit-tests.yml` GitHub Actions workflow is failing because it cannot fetch Railway deployment URLs to test the auto-deployed services.

**Original Issue**: Empty `BACKEND_URL` and `FRONTEND_URL` environment variables caused health check failures.

```
🧪 Testing Railway backend at:
⏳ Backend not ready yet... (1/60)
...
❌ Backend failed to respond after 5 minutes
```

## Root Causes Identified

1. **Original workflow** used hardcoded `RAILWAY_BACKEND_URL` and `RAILWAY_FRONTEND_URL` secrets that were never configured
2. Railway auto-deploys via GitHub integration, but workflow needs to dynamically fetch URLs
3. Environment-specific deployments (PR previews vs main branch) require environment-agnostic queries
4. Secret naming: Should be `RAILWAY_TOKEN_ACCOUNT` not `RAILWAY_TOKEN`

## Solutions Attempted

### ✅ Attempt 1: Railway CLI with project context
**Commit**: `812fc3e`
- Installed Railway CLI in workflow
- Used `railway status --json` to fetch URLs
- **Result**: Failed with "Project Token not found" - CLI requires project context/config

### ✅ Attempt 2: Railway GraphQL API with environment ID
**Commit**: `ec38415`
- Switched to direct GraphQL API calls
- Required `RAILWAY_TOKEN`, `RAILWAY_PROJECT_ID`, `RAILWAY_ENVIRONMENT_ID`
- **Result**: Failed - environment ID changes between PRs and main branch (not sustainable)

### ✅ Attempt 3: Environment-agnostic GraphQL queries
**Commit**: `4a73fdd`
- Query all recent deployments (last 20) for the project
- Filter by service name and deployment status
- No environment ID required
- **Result**: Failed with "Project not found" - wrong secret name

### ✅ Attempt 4: Added diagnostics
**Commit**: `d85ca97`
- Added secret verification step
- Added project listing for debugging
- Enhanced error messages with troubleshooting
- **Result**: Improved debugging but still using wrong secret name

### ✅ Attempt 5: Correct secret name
**Commit**: `250020d` (current)
- Changed `RAILWAY_TOKEN` → `RAILWAY_TOKEN_ACCOUNT`
- Updated all references in both backend and frontend jobs
- **Status**: Pending test

## Current Implementation

**Branch**: `claude/fix-unit-tests-011CUnQpdmhjVc3gZCqEds6n`

### Workflow Steps:
1. Wait 3 minutes for Railway auto-deployment
2. Verify secrets are configured (`RAILWAY_TOKEN_ACCOUNT`, `RAILWAY_PROJECT_ID`)
3. List all projects accessible to token (for debugging)
4. Query Railway GraphQL API for recent deployments
5. Filter by service name (backend/frontend) and status (SUCCESS/ACTIVE)
6. Extract deployment URLs
7. Poll health endpoints until ready (5 min timeout)

### GraphQL Query:
```graphql
query {
  project(id: "PROJECT_ID") {
    deployments(first: 20) {
      edges {
        node {
          id
          staticUrl
          status
          environment { name }
          service { name }
        }
      }
    }
  }
}
```

### Required GitHub Secrets:
- `RAILWAY_TOKEN_ACCOUNT` - Railway account API token (from railway.app/account/tokens)
- `RAILWAY_PROJECT_ID` - Railway project UUID (from project settings or URL)

## Next Steps

- [ ] Verify `RAILWAY_TOKEN_ACCOUNT` and `RAILWAY_PROJECT_ID` secrets are configured in GitHub
- [ ] Test workflow runs successfully on this PR
- [ ] Verify it works for both PR previews and main branch deployments
- [ ] Consider reducing wait time if deployments are consistently faster
- [ ] Merge PR if all tests pass

## Testing Notes

The workflow should:
- ✅ Work without Railway CLI installation
- ✅ Work for PR preview environments
- ✅ Work for main branch production environment
- ✅ Provide clear error messages if secrets are misconfigured
- ✅ Show available projects/deployments for debugging
- ✅ Timeout gracefully if deployments fail

## Files Changed

- `.github/workflows/unit-tests.yml` - Main workflow file
- `CLAUDE.md` - Updated Railway compatibility notes
