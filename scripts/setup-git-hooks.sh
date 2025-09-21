#!/bin/bash

# Git Hooks Setup Script
# Configures comprehensive pre-commit hooks for code quality and security

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Create comprehensive pre-commit hook
create_pre_commit_hook() {
    log_info "Creating comprehensive pre-commit hook..."
    
    mkdir -p .git/hooks
    
    cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🔍 Running pre-commit checks...${NC}"

# Initialize error counter
ERRORS=0

# Check for secrets and sensitive files
echo -e "${BLUE}🔐 Checking for secrets and sensitive files...${NC}"

# Check if .env file is being committed
if git diff --cached --name-only | grep -E '^\.env$'; then
    echo -e "${RED}❌ .env file contains secrets and should not be committed!${NC}"
    echo -e "${YELLOW}Run: git reset HEAD .env${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check for other sensitive files
if git diff --cached --name-only | grep -E '\.(key|pem|p12|pfx|crt)$'; then
    echo -e "${RED}❌ Certificate/key files detected in commit:${NC}"
    git diff --cached --name-only | grep -E '\.(key|pem|p12|pfx|crt)$'
    ERRORS=$((ERRORS + 1))
fi

# Check for hardcoded secrets in staged changes
if git diff --cached | grep -E 'password.*=.*["\047].*["\047]' -i | head -5; then
    echo -e "${RED}❌ Potential hardcoded passwords detected${NC}"
    ERRORS=$((ERRORS + 1))
fi

if git diff --cached | grep -E '(secret|key|token).*=.*["\047].{8,}["\047]' -i | head -5; then
    echo -e "${RED}❌ Potential hardcoded secrets/keys detected${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Backend checks (Go)
if git diff --cached --name-only | grep -q '\.go$'; then
    echo -e "${BLUE}🏗️  Running Go backend checks...${NC}"
    
    cd backend
    
    # Format check
    echo "  📝 Formatting Go code..."
    if ! gofmt -l . | grep -q .; then
        echo -e "    ${GREEN}✓ Go code is properly formatted${NC}"
    else
        echo -e "${RED}    ❌ Go code needs formatting:${NC}"
        gofmt -l .
        echo -e "${YELLOW}    Run: gofmt -s -w .${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Go vet check
    echo "  🔍 Running go vet..."
    if go vet ./...; then
        echo -e "    ${GREEN}✓ go vet passed${NC}"
    else
        echo -e "${RED}    ❌ go vet failed${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Go mod tidy check
    echo "  📦 Checking go.mod and go.sum..."
    cp go.mod go.mod.bak
    cp go.sum go.sum.bak
    go mod tidy
    
    if diff -q go.mod go.mod.bak && diff -q go.sum go.sum.bak; then
        echo -e "    ${GREEN}✓ go.mod and go.sum are tidy${NC}"
        rm go.mod.bak go.sum.bak
    else
        echo -e "${RED}    ❌ go.mod/go.sum need tidying${NC}"
        echo -e "${YELLOW}    Run: go mod tidy${NC}"
        mv go.mod.bak go.mod
        mv go.sum.bak go.sum
        ERRORS=$((ERRORS + 1))
    fi
    
    # Quick unit tests
    echo "  🧪 Running quick unit tests..."
    if go test -short -timeout=30s ./...; then
        echo -e "    ${GREEN}✓ Unit tests passed${NC}"
    else
        echo -e "${RED}    ❌ Unit tests failed${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Security check (if gosec is available)
    if command -v gosec >/dev/null 2>&1; then
        echo "  🛡️  Running security scan..."
        if gosec -quiet ./...; then
            echo -e "    ${GREEN}✓ Security scan passed${NC}"
        else
            echo -e "${YELLOW}    ⚠️  Security scan found issues${NC}"
            # Don't fail commit on security warnings, just notify
        fi
    fi
    
    cd ..
fi

# Frontend checks (Node.js/React)
if git diff --cached --name-only | grep -qE '\.(js|jsx|ts|tsx|json)$'; then
    echo -e "${BLUE}🎨 Running frontend checks...${NC}"
    
    cd frontend
    
    # Lint check
    echo "  🔍 Running ESLint..."
    if npm run lint; then
        echo -e "    ${GREEN}✓ ESLint passed${NC}"
    else
        echo -e "${RED}    ❌ ESLint failed${NC}"
        echo -e "${YELLOW}    Run: npm run lint${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Type check (if TypeScript)
    if [ -f "tsconfig.json" ]; then
        echo "  📝 Running TypeScript check..."
        if npx tsc --noEmit; then
            echo -e "    ${GREEN}✓ TypeScript check passed${NC}"
        else
            echo -e "${RED}    ❌ TypeScript check failed${NC}"
            ERRORS=$((ERRORS + 1))
        fi
    fi
    
    # Quick tests
    echo "  🧪 Running frontend tests..."
    if npm test -- --run; then
        echo -e "    ${GREEN}✓ Frontend tests passed${NC}"
    else
        echo -e "${RED}    ❌ Frontend tests failed${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    
    # Security audit (only high-severity)
    echo "  🛡️  Running security audit..."
    if npm audit --audit-level=high; then
        echo -e "    ${GREEN}✓ No high-severity vulnerabilities${NC}"
    else
        echo -e "${YELLOW}    ⚠️  High-severity vulnerabilities found${NC}"
        echo -e "${YELLOW}    Run: npm audit fix${NC}"
        # Don't fail commit, but notify
    fi
    
    cd ..
fi

# Container checks
if git diff --cached --name-only | grep -qE '(Dockerfile|Containerfile)$'; then
    echo -e "${BLUE}🐳 Running container checks...${NC}"
    
    if command -v hadolint >/dev/null 2>&1; then
        echo "  🔍 Running Dockerfile linting..."
        
        for dockerfile in backend/Dockerfile backend/Containerfile frontend/Dockerfile frontend/Containerfile; do
            if [ -f "$dockerfile" ] && git diff --cached --name-only | grep -q "$dockerfile"; then
                if hadolint "$dockerfile"; then
                    echo -e "    ${GREEN}✓ $dockerfile passed${NC}"
                else
                    echo -e "${YELLOW}    ⚠️  $dockerfile has issues${NC}"
                fi
            fi
        done
    else
        echo -e "${YELLOW}  ⚠️  hadolint not found, skipping Dockerfile checks${NC}"
    fi
fi

# Documentation checks
if git diff --cached --name-only | grep -E '\.(go|js|jsx|ts|tsx)$' | grep -qv test; then
    if ! git diff --cached --name-only | grep -q '\.md$'; then
        echo -e "${YELLOW}⚠️  Code changes detected but no documentation updated${NC}"
        echo -e "${YELLOW}   Consider updating relevant .md files if API changes were made${NC}"
    fi
fi

# Check for TODOs/FIXMEs in production code
if git diff --cached | grep -E 'TODO|FIXME|XXX|HACK' -i; then
    echo -e "${YELLOW}⚠️  TODO/FIXME comments found in staged changes:${NC}"
    git diff --cached | grep -E 'TODO|FIXME|XXX|HACK' -i | head -5
    echo -e "${YELLOW}   Consider addressing these before committing${NC}"
fi

# Final result
echo
if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}🎉 All pre-commit checks passed!${NC}"
    echo -e "${GREEN}✅ Commit is ready${NC}"
    exit 0
else
    echo -e "${RED}💥 Pre-commit checks failed with $ERRORS error(s)${NC}"
    echo -e "${RED}❌ Please fix the issues above before committing${NC}"
    echo
    echo -e "${BLUE}Quick fixes:${NC}"
    echo -e "  ${YELLOW}Backend:${NC} cd backend && make fmt vet test-unit"
    echo -e "  ${YELLOW}Frontend:${NC} cd frontend && npm run lint && npm test"
    echo -e "  ${YELLOW}Secrets:${NC} git reset HEAD .env (if applicable)"
    echo
    exit 1
fi
EOF
    
    chmod +x .git/hooks/pre-commit
    log_success "Pre-commit hook created and enabled"
}

# Create pre-push hook
create_pre_push_hook() {
    log_info "Creating pre-push hook for integration checks..."
    
    cat > .git/hooks/pre-push << 'EOF'
#!/bin/bash
set -e

echo -e "\033[0;34m🚀 Running pre-push checks...\033[0m"

# Check if we can build the Docker containers
echo "🐳 Checking container builds..."

if command -v podman >/dev/null 2>&1; then
    CONTAINER_CMD="podman"
elif command -v docker >/dev/null 2>&1; then
    CONTAINER_CMD="docker"
else
    echo -e "\033[1;33m⚠️  Neither podman nor docker found, skipping container checks\033[0m"
    exit 0
fi

# Test backend container build
echo "  🏗️  Testing backend container build..."
cd backend
if $CONTAINER_CMD build -t leaflock-backend-test -f Dockerfile . >/dev/null 2>&1; then
    echo -e "    \033[0;32m✓ Backend container builds successfully\033[0m"
    $CONTAINER_CMD rmi leaflock-backend-test >/dev/null 2>&1 || true
else
    echo -e "    \033[0;31m❌ Backend container build failed\033[0m"
    exit 1
fi
cd ..

# Test frontend container build
echo "  🎨 Testing frontend container build..."
cd frontend
if $CONTAINER_CMD build -t leaflock-frontend-test -f Dockerfile . >/dev/null 2>&1; then
    echo -e "    \033[0;32m✓ Frontend container builds successfully\033[0m"
    $CONTAINER_CMD rmi leaflock-frontend-test >/dev/null 2>&1 || true
else
    echo -e "    \033[0;31m❌ Frontend container build failed\033[0m"
    exit 1
fi
cd ..

echo -e "\033[0;32m🎉 Pre-push checks passed!\033[0m"
EOF
    
    chmod +x .git/hooks/pre-push
    log_success "Pre-push hook created and enabled"
}

# Create commit message template and hook
create_commit_msg_hook() {
    log_info "Setting up commit message template and validation..."
    
    # Create commit message template
    cat > .gitmessage << 'EOF'
# Title: Brief description (50 chars or less)
#
# Body: Explain what and why vs. how (wrap at 72 chars)
#
# Type: feat|fix|docs|style|refactor|test|chore
# Scope: backend|frontend|docker|security|config
#
# Examples:
# feat(backend): add user authentication endpoints
# fix(frontend): resolve login form validation issue  
# docs: update API documentation for v1.2
# security(backend): implement rate limiting
#
# - Use imperative mood in subject line
# - Separate subject from body with blank line
# - Reference issues: Closes #123, Fixes #456
# - Break lines at 72 characters in body
EOF
    
    git config commit.template .gitmessage
    
    # Create commit message validation hook
    cat > .git/hooks/commit-msg << 'EOF'
#!/bin/bash

commit_regex='^(feat|fix|docs|style|refactor|test|chore|security)(\([a-z]+\))?: .{1,50}'

if ! grep -qE "$commit_regex" "$1"; then
    echo "❌ Invalid commit message format!"
    echo ""
    echo "Format: type(scope): description"
    echo ""
    echo "Types: feat, fix, docs, style, refactor, test, chore, security"
    echo "Scopes: backend, frontend, docker, security, config"
    echo ""
    echo "Examples:"
    echo "  feat(backend): add user authentication"
    echo "  fix(frontend): resolve login validation bug"
    echo "  docs: update README installation steps"
    echo ""
    exit 1
fi

# Check commit message length
if [ $(head -1 "$1" | wc -c) -gt 72 ]; then
    echo "❌ Commit message subject line is too long ($(head -1 "$1" | wc -c) > 72)"
    echo "Keep it under 72 characters"
    exit 1
fi
EOF
    
    chmod +x .git/hooks/commit-msg
    log_success "Commit message template and validation created"
}

# Setup secrets baseline
setup_secrets_baseline() {
    log_info "Setting up secrets detection baseline..."
    
    cat > .secrets.baseline << 'EOF'
{
  "version": "1.4.0",
  "plugins_used": [
    {
      "name": "ArtifactoryDetector"
    },
    {
      "name": "AWSKeyDetector"
    },
    {
      "name": "Base64HighEntropyString",
      "limit": 4.5
    },
    {
      "name": "BasicAuthDetector"
    },
    {
      "name": "CloudantDetector"
    },
    {
      "name": "HexHighEntropyString",
      "limit": 3.0
    },
    {
      "name": "JwtTokenDetector"
    },
    {
      "name": "KeywordDetector",
      "keyword_exclude": ""
    },
    {
      "name": "MailchimpDetector"
    },
    {
      "name": "PrivateKeyDetector"
    },
    {
      "name": "SlackDetector"
    },
    {
      "name": "SoftlayerDetector"
    },
    {
      "name": "SquareOAuthDetector"
    },
    {
      "name": "StripeDetector"
    },
    {
      "name": "TwilioKeyDetector"
    }
  ],
  "filters_used": [
    {
      "path": "detect_secrets.filters.allowlist.is_line_allowlisted"
    },
    {
      "path": "detect_secrets.filters.common.is_baseline_file"
    },
    {
      "path": "detect_secrets.filters.common.is_ignored_due_to_verification_policies",
      "min_level": 2
    },
    {
      "path": "detect_secrets.filters.heuristic.is_indirect_reference"
    },
    {
      "path": "detect_secrets.filters.heuristic.is_likely_id_string"
    },
    {
      "path": "detect_secrets.filters.heuristic.is_lock_file"
    },
    {
      "path": "detect_secrets.filters.heuristic.is_not_alphanumeric_string"
    },
    {
      "path": "detect_secrets.filters.heuristic.is_potential_uuid"
    },
    {
      "path": "detect_secrets.filters.heuristic.is_prefixed_with_dollar_sign"
    },
    {
      "path": "detect_secrets.filters.heuristic.is_sequential_string"
    },
    {
      "path": "detect_secrets.filters.heuristic.is_swagger_file"
    },
    {
      "path": "detect_secrets.filters.heuristic.is_templated_secret"
    }
  ],
  "results": {},
  "generated_at": "2025-01-01T00:00:00Z"
}
EOF
    
    log_success "Secrets detection baseline created"
}

# Main function
main() {
    echo -e "${BLUE}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║                 🪝 LEAFLOCK GIT HOOKS SETUP 🪝                     ║
║                                                                ║
║     Comprehensive code quality and security automation        ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    # Check if we're in a git repository
    if [ ! -d ".git" ]; then
        log_error "This script must be run from the root of a git repository"
        exit 1
    fi
    
    log_info "Setting up comprehensive Git hooks for LeafLock project..."
    
    create_pre_commit_hook
    create_pre_push_hook
    create_commit_msg_hook
    setup_secrets_baseline
    
    # Install tools recommendations
    echo
    log_info "Recommended additional tools for enhanced experience:"
    echo -e "  ${YELLOW}Go security scanner:${NC} go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"
    echo -e "  ${YELLOW}Dockerfile linter:${NC} brew install hadolint # or see hadolint.github.io/hadolint/"
    echo -e "  ${YELLOW}Pre-commit framework:${NC} pip install pre-commit && pre-commit install"
    echo -e "  ${YELLOW}Secrets detection:${NC} pip install detect-secrets"
    echo
    
    log_success "Git hooks setup completed successfully!"
    echo
    log_info "Your repository now has:"
    echo -e "  ${GREEN}✓${NC} Pre-commit hooks for code quality and security"
    echo -e "  ${GREEN}✓${NC} Pre-push hooks for container build verification"
    echo -e "  ${GREEN}✓${NC} Commit message format validation"
    echo -e "  ${GREEN}✓${NC} Secrets detection configuration"
    echo
    log_info "All commits will now be automatically validated for:"
    echo -e "  • Go code formatting, vetting, and testing"
    echo -e "  • Frontend linting, type checking, and testing"
    echo -e "  • Security vulnerabilities and secret detection"
    echo -e "  • Container build verification"
    echo -e "  • Documentation freshness"
    echo
}

main "$@"
