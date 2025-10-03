#!/usr/bin/env bash
# Test MegaLinter linters individually
# Usage: ./scripts/test-linters.sh [LINTER_NAME]
# Example: ./scripts/test-linters.sh GO_GOLANGCI_LINT

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Linters to test
LINTERS=(
    "GO_GOLANGCI_LINT"
    "TYPESCRIPT_ES"
    "TYPESCRIPT_PRETTIER"
    "JAVASCRIPT_ES"
    "JAVASCRIPT_PRETTIER"
    "BASH_SHELLCHECK"
    "DOCKERFILE_HADOLINT"
    "YAML_YAMLLINT"
    "JSON_JSONLINT"
    "MARKDOWN_MARKDOWNLINT"
    "SQL_SQLFLUFF"
    "REPOSITORY_SECRETLINT"
)

# Function to test a single linter
test_linter() {
    local linter="$1"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}Testing linter: ${linter}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    if npx mega-linter-runner -e "$linter" 2>&1 | tee "/tmp/megalinter-${linter}.log"; then
        echo -e "${GREEN}✅ ${linter} passed${NC}"
        return 0
    else
        echo -e "${RED}❌ ${linter} failed${NC}"
        echo -e "${YELLOW}See log: /tmp/megalinter-${linter}.log${NC}"
        return 1
    fi
}

# Main logic
if [ $# -eq 0 ]; then
    # Test all linters
    echo -e "${BLUE}Testing all ${#LINTERS[@]} linters...${NC}"
    echo ""

    passed=0
    failed=0

    for linter in "${LINTERS[@]}"; do
        if test_linter "$linter"; then
            ((passed++))
        else
            ((failed++))
        fi
        echo ""
    done

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}Passed: ${passed}/${#LINTERS[@]}${NC}"
    echo -e "${RED}Failed: ${failed}/${#LINTERS[@]}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    if [ "$failed" -eq 0 ]; then
        echo -e "${GREEN}🎉 All linters passed!${NC}"
        exit 0
    else
        echo -e "${RED}⚠️  Some linters failed. Check logs in /tmp/megalinter-*.log${NC}"
        exit 1
    fi
else
    # Test specific linter
    linter="$1"

    # Check if linter is valid
    if [[ ! " ${LINTERS[*]} " =~ ${linter} ]]; then
        echo -e "${RED}Error: Unknown linter '${linter}'${NC}"
        echo -e "${YELLOW}Available linters:${NC}"
        for l in "${LINTERS[@]}"; do
            echo "  - $l"
        done
        exit 1
    fi

    test_linter "$linter"
fi
