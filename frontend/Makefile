.PHONY: clean-caches check-all-fast help

# Default target
help:
	@echo "Available targets:"
	@echo "  clean-caches    - Clean various caches (pnpm, npm, system)"
	@echo "  check-all-fast  - Run check-all with increased timeout"
	@echo "  help            - Show this help message"

# Clean various caches to free up disk space
clean-caches:
	@echo "Cleaning pnpm store..."
	@pnpm store prune
	@echo "Cleaning node_modules cache..."
	@rm -rf node_modules/.vite
	@echo "Cleaning test coverage..."
	@rm -rf coverage
	@echo "Cleaning dist folder..."
	@rm -rf dist
	@echo "Cleaning TypeScript build cache..."
	@rm -f tsconfig.tsbuildinfo
	@echo "Cleaning npm cache (if npm is available)..."
	@npm cache clean --force 2>/dev/null || true
	@echo "All caches cleaned successfully!"

# Run check-all with a longer timeout
check-all-fast:
	@echo "Running check-all with extended timeout..."
	@pnpm run type-check && \
	pnpm run lint && \
	pnpm run format:check && \
	pnpm run test

# Check disk space
disk-space:
	@df -h | grep -E "(Filesystem|/dev/sdd)"
	@echo ""
	@du -sh . 2>/dev/null || echo "Cannot calculate current directory size"
