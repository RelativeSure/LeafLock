#!/bin/bash
cd /home/rasmus/repos/LeafLock/backend

# Run tests and generate coverage profile
echo "Running Go tests with coverage..."
go test ./auth -run "^Test(EnhancedClerkMiddleware_NoAuth|EnhancedClerkMiddleware_InvalidFormat|EnhancedClerkMiddleware_Debug|ValidateClerkTokenEnhancedWithDebug_Not|GetDebugInfo|IsClerkInitialized|SafeClerkMiddleware|IsTokenExpired|MinFunction|LoadConfig|GetEnv|Config|NewClerkErrorHandler|CategorizeClerkError|SecureClerkError)" -coverprofile=coverage_passing.out -covermode=atomic

# Show coverage breakdown by file
echo ""
echo "Coverage breakdown by file:"
go tool cover -func=coverage_passing.out | grep -E "(clerk_middleware_enhanced|clerk_error_handler|config|common)" | grep -v "100.0%"

# Show total coverage
echo ""
echo "Total coverage:"
go tool cover -func=coverage_passing.out | grep total

# Test utils
echo ""
echo "Testing utils package..."
go test ./utils -run "^Test(NewSecurity|Log|Redact|Structured)" -coverprofile=utils_coverage.out -covermode=atomic

echo ""
echo "Utils coverage:"
go tool cover -func=utils_coverage.out | grep "security_logger"